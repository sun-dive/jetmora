<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// The PHP side of tools/verify-judge.mjs: what the thread service's own code answers, for the JavaScript to be held to.
// Reads JSON from stdin and writes JSON; bytes are hex throughout, and a value is its 8 raw bytes.
//   php tools/judge-run.php preimage    [{entry: {version, inputs: [{prevEntry, index, sequence}], outputs: [{value, locking}],
//                                         locktime}, input, scriptCode, value}, ...]
//                                       → Preimage::build: [{preimage} | {thrown: class, message}, ...]
//   php tools/judge-run.php judge       [{entry, input, lock, value}, ...], entry as its canonical bytes
//                                       → CovenantThread::judge: [{accepted, stack} | {accepted: false, error}
//                                         | {noVerdict: class, message} | {thrown: class, message}, ...]
//   php tools/judge-run.php ecdsa       [{sig, pub, digest, trailing}, ...] → Secp256k1::verifyDigest: [bool, ...]
//   php tools/judge-run.php ecdsa-sign  [{key, digest}, ...] → Secp256k1::sign and publicKey: [{sig, pub33, pub65}, ...]
//   php tools/judge-run.php counter     → the hex of server/verify-wired.php's counter covenant, assembled from its source
// noVerdict is VersionError or JfHostError: the two the service answers 501 for (server/append.php).
declare(strict_types=1);
require_once __DIR__ . '/../server/wallet/jetmora/thread.php';
require_once __DIR__ . '/../server/interpreter-jf.php';
require_once __DIR__ . '/../server/secp256k1.php';
require_once __DIR__ . '/../server/jf-asm.php';

$mode = $argv[1] ?? '';
if ($mode === 'counter') {
  // the 7 Sept counter, assembled from verify-wired.php itself, as basic/test/thread-ticks.php reads it
  $src = (string)file_get_contents(__DIR__ . '/../server/verify-wired.php');
  if (!preg_match("/const COUNTER_SRC = <<<'ASM'\n(.*?)\nASM;/s", $src, $m)) { fwrite(STDERR, "COUNTER_SRC not found\n"); exit(1); }
  echo bin2hex(jf_asm($m[1]));
  exit(0);
}

$in = json_decode((string)stream_get_contents(STDIN), true);
if (!is_array($in)) { fwrite(STDERR, "stdin is not a JSON list\n"); exit(1); }
$thrown = fn(Throwable $e): array => ['thrown' => get_class($e), 'message' => $e->getMessage()];
$out = [];
foreach ($in as $c) {
  switch ($mode) {
    case 'preimage':
      $e = $c['entry'];
      $entry = ['version' => $e['version'], 'locktime' => $e['locktime'],
        'inputs' => array_map(fn($i) => ['prevEntry' => hex2bin($i['prevEntry']), 'index' => $i['index'],
                                          'unlocking' => '', 'sequence' => $i['sequence']], $e['inputs']),
        'outputs' => array_map(fn($o) => ['value' => hex2bin($o['value']), 'locking' => hex2bin($o['locking'])], $e['outputs'])];
      try { $out[] = ['preimage' => bin2hex(Preimage::build($entry, $c['input'], hex2bin($c['scriptCode']), hex2bin($c['value'])))]; }
      catch (Throwable $x) { $out[] = $thrown($x); }
      break;
    case 'judge':
      try {
        $v = CovenantThread::judge(CovenantEntry::decode(hex2bin($c['entry'])), $c['input'], hex2bin($c['lock']), hex2bin($c['value']));
        $out[] = isset($v['stack']) ? ['accepted' => $v['accepted'], 'stack' => array_map('strval', $v['stack'])]
                                    : ['accepted' => false, 'error' => bin2hex($v['error'])];
      } catch (VersionError | JfHostError $x) {
        $out[] = ['noVerdict' => get_class($x), 'message' => $x->getMessage()];
      } catch (Throwable $x) {
        $out[] = $thrown($x);
      }
      break;
    case 'ecdsa':
      $out[] = Secp256k1::verifyDigest(hex2bin($c['sig']), hex2bin($c['pub']), hex2bin($c['digest']), (bool)($c['trailing'] ?? false));
      break;
    case 'ecdsa-sign':
      $key = hex2bin($c['key']);
      $out[] = ['sig' => bin2hex(Secp256k1::sign($key, hex2bin($c['digest']))),
                'pub33' => bin2hex(Secp256k1::publicKey($key)), 'pub65' => bin2hex(Secp256k1::publicKey($key, false))];
      break;
    default:
      fwrite(STDERR, "mode: preimage, judge, ecdsa, ecdsa-sign or counter\n"); exit(1);
  }
}
echo json_encode($out);
