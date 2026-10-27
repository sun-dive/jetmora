<?php
// © 2026 sun-dive — Apache License 2.0.
//
// Ticks of a covenant thread, built and judged by the PHP JF interpreter, for basic/test/thread.mjs.
// Reads JSON from stdin: { keys: { name: seedHex }, cases: [ case, … ] }, a case being
//   { script: hex,  the tip's locking script
//     value: n,     the tip's value (the tick count)
//     seq: n,       the tick's nSequence
//     outputs: [ { value: n, locking: hex }, … ],
//     unlock: { kind: 'sign', key: name, flip?: bool, msgFlip?: bool, extra?: hex, longSig?: bool,
//               swap?: bool, onlySig?: bool, lit?: bool } | { kind: 'raw', hex },
//     version?: n,   the entry's nVersion, JF revision 3 when absent
//     tamper?: bool  the successor's value changed after the tick was signed }
// and writes, per case, the preimage, the unlocking script, the verdict of CovenantThread::judge, and asSigned:
// verifyTick's verdict on the preimage that was signed. A tick this host cannot judge (its lock declares no version, or
// one this host does not serve) gives cannotJudge.
// It writes the tick as judged too: entry (its bytes), lock (the tip's script) and value (its 8 bytes), for a judge
// that is given only those (tools/thread.mjs).
// A script given as "hand" is the 7 Sept counter, assembled from verify-wired.php itself.
declare(strict_types=1);
require_once __DIR__ . '/../../server/interpreter-jf.php';
require_once __DIR__ . '/../../server/wallet/jetmora/thread.php';
require_once __DIR__ . '/../../server/dispatch.php';
require_once __DIR__ . '/../../server/jf-asm.php';
require_once __DIR__ . '/../../server/ed25519-sign.php';

function handCounter(): string
{
  $src = (string)file_get_contents(__DIR__ . '/../../server/verify-wired.php');
  if (!preg_match("/const COUNTER_SRC = <<<'ASM'\n(.*?)\nASM;/s", $src, $m)) throw new RuntimeException('COUNTER_SRC not found');
  return jf_asm($m[1]);
}
$HAND = handCounter();
$script = fn(string $h) => $h === 'hand' ? $HAND : hex2bin($h);

/** A jetForth direct push: the opcode is the length, 1..72. */
function push(string $b): string { return chr(strlen($b)) . $b; }
function hash256(string $b): string { return hash('sha256', hash('sha256', $b, true), true); }

$in = json_decode((string)stream_get_contents(STDIN), true);
$keys = [];
foreach ($in['keys'] as $name => $seed) $keys[$name] = [hex2bin($seed), Ed25519Sign::publicKey(hex2bin($seed))];
$genesis = hash('sha256', 'a thread', true);

$out = [];
foreach ($in['cases'] as $c) {
  $S = $script($c['script']);
  $u = $c['unlock'];
  $t = CovenantThread::tick($genesis, 0, $S, pack('P', $c['value']),
    array_map(fn($o) => ['value' => $o['value'], 'locking' => $script($o['locking'])], $c['outputs']),
    $c['seq'],
    function (string $pre) use ($u, $keys): string {
      if ($u['kind'] === 'raw') return hex2bin($u['hex']);
      [$seed, $pub] = $keys[$u['key']];
      $msg = hash256($pre);
      if (!empty($u['msgFlip'])) $msg[0] = chr(ord($msg[0]) ^ 1);
      $sig = Ed25519Sign::sign($msg, $seed);
      if (!empty($u['flip'])) $sig[5] = chr(ord($sig[5]) ^ 1);
      if (!empty($u['longSig'])) $sig .= "\x00";
      if (!empty($u['onlySig'])) return push($sig);
      if (!empty($u['lit'])) return push($sig) . chr(JF_LIT['LIT8']) . "\x20";   // a number where the key belongs
      $s = !empty($u['swap']) ? push($pub) . push($sig) : push($sig) . push($pub);
      return $s . (isset($u['extra']) ? push(hex2bin($u['extra'])) : '');
    }, $c['version'] ?? null);
  if (!empty($c['tamper'])) $t['entry']['outputs'][0]['value'] += 1;
  $unlock = $t['entry']['inputs'][0]['unlocking'];
  $prev = pack('P', $c['value']);
  $r = ['preimage' => bin2hex(Preimage::build($t['entry'], 0, $S, $prev)), 'unlocking' => bin2hex($unlock),
        'asSigned' => InterpreterJF::verifyTick($unlock, $S, $t['preimage'])['accepted'],
        'entry' => bin2hex(CovenantEntry::encode($t['entry'])), 'lock' => bin2hex($S), 'value' => bin2hex($prev)];
  try {
    $v = CovenantThread::judge($t['entry'], 0, $S, $prev);
  } catch (VersionError $e) {
    $out[] = $r + ['accepted' => false, 'cannotJudge' => $e->getMessage()];
    continue;
  }
  $r += ['accepted' => $v['accepted'],
         'result' => isset($v['stack']) ? ['stack' => array_map('strval', $v['stack'])] : ['error' => bin2hex($v['error'])]];
  $out[] = $r;
}
echo json_encode($out);
