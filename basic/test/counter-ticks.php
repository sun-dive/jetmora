<?php
// © 2026 sun-dive — Apache License 2.0.
//
// The 7 Sept counter's ticks, built for any covenant script and judged by the PHP JF interpreter.
// Reads JSON from stdin: {"name": hex | null, ...}; null is the hand-written counter, assembled from
// server/verify-wired.php itself. Writes, per name: the script, and per tick its preimage, whether the
// covenant accepted it, and what the interpreter left or raised.
//   accepted = the run ends with exactly one item, and it is non-zero (verify-wired's runCovenant)
declare(strict_types=1);
require_once __DIR__ . '/../../server/jf-asm.php';
require_once __DIR__ . '/../../server/interpreter-jf.php';
require_once __DIR__ . '/../../server/wallet/jetmora/thread.php';
require_once __DIR__ . '/../../server/dispatch.php';

function handCounter(): string
{
  $src = (string)file_get_contents(__DIR__ . '/../../server/verify-wired.php');
  if (!preg_match("/const COUNTER_SRC = <<<'ASM'\n(.*?)\nASM;/s", $src, $m)) throw new RuntimeException('COUNTER_SRC not found');
  return jf_asm($m[1]);
}

function judge(string $script, string $preimage): array
{
  $vm = new InterpreterJF();
  $vm->setPreimage($preimage);
  try {
    $stack = $vm->run($script);
    return ['accepted' => count($stack) === 1 && gmp_sign($stack[0]) !== 0,
            'result' => ['stack' => array_map(fn($g) => gmp_strval($g), $stack)]];
  } catch (Throwable $e) {
    return ['accepted' => false, 'result' => ['error' => bin2hex($e->getMessage())]];
  }
}

$P2PKH = "\x76\xa9\x14" . str_repeat("\x99", 20) . "\x88\xac";
$out = [];
foreach (json_decode((string)stream_get_contents(STDIN), true) as $name => $hex) {
  $S = $hex === null ? handCounter() : hex2bin($hex);
  $genesis = CovenantThread::create(hash('sha256', 'counter source', true), $S, '',
                                    CovenantThread::authorisedHashes([str_repeat("\x02", 33)]));
  // [what the tick is, the tip's value, the successors]
  $cases = [
    ['41 → 42', 41, [[42, $S]]],
    ['41 → 43, a value skipped', 41, [[43, $S]]],
    ['41 → 41, no advance', 41, [[41, $S]]],
    ['41 → 40, backwards', 41, [[40, $S]]],
    ['a successor with a different script', 41, [[42, $P2PKH]]],
    ['an extra output', 41, [[42, $S], [1, "\x51"]]],
    ['the extra output first', 41, [[1, "\x51"], [42, $S]]],
    ['two successors, both the counter', 41, [[42, $S], [42, $S]]],
    ['the successor one byte shorter', 41, [[42, substr($S, 0, -1)]]],
    ['the successor one byte longer', 41, [[42, $S . "\x00"]]],
    ['0 → 1', 0, [[1, $S]]],
    ['2^32-1 → 2^32, a carry', 4294967295, [[4294967296, $S]]],
    ['41 → 42 + 2^32, high bytes changed', 41, [[4294967338, $S]]],
    ['2^63-2 → 2^63-1', PHP_INT_MAX - 1, [[PHP_INT_MAX, $S]]],
  ];
  $ticks = [];
  foreach ($cases as [$what, $v, $outs]) {
    $t = CovenantThread::tick($genesis['id'], 0, $S, pack('P', $v),
      array_map(fn($o) => ['value' => $o[0], 'locking' => $o[1]], $outs), 1, fn(string $p) => chr(JF_SMALL0 + 1));
    $ticks[] = ['case' => $what, 'preimage' => bin2hex($t['preimage'])] + judge($S, $t['preimage']);
  }
  // and as a thread: five ticks, each from the last one's tip
  $tip = $genesis['id'];
  for ($n = 0; $n < 5; $n++) {
    $t = CovenantThread::tick($tip, 0, $S, pack('P', $n), [['value' => $n + 1, 'locking' => $S]], 1,
      fn(string $p) => chr(JF_SMALL0 + 1));
    $ticks[] = ['case' => sprintf('the thread, tick %d → %d', $n, $n + 1), 'preimage' => bin2hex($t['preimage'])]
             + judge($S, $t['preimage']);
    $tip = $t['hash'];
  }
  $out[$name] = ['script' => bin2hex($S), 'ticks' => $ticks];
}
echo json_encode($out);
