<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// Run the `SV` interpreter against the conformance vectors and report.
// ⚠ Only oracle=bsv vectors are this set's contract. oracle=013 belongs to `BT`; oracle=jetmora to
//   jetmora's own set. Running the wrong subset against the wrong interpreter proves nothing.
//
//   php server/verify-sv.php            → the 49 bsv vectors
//   php server/verify-sv.php --all      → all 75, so the misses are visible and attributable
declare(strict_types=1);
require_once __DIR__ . '/interpreter-sv.php';

if (!extension_loaded('gmp')) {
  fwrite(STDERR, "⛔ ext-gmp is required. Measured: BCMath is ~1,150× slower at the ceiling and has no\n");
  fwrite(STDERR, "   bitwise operations at all, and PHP's native int silently becomes a float on overflow.\n");
  exit(2);
}

$all = in_array('--all', $argv, true);
$doc = json_decode(file_get_contents(__DIR__ . '/../vectors/core.json'), true);
$want = $all ? ['bsv', '013', 'jetmora'] : ['bsv'];

$pass = $fail = $skip = 0;
$failures = [];

foreach ($doc['vectors'] as $v) {
  if (!in_array($v['oracle'], $want, true)) { $skip++; continue; }
  $vm = new InterpreterSV();
  try {
    $stack = $vm->run(hex2bin($v['script']));
    $got   = sv_stack_hash($stack);
    $ok    = isset($v['result_hash']) && $got === $v['result_hash'];
    if ($ok) { $pass++; }
    else {
      $fail++;
      $failures[] = [$v['id'], $v['oracle'],
        'expected ' . implode(' ', $v['stack'] ?? ['?']),
        'got      ' . implode(' ', array_map('bin2hex', $stack))];
    }
  } catch (Throwable $e) {
    // A vector with no expected stack is meant to fail; treat a throw as the expected outcome.
    if (!isset($v['stack'])) { $pass++; continue; }
    $fail++;
    $failures[] = [$v['id'], $v['oracle'],
      'expected ' . implode(' ', $v['stack']), 'threw    ' . $e->getMessage()];
  }
}

foreach ($failures as [$id, $oracle, $exp, $got]) {
  printf("  ✗ %-24s (oracle=%s)\n      %s\n      %s\n", $id, $oracle, $exp, $got);
}
printf("\n%s  %d passed, %d failed%s  [%s]\n",
  $fail === 0 ? '✅' : '⚠',
  $pass, $fail,
  $skip ? sprintf(', %d not this set\'s contract', $skip) : '',
  implode('+', $want));
exit($fail === 0 ? 0 : 1);
