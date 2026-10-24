<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
// Version dispatch (§6b) — the cases that matter, including the ones that must FAIL.
declare(strict_types=1);
require_once __DIR__ . '/dispatch.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); }
  else    { $fail++; printf("  ✗ %s\n", $what); }
}
/** assert that a callable throws */
function throws(callable $f, string $what): void {
  try { $f(); ok(false, "$what — DID NOT THROW"); }
  catch (Throwable $e) { ok(true, "$what"); }
}

echo "── the legacy chain must be untouched ──\n";
$v = version_parse(103);
ok(($v['legacy'] ?? null) === 103, 'version 103 parses as LEGACY 103, not a family');
ok(!isset($v['family']), '103 names no family');
$v = version_parse(1);
ok(($v['legacy'] ?? null) === 1, 'version 1 parses as legacy too');

echo "\n── families round-trip ──\n";
foreach ([['SV',1], ['BT',1], ['JF',1], ['JF',65535], ['XY',7]] as [$f,$r]) {
  $n = version_build($f, $r);
  $p = version_parse($n);
  ok(($p['family'] ?? null) === $f && ($p['revision'] ?? null) === $r,
     sprintf('%s rev %-5d → nVersion 0x%08x → back to %s rev %d', $f, $r, $n, $f, $r));
}

echo "\n── the wire layout is what the spec says ──\n";
$n = version_build('SV', 1);
$wire = pack('V', $n);                       // u32 little-endian, as entry.mjs writes it
ok(bin2hex($wire) === '01005356', 'SV rev 1 serializes as 01 00 53 56  (rev, then "SV" readable in a dump)');
ok(bin2hex(pack('V', 103)) === '67000000', 'legacy 103 serializes as 67 00 00 00  — high half zero');

echo "\n── things that MUST be refused ──\n";
// ⚠ BOTH BYTES must be set, or the test passes for the wrong reason: an earlier version used
//    0x00615600, whose FOURTH byte is zero, so it was refused for the wrong character. Mutation testing
//    caught it — relaxing the legality rule to "any printable byte" still passed.
throws(fn() => version_parse(0x76610000), 'lowercase family `av` is refused (one spelling of one thing)');
throws(fn() => version_parse(0x56200000), 'a space in the family is refused');
throws(fn() => version_parse(0x2d2d0000), 'punctuation `--` is refused');
throws(fn() => version_build('S', 1),     'a one-character family is refused');
throws(fn() => version_build('SVX', 1),   'a three-character family is refused');
throws(fn() => version_build('SV', 70000),'a revision above 0xffff is refused');
$z = version_parse(0);
ok(($z['legacy'] ?? null) === 0, 'an all-zero field is LEGACY 0, never a family — uninitialised data cannot dispatch');
throws(fn() => interpreter_for(0),        'and legacy 0 dispatches nowhere');

echo "\n── dispatch ──\n";
throws(fn() => interpreter_for(103), 'legacy 103 has no interpreter and says why');
$bt = interpreter_for(version_build('BT', 1));
ok($bt instanceof InterpreterBT, 'BT rev 1 dispatches to InterpreterBT');
$jf = interpreter_for(version_build('JF', 3));
ok($jf instanceof InterpreterJF, 'JF rev 1 dispatches to InterpreterJF');
// ⚠ Registering JF must not make an UNREGISTERED family fall back to it — that is §6b's whole point,
//   and it is worth re-asserting here now that all three sets exist.
throws(fn() => interpreter_for(version_build('JZ', 1)), 'JZ is not registered — refused, not substituted');
throws(fn() => interpreter_for(version_build('JF', 1)), 'JF revision 1 is not registered — refused');
throws(fn() => interpreter_for(version_build('JF', 2)), 'JF revision 2 is not registered — refused');
throws(fn() => interpreter_for(version_build('JF', 4)), 'JF revision 4 is not registered — refused');

// ★★★ THE POINT OF THE WHOLE SET MODEL, IN ONE ASSERTION:
//     byte 0x7f is OP_SUBSTR under BT and OP_SPLIT under SV. The SAME SCRIPT must give DIFFERENT
//     answers, decided by what the entry declared — never by which interpreter happened to be loaded.
$script = hex2bin('05010203040551537f');            // push [1..5], OP_1, OP_3, 0x7f
$btOut = implode(' ', array_map('bin2hex', $bt->run($script)));
ok($btOut === '020304', "0x7f under BT is SUBSTR → $btOut");
$svThrew = false;
try { interpreter_for(version_build('SV', 1))->run($script); } catch (Throwable) { $svThrew = true; }
ok($svThrew, '0x7f under SV is SPLIT and rejects the same bytes — a different set, a different answer');
throws(fn() => interpreter_for(version_build('SV', 2)), 'SV revision 2 is not registered — refused');

$vm = interpreter_for(version_build('SV', 1));
ok($vm instanceof InterpreterSV, 'SV rev 1 dispatches to InterpreterSV');

echo "\n── and the dispatched interpreter actually runs ──\n";
$stack = $vm->run(hex2bin('525393'));          // OP_2 OP_3 OP_ADD
ok(count($stack) === 1 && bin2hex($stack[0]) === '05', 'OP_2 OP_3 OP_ADD → 05 through the dispatcher');

echo "\n── ⚠ the rule §6b actually states ──\n";
// "MUST apply the semantics of the version named in that entry, and MUST NOT apply its own."
// ⇒ There is no fallback, no "nearest", no "latest". An unregistered version is an ERROR, never a guess.
$fellBack = false;
try { interpreter_for(version_build('ZZ', 1)); $fellBack = true; } catch (Throwable) {}
ok(!$fellBack, 'an unknown family NEVER falls back to a registered one');

echo "\n── a host that lacks what a tick needs gives no verdict (spec §3.3) ──\n";
// Without ext/gmp: `php -n` reads no php.ini, so a shared gmp is not loaded. A PHP with gmp built in
// cannot show this case here, and the check is skipped, never counted as passed.
$child = <<<'PHP'
require $argv[1] . '/dispatch.php';
require_once $argv[1] . '/interpreter-jf.php';
$what = function (callable $f): string {
  try { $f(); return 'no error'; } catch (Throwable $e) { return get_class($e); }
};
echo json_encode([
  'gmp'      => extension_loaded('gmp'),
  'dispatch' => $what(fn() => interpreter_for(version_build('JF', 3))),
  'new'      => $what(fn() => new InterpreterJF()),
  'tick'     => $what(fn() => InterpreterJF::verifyTick('', "\x51", null)),
]);
PHP;
$proc = proc_open([PHP_BINARY, '-n', '-r', $child, '--', __DIR__], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
$out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
fclose($pipes[1]); fclose($pipes[2]); proc_close($proc);
$r = json_decode($out, true);
if (!is_array($r)) {
  ok(false, 'the host without ext/gmp answered: ' . trim($out . ' ' . $err));
} elseif ($r['gmp']) {
  echo "  - skipped: this PHP has ext/gmp built in, so php -n cannot take it away\n";
} else {
  ok($r['dispatch'] === 'JfHostError', "without ext/gmp, JF rev 3 dispatches to JfHostError, not a crash → {$r['dispatch']}");
  ok($r['new'] === 'JfHostError', "without ext/gmp, new InterpreterJF → {$r['new']}");
  ok($r['tick'] === 'JfHostError', "without ext/gmp, verifyTick gives no verdict → {$r['tick']}");
}

// A host may ship interpreter-jf.php alone, while dispatch.php registers every set. A tick naming a set
// whose file is not here gets a VersionError, never an error from inside require_once.
// ⚠ Last, because without the check a failed require_once can be fatal.
$absent = __DIR__ . '/no-such-dir/interpreter-xy.php';
ok(!file_exists($absent), 'the file registered for XY is not on this host');
register_set('XY', $absent, 'InterpreterXY', [1]);
$caught = 'no error';
try { interpreter_for(version_build('XY', 1)); } catch (Throwable $e) { $caught = get_class($e); }
ok($caught === 'VersionError', "XY rev 1 names a set this host does not ship → $caught");

printf("\n%s  %d passed, %d failed\n", $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
