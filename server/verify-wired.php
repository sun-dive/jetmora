<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ A REAL COVENANT, WIRED END TO END ════════════════════════════════════════════════════════════════
//
// ★★★ THIS IS THE TEST THAT WAS NEVER RUN. The first chain's entries had `unlocking = 0` and no
//   covenant ever ran. Here a covenant SCRIPT actually executes over the preimage of a real tick, and
//   ★ **a tick that breaks the rule is REFUSED BY THE COVENANT ITSELF**, not by a check around it.
//
// ★★ `OP_PUSH_TX` IS UNNECESSARY IN `JF`. On Bitcoin it exists because Script cannot introspect, so the
//   preimage must be PUSHED and proved genuine via CHECKSIG against a published constant. jetForth has
//   `PREIMAGE` as a WORD — the interpreter hands over the genuine preimage. **The trick becomes a
//   primitive**, and the whole `(a, k)` published-keypair apparatus disappears.
//
// ── THE COVENANT: a counter that may only increment ──────────────────────────────────────────────────
// The state is the OUTPUT VALUE. §3: *"an application-defined quantity... MUST NOT be interpreted as
// money, and MAY be zero"* — so a counter is exactly what it is for. ★ The script never changes, so it
// needs no self-modification: it requires the successor to carry the SAME script and value + 1.
//
// ⚠ PREIMAGE LAYOUT, and the offsets are why this works at all:
//     version 4 · hashPrevouts 32 · hashSequence 32 · outpoint 36 · varint+scriptCode · value 8
//     · nSequence 4 · hashOutputs 32 · locktime 4 · sighashType 4
//   ⇒ scriptCode starts at 105 (assuming a 1-byte varint, script < 253 bytes) and the TRAILING part is
//     always 52 bytes. **So value sits at u-52 and hashOutputs at u-40, whatever the script's length.**
//   ★ Reading from the END is what makes the offsets independent of the script — the same reason a
//     Bitcoin covenant peels from the back.
declare(strict_types=1);
require_once __DIR__ . '/jf-asm.php';
require_once __DIR__ . '/interpreter-jf.php';
require_once __DIR__ . '/wallet/jetmora/thread.php';
require_once __DIR__ . '/dispatch.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── the covenant, in jetForth ───────────────────────────────────────────────────────────────────────
// ⚠ Scratch slots: 8 = preimage length · 16 = old value · 24 = script length
const COUNTER_SRC = <<<'ASM'
  1000 PREIMAGE  DUP 8 !
  2DUP 8 @ 52 - 8 2000 SUBSTR BIN2NUM 16 !
  2DUP 8 @ 40 - 32 2100 SUBSTR 2DROP
  2DUP 105 8 @ 157 - 2200 SUBSTR 24 ! DROP
  16 @ 1+ 8 3000 NUM2BIN 2DROP
  24 @ 3008 C!
  2200 3009 24 @ MOVE
  3000 24 @ 9 + 4000 HASH256
  4000 32 2100 32 BYTES=
  NIP NIP
ASM;

$script = jf_asm(COUNTER_SRC);
printf("── the covenant: %d bytes of jetForth bytecode ──\n", strlen($script));
ok(strlen($script) > 0 && strlen($script) < 253, 'it assembles, and fits a 1-byte varint');

/** Run the covenant over a tick's preimage. Returns its verdict. */
function runCovenant(string $script, string $preimage): bool
{
  $vm = new InterpreterJF();
  $vm->setPreimage($preimage);
  $stack = $vm->run($script);
  if (count($stack) !== 1) throw new RuntimeException('covenant left ' . count($stack) . ' items, want 1');
  return gmp_sign($stack[0]) !== 0;                 // Forth TRUE is all bits set
}

/** One tick: successor carries $newValue and the SAME script. */
function tickTo(string $script, string $tip, int $oldValue, int $newValue): array
{
  return CovenantThread::tick(
    $tip, 0, $script, pack('P', $oldValue),
    [['value' => $newValue, 'locking' => $script]],
    1,
    // ⚠ Nothing needs pushing: JF's PREIMAGE is native, so the unlocking script carries only what the
    //   covenant cannot derive. Here that is nothing — but it MUST NOT be empty (that is a log row),
    //   so it carries OP_1 as an explicit "no arguments".
    fn(string $pre) => chr(JF_SMALL0 + 1)
  );
}

// ── ✅ a VALID tick ─────────────────────────────────────────────────────────────────────────────────
echo "\n── ✅ a valid tick: the counter increments ──\n";
$genesis = CovenantThread::create(hash('sha256','counter source',true), $script, '',
                                  CovenantThread::authorisedHashes([str_repeat("\x02",33)]));
$t = tickTo($script, $genesis['id'], 41, 42);
// ⚠ THE RELATIONSHIP THE OFFSETS DEPEND ON, asserted rather than assumed:
//   preimage = 105 (version+hashPrevouts+hashSequence+outpoint+varint) + scriptLen + 52 (trailing)
ok(strlen($t['preimage']) === 105 + strlen($script) + 52,
   sprintf('preimage = 105 + script(%d) + 52 = %d bytes — the offsets hold', strlen($script), strlen($t['preimage'])));
ok(substr($t['preimage'], 105, strlen($script)) === $script,
   '...and scriptCode really is at offset 105, which is what the covenant reads');
ok(runCovenant($script, $t['preimage']), '★★★ THE COVENANT ACCEPTS IT — 41 → 42');

// ── ⛔ ticks that BREAK THE RULE ─────────────────────────────────────────────────────────────────────
echo "\n── ⛔ and the covenant REFUSES what breaks its rule ──\n";
ok(!runCovenant($script, tickTo($script, $genesis['id'], 41, 43)['preimage']),
   '⛔ 41 → 43 is REFUSED — it skipped a value');
ok(!runCovenant($script, tickTo($script, $genesis['id'], 41, 41)['preimage']),
   '⛔ 41 → 41 is REFUSED — it did not advance');
ok(!runCovenant($script, tickTo($script, $genesis['id'], 41, 40)['preimage']),
   '⛔ 41 → 40 is REFUSED — it went backwards');

// ★★ the sharpest one: the successor tries to change the SCRIPT, which is how a covenant is escaped
$escape = CovenantThread::tick($genesis['id'], 0, $script, pack('P', 41),
  [['value' => 42, 'locking' => "\x76\xa9\x14" . str_repeat("\x99",20) . "\x88\xac"]], 1,
  fn(string $pre) => chr(JF_SMALL0 + 1));
ok(!runCovenant($script, $escape['preimage']),
   '⛔⛔ a successor with a DIFFERENT script is REFUSED — the covenant survives its own spend');

// ★ and a successor that pays a second output the covenant did not authorise
$extra = CovenantThread::tick($genesis['id'], 0, $script, pack('P', 41),
  [['value' => 42, 'locking' => $script],
   ['value' => 1,  'locking' => "\x51"]], 1,
  fn(string $pre) => chr(JF_SMALL0 + 1));
ok(!runCovenant($script, $extra['preimage']),
   '⛔ an EXTRA output is REFUSED — hashOutputs covers all of them');

// ── the chain continues ─────────────────────────────────────────────────────────────────────────────
echo "\n── ★ and it runs as a THREAD, not a single step ──\n";
$tip = $genesis['id']; $v = 0; $steps = 0;
for ($n = 0; $n < 5; $n++) {
  $step = tickTo($script, $tip, $v, $v + 1);
  if (!runCovenant($script, $step['preimage'])) break;
  $tip = $step['hash']; $v++; $steps++;
}
ok($steps === 5, sprintf('five consecutive ticks, each accepted by the covenant (counter now %d)', $v));
ok($tip !== $genesis['id'], 'the tip moved — every link verified by the program, not by an operator');

printf("\n%s  %d passed, %d failed   [a real covenant, wired end to end]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
