<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── BSV TRANSACTIONS + BIP143 SIGHASH, GRADED BY THE BIP'S OWN WORKED EXAMPLES ──────────────────────
//
// The build sequence's own instruction for this item: *"⚠ where SILENT failures live; vectors first."*
//
// ★★★ THE VECTORS GRADE TWO THINGS AT ONCE, and that is the point. Every case starts from the BIP's
//   **raw unsigned transaction hex**, so the parser must read it correctly before the sighash can even
//   be attempted. ⇒ A parse bug cannot hide behind a correct sighash, or the reverse.
//
// ★★ AND THE PREIMAGE IS CHECKED, NOT ONLY THE HASH. A wrong preimage that happens to hash correctly is
//   impossible, but a RIGHT hash from a preimage assembled by luck is not what we want to ship — and
//   the three intermediate hashes are checked separately again, so a failure says WHICH field is wrong
//   instead of just "the answer differs".
//
// ⚠ These vectors have FORKID clear (they are BTC's). ★ That grades the LAYOUT exactly, which is all
//   the layout depends on: with BSV's fork id of 0, FORKID only changes the flag byte. The
//   FORKID-specific path is graded below against the live covenants' own scope constants.
declare(strict_types=1);
require_once __DIR__ . '/wallet/bsv/transaction.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}
function refuses(callable $f, string $needle, string $what): void {
  global $pass, $fail;
  try { $f(); $fail++; printf("  ✗ %s — DID NOT REFUSE\n", $what); }
  catch (Throwable $e) {
    if (str_contains($e->getMessage(), $needle)) $pass++;
    else { $fail++; printf("  ✗ %s — wrong reason: %s\n", $what, $e->getMessage()); }
  }
}
/** ⚠ BIP-143 prints scriptCode WITH its varint prefix; our API takes it raw. Strip, don't double it. */
function stripLen(string $hex): string {
  [$len, $o] = BsvBytes::readVarint((string)hex2bin($hex), 0);
  $raw = substr((string)hex2bin($hex), $o);
  if (strlen($raw) !== $len) throw new RuntimeException('vector scriptCode length disagrees with itself');
  return $raw;
}

$V = json_decode(file_get_contents(__DIR__ . '/wallet/bsv/bip143-vectors.json'), true);

echo "── BIP-143's own worked examples ──\n";
foreach ($V['vectors'] as $v) {
  $n  = $v['name'];
  $tx = BsvTx::parse($v['unsignedTx']);
  // ★ round trip FIRST: the sighash below is meaningless if the parse was wrong.
  ok($tx->hex() === $v['unsignedTx'], "$n — the raw tx round-trips byte for byte");
  $sc = stripLen($v['scriptCodeWithLen']);
  $pre = BsvSighash::preimage($tx, $v['inputIndex'], $sc, $v['amount'], $v['sighashType']);
  ok(bin2hex($pre) === $v['preimage'], "$n — the PREIMAGE matches the BIP byte for byte");
  ok(bin2hex(BsvSighash::hash($tx, $v['inputIndex'], $sc, $v['amount'], $v['sighashType']))
     === $v['sighash'], "$n — the sighash");
  // ★ the three intermediates, so a failure names the field rather than the answer
  ok(substr(bin2hex($pre), 8, 64)   === $v['hashPrevouts'], "$n — hashPrevouts");
  ok(substr(bin2hex($pre), 72, 64)  === $v['hashSequence'], "$n — hashSequence");
  ok(str_contains(bin2hex($pre), $v['hashOutputs']),        "$n — hashOutputs");
}
printf("  %d vectors × 6 checks\n", count($V['vectors']));

// ── ⚠ the flags actually change the answer ──────────────────────────────────────────────────────────
// ★ A preimage builder that IGNORED the flags would still pass a suite made only of SIGHASH_ALL cases.
echo "\n── ⚠ each flag changes the preimage ──\n";
$v0 = $V['vectors'][0];
$tx = BsvTx::parse($v0['unsignedTx']);
$sc = stripLen($v0['scriptCodeWithLen']);
$h  = fn(int $t) => bin2hex(BsvSighash::hash($tx, 1, $sc, $v0['amount'], $t));
$seen = [];
foreach ([BsvSighash::ALL, BsvSighash::NONE, BsvSighash::SINGLE, BsvSighash::ALL_FORKID,
          BsvSighash::ALL | BsvSighash::ANYONECANPAY, 0xc1, 0x83] as $t) $seen[] = $h($t);
ok(count(array_unique($seen)) === count($seen),
   '★★ all 7 flag combinations give DIFFERENT sighashes — including 0x41 vs 0x01, so FORKID is really in there');
ok($h(BsvSighash::ALL_FORKID) !== $h(BsvSighash::ALL),
   '⚠ 0x41 and 0x01 differ — a signature made under the wrong one is refused by every node');
// ⚠⚠ ANYONECANPAY must zero BOTH prevouts and sequences — the battery relies on exactly this
$acp = bin2hex(BsvSighash::preimage($tx, 1, $sc, $v0['amount'], 0xc1));
ok(substr($acp, 8, 128) === str_repeat('0', 128),
   '★ 0xc1 (the battery\'s scope) zeroes prevouts AND sequences — which is what lets a sponsor add inputs');

// ── ⛔ SIGHASH_SINGLE past the last output ──────────────────────────────────────────────────────────
// ⚠⚠ Bitcoin's LEGACY algorithm returns uint256(1) here — a notorious bug. BIP-143 does not, and
//   copying the old behaviour produces a signature no BSV node accepts.
echo "\n── ⛔ SIGHASH_SINGLE past the last output ──\n";
$one = new BsvTx(1, [
  ['txid' => str_repeat("\x11", 32), 'vout' => 0, 'script' => '', 'sequence' => 0xffffffff],
  ['txid' => str_repeat("\x22", 32), 'vout' => 1, 'script' => '', 'sequence' => 0xffffffff],
], [['value' => 1000, 'script' => "\x51"]], 0);
$p = bin2hex(BsvSighash::preimage($one, 1, "\x51", 1000, BsvSighash::SINGLE));
ok(substr($p, -80, 64) === str_repeat('0', 64),
   '⛔ input 1 has no matching output ⇒ hashOutputs is ZEROS, not the legacy uint256(1) bug');
ok(bin2hex(BsvSighash::preimage($one, 0, "\x51", 1000, BsvSighash::SINGLE)) !== $p,
   '★ ...while input 0 DOES have one, so the two differ');

// ── ⚠ the silent encoders ───────────────────────────────────────────────────────────────────────────
echo "\n── ⚠ 8-byte amounts and multi-byte varints ──\n";
// ⚠ 2^48 is in vector 3 already; this pins the boundary a 4-byte pack would cross.
$big = new BsvTx(1, [['txid' => str_repeat("\x33", 32), 'vout' => 0, 'script' => '',
                      'sequence' => 0xffffffff]], [['value' => 0x1_0000_0000, 'script' => "\x51"]], 0);
ok(BsvTx::parse($big->hex())->outputs[0]['value'] === 0x1_0000_0000,
   '⚠ an amount of exactly 2^32 survives a round trip — a 4-byte pack loses it here');
ok(BsvTx::parse($big->hex())->hex() === $big->hex(), '...and the whole tx still round-trips');
// ⚠⚠ NO BIP-143 vector crosses the 0xfd varint boundary — the longest scriptCode there is 207 bytes.
foreach ([0xfc, 0xfd, 0xffff, 0x10000] as $len) {
  $t = new BsvTx(1, [['txid' => str_repeat("\x44", 32), 'vout' => 0, 'script' => '',
                      'sequence' => 0xffffffff]], [['value' => 1, 'script' => str_repeat("\x51", $len)]], 0);
  ok(BsvTx::parse($t->hex())->outputs[0]['script'] === str_repeat("\x51", $len),
     sprintf('a %d-byte script round-trips (varint boundary %s)', $len,
             $len < 0xfd ? '1 byte' : ($len <= 0xffff ? '3 bytes' : '5 bytes')));
}
// ★ and the scriptCode varint is inside the PREIMAGE, so its width shifts everything after it
$short = BsvSighash::preimage($big, 0, str_repeat("\x51", 0xfc), 1);
$long  = BsvSighash::preimage($big, 0, str_repeat("\x51", 0xfd), 1);
ok(strlen($long) - strlen($short) === 3,
   '★ crossing 0xfd adds 3 bytes to the preimage (1 script byte + 2 varint) — not 1');

// ── ★ txid orientation ──────────────────────────────────────────────────────────────────────────────
echo "\n── ★ txid is REVERSED for display ──\n";
$tx1 = BsvTx::parse($V['vectors'][1]['unsignedTx']);
ok($tx1->txid() === bin2hex(strrev(BsvBytes::dsha256($tx1->serialize()))), 'txid = reverse(dsha256(raw))');
ok($tx1->txid() !== bin2hex(BsvBytes::dsha256($tx1->serialize())),
   '⚠ ...and it is NOT the unreversed hash — the wire order and the display order are opposites');
ok(strlen($tx1->txid()) === 64, 'it is 64 hex characters');

// ── ★ the fee floor ─────────────────────────────────────────────────────────────────────────────────
echo "\n── ★ fee at 100 sat/KB ──\n";
ok($tx1->fee() === (int)ceil(strlen($tx1->serialize()) / 10), '100 sat/KB over the serialized size');
ok($tx1->fee() >= 1, '⚠ rounded UP — a fee below the floor is a transaction that never confirms');

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────
echo "\n── refusals ──\n";
refuses(fn() => BsvTx::parse($V['vectors'][0]['unsignedTx'] . 'ff'), 'trailing byte',
        '⛔ trailing bytes are REFUSED — ignoring them makes two transactions parse as one');
refuses(fn() => BsvTx::parse('0100000001'), 'the data ends first', 'a truncated transaction is refused');
refuses(fn() => BsvSighash::preimage($tx1, 9, "\x51", 1), 'no input at index', 'a bad input index is refused');
refuses(fn() => BsvSighash::preimage($tx1, 0, "\x51", -1), 'cannot be negative', 'a negative amount is refused');

// ── ⛔ and it does NOT reach into jetmora's preimage ─────────────────────────────────────────────────
echo "\n── ⛔ the two sighashes stay apart ──\n";
$src = file_get_contents(__DIR__ . '/wallet/bsv/transaction.php');
ok(!preg_match('#(require|include)[^;]*preimage\.php#', $src),
   "⛔ this file does not import jetmora's preimage.php — it was READ, not reused");
ok(!class_exists('Preimage', false), '...and Preimage is not even loaded here');

printf("\n%s  %d passed, %d failed   [BSV transaction + BIP143 sighash · the BIP's own vectors]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
