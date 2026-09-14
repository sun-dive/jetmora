<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE SIGHASH PREIMAGE, GRADED AGAINST AN INDEPENDENT IMPLEMENTATION ───────────────────────────────
//
// ★★★ WHY THIS IS THE GRADE THAT COUNTS. `OP_PUSH_TX` is secure ONLY because a verifier recomputes the
//   preimage and `CHECKSIG` fails if the pushed one differs. ⇒ **If two implementations disagree by one
//   byte, a covenant that validates for one party is refused by another** — and nothing would say why.
//   Self-consistency proves nothing here; only agreement with a separate implementation does.
//
// ⚠ VECTORS PINNED FROM `tools/preimage.mjs` (the JS reference, written independently from BIP143), so
//   this suite needs no node at runtime. Regenerate with:
//     node -e "import('./tools/preimage.mjs')..."  — see git history for the generator used.
//   ★ Same discipline as the ECDSA vector in verify-rfc6979.php: mint against an independent
//   implementation, check it there, then pin it.
//
// ⚠⚠ THE LAYOUT IS BIP143's, a published specification ⇒ no licence exposure. ⛔ It is NOT 0.1.3's
//   sighash: the original is O(n²) with no hashPrevouts/hashOutputs, so OP_PUSH_TX cannot be built on
//   it. **jetmora is not "pure 0.1.3" on sighash and says so.**
declare(strict_types=1);
require_once __DIR__ . '/preimage.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

const XCHK = [
  ['1 in 1 out', '4a4600010110101010101010101010101010101010101010101010101010101010101010100000000003515200e80300000100000000000000001976a914202020202020202020202020202020202020202088ac00000000',
   '4a460001892661fa358c297d3ae05d2d628ba1b7ccedaa560455dfa5fdf9e39f8cc7129ef8970eec53026cb808e93ef27eedbf743f34d173d83becca59c78b79db8863821010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e8030000159a48968d4660726c2fc164bb84934022b1f7017f3a63619e3ab888ff85a97b0000000001000000'],
  ['1 in 2 out', '4a4600010110101010101010101010101010101010101010101010101010101010101010100000000003515200e80300000200000000000000001976a914202020202020202020202020202020202020202088ac07000000000000001976a914212121212121212121212121212121212121212188ac00000000',
   '4a460001892661fa358c297d3ae05d2d628ba1b7ccedaa560455dfa5fdf9e39f8cc7129ef8970eec53026cb808e93ef27eedbf743f34d173d83becca59c78b79db8863821010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e80300007b5a8f1479116ebff3ae9850af391ff1d796b30eb5b1edd94252151926f1c87c0000000001000000'],
  ['2 in 1 out', '4a4600010210101010101010101010101010101010101010101010101010101010101010100000000003515200e803000011111111111111111111111111111111111111111111111111111111111111110100000003515201e90300000100000000000000001976a914202020202020202020202020202020202020202088ac00000000',
   '4a46000170bdc2ea8cfd90750ba819b535a0b26cc8ea0497000e38e138fa8733ccf972434811e9ea590218c02ee7894fc0a72f6f4efc7d7fec351fe7036388ebf6f7b0461010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e8030000159a48968d4660726c2fc164bb84934022b1f7017f3a63619e3ab888ff85a97b0000000001000000'],
  ['2 in 2 out', '4a4600010210101010101010101010101010101010101010101010101010101010101010100000000003515200e803000011111111111111111111111111111111111111111111111111111111111111110100000003515201e90300000200000000000000001976a914202020202020202020202020202020202020202088ac07000000000000001976a914212121212121212121212121212121212121212188ac00000000',
   '4a46000170bdc2ea8cfd90750ba819b535a0b26cc8ea0497000e38e138fa8733ccf972434811e9ea590218c02ee7894fc0a72f6f4efc7d7fec351fe7036388ebf6f7b0461010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e80300007b5a8f1479116ebff3ae9850af391ff1d796b30eb5b1edd94252151926f1c87c0000000001000000'],
  ['3 in 1 out', '4a4600010310101010101010101010101010101010101010101010101010101010101010100000000003515200e803000011111111111111111111111111111111111111111111111111111111111111110100000003515201e903000012121212121212121212121212121212121212121212121212121212121212120200000003515202ea0300000100000000000000001976a914202020202020202020202020202020202020202088ac00000000',
   '4a46000183ed44df2655c0dbf756b8b52aba75d9ac71f09ac6d20ea6202d3328662cec925a396a571369fbcf3a11d62d43b890a1ff4ee494c8b43a8f23c9c5b956ccfd1b1010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e8030000159a48968d4660726c2fc164bb84934022b1f7017f3a63619e3ab888ff85a97b0000000001000000'],
  ['3 in 2 out', '4a4600010310101010101010101010101010101010101010101010101010101010101010100000000003515200e803000011111111111111111111111111111111111111111111111111111111111111110100000003515201e903000012121212121212121212121212121212121212121212121212121212121212120200000003515202ea0300000200000000000000001976a914202020202020202020202020202020202020202088ac07000000000000001976a914212121212121212121212121212121212121212188ac00000000',
   '4a46000183ed44df2655c0dbf756b8b52aba75d9ac71f09ac6d20ea6202d3328662cec925a396a571369fbcf3a11d62d43b890a1ff4ee494c8b43a8f23c9c5b956ccfd1b1010101010101010101010101010101010101010101010101010101010101010000000001976a914cccccccccccccccccccccccccccccccccccccccc88ac3930000000000000e80300007b5a8f1479116ebff3ae9850af391ff1d796b30eb5b1edd94252151926f1c87c0000000001000000'],
];

echo "── PHP vs the independent JS reference, same inputs ──\n";
$scriptCode = "\x76\xa9\x14" . str_repeat("\xcc", 20) . "\x88\xac";
foreach (XCHK as [$label, $entryHex, $wantHex]) {
  $e   = CovenantEntry::decode(hex2bin($entryHex));
  $got = bin2hex(Preimage::build($e, 0, $scriptCode, pack('P', 12345)));
  ok($got === $wantHex, sprintf('%-12s preimage matches (%d bytes)', $label, strlen($wantHex) / 2));
}

echo "\n── the refusals that keep it honest ──\n";
$e = CovenantEntry::decode(hex2bin(XCHK[0][1]));
foreach ([
  [0x41, 'FORKID must not be set', '⛔ FORKID is refused (§5.0c) — replay protection would rebuild the censorship freeze'],
  [0x02, 'SIGHASH_ALL only',       'SIGHASH_NONE is refused — v1 assigns no other flag'],
  [0x03, 'SIGHASH_ALL only',       'SIGHASH_SINGLE is refused'],
  [0x81, 'SIGHASH_ALL only',       'ANYONECANPAY is refused'],
] as [$type, $needle, $what]) {
  try { Preimage::build($e, 0, $scriptCode, pack('P', 0), $type); ok(false, "$what — DID NOT REFUSE"); }
  catch (Throwable $ex) { ok(str_contains($ex->getMessage(), $needle), $what); }
}
try { Preimage::build($e, 9, $scriptCode, pack('P', 0)); ok(false, 'no input at index 9'); }
catch (Throwable $ex) { ok(str_contains($ex->getMessage(), 'no input at index'), 'a missing input index is refused'); }
try { Preimage::build($e, 0, $scriptCode, "\x00"); ok(false, 'short value'); }
catch (Throwable $ex) { ok(str_contains($ex->getMessage(), '8 raw bytes'), 'a non-8-byte value is refused'); }

// ⚠ the circularity a state-peeling covenant must resolve, exposed rather than rediscovered
ok(Preimage::scriptCodeVarintSize(100) === 1 && Preimage::scriptCodeVarintSize(300) === 3,
   '⚠ scriptCode varint size is exposed — a covenant that peels its own state must build, measure, rebuild');

printf("\n%s  %d passed, %d failed   [sighash preimage · graded against the JS reference]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
