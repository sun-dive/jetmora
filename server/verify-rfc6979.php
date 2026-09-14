<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// Grades the deterministic signer. ⚠ Two different graders, because they prove DIFFERENT things and
// neither alone is enough:
//
//   1. ★★★ RFC 6979's OWN Appendix A.2.5 vectors (P-256) grade the `k` GENERATOR exactly.
//      `k` depends only on the group order, the private key and the digest — never on the curve's
//      points — so P-256's order grades the algorithm, and secp256k1 then uses the same function.
//      ⛔ I could not find an authoritative RFC 6979 vector FOR secp256k1: a widely-quoted one is
//        byte-identical to the P-256 value, which cannot be right because the orders differ.
//        **A plausible vector is worse than none.**
//
//   2. ★★ openssl grades SIGNATURE VALIDITY, and it is non-circular: it shares no code with us.
//      ⇒ Together: (1) says we derive the same k as everyone else, (2) says the signature is real.
//      ⚠ Verifying our own signature with our own verifier proves NEITHER — it is included below only
//        as a round-trip, and is labelled as such rather than counted as evidence.
//
// ⚠ openssl is used ONLY here, as an oracle. Nothing in the chain core or the wallet depends on it.
//
//   php server/verify-rfc6979.php          → 100 keypairs
//   php server/verify-rfc6979.php 500
declare(strict_types=1);
require_once __DIR__ . '/secp256k1.php';

if (!extension_loaded('gmp'))     { fwrite(STDERR, "⛔ ext-gmp required\n"); exit(2); }
$oracle = extension_loaded('openssl') && in_array('secp256k1', openssl_get_curve_names() ?: [], true);

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── 1. the AUTHORITATIVE grade: RFC 6979 Appendix A.2.5, curve P-256 ────────────────────────────────
echo "── RFC 6979 §A.2.5 (P-256) — the k generator, graded by the RFC itself ──\n";
$qP256 = gmp_init('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16);
$xP256 = gmp_init('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721', 16);
foreach ([
  ['sample', 'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60'],
  ['test',   'D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0'],
] as [$msg, $want]) {
  $k   = Rfc6979::k($qP256, $xP256, hash('sha256', $msg, true), 'sha256');
  $got = strtoupper(str_pad(gmp_strval($k, 16), 64, '0', STR_PAD_LEFT));
  ok($got === $want, sprintf('"%s" → k = %s…', $msg, substr($got, 0, 24)));
}
// ⚠ the helpers have their own edge cases, and both are silent when wrong
ok(gmp_strval(Rfc6979::bits2int(hex2bin('ffff'), 8)) === '255',
   'bits2int SHIFTS RIGHT for an over-long input, never truncates bytes');
ok(bin2hex(Rfc6979::int2octets(gmp_init(1), 4)) === '00000001',
   'int2octets pads to a fixed width');

// ── 2. secp256k1, graded by openssl ─────────────────────────────────────────────────────────────────
echo "\n── secp256k1 signing — validity graded by openssl (shares no code with us) ──\n";
if (!$oracle) {
  echo "  ⚠ openssl secp256k1 unavailable — validity NOT graded on this host\n";
} else {
  $N = isset($argv[1]) ? max(1, (int)$argv[1]) : 100;
  $agreed = 0; $rt = 0; $det = 0; $distinct = [];
  for ($i = 0; $i < $N; $i++) {
    do { $dRaw = random_bytes(32); $d = gmp_import($dRaw, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN); }
    while (gmp_cmp($d, 1) < 0);
    $pub = Secp256k1::publicKey($d, true);
    $msg = random_bytes(1 + random_int(0, 120));
    $dig = hash('sha256', $msg, true);
    $sig = Secp256k1::sign($d, $dig);

    // ★ the non-circular grade: openssl must accept a signature we made
    $prefix = "\x30\x36\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x22\x00";
    $pem = "-----BEGIN PUBLIC KEY-----\n"
         . chunk_split(base64_encode($prefix . $pub), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = @openssl_pkey_get_public($pem);
    if ($key !== false && openssl_verify($msg, $sig, $key, OPENSSL_ALGO_SHA256) === 1) $agreed++;

    if (Secp256k1::verifyDigest($sig, $pub, $dig)) $rt++;                 // round trip only
    if (Secp256k1::sign($d, $dig) === $sig) $det++;                       // determinism
    $distinct[bin2hex(substr($sig, 0, 12))] = true;
  }
  ok($agreed === $N, "openssl accepts every signature we produced ($agreed/$N)");
  ok($rt === $N,     "round trip: our verifier accepts them too ($rt/$N) — not evidence, just consistency");
  ok($det === $N,    "DETERMINISTIC: signing twice gives identical bytes ($det/$N)");
  ok(count($distinct) === $N, 'and different keys/messages give different signatures — no k reuse');
}

// ── 3. the properties that do not need an oracle ────────────────────────────────────────────────────
echo "\n── properties ──\n";
$d   = gmp_init('0000000000000000000000000000000000000000000000000000000000000001', 16);
$dig = hash('sha256', 'jetmora', true);
$a = Secp256k1::sign($d, $dig);
$b = Secp256k1::sign($d, hash('sha256', 'jetmorb', true));
ok($a !== $b, 'a one-character message change produces a different signature');
// ⚠⚠ THE FAILURE THAT MATTERS: the same k twice would leak the key. Different messages MUST give
//    different r, because r is derived from k.
$ra = bin2hex(substr($a, 4, 32)); $rb = bin2hex(substr($b, 4, 32));
ok($ra !== $rb, 'and a DIFFERENT r — the same r twice under one key is what leaks it');
ok(Secp256k1::verifyDigest($a, Secp256k1::publicKey($d), $dig), 'k=1 edge key still signs and verifies');

$sigLowS = Secp256k1::sign($d, $dig, true);
$der = Secp256k1::decodeDer($sigLowS);
$n   = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
ok($der !== null && gmp_cmp(gmp_mul($der[1], 2), $n) <= 0, 'lowS:true normalises s to the lower half');
ok(Secp256k1::verifyDigest($sigLowS, Secp256k1::publicKey($d), $dig), '...and the normalised signature still verifies');
ok(Secp256k1::decodeDer(Secp256k1::sign($d, $dig)) !== null, 'our DER survives our own STRICT parser');

try { Secp256k1::sign(gmp_init(0), $dig); ok(false, 'a zero private key is refused'); }
catch (Throwable) { ok(true, 'a zero private key is refused'); }
try { Secp256k1::sign($d, 'short'); ok(false, 'a non-32-byte digest is refused'); }
catch (Throwable) { ok(true, 'a non-32-byte digest is refused'); }

// ── ⏱ SCALAR BLINDING — a TIMING regression test ────────────────────────────────────────────────────
// ⚠⚠⚠ WHY THIS IS A TEST. Signing runs behind a web form, so the attacker chooses the request and
//   measures the response. `mulRaw` does work proportional to the BITS of its scalar, so unblinded it
//   leaks the secret's bit length outright. MEASURED before the fix: a 1-bit key took 0.001 ms and a
//   255-bit key 1.046 ms — **a ratio of 1576x**. After blinding: 1.00x.
// ★ The threshold is deliberately loose (3x) so this fails on a REGRESSION, not on a noisy host. A real
//   regression is three orders of magnitude, not a few percent.
echo "\n── ⏱ scalar blinding ──\n";
$bench = function (callable $f, int $n = 200): float {
  $t = microtime(true); for ($i = 0; $i < $n; $i++) $f(); return (microtime(true) - $t) / $n;
};
$dLo = gmp_init(1);                           // 1 bit
$dHi = gmp_sub(gmp_pow(2, 255), 1);           // 255 bits
$tl = $bench(fn() => Secp256k1::publicKey($dLo));
$th = $bench(fn() => Secp256k1::publicKey($dHi));
$ratio = $tl > 0 ? $th / $tl : INF;
ok($ratio < 3.0, sprintf('timing does not track the secret bit length (ratio %.2fx, was 1576x unblinded)', $ratio));
// ⚠ and blinding must not change the ANSWER — a blinded multiply that returns a different point would
//   be caught by openssl above, but check the sharpest case directly: d=1 must give the generator.
ok(bin2hex(Secp256k1::publicKey($dLo)) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
   'd=1 still yields the generator point G');
$stable = true;
for ($i = 0; $i < 30; $i++) if (Secp256k1::publicKey($dHi) !== Secp256k1::publicKey($dHi)) $stable = false;
ok($stable, 'the same key gives the same public key across 30 randomly-blinded calls');

// ── ⛔⛔ DER STRICTNESS — a MEASURED divergence from @bsv/sdk 2.1.4 ──────────────────────────────────
//
// ⚠⚠⚠ FOUND 8 Sept 2026 by testing the SDK directly. The audit established that its curve code is
//   `elliptic` + `bn.js`, **vendored and stripped of attribution** (`_wnafT1`, `_endoWnafT1` — elliptic's
//   private scratch buffers, verbatim). ⇒ A renamed fork **cannot receive upstream security patches**,
//   and one of elliptic's has not made it across.
//
// ★★★ THE PAIR BELOW IS THE SAME SIGNATURE TWICE. `r`'s high bit is set, so canonical DER REQUIRES a
//   leading `0x00`. Strip it and the numeric value is unchanged — but the bytes are not.
//   | **@bsv/sdk 2.1.4** | ⛔ **ACCEPTS BOTH, and VERIFIES BOTH** — CVE-2024-42460's shape |
//   | **ours** | ✅ accepts the canonical one, REFUSES the mutated one |
//
// ⚠⚠ THE RISK IS NOT THAT THE MUTANT GETS MINED — BSV has enforced strict DER (BIP-66) since 2015, so
//   the NETWORK refuses it. ⇒ The risk is that **the SDK's verifier is MORE PERMISSIVE THAN CONSENSUS**:
//   it reports "valid" for a signature no node would accept. A verifier built on it can believe a
//   transaction is good when it could never confirm. ★ This project has hit that exact shape before —
//   the explicit-flag path that never read the tx version.
//
// ⇒ So this is not a test OF the SDK. It is a test that OUR parser stays strict, pinned with a real
//   divergence so the reason survives after the SDK is gone.
echo "\n── ⛔ DER strictness, pinned against a measured SDK divergence ──\n";
$canonical = '3045022100b50cafb865954531c5c3a082c3a96c6e4c73210841a3bf37218b28285c74cb5f'
           . '02206c5e41021504ec466129102274eabeaba72c41f7d3e3cf19cd39a61222c5a089';
$mutated   = '30440220b50cafb865954531c5c3a082c3a96c6e4c73210841a3bf37218b28285c74cb5f'
           . '02206c5e41021504ec466129102274eabeaba72c41f7d3e3cf19cd39a61222c5a089';
$c = Secp256k1::decodeDer((string)hex2bin($canonical));
$m = Secp256k1::decodeDer((string)hex2bin($mutated));
ok($c !== null, 'the canonical form (r padded with 0x00) is accepted');
ok($m === null, "⛔ the mutated form — 0x00 stripped from a high-bit r — is REFUSED (the SDK accepts it)");
// ★ and they really are the same number, which is what makes it MALLEABILITY rather than corruption
ok($c !== null && gmp_cmp($c[0], gmp_init(substr($canonical, 10, 64), 16)) === 0,
   '★ ...and the two encode the SAME r, so accepting both is malleability, not a different signature');
// ⚠ the sighash byte must not become a loophole: allowTrailing permits trailing bytes, NOT bad integers
ok(Secp256k1::decodeDer((string)hex2bin($mutated . '41'), true) === null,
   '⚠ allowTrailing does NOT relax the integer rules — the mutant is still refused with a sighash byte');
ok(Secp256k1::decodeDer((string)hex2bin($canonical . '41'), true) !== null,
   '...while the canonical form with a sighash byte is accepted, which Bitcoin needs');
// ⛔ the BER forms the SDK correctly rejects — ours must too, or we are the permissive one
ok(Secp256k1::decodeDer((string)hex2bin('3081' . substr($canonical, 2))) === null,
   '⛔ a long-form (BER) length is refused');
ok(Secp256k1::decodeDer((string)hex2bin($canonical . 'ff')) === null,
   '⛔ a trailing byte is refused when trailing is not permitted');

printf("\n%s  %d passed, %d failed   [RFC 6979 + secp256k1 signing]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
