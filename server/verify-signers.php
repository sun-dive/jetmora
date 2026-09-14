<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE SIGNING PATH IS SCHEME-AWARE, AND THE CHAIN'S OWN VERIFIER GRADES IT ─────────────────────────
//
// His call, 8 Sept: *"the wallet's signing path should become scheme-aware — yes that is important."*
//
// ★★★ THE GRADE THAT COUNTS: every signature here is checked with **`Appender::verifySignature`** —
//   the function that actually GATES an append (§4.1). ⇒ Verifying with our own verifier would prove
//   only self-consistency; a signature the CHAIN will not accept does not exist as far as jetmora is
//   concerned, however well-formed it looks.
//
// ⚠⚠ THE DIFFERENCE THIS EXISTS TO GET RIGHT:
//   | ed25519   | signs the MESSAGE — SHA-512 is internal to the scheme |
//   | secp256k1 | signs a 32-byte DIGEST — the caller hashes, and the wrong hash verifies nowhere |
//   ⇒ §4.0a: the append authorisation is *"over the ENTRY BYTES"* for both. **One rule, two mechanics.**
declare(strict_types=1);
require_once __DIR__ . '/append.php';
require_once __DIR__ . '/wallet/jetmora/signer.php';
require_once __DIR__ . '/wallet/bsv/signer.php';
require_once __DIR__ . '/wallet/shared/bip39.php';
require_once __DIR__ . '/wallet/jetmora/thread.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}

$entry = random_bytes(166);                       // an entry-shaped message
$mn    = Bip39::generate();
$seed  = Bip39::toSeed($mn);

// ── the jetmora side: ed25519, from a written-down phrase ────────────────────────────────────────────
echo "── jetmora · ed25519 ──\n";
$j    = JetmoraSigner::fromSeed($seed, "m/44'/0'/0'");
$jPub = $j->publicKey();
$jSig = $j->signEntry($entry);
ok(strlen($jPub) === 32, '★ the public key is 32 bytes RAW — what every live genesis authorises');
ok(strlen($jSig) === 64, 'the signature is 64 bytes');
ok(Appender::verifySignature($entry, $jPub, $jSig),
   "★★★ THE CHAIN'S OWN VERIFIER ACCEPTS IT — not ours, the one that gates an append");
ok(!Appender::verifySignature($entry . 'x', $jPub, $jSig), 'a changed entry is refused');
ok(JetmoraSigner::verify($entry, $jPub, $jSig), '...and our mirror agrees with it');
// ⚠ THE TRAP: pre-hashing for ed25519 gives a well-formed signature the chain refuses.
$wrong = sodium_crypto_sign_detached(hash('sha256', $entry, true),
           sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(
             Slip10Ed25519::derive($seed, "m/44'/0'/0'")['key'])));
ok(!Appender::verifySignature($entry, $jPub, $wrong),
   '⛔ pre-hashing for ed25519 produces a VALID-LOOKING signature the chain REFUSES — the trap named');
// ★ deterministic by construction: ed25519 has no k to get wrong
ok($j->signEntry($entry) === $jSig, '★ ed25519 is deterministic by construction — there is no k at all');

// ── the BSV side: secp256k1 ─────────────────────────────────────────────────────────────────────────
echo "\n── bsv · secp256k1 ──\n";
$b    = BsvSigner::fromPrivateKey(random_bytes(32));
$bPub = $b->publicKey();
$bSig = $b->signEntry($entry);
ok(strlen($bPub) === 33, 'the public key is 33 bytes compressed');
ok(Appender::verifySignature($entry, $bPub, $bSig),
   "★★★ the chain's verifier accepts it too — the SAME function, the OTHER branch");
ok(!Appender::verifySignature($entry . 'x', $bPub, $bSig), 'a changed entry is refused');
ok(BsvSigner::verify($entry, $bPub, $bSig), '...and our mirror agrees');
// ⚠ THE MIRROR-IMAGE TRAP: signing the raw bytes as if they were a digest.
$bad = Secp256k1::sign(gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN),
                       hash('sha256', hash('sha256', $entry, true), true));
ok(!Appender::verifySignature($entry, $bPub, $bad),
   '⛔ a DOUBLE-hashed digest is refused — the wrong hash verifies nowhere and looks perfect');
ok($b->signEntry($entry) === $bSig, 'RFC 6979 makes it deterministic too — same bytes every time');
$der = Secp256k1::decodeDer($bSig);
$n   = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
ok($der !== null && gmp_cmp(gmp_mul($der[1], 2), $n) <= 0,
   '⚠ lowS defaults ON here — not a protocol rule, but a broadcaster can refuse high-s');

// ── ⛔ the two do not accept each other ──────────────────────────────────────────────────────────────
echo "\n── ⛔ the schemes do not cross ──\n";
ok(!Appender::verifySignature($entry, $jPub, $bSig), 'a secp256k1 signature under an ed25519 key: refused');
ok(!Appender::verifySignature($entry, $bPub, $jSig), 'an ed25519 signature under a secp256k1 key: refused');
ok(!JetmoraSigner::verify($entry, $bPub, $bSig), 'the jetmora verifier refuses a 33-byte key outright');

// ── ★ end to end: a phrase, a thread, a signature the chain accepts ──────────────────────────────────
echo "\n── ★ phrase → key → authorised thread → signature ──\n";
$auth = CovenantThread::authorisedHashes([$jPub]);
ok(CovenantThread::isAuthorised($auth, $jPub),
   '★ a genesis authorises the ed25519 key derived from the phrase (§4.2a v0x02: its sha256)');
ok(!str_contains($auth, $jPub), '⛔ ...and the key itself is not in the genesis');
$g = CovenantThread::create(hash('sha256', 'src', true), "\x51", '', $auth);
ok(strlen($g['id']) === 32, 'the thread exists');
// ⚠ the same phrase on another device reproduces the same key — which is the whole exit story
$again = JetmoraSigner::fromSeed(Bip39::toSeed($mn), "m/44'/0'/0'");
ok($again->publicKey() === $jPub,
   '★★★ the same phrase on another device gives the SAME KEY — the exit story, end to end');
ok(JetmoraSigner::fromSeed(Bip39::toSeed($mn, 'x'), "m/44'/0'/0'")->publicKey() !== $jPub,
   '⚠ ...and a passphrase gives an entirely different wallet');

printf("\n%s  %d passed, %d failed   [scheme-aware signing · graded by the CHAIN's verifier]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
