<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── BIP-32 + WIF, GRADED BY THE BIP'S OWN VECTORS ────────────────────────────────────────────────────
//
// ★★★ TWO independent grades, and they check different halves:
//   1. **BIP-32 test vector 1** — six chains, xprv AND xpub. ⇒ Grades derivation (hardened AND normal)
//      and the 78-byte serialization together, because a wrong depth, fingerprint or index produces a
//      correct KEY inside a wrong xprv, and only the string catches it.
//   2. **The 24 BIP-39 vectors' `xprv` field** — already on disk from stage 3a. ⇒ Grades the whole path
//      **mnemonic → seed → master → xprv** in one line each, which nothing else does end to end.
//
// ⚠ BIP-32 is secp256k1-specific. The jetmora side is SLIP-0010 over ed25519 — a DIFFERENT algorithm,
//   and `verify-slip10.php` grades that separately. They must not be confused, so they are not shared.
declare(strict_types=1);
require_once __DIR__ . '/wallet/bsv/bip32.php';
require_once __DIR__ . '/wallet/bsv/address.php';
require_once __DIR__ . '/wallet/shared/bip39.php';

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

// ── BIP-32 test vector 1 ────────────────────────────────────────────────────────────────────────────
echo "── BIP-32 test vector 1 ──\n";
const V1 = [
 ['m', 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
       'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'],
 ["m/0'", 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
          'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'],
 ["m/0'/1", 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
            'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'],
 ["m/0'/1/2'", 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
                'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'],
 ["m/0'/1/2'/2", 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
                  'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'],
 ["m/0'/1/2'/2/1000000000", 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
                             'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'],
];
$seed = hex2bin('000102030405060708090a0b0c0d0e0f');
foreach (V1 as [$path, $xpub, $xprv]) {
  $n = Bip32::derive($seed, $path);
  ok(Bip32::serialize($n, true)  === $xprv, "$path — xprv");
  ok(Bip32::serialize($n, false) === $xpub, "$path — xpub");
}
printf("  6 chains × xprv + xpub — hardened AND normal steps\n");
// ★ The vector set deliberately mixes them, so passing it proves BOTH derivation modes.
ok(str_contains(V1[2][0], '/1') && str_contains(V1[1][0], "'"),
   '★ the path set mixes hardened and NORMAL steps — both modes are graded, not just one');

// ── the BIP-39 vectors' xprv: the whole path, mnemonic → xprv ────────────────────────────────────────
echo "\n── mnemonic → seed → master → xprv, on all 24 BIP-39 vectors ──\n";
$v39 = json_decode(file_get_contents(__DIR__ . '/wallet/shared/bip39-vectors.json'), true);
$hit = 0;
foreach ($v39 as [$entropyHex, $mnemonic, $seedHex, $xprv]) {
  if (Bip32::serialize(Bip32::master(Bip39::toSeed($mnemonic, 'TREZOR'))) === $xprv) $hit++;
}
ok($hit === 24, "★★★ all 24 ($hit) — BIP-39 and BIP-32 agree END TO END, from words a person writes down");

// ── WIF ─────────────────────────────────────────────────────────────────────────────────────────────
echo "\n── WIF ──\n";
// ⚠ The canonical example: key = 0x01, compressed, mainnet.
$k1 = str_pad("\x01", 32, "\x00", STR_PAD_LEFT);
$w  = Wif::encode($k1, true);
ok($w[0] === 'K' || $w[0] === 'L', "a compressed mainnet WIF starts K or L ($w[0])");
ok(Wif::encode($k1, false)[0] === '5', 'an UNCOMPRESSED mainnet WIF starts 5');
$d = Wif::decode($w);
ok($d !== null && $d['key'] === $k1 && $d['compressed'] === true, 'round-trips, compression flag intact');
// ⚠⚠ The 0x01 suffix is not decoration: the same key with and without it gives DIFFERENT addresses,
//    which is a classic way to lose funds that are provably yours.
ok(Wif::encode($k1, true) !== Wif::encode($k1, false),
   '⚠ compressed and uncompressed WIFs differ — the same key, two addresses');
ok(Wif::decode('not a wif') === null, 'garbage is refused');
ok(Wif::decode(substr($w, 0, -1) . 'x') === null, 'a mutated checksum is refused');

// ── ⛔ §2c-i SURVIVES: this encoder cannot emit an ADDRESS ───────────────────────────────────────────
echo "\n── ⛔ §2c-i ──\n";
foreach ([0x00 => 'P2PKH mainnet', 0x05 => 'P2SH mainnet', 0x6f => 'P2PKH testnet', 0xc4 => 'P2SH testnet']
         as $v => $what)
  refuses(fn() => Base58KeyCodec::encode(random_bytes(20), $v), 'is an ADDRESS version',
          "⛔ $what is refused — the encoder CANNOT produce an address");
ok(!method_exists('Base58Check', 'encode'),
   '★ and Base58Check still has no encode() at all — §2c-i enforced in two places, not one');
// ★ the proof it matters: a P2PKH address built from the same bytes would decode as one
ok(Base58Check::decode(Wif::encode($k1)) !== null,
   '⚠ a WIF IS valid base58check — which is exactly why §2c-i is about ADDRESSES, not the encoding');

// ── the differences from SLIP-0010, asserted rather than commented ───────────────────────────────────
echo "\n── ⚠ BIP-32 is not SLIP-0010 ──\n";
$I = hash_hmac('sha512', $seed, 'Bitcoin seed', true);
ok(substr($I, 0, 32) === Bip32::master($seed)['key'], 'the HMAC key is "Bitcoin seed"');
ok(hash_hmac('sha512', $seed, 'ed25519 seed', true) !== $I,
   '⚠ "ed25519 seed" gives a different master — the wrong string is a silent fork');
// ★★ child = (IL + kpar) mod n, NOT IL. Assert the difference is real on a live derivation.
$m = Bip32::master($seed); $c = Bip32::child($m, Bip32::HARDENED);
$IL = substr(hash_hmac('sha512', "\x00" . $m['key'] . pack('N', Bip32::HARDENED), $m['chain'], true), 0, 32);
ok($c['key'] !== $IL,
   '★★ the child key is (IL + kpar) mod n, NOT IL — taking IL directly is SLIP-0010 and yields another wallet');
ok($c['depth'] === 1 && $c['parentFp'] === Bip32::fingerprint($m),
   'depth and parent fingerprint are carried — a wrong one gives a right key in a wrong xprv');

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────
echo "\n── refusals ──\n";
refuses(fn() => Bip32::derive($seed, "0'"), 'starts with "m/"', 'a path without "m/" is refused');
refuses(fn() => Bip32::derive($seed, 'm/x'), 'not a path index', 'a non-numeric segment is refused');
refuses(fn() => Bip32::master(random_bytes(8)), '16 to 64 bytes', 'a short seed is refused');
refuses(fn() => Wif::encode(random_bytes(31)), 'is 32 bytes', 'a short key is refused');

// ── ★ the signer takes a phrase and a WIF, and the CHAIN still accepts what it signs ────────────────
echo "\n── ★ BsvSigner · phrase and WIF ──\n";
require_once __DIR__ . '/append.php';
require_once __DIR__ . '/wallet/bsv/signer.php';
$mn    = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
$sgn   = BsvSigner::fromSeed(Bip39::toSeed($mn));
$entry = random_bytes(166);
ok(Appender::verifySignature($entry, $sgn->publicKey(), $sgn->signEntry($entry)),
   "★★★ a phrase → BIP-32 → a signature THE CHAIN'S OWN VERIFIER accepts");
ok(BsvSigner::fromSeed(Bip39::toSeed($mn))->publicKey() === $sgn->publicKey(),
   'the same phrase gives the same key — the exit story on the BSV side too');
// ⚠⚠ the compression flag must SURVIVE the WIF round trip, or the key spends a different address
$w = $sgn->toWif();
ok(BsvSigner::fromWif($w)->publicKey() === $sgn->publicKey(), 'WIF round-trips through the signer');
$unc = BsvSigner::fromPrivateKey(Bip32::derive(Bip39::toSeed($mn), "m/44'/236'/0'/0/0")['key'], false);
ok(strlen($unc->publicKey()) === 65 && strlen($sgn->publicKey()) === 33,
   '⚠⚠ the compression flag TRAVELS — 65 bytes vs 33, which is two different addresses for one key');
ok(BsvSigner::fromWif($unc->toWif())->publicKey() === $unc->publicKey(),
   '★ ...and it survives the WIF round trip, which is how that key is lost when it does not');
try { BsvSigner::fromWif('nonsense'); ok(false, 'a bad WIF is refused'); }
catch (Throwable $e) { ok(str_contains($e->getMessage(), 'not a valid WIF'), 'a bad WIF is refused'); }
ok(BsvSigner::fromSeed(Bip39::toSeed($mn), "m/44'/236'/0'/0/1")->publicKey() !== $sgn->publicKey(),
   'the next address index is a different key');

printf("\n%s  %d passed, %d failed   [BIP-32 + WIF · BIP-32 and BIP-39 official vectors]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
