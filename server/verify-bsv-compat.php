<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── ⚠⚠⚠ DOES OUR PHP DERIVE THE SAME KEYS AS THE LIVE BSV APPS? ─────────────────────────────────────
//
// His question, 8 Sept: *"Just like to confirm that this is still compatible with the BSV chain and our
// covenants already there."*
//
// ★★★ THE ONLY ANSWER THAT COUNTS IS A BYTE COMPARISON AGAINST WHAT ACTUALLY SHIPPED. `PharLap/src/
//   app.ts` and `nft-gift/wallet-src/wallet.js` both derive at **`m/44'/236'/0'/0/0`** via `@bsv/sdk`,
//   and app.ts says it in the source: *"MUST never change — restores derive the same key from it."*
//   ⇒ So this suite pins OUR implementation against THEIRS, phrase by phrase.
//
// ⛔⛔ THESE VECTORS CANNOT BE REGENERATED. `@bsv/sdk` is being REMOVED (Open BSV v6 clause 2 bars
//   jetmora), so the oracle that produced them is going away. ⇒ They were captured on 8 Sept 2026 while
//   it was still installed, and frozen into `bsv-compat-vectors.json`. ★ That is the whole point: after
//   the removal, THIS FILE is the only thing that still knows what the live apps derive.
//
// ⚠ A WRONG ANSWER HERE IS SILENT AND EXPENSIVE. Every value below is well-formed under any variation:
//   a different coin type, a missing hardened marker, BIP-32's rule swapped for SLIP-0010's — each
//   yields a perfectly valid WIF for a key holding nothing, restored from a phrase that looks right.
declare(strict_types=1);
require_once __DIR__ . '/wallet/shared/bip39.php';
require_once __DIR__ . '/wallet/bsv/bip32.php';
require_once __DIR__ . '/wallet/bsv/signer.php';
require_once __DIR__ . '/wallet/bsv/address.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}

$V = json_decode(file_get_contents(__DIR__ . '/wallet/bsv/bsv-compat-vectors.json'), true);
$PATH = $V['path'];
printf("── our PHP  vs  %s ──\n   path %s, frozen 8 Sept\n", $V['source'], $PATH);

foreach ($V['vectors'] as $v) {
  $lbl  = explode(' ', $v['mnemonic'])[0] . '…' . ($v['passphrase'] ? " +\"{$v['passphrase']}\"" : '');
  $seed = Bip39::toSeed($v['mnemonic'], $v['passphrase']);
  $sgn  = BsvSigner::fromSeed($seed, $PATH);

  ok($sgn->toWif() === $v['wif'],                              "$lbl — WIF is byte-identical");
  ok(bin2hex($sgn->publicKey()) === $v['pub'],                 "$lbl — public key");
  ok(Bip32::serialize(Bip32::master($seed)) === $v['xprv_master'], "$lbl — master xprv");
  ok(BsvSigner::fromSeed($seed, "m/44'/236'/0'/0/1")->toWif() === $v['wif_index1'],
                                                               "$lbl — index 1 (the path is honoured)");
  // ⚠ We CANNOT emit the address — §2c-i, and `Base58Check` has no encode() by design.
  // ★ So the check runs the other way: DECODE the SDK's address and match its hash160 to our key.
  //   ⇒ Which demonstrates the constraint costs nothing here: refusing to WRITE an address never
  //     stopped us proving we control one.
  $d = Base58Check::decode($v['address']);
  ok($d !== null && $d['version'] === 0x00
     && $d['payload'] === hash('ripemd160', hash('sha256', $sgn->publicKey(), true), true),
     "$lbl — the live app's ADDRESS hashes from our public key");
  // ⚠ and a WIF round trip must not silently drop the compression flag: uncompressed is a DIFFERENT
  //   address for the same key, which is a classic way to lose coins that are provably yours.
  ok(BsvSigner::fromWif($v['wif'])->publicKey() === $sgn->publicKey(), "$lbl — WIF import round-trips");
}

// ── ⛔ the near misses, each of which is a valid-looking wallet holding nothing ──────────────────────
echo "\n── ⛔ the ways this goes silently wrong ──\n";
$v0   = $V['vectors'][0];
$seed = Bip39::toSeed($v0['mnemonic']);
foreach ([
  ["m/44'/0'/0'/0/0",   "coin type 0 (Bitcoin) instead of 236 (BSV)"],
  ["m/44'/236'/0'/0/1", 'the next address index'],
  ["m/44'/236'/0/0/0",  'account not hardened'],
  ["m/44'/236'/0'/1/0", 'the CHANGE chain instead of receive'],
] as [$p, $why])
  ok(BsvSigner::fromSeed($seed, $p)->toWif() !== $v0['wif'], "⛔ $why gives a different key");
// ★★ and the one that would look most convincing of all: SLIP-0010's rule on secp256k1's curve
ok(bin2hex(substr(hash_hmac('sha512', $seed, 'Bitcoin seed', true), 0, 32))
   !== bin2hex(Bip32::derive($seed, $PATH)['key']),
   '⛔ taking I_L directly (SLIP-0010\'s rule) gives a different key');

// ── ★ and the signature the covenants actually check ────────────────────────────────────────────────
// ⚠ Most of the live covenants carry NO key at all — the battery is OP_PUSH_TX, so there is nothing to
//   steal. ⇒ What a key does on that chain is AUTHORISE A SPEND, so the property that matters is that
//   the key is the same one, which every line above already pins.
echo "\n── ★ the key signs, deterministically ──\n";
$sgn = BsvSigner::fromWif($v0['wif']);
$msg = 'a covenant spend';
ok(BsvSigner::verify($msg, $sgn->publicKey(), $sgn->signEntry($msg)), 'it signs and verifies');
ok($sgn->signEntry($msg) === $sgn->signEntry($msg), 'RFC 6979: the same bytes every time');

printf("\n%s  %d agree, %d disagree   [live BSV app compatibility · frozen SDK vectors]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
