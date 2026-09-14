<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── BIP-39, GRADED BY THE OFFICIAL VECTORS ───────────────────────────────────────────────────────────
//
// ★★★ 24 English vectors, verbatim from the reference implementation, each carrying entropy, mnemonic
//   and seed — with the passphrase `TREZOR` throughout. ⇒ **Both directions are graded**: entropy →
//   mnemonic AND mnemonic → seed. Passing one and not the other would leave a wallet that generates
//   correct words and derives the wrong keys, which is the failure with no symptom.
//
// ⚠ The WORDLIST is verified structurally too, because a single wrong word breaks interoperability
//   silently: BIP-39 requires the first FOUR LETTERS to identify each word unambiguously, and that is
//   a property a corrupted list would fail.
declare(strict_types=1);
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
    if (str_contains($e->getMessage(), $needle)) { $pass++; }
    else { $fail++; printf("  ✗ %s — wrong reason: %s\n", $what, $e->getMessage()); }
  }
}

// ── the wordlist itself ─────────────────────────────────────────────────────────────────────────────
echo "── the wordlist ──\n";
$w = Bip39::words();
ok(count($w) === 2048,              'exactly 2048 words');
ok(count(array_unique($w)) === 2048,'all unique');
$sorted = $w; sort($sorted, SORT_STRING);
ok($w === $sorted,                  'sorted alphabetically');
ok(count(array_unique(array_map(fn($x) => substr($x, 0, 4), $w))) === 2048,
   '★ the first FOUR LETTERS identify each word — BIP-39 requires it, and a corrupted list would fail');
ok($w[0] === 'abandon' && $w[2047] === 'zoo', 'begins "abandon", ends "zoo"');
printf("  %d wordlist checks\n", 5);

// ── the 24 official vectors, BOTH directions ────────────────────────────────────────────────────────
echo "\n── the official vectors ──\n";
$vectors = json_decode(file_get_contents(__DIR__ . '/wallet/shared/bip39-vectors.json'), true);
ok(is_array($vectors) && count($vectors) === 24, '24 english vectors loaded');
$mOK = $sOK = $rOK = 0;
foreach ($vectors as [$entropyHex, $mnemonic, $seedHex, $xprv]) {
  $entropy = hex2bin($entropyHex);
  if (Bip39::fromEntropy($entropy) === $mnemonic)                       $mOK++;
  if (bin2hex(Bip39::toSeed($mnemonic, 'TREZOR')) === $seedHex)         $sOK++;
  if (Bip39::toEntropy($mnemonic) === $entropy)                         $rOK++;   // and back again
}
ok($mOK === 24, "entropy → mnemonic on all 24 ($mOK)");
ok($sOK === 24, "★★ mnemonic → SEED on all 24 ($sOK) — the half that silently breaks key derivation");
ok($rOK === 24, "mnemonic → entropy round-trips on all 24 ($rOK)");
printf("  24 vectors × 3 directions\n");

// ── the checksum, which is the whole reason a mnemonic beats hex ────────────────────────────────────
echo "\n── ⛔ the checksum earns its keep ──\n";
$m = Bip39::fromEntropy(str_repeat("\x00", 16));
ok($m === 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
   'all-zero entropy gives the canonical "abandon…about"');
// ⚠ swap two words: still 12 valid words, still the right length — ONLY the checksum catches it
$sw = explode(' ', Bip39::fromEntropy(hex2bin('7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f')));
[$sw[0], $sw[1]] = [$sw[1], $sw[0]];
refuses(fn() => Bip39::toEntropy(implode(' ', $sw)), 'checksum does not match',
        '★★★ two TRANSPOSED words are caught — hex could not catch this');
refuses(fn() => Bip39::toEntropy('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'),
        'checksum does not match', 'a wrong final word is caught');
// ⚠ "zebra" IS a BIP-39 word — my first attempt used it and was caught as a CHECKSUM failure, which
//   was the code being right and the test being wrong. "bitcoin" is genuinely absent from the list.
refuses(fn() => Bip39::toEntropy('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bitcoin'),
        'not a BIP-39 word', 'a word outside the list is caught, and named');
refuses(fn() => Bip39::toEntropy('abandon abandon about'), '12, 15, 18, 21 or 24 words',
        'a wrong word count is refused');
ok(Bip39::isValid($m) && !Bip39::isValid(implode(' ', $sw)), 'isValid() agrees with toEntropy()');

// ── generation, and the sizes the spec allows ───────────────────────────────────────────────────────
echo "\n── generation ──\n";
foreach ([128 => 12, 160 => 15, 192 => 18, 224 => 21, 256 => 24] as $bits => $words) {
  $g = Bip39::generate($bits);
  ok(count(explode(' ', $g)) === $words && Bip39::isValid($g), "$bits bits → $words words, valid");
}
refuses(fn() => Bip39::generate(129), '128, 160, 192, 224 or 256', 'an off-spec strength is refused');
refuses(fn() => Bip39::fromEntropy(random_bytes(17)), '16, 20, 24, 28 or 32 bytes',
        'off-spec entropy is refused');
$a = Bip39::generate(); $b = Bip39::generate();
ok($a !== $b, 'two generations differ');

// ── the passphrase, and the trap in it ──────────────────────────────────────────────────────────────
echo "\n── the passphrase ──\n";
ok(Bip39::toSeed($m, '') !== Bip39::toSeed($m, 'x'),
   '★ a passphrase is a 25th word: a different one is a DIFFERENT WALLET');
ok(strlen(Bip39::toSeed($m)) === 64, 'the seed is 64 bytes');
// ⚠⚠ THE TRAP: a seed comes back for an INVALID mnemonic too, because BIP-39 defines it over the
//    string. A wallet must call toEntropy() to check; getting a seed proves nothing.
ok(strlen(Bip39::toSeed('not even close to a mnemonic')) === 64,
   '⚠ an INVALID mnemonic still yields a seed — validity must be checked separately, never inferred');

// ── ⛔ NFKD: refuse rather than differ ───────────────────────────────────────────────────────────────
echo "\n── ⛔ NFKD ──\n";
ok(Bip39::nfkd('plain ascii') === 'plain ascii', 'ASCII passes through — NFKD is the identity there');
if (extension_loaded('intl')) {
  ok(Bip39::nfkd("é") !== '', 'non-ASCII normalises via ext-intl');
} else {
  refuses(fn() => Bip39::toSeed($m, "café"), 'ext-intl is unavailable',
          '★★★ a non-ASCII passphrase is REFUSED, not silently unnormalised — a different seed here '
        . 'means a wallet that cannot recover anywhere else');
}

// ── ⌨★★★ CJK INPUT METHODS — a real way to lose a wallet ────────────────────────────────────────────
// His question, 8 Sept: *"could browsers using double byte languages corrupt the seed phrase?"*
// ⇒ MEASURED, and one of the two risks was real.
echo "\n── ⌨ CJK input ──\n";
// ✅ NOT a risk: PHP's \s under /u already matches the separators these locales produce.
foreach (["\u{3000}" => 'U+3000 IDEOGRAPHIC space — what Japanese mnemonics are separated by',
          "\u{00a0}" => 'U+00A0 no-break space — the classic copy-paste artifact'] as $sep => $why) {
  $joined = str_replace(' ', $sep, $m);
  ok(Bip39::toEntropy($joined) === Bip39::toEntropy($m), "handles $why");
}
// ⛔ REAL: an IME in full-width mode produces characters that LOOK IDENTICAL and are not the same bytes.
$fw = '';
foreach (preg_split('//u', $m, -1, PREG_SPLIT_NO_EMPTY) as $c)
  $fw .= $c === ' ' ? "\u{3000}" : mb_chr(mb_ord($c) - 0x21 + 0xFF01);
ok($fw !== $m && mb_strlen($fw) === mb_strlen($m),
   '★ full-width "abandon" is ａｂａｎｄｏｎ — same length on screen, 3x the bytes, NOT in the wordlist');
ok(Bip39::toEntropy($fw) === Bip39::toEntropy($m),
   '★★★ a full-width mnemonic from a CJK IME now yields the SAME ENTROPY');
ok(Bip39::toSeed($fw) === Bip39::toSeed($m),
   '★★★ ...and the SAME SEED — a user in Japan or Taiwan can type a perfect phrase and have it work');
// ⚠ and the fold is CHECKED, not blind: anything still non-ASCII afterwards is refused as before
if (!extension_loaded('intl'))
  refuses(fn() => Bip39::toSeed($m, "caf\u{e9}"), 'passphrase contains characters',
          '⛔ genuinely non-ASCII is STILL refused, and the message names WHICH input');

printf("\n%s  %d passed, %d failed   [BIP-39 · official vectors]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
