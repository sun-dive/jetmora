<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// Graded by BIP-350's OWN test vectors, verbatim — including every invalid case, because an address
// decoder that only accepts the right answers has not been tested at all.
//
// ★★ And one grade BIP-350 cannot give: the §2c-i property that a jetmora address MUST NOT parse as a
//    Bitcoin address. That is checked directly, against the base58check decoder in the same file.
declare(strict_types=1);
// ⚠ ONE TEST, BOTH SIDES — a test may cross the boundary that the CODE may not, and this one
//   must, because the §2c-i property is precisely that the two do not overlap.
require_once __DIR__ . '/wallet/jetmora/address.php';
require_once __DIR__ . '/wallet/bsv/address.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── BIP-350 §Test vectors — VALID bech32m strings ───────────────────────────────────────────────────
echo "── BIP-350 valid bech32m strings ──\n";
foreach ([
  'A1LQFN3A', 'a1lqfn3a',
  'an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6',
  'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx',
  '11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8',
  'split1checkupstagehandshakeupstreamerranterredcaperredlc445v',
  '?1v759aa',
] as $s) {
  $d = Bech32::decode($s);
  ok($d !== null && $d['spec'] === Bech32::BECH32M, "should decode as bech32m: $s");
}
printf("  %d valid strings\n", 7);

// ── BIP-350 §Test vectors — INVALID, with the RFC's own stated reason ───────────────────────────────
echo "\n── BIP-350 invalid bech32m strings (each must be REFUSED) ──\n";
foreach ([
  ["\x20" . '1xj0phk',  'HRP character out of range'],
  ["\x7F" . '1g6xzxy',  'HRP character out of range'],
  ["\x80" . '1vctc34',  'HRP character out of range'],
  ['an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4',
                        'overall max length exceeded'],
  ['qyrz8wqd2c9m',      'no separator character'],
  ['1qyrz8wqd2c9m',     'empty HRP'],
  ['y1b0jsk6g',         'invalid data character'],
  ['lt1igcx5c0',        'invalid data character'],
  ['in1muywd',          'too short checksum'],
  ['mm1crxm3i',         'invalid character in checksum'],
  ['au1s5cgom',         'invalid character in checksum'],
  ['M1VUXWEZ',          'checksum calculated with uppercase form of HRP'],
  ['16plkw9',           'empty HRP'],
  ['1p2gdwpf',          'empty HRP'],
] as [$s, $why]) {
  ok(Bech32::decode($s) === null, "must refuse ($why): " . bin2hex(substr($s, 0, 12)));
}
printf("  %d invalid strings\n", 14);

// ── BIP-350 segwit addresses: the full stack, HRP + version + 8↔5 conversion ────────────────────────
echo "\n── BIP-350 segwit addresses → scriptPubKey ──\n";
function segwitScript(string $addr, array $hrps): ?string {
  $d = Bech32::decode($addr);
  if ($d === null || !in_array($d['hrp'], $hrps, true) || count($d['data']) < 1) return null;
  $ver = $d['data'][0];
  if ($ver > 16) return null;
  // ⚠ version 0 is bech32; every other version is bech32m. Accepting either for both is the exact
  //   mistake BIP-350's "Invalid checksum (Bech32 instead of Bech32m)" vectors are there to catch.
  if ($ver === 0 && $d['spec'] !== Bech32::BECH32)  return null;
  if ($ver !== 0 && $d['spec'] !== Bech32::BECH32M) return null;
  $prog = Bech32::convertBits(array_slice($d['data'], 1), 5, 8, false);
  if ($prog === null || count($prog) < 2 || count($prog) > 40) return null;
  if ($ver === 0 && count($prog) !== 20 && count($prog) !== 32) return null;
  $op = $ver === 0 ? 0x00 : 0x50 + $ver;
  return bin2hex(chr($op) . chr(count($prog)) . pack('C*', ...$prog));
}
foreach ([
  ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
  ['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
   '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
  ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y',
   '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'],
  ['BC1SW50QGDZ25J', '6002751e'],
  ['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', '5210751e76e8199196d454941c45d1b3a323'],
  ['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
   '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c',
   '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
   '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'],
] as [$addr, $want]) {
  ok(segwitScript($addr, ['bc', 'tb']) === $want, "scriptPubKey mismatch: $addr");
}
printf("  %d addresses → correct scriptPubKey\n", 8);

echo "\n── BIP-350 invalid segwit addresses (each must be REFUSED) ──\n";
foreach ([
  ['tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut', 'invalid HRP'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd', 'bech32 instead of bech32m'],
  ['tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf', 'bech32 instead of bech32m'],
  ['BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL', 'bech32 instead of bech32m'],
  ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh', 'bech32m instead of bech32'],
  ['tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47', 'bech32m instead of bech32'],
  ['bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4', 'invalid character in checksum'],
  ['BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R', 'invalid witness version'],
  ['bc1pw5dgrnzv', 'invalid program length (1 byte)'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav', 'program length 41'],
  ['BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 'invalid program length for v0'],
  ['tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq', 'mixed case'],
  ['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf', 'zero padding over 4 bits'],
  ['tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j', 'non-zero padding'],
  ['bc1gmk9yu', 'empty data section'],
] as [$addr, $why]) {
  ok(segwitScript($addr, ['bc', 'tb']) === null, "must refuse ($why): $addr");
}
printf("  %d invalid addresses\n", 15);

// ── ⛔⛔ §2c-i — THE PROPERTY BIP-350 CANNOT GRADE ──────────────────────────────────────────────────
echo "\n── §2c-i: a jetmora address must not be a Bitcoin address ──\n";
$mkB58 = function (int $ver, string $p): string {
  $d = chr($ver) . $p;
  $d .= substr(hash('sha256', hash('sha256', $d, true), true), 0, 4);
  $A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  $n = gmp_import($d, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN); $o = '';
  while (gmp_sign($n) > 0) { $o = $A[gmp_intval(gmp_mod($n, 58))] . $o; $n = gmp_div_q($n, 58); }
  return str_repeat('1', strlen($d) - strlen(ltrim($d, "\x00"))) . $o;
};
$leadingJ = 0; $parses = 0;
for ($i = 0; $i < 100; $i++) {
  $addr = JetAddress::encode(random_bytes(32));
  ok(str_starts_with($addr, 'j1'), "must start with j1: $addr");
  if ($addr[0] === 'j') $leadingJ++;
  // ★★★ THE POINT: a Bitcoin wallet's validator must not accept it
  if (Base58Check::looksLikeBitcoinAddress($addr)) $parses++;
}
ok($leadingJ === 100, 'every jetmora address starts with j');
ok($parses === 0,     '⛔ NONE parses as base58check — the distinction is STRUCTURAL, not advisory');
// ⚠ and the contrast: base58check version 0x69 DOES give a leading j, and DOES parse. Ruled out.
$b58j = $mkB58(0x69, random_bytes(20));
ok($b58j[0] === 'j', 'base58check 0x69 also gives a leading j...');
ok(Base58Check::looksLikeBitcoinAddress($b58j), '...⛔ and it PARSES as base58check — why §2c-i rejects it');

echo "\n── round trip and refusals ──\n";
foreach ([1, 20, 32, 33, 50] as $len) {
  $p = random_bytes($len);
  $a = JetAddress::encode($p, 0);
  $d = JetAddress::decode($a);
  ok($d !== null && $d['payload'] === $p && $d['version'] === 0, "round trip $len bytes");
}
// ⚠ THE CEILING IS A REAL LIMIT, so test it rather than trip over it: bech32's error-detection
//   guarantee holds within 90 characters, so the cap is the format working, not a shortcoming.
ok(Bech32::payloadMax('j') === 50, 'HRP j: the payload ceiling is 50 bytes');
ok(strlen(JetAddress::encode(random_bytes(50))) === 89, '...a 50-byte payload gives an 89-char address');
try { JetAddress::encode(random_bytes(51)); ok(false, '51 bytes must be refused'); }
catch (InvalidArgumentException $e) {
  ok(str_contains($e->getMessage(), 'ceiling for HRP'), '51 bytes is refused, naming the ceiling');
}
$a = JetAddress::encode(random_bytes(32));
ok(JetAddress::decode(substr($a, 0, -1) . 'q') === null, 'a mutated checksum is refused');
ok(JetAddress::decode(strtoupper(substr($a, 0, 5)) . substr($a, 5)) === null, 'mixed case is refused');
ok(JetAddress::decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4') === null, 'a bitcoin address is not a jetmora address');
// ⛔ a bech32 (not -m) string with our HRP must be refused, or the weakness is back
$five = Bech32::convertBits(array_values(unpack('C*', random_bytes(32))), 8, 5, true);
$b32  = Bech32::encode('j', array_merge([0], $five), Bech32::BECH32);
ok(Bech32::decode($b32) !== null, 'a bech32 j-string is well-formed bech32...');
ok(JetAddress::decode($b32) === null, '...⛔ and JetAddress still refuses it — bech32m only');

echo "\n── base58check DECODE, which §2c needs for external rails ──\n";
$p20 = random_bytes(20);
$d = Base58Check::decode($mkB58(0x00, $p20));
ok($d !== null && $d['version'] === 0 && $d['payload'] === $p20, 'reads a BSV mainnet P2PKH address');
ok(Base58Check::decode('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2') !== null, 'reads a real-shaped mainnet address');
ok(Base58Check::decode('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3') === null, 'refuses a bad checksum');
ok(Base58Check::decode('1BvBMSEY0stWetqTFn5Au4m4GFg7xJaNVN2') === null, 'refuses a character outside the alphabet');
ok(!method_exists('Base58Check', 'encode'), '⛔ there is NO encode() — §2c-i enforced by absence');

printf("\n%s  %d passed, %d failed   [addresses · BIP-350 vectors + §2c-i]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
