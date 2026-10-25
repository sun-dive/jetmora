<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// server/ed25519.php graded against libsodium 1.0.22, whose rules it takes. ext/sodium at that version is the oracle,
// case by case, and on every case the two must give the same verdict. The corpus is built the same way on every host,
// and the oracle's verdicts over it are pinned below as SPECIAL_DIGEST and SWEEP_DIGEST, so a PHP without sodium is
// graded by them instead. A PHP with another libsodium is graded by them too, and shown where its library differs.
//
//   php server/verify-ed25519.php [sigs=2000] [seed=20261025] [--ed25519=FILE] [--export]
//     sigs       valid signatures in the sweep, each with three single-bit mutations
//     --ed25519  grade FILE instead of the ed25519.php beside this file
//     --export   grade nothing: write the special and sweep cases as JSON on stdout, each with ed25519.php's refusing
//                rule and, where the oracle is loaded, libsodium's verdict, for tools/verify-ed25519.mjs
//
// Test signatures are made with ext/sodium, or on a PHP without it with the sodium_compat whose autoload.php
// JETMORA_SODIUM_COMPAT names. Signing is not under test, and Ed25519 signing is deterministic,
// so either signer makes the same corpus. The special cases are built with ed25519.php's own arithmetic, as
// verify-secp256k1-native.php builds its branch cases: a construction that changed would change the cases, and the
// pinned digest would catch it.
//
// Four parts:
//   special  exhaustive where implementations differ. For A and for R separately: each of the 14 small-order
//            encodings (the 8 points, either sign bit, and p and p + 1), built so that the equation holds and only the
//            small-order rule refuses; the 38 encodings of y from p to 2^255 − 1 with either sign; every y below 19
//            with either sign; 64 random y, about half of them off the curve. Keys of mixed order, a valid key plus each
//            of the 8 small-order points, signed so that the cofactorless equation holds, and so that only the
//            cofactored one does. S at 0, 1, L − 1, L, L + 1, 2L, 2^252, 2^253 and 2^256 − 1, and S + L and S + kL of
//            valid signatures. R of the negated point, so that the equation holds but for the sign of x. The twelve
//            cases of 'Taming the many EdDSAs' (Chalkias et al. 2020), built by their construction. RFC 8032's test
//            vectors, wrong lengths, and empty and long messages. Each case built to be refused by a rule must be
//            refused by that rule, by ed25519.php's own account: rule 3 can be seen no other way (ed25519.php says why).
//   sweep    random keys and messages: valid signatures, and single-bit mutations of signature, key and message.
//   layers   the field, the scalars and the window against gmp where it is loaded; limbs at the widest the formulas
//            allow; the constants and B_ODD rebuilt from B; the 8 small-order points and their orders.
//   edges    garbage of every length gives false and never throws; ed25519.php calls no sodium, gmp, bcmath or openssl.
declare(strict_types=1);

const DEFAULT_SIGS = 2000, DEFAULT_SEED = 20261025;
const ORACLE_VERSION = '1.0.22';
/** sha256 over each part's cases and libsodium 1.0.22's verdict on each: at the default seed, and the sweep's at the default sigs. */
const SPECIAL_DIGEST = '9a4a488a74044e866f1ccd3d4de0988fd59fad9c0fee0655f727680a335e62df';
const SWEEP_DIGEST   = '85c9c0c0ebf164d9e9b4b4d4abe86563cfffe6f995a3d85efa9a6bb668761905';
const P_HEX = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed';
const L_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';

$plain = array_values(array_filter(array_slice($argv, 1), fn($a) => !str_starts_with($a, '--')));
$opt = function (string $name) use ($argv): ?string {
  foreach ($argv as $a) if (str_starts_with($a, "--$name=")) return substr($a, strlen($name) + 3);
  return null;
};
$sigs = (int)($plain[0] ?? DEFAULT_SIGS);
$seed = (int)($plain[1] ?? DEFAULT_SEED);
$file = $opt('ed25519') ?? __DIR__ . '/ed25519.php';
require_once $file;
$pinned = $sigs === DEFAULT_SIGS && $seed === DEFAULT_SEED;
$export = in_array('--export', $argv, true);
if ($export) ob_start();                                // stdout carries the JSON alone

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── the oracle, and the signer ───────────────────────────────────────────────────────────────────────
$sodium = extension_loaded('sodium');
$oracle = $sodium && SODIUM_LIBRARY_VERSION === ORACLE_VERSION;
$other = $sodium && !$oracle;                           // a libsodium whose verdicts are shown, never graded against
if (!$sodium) {
  $compat = getenv('JETMORA_SODIUM_COMPAT') ?: '';
  if (!is_file($compat)) {
    fwrite(STDERR, "⛔ nothing to sign with: no ext/sodium, and JETMORA_SODIUM_COMPAT names no sodium_compat autoload.php\n");
    exit(2);
  }
  require_once $compat;
  ParagonIE_Sodium_Compat::$fastMult = true;            // its native multiply: the keys are test keys, and public
}
printf("  - grading %s\n", realpath($file) ?: $file);
if ($oracle) echo "  - the oracle: ext/sodium, libsodium " . SODIUM_LIBRARY_VERSION . "\n";
elseif ($other) echo '  - no oracle: this PHP has libsodium ' . SODIUM_LIBRARY_VERSION . ', not the ' . ORACLE_VERSION
                     . " the rules are taken from. Graded by the pinned digests; where this library differs is shown.\n";
else echo "  - no oracle: ext/sodium is not loaded. Graded by the pinned digests; signed by sodium_compat.\n";

/** libsodium's verdict. A wrong length throws there: a refusal, as the engine has always counted it. */
function sodiumVerdict(string $sig, string $msg, string $pub): bool {
  try { return sodium_crypto_sign_verify_detached($sig, $msg, $pub); } catch (Throwable) { return false; }
}

// ── ed25519.php's own arithmetic, for building cases ─────────────────────────────────────────────────
$C = Closure::bind(static fn(string $m, ...$a) => self::$m(...$a), null, Ed25519::class);
$C('init');
function E(string $m, mixed ...$a): mixed { return ($GLOBALS['C'])($m, ...$a); }

const F0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const F1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const IDENTITY = [F0, F1, F1, F0];
$Z32 = str_repeat("\0", 32);
$L = strrev(hex2bin(L_HEX));                            // little-endian, as every scalar here
$P = strrev(hex2bin(P_HEX));

// little-endian integers, independent of the file under test
function le_add(string $a, string $b): string {
  $n = max(strlen($a), strlen($b)); $a = str_pad($a, $n, "\0"); $b = str_pad($b, $n, "\0");
  $out = ''; $c = 0;
  for ($i = 0; $i < $n; $i++) { $v = ord($a[$i]) + ord($b[$i]) + $c; $out .= chr($v & 0xFF); $c = $v >> 8; }
  return $c ? $out . chr($c) : $out;
}
function le_mul(string $a, string $b): string {
  $x = array_values(unpack('v*', strlen($a) % 2 ? "$a\0" : $a));
  $y = array_values(unpack('v*', strlen($b) % 2 ? "$b\0" : $b));
  $c = array_fill(0, count($x) + count($y), 0);
  foreach ($x as $i => $xi) foreach ($y as $j => $yj) $c[$i + $j] += $xi * $yj;
  $out = ''; $carry = 0;
  foreach ($c as $v) { $v += $carry; $out .= pack('v', $v & 0xFFFF); $carry = $v >> 16; }
  for (; $carry; $carry >>= 16) $out .= pack('v', $carry & 0xFFFF);
  return $out;
}
function le_int(int $v): string { return pack('P', $v); }
function le_fits(string $a, int $len): bool { return strlen(rtrim($a, "\0")) <= $len; }
function flipBit(string $b, int $bit): string { $i = intdiv($bit, 8); $b[$i] = chr(ord($b[$i]) ^ (1 << ($bit % 8))); return $b; }

/** (a·b + c) mod L, each little-endian and below 2^255. */
function sc(string $a, string $b = "\x01", string $c = ''): string {
  return E('scReduce', str_pad(substr(le_add(le_mul($a, $b), $c), 0, 64), 64, "\0"));
}
function hram(string $R, string $A, string $M): string { return E('scReduce', hash('sha512', $R . $A . $M, true)); }
/** The point an encoding reads as, or null off the curve: decodeNegated's point, negated back. */
function pt(string $enc): ?array { $n = E('decodeNegated', $enc); return $n === null ? null : pneg($n); }
function pneg(array $p): array { return [E('neg', $p[0]), $p[1], $p[2], E('neg', $p[3])]; }
function padd(array $p, array $q): array { return E('p3', E('addCached', $p, E('cached', $q), false)); }
/** A p2 point as p3: (XZ, YZ, Z², XY). */
function p3of(array $p): array { return [E('mul', $p[0], $p[2]), E('mul', $p[1], $p[2]), E('sq', $p[2]), E('mul', $p[0], $p[1])]; }
function base(string $k): array { return p3of(E('mulAdd', '', IDENTITY, $k)); }     // [k]B
function enc(array $p): string { return E('encode', [$p[0], $p[1], $p[2]]); }

// the small-order points: [k]T for k = 0..7, T of order 8, the y of order 8 with the sign bit clear
$T8 = pt(hex2bin('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'));
$tor = [IDENTITY];
for ($k = 1; $k <= 8; $k++) $tor[$k] = padd($tor[$k - 1], $T8);
$torEnc = array_map('enc', array_slice($tor, 0, 8));
$torIndex = array_flip($torEnc);                        // canonical encoding => k
/** k with [k]T = the point $enc reads as, for a small-order encoding. */
$kOf = fn(string $enc): int => $torIndex[enc(pt($enc))];
/** −[h]·[k]T as a multiple of T: h mod 8 is h's low three bits, L being odd. */
$negHk = fn(string $h, int $k): int => (8 - ((ord($h[0]) & 7) * $k) % 8) % 8;

// the 14 small-order encodings: seven y, either sign bit; and which point each reads as
$small = [];
foreach (['0000000000000000000000000000000000000000000000000000000000000000', '0100000000000000000000000000000000000000000000000000000000000000',
          '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
          'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
          'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'] as $y)
  foreach ([0, 0x80] as $sign) { $e = hex2bin($y); $e[31] = chr(ord($e[31]) | $sign); $small[] = $e; }
/** y + p for y below 19: a non-canonical encoding. */
$nonCanonical = function (int $y, int $sign) use ($P): string {
  $e = substr(le_add($P, chr($y)), 0, 32); $e[31] = chr(ord($e[31]) | $sign); return $e;
};
$isCanonical = fn(string $e): bool => strcmp(strrev(substr($e, 0, 31) . chr(ord($e[31]) & 0x7f)), strrev($P)) < 0;

// ── the signer ───────────────────────────────────────────────────────────────────────────────────────
$rnd = fn(string $tag): string => hash('sha256', "$seed:$tag", true);
$num = fn(string $tag, int $mod): int => unpack('N', $rnd($tag))[1] % $mod;
$bytes = function (string $tag, int $n) use ($rnd): string { $b = ''; for ($i = 0; strlen($b) < $n; $i++) $b .= $rnd("$tag/$i"); return substr($b, 0, $n); };
$keyOf = fn(string $name): string => sodium_crypto_sign_seed_keypair(hash('sha256', "$seed:key:$name", true));
$signed = function (string $kp, string $msg): array {
  return [sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($kp)), $msg, sodium_crypto_sign_publickey($kp)];
};
/** The sweep: random keys and messages, each valid signature followed by three single-bit mutations of it. */
$sweep = function () use ($sigs, $num, $bytes, $keyOf, $signed) {
  $kp = null;
  for ($i = 0; $i < $sigs; $i++) {
    if ($i % 4 === 0) $kp = $keyOf("sweep " . intdiv($i, 4));
    $len = $num("len $i", 4) === 0 ? $num("short $i", 9) : $num("long $i", 201);
    [$sig, $msg, $pub] = $signed($kp, $bytes("msg $i", $len));
    yield ["sweep $i", $sig, $msg, $pub];
    $all = $sig . $pub . $msg;
    for ($j = 0; $j < 3; $j++) {
      $m = flipBit($all, $num("bit $i $j", 8 * strlen($all)));
      yield ["sweep $i, bit flipped", substr($m, 0, 64), substr($m, 96), substr($m, 64, 32)];
    }
  }
};

// ── grading ──────────────────────────────────────────────────────────────────────────────────────────
function caseKey(string $sig, string $msg, string $pub): string { return bin2hex($sig) . "\0" . bin2hex($pub) . "\0" . hash('sha256', $msg); }
/**
 * ed25519.php on every case, against the oracle where there is one. Returns the sha256 over each case and the oracle's
 * verdict, or with no oracle ed25519.php's. $why counts the refusing rule, by ed25519.php's account. The verdict is
 * read from refusal(), which verify() is, so each case is computed once; the special part checks the two agree.
 */
function grade(string $part, iterable $cases, bool $oracle, bool $other, ?array &$why = null): string {
  $h = hash_init('sha256'); $n = $same = $otherN = 0; $diffs = []; $why = []; $otherDiffs = [];
  foreach ($cases as $c) {
    [$label, $sig, $msg, $pub] = $c;
    $r = E('refusal', $sig, $msg, $pub);                // what verify() returns is whether this is null
    $got = $r === null;
    $want = $oracle ? sodiumVerdict($sig, $msg, $pub) : $got;
    $n++;
    hash_update($h, caseKey($sig, $msg, $pub) . "\0" . ($want ? '1' : '0') . "\n");
    $why[$r ?? 'accepted'] = ($why[$r ?? 'accepted'] ?? 0) + 1;
    if ($other && sodiumVerdict($sig, $msg, $pub) !== $got) { $otherN++; if (count($otherDiffs) < 6) $otherDiffs[] = $label; }
    if ($want === $got) { $same++; continue; }
    if (count($diffs) < 8) $diffs[] = [$label, $want, $got, $sig, $pub];
  }
  foreach ($diffs as [$label, $want, $got, $sig, $pub])
    printf("    differs: %s\n      sig %s\n      key %s\n      libsodium %s, ed25519.php %s\n", $label, bin2hex($sig), bin2hex($pub),
           var_export($want, true), var_export($got, true));
  ksort($why);
  $mix = implode(', ', array_map(fn($k, $v) => "$v $k", array_keys($why), $why));
  if ($oracle) ok($same === $n, "$part: $same of $n cases give libsodium " . ORACLE_VERSION . "'s verdict ($mix)");
  else echo "  - $part: $n cases run on ed25519.php alone ($mix)\n";
  if ($other) printf("  - libsodium %s differs from ed25519.php on %d of them%s\n", SODIUM_LIBRARY_VERSION, $otherN,
                     $otherDiffs ? ': ' . implode('; ', $otherDiffs) : '');
  return hash_final($h);
}
function pin(string $part, string $digest, string $want, bool $pinned, bool $oracle): void {
  if (!$pinned) { echo "  - $part: not the default " . ($part === 'special' ? 'seed' : 'sigs and seed') . ", so the pinned digest does not apply\n"; return; }
  ok($digest === $want, ($oracle ? "$part: libsodium still gives the pinned verdicts" : "$part: ed25519.php gives libsodium's pinned verdicts")
                        . " ($digest)");
}

// ── 1. the special cases ─────────────────────────────────────────────────────────────────────────────
echo "\n── special: the encodings, orders and scalars where implementations differ ──\n";
$t0 = microtime(true);
$cases = [];                                            // [label, sig, msg, pub, the rule it is built for: null accepts, '-' none]
$add = function (string $label, string $sig, string $msg, string $pub, ?string $aim) use (&$cases) { $cases[] = [$label, $sig, $msg, $pub, $aim]; };
$scalar = fn(string $tag): string => E('scReduce', $rnd("$tag/a") . $rnd("$tag/b"));
/** A key of known a: [a]B, plus [k]T. */
$keyPair = function (string $tag, int $k = 0) use ($scalar, $tor): array {
  $a = $scalar($tag);
  return [$a, enc(padd(base($a), $tor[$k]))];
};
/**
 * R ‖ S over a key [a]B + [kA]T, with R = [r]B + [kR]T: the first message, from "$tag 0" on, for which $want(kR, needed)
 * holds, where needed is the multiple of T that makes the cofactorless equation hold. $kRs says which kR to try, and
 * $hashR, given R, says what is hashed as R (R itself unless a case says otherwise).
 */
$search = function (string $tag, string $a, string $A, int $kA, array $kRs, callable $want, ?callable $hashR = null, ?string $Rfixed = null)
  use ($scalar, $tor, $negHk): array {
  $r = $scalar("$tag r");
  $rB = base($r);
  $Rs = [];
  foreach ($kRs as $kR) $Rs[$kR] = $Rfixed ?? enc(padd($rB, $tor[$kR]));
  for ($j = 0; $j < 400; $j++) {
    $M = "$tag $j";
    foreach ($Rs as $kR => $R) {
      $h = hram($hashR ? $hashR($R) : $R, $A, $M);
      if ($want($kR, $negHk($h, $kA))) return [$R . sc($h, $a, $Rfixed === null ? $r : ''), $M, $h];
    }
  }
  throw new RuntimeException("no message found for $tag");
};
$every = range(0, 7);

// RFC 8032 section 7.1, tests 1 to 3
foreach ([['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
           'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
          ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
           '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
          ['fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
           '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a']] as $i => [$pk, $m, $sg])
  $add('RFC 8032 test ' . ($i + 1), hex2bin($sg), hex2bin($m), hex2bin($pk), null);

// the small-order encodings as A: the equation holds with R = [r]B + [kR]T and S = r, so only the key's rule refuses
foreach ($small as $i => $e) {
  $kA = $kOf($e);
  [$sig, $M] = $search("small A $i", $Z32, $e, $kA, $every, fn($kR, $need) => $kR === $need);
  $add('small-order A ' . bin2hex($e), $sig, $M, $e, $isCanonical($e) ? '4 A small order' : '3 A canonical');
}
// the small-order encodings as R: a key of order 8L, S = h·a, and the message for which −[h]A's torsion is R's point
foreach ($small as $i => $e) {
  $kE = $kOf($e);
  [$a, $A] = $keyPair("small R $i key", 1);
  [$sig, $M] = $search("small R $i", $a, $A, 1, [$kE], fn($kR, $need) => $kR === $need, null, $e);
  $add('small-order R ' . bin2hex($e), $sig, $M, $A, '2 R small order');
}
// y from p to 2^255 − 1, and every y below 19, with either sign, as A and as R, beside a valid signature
[$a0, $A0] = $keyPair('plain key');
[$sig0, $M0] = $search('plain', $a0, $A0, 0, [0], fn($kR, $need) => true);
for ($y = 0; $y < 19; $y++) foreach ([0, 0x80] as $sign) {
  $nc = $nonCanonical($y, $sign);
  $add("non-canonical A, y = p + $y, sign $sign", $sig0, $M0, $nc, '3 A canonical');
  $add("non-canonical R, y = p + $y, sign $sign", $nc . substr($sig0, 32), $M0, $A0, $y < 2 ? '2 R small order' : '6 the equation');
  $cy = str_pad(chr($y), 32, "\0"); $cy[31] = chr($sign);
  $add("A with y = $y, sign $sign", $sig0, $M0, $cy, $y < 2 ? '4 A small order' : '-');
  $add("R with y = $y, sign $sign", $cy . substr($sig0, 32), $M0, $A0, $y < 2 ? '2 R small order' : '6 the equation');
}
// random y, on the curve or off it, with either sign, as A and as R
for ($i = 0; $i < 64; $i++) foreach ([0, 0x80] as $sign) {
  $y = $rnd("y $i"); $y[31] = chr((ord($y[31]) & 0x7f) | $sign);
  $add("A with a random y $i, sign $sign", $sig0, $M0, $y, $isCanonical($y) ? '-' : '3 A canonical');
  $add("R with a random y $i, sign $sign", $y . substr($sig0, 32), $M0, $A0, '6 the equation');
}
// keys of mixed order, [a]B + [k]T for each k: signed so the cofactorless equation holds, so only the cofactored one does,
// and with R = [r]B, whose equation holds exactly when [h]·[k]T is the identity
for ($k = 0; $k < 8; $k++) for ($j = 0; $j < 4; $j++) {
  [$a, $A] = $keyPair("mixed $k $j", $k);
  [$sig, $M] = $search("mixed $k $j holds", $a, $A, $k, $every, fn($kR, $need) => $kR === $need);
  $add("mixed-order A, k = $k: the cofactorless equation holds", $sig, $M, $A, null);
  [$sig, $M] = $search("mixed $k $j cofactored", $a, $A, $k, $every, fn($kR, $need) => $kR !== $need);
  $add("mixed-order A, k = $k: only the cofactored equation holds", $sig, $M, $A, '6 the equation');
  if ($k % 2 === 1) {                                   // [h]·[k]T is the identity only for h a multiple of 8
    [$sig, $M] = $search("mixed $k $j prime R", $a, $A, $k, [0], fn($kR, $need) => $need !== 0);
    $add("mixed-order A, k = $k, R of order L: [h]A's torsion left over", $sig, $M, $A, '6 the equation');
    [$sig, $M] = $search("mixed $k $j prime R holds", $a, $A, $k, [0], fn($kR, $need) => $need === 0);
    $add("mixed-order A, k = $k, R of order L, h a multiple of 8", $sig, $M, $A, null);
  }
}
// S at its edges, and S + L and S + kL of valid signatures
$Lm1 = $L; $Lm1[0] = chr(ord($L[0]) - 1);
$Sedges = ['0' => $Z32, '1' => str_pad("\x01", 32, "\0"), 'L - 1' => $Lm1, 'L' => $L, 'L + 1' => substr(le_add($L, "\x01"), 0, 32),
           '2L' => substr(le_add($L, $L), 0, 32), '2^252' => str_repeat("\0", 31) . "\x10", '2^253' => str_repeat("\0", 31) . "\x20",
           '2^256 - 1' => str_repeat("\xff", 32)];
$plusL = function (string $S, int $k) use ($L): ?string { $v = le_add($S, le_mul($L, le_int($k))); return le_fits($v, 32) ? substr($v, 0, 32) : null; };
for ($i = 0; $i < 3; $i++) {
  [$a, $A] = $keyPair("S key $i");
  [$sig, $M] = $search("S $i", $a, $A, 0, [0], fn($kR, $need) => true);
  $add("S edges $i: the signature itself", $sig, $M, $A, null);
  foreach ($Sedges as $what => $S)
    $add("S = $what", substr($sig, 0, 32) . $S, $M, $A, strcmp(strrev($S), strrev($L)) < 0 ? '6 the equation' : '1 S < L');
}
for ($i = 0; $i < 24; $i++) {
  [$sig, $M, $A] = $signed($keyOf("S + L $i"), $bytes("S + L msg $i", $i * 3));
  $add("S + L, signed by sodium $i", substr($sig, 0, 32) . $plusL(substr($sig, 32), 1), $M, $A, '1 S < L');
  for ($k = 15; ($big = $plusL(substr($sig, 32), $k)) === null; $k--);
  $add("S + {$k}L, the largest below 2^256, $i", substr($sig, 0, 32) . $big, $M, $A, '1 S < L');
}
// 'Taming the many EdDSAs', its twelve cases by their construction. T is of order 8; a key [a]B + T is of mixed order.
$Tn = fn(int $k): string => $torEnc[$k];
[$a, $A] = $keyPair('taming key', 1);
[$sig, $M] = $search('taming 0', $Z32, $Tn(1), 1, [3], fn($kR, $need) => $kR === $need, null, $Tn(3));
$add('taming 0: S = 0, small-order A and R', $sig, $M, $Tn(1), '2 R small order');
[$sig, $M] = $search('taming 1', $Z32, $Tn(1), 1, range(1, 7), fn($kR, $need) => $kR === $need);
$add('taming 1: small-order A, mixed-order R', $sig, $M, $Tn(1), '4 A small order');
[$sig, $M] = $search('taming 2', $a, $A, 1, [5], fn($kR, $need) => $kR === $need, null, $Tn(5));
$add('taming 2: mixed-order A, small-order R', $sig, $M, $A, '2 R small order');
[$sig, $M] = $search('taming 3', $a, $A, 1, range(1, 7), fn($kR, $need) => $kR === $need);
$add('taming 3: mixed-order A and R, the cofactorless equation holds', $sig, $M, $A, null);
[$sig, $M] = $search('taming 4', $a, $A, 1, range(1, 7), fn($kR, $need) => $kR !== $need);
$add('taming 4: mixed-order A and R, only the cofactored equation holds', $sig, $M, $A, '6 the equation');
[$sig, $M] = $search('taming 5', $a, $A, 1, [0], fn($kR, $need) => $need !== 0);
$add('taming 5: mixed-order A, R of order L, only the cofactored equation holds', $sig, $M, $A, '6 the equation');
[$ap, $Ap] = $keyPair('taming prime key');
[$sig, $M] = $search('taming 6', $ap, $Ap, 0, [0], fn($kR, $need) => true);
$add('taming 6: S > L', substr($sig, 0, 32) . $plusL(substr($sig, 32), 1), $M, $Ap, '1 S < L');
for ($k = 15; ($big = $plusL(substr($sig, 32), $k)) === null; $k--);
$add('taming 7: S much greater than L', substr($sig, 0, 32) . $big, $M, $Ap, '1 S < L');
// non-canonical R of small order: hashed as its canonical encoding (case 8), or as the bytes given (case 9)
$R8 = $Tn(0); $R8[31] = "\x80";                         // the identity, x = 0 with the sign bit set
[$sig, $M] = $search('taming 8', $a, $A, 1, [0], fn($kR, $need) => $kR === $need, fn($R) => $torEnc[0], $R8);
$add('taming 8: non-canonical small-order R, hashed reduced', $sig, $M, $A, '2 R small order');
$R9 = $nonCanonical(1, 0);                              // the identity as p + 1
[$sig, $M] = $search('taming 9', $a, $A, 1, [0], fn($kR, $need) => $kR === $need, null, $R9);
$add('taming 9: non-canonical small-order R, hashed as given', $sig, $M, $A, '2 R small order');
// non-canonical A of small order: the point of order 2 with x = 0 and the sign bit set (case 10, hashed reduced), the
// identity as p + 1 (case 11, hashed as given)
$A10 = $Tn(4); $A10[31] = chr(ord($A10[31]) | 0x80);
[$sig, $M] = $search('taming 10', $Z32, $Tn(4), 4, $every, fn($kR, $need) => $kR === $need);   // hashed as Tn(4)
$add('taming 10: non-canonical small-order A, hashed reduced', $sig, $M, $A10, '4 A small order');
$A11 = $nonCanonical(1, 0x80);
[$sig, $M] = $search('taming 11', $Z32, $A11, 0, $every, fn($kR, $need) => $kR === $need);
$add('taming 11: non-canonical small-order A, hashed as given', $sig, $M, $A11, '3 A canonical');
// wrong lengths, the signs flipped, and messages empty and long
[$sig, $M, $A] = $signed($keyOf('lengths'), 'a message');
foreach (['no bytes' => '', 'the first 63 bytes' => substr($sig, 0, 63), 'a byte more' => "$sig\0", 'twice' => $sig . $sig] as $what => $s)
  $add("a signature of $what", $s, $M, $A, 'lengths');
foreach (['no bytes' => '', 'the first 31 bytes' => substr($A, 0, 31), 'a byte more' => "$A\0", 'twice' => $A . $A] as $what => $p)
  $add("a key of $what", $sig, $M, $p, 'lengths');
$add('R with its sign bit flipped', flipBit($sig, 255), $M, $A, '6 the equation');
// R = −[r]B and S = r + h·a, h hashed over that R: [S]B − [h]A is [r]B, so the equation holds but for the sign of x,
// which only comparing all 32 bytes refuses
for ($i = 0; $i < 4; $i++) {
  [$na, $nA] = $keyPair("negated R key $i");
  $nr = $scalar("negated R $i");
  $Rn = enc(pneg(base($nr)));
  $add("R of the negated point, the equation holding but for x's sign, $i", $Rn . sc(hram($Rn, $nA, "negated R $i"), $na, $nr), "negated R $i", $nA, '6 the equation');
}
$add('A with its sign bit flipped: the negated key', $sig, $M, flipBit($A, 255), '6 the equation');
foreach (['empty' => '', 'one zero byte' => "\0", '64 KiB' => $bytes('64k', 65536), '1 MiB' => str_repeat($bytes('1m', 4096), 256)] as $what => $m) {
  [$sig, , $A] = $signed($keyOf("message $what"), $m);
  $add("a message $what", $sig, $m, $A, null);
  if ($m !== '') $add("a message $what, its last byte changed", $sig, substr($m, 0, -1) . chr(ord($m[-1]) ^ 1), $A, '6 the equation');
  $add("a message $what, a byte added", $sig, "$m\0", $A, '6 the equation');
}
printf("    (%d cases built in %.1f s)\n", count($cases), microtime(true) - $t0);

// --export: each case as [label, sig, msg, pub in hex, ed25519.php's refusing rule or null, libsodium's verdict or null],
// and the digests that apply at these sigs and seed
if ($export) {
  ob_end_clean();
  $row = fn(array $c): array => [$c[0], bin2hex($c[1]), bin2hex($c[2]), bin2hex($c[3]), E('refusal', $c[1], $c[2], $c[3]),
                                  $oracle ? sodiumVerdict($c[1], $c[2], $c[3]) : null];
  echo json_encode(['oracle' => $oracle ? SODIUM_LIBRARY_VERSION : null, 'rules' => ORACLE_VERSION,
                    'digests' => ['special' => $seed === DEFAULT_SEED ? SPECIAL_DIGEST : null, 'sweep' => $pinned ? SWEEP_DIGEST : null],
                    'special' => array_map($row, $cases), 'sweep' => array_map($row, iterator_to_array($sweep(), false))],
                   JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
  exit(0);
}

// each case reaches the verdict it was built for, by the oracle where there is one; and is refused by the rule it aims at
$missed = []; $aimed = 0; $wrongRule = []; $rules = []; $apart = [];
foreach ($cases as [$label, $sig, $msg, $pub, $aim]) {
  $mine = Ed25519::verify($sig, $msg, $pub);
  $r = E('refusal', $sig, $msg, $pub);
  if ($mine !== ($r === null)) $apart[] = $label;
  if ($aim === '-') continue;
  $aimed++;
  $v = $oracle ? sodiumVerdict($sig, $msg, $pub) : $mine;
  if ($v !== ($aim === null)) $missed[] = $label;
  $rules[$aim ?? 'accepted'] = ($rules[$aim ?? 'accepted'] ?? 0) + 1;
  if ($r !== $aim) $wrongRule[] = "$label: " . ($r ?? 'accepted') . ', built for ' . ($aim ?? 'acceptance');
}
ok($missed === [], sprintf('each case reaches the verdict it was built for, by %s (%d of %d)%s',
   $oracle ? 'libsodium ' . ORACLE_VERSION : 'ed25519.php', $aimed - count($missed), $aimed, $missed ? ': ' . implode('; ', array_slice($missed, 0, 5)) : ''));
ksort($rules);
ok($wrongRule === [], sprintf('and is refused by the rule it was built for, by ed25519.php\'s account (%s)%s',
   implode(', ', array_map(fn($k, $v) => "$v $k", array_keys($rules), $rules)), $wrongRule ? ': ' . implode('; ', array_slice($wrongRule, 0, 5)) : ''));
ok($apart === [], sprintf('verify() is true exactly when refusal() names no rule, on all %d%s', count($cases),
   $apart ? ': ' . implode('; ', array_slice($apart, 0, 5)) : ''));
$digest = grade('special', $cases, $oracle, $other, $why);
pin('special', $digest, SPECIAL_DIGEST, $seed === DEFAULT_SEED, $oracle);   // sigs does not reach it
ok(($why['5 A on the curve'] ?? 0) >= 40 && ($why['accepted'] ?? 0) >= 50,
   sprintf('the special cases reach every rule: %d keys off the curve, %d accepted', $why['5 A on the curve'] ?? 0, $why['accepted'] ?? 0));

// ── 2. the sweep ─────────────────────────────────────────────────────────────────────────────────────
echo "\n── sweep: random keys and messages, and single-bit mutations ──\n";
$t0 = microtime(true);
$digest = grade('sweep', $sweep(), $oracle, $other, $why);
printf("    (%.1f s)\n", microtime(true) - $t0);
pin('sweep', $digest, SWEEP_DIGEST, $pinned, $oracle);
ok(($why['accepted'] ?? 0) >= $sigs && ($why['6 the equation'] ?? 0) >= $sigs,
   sprintf('the sweep reaches both verdicts: %d accepted, %d refused by the equation', $why['accepted'] ?? 0, $why['6 the equation'] ?? 0));

// ── 3. the layers ────────────────────────────────────────────────────────────────────────────────────
echo "\n── layers: the field, the scalars and the window ──\n";
$U = [1 << 25, 1 << 24, 1 << 25, 1 << 24, 1 << 25, 1 << 24, 1 << 25, 1 << 24, 1 << 25, 1 << 24];   // a reduced limb, give or take 1%
$reduced = function ($a) use ($U): bool {
  if (!is_array($a) || count($a) !== 10) return false;
  foreach ($a as $i => $l) if (!is_int($l) || abs($l) > intdiv(101 * $U[$i], 100)) return false;
  return true;
};
mt_srand($seed);
$wide = function (float $m, int $how) use ($U): array {
  $v = [];
  foreach ($U as $i => $u) { $b = (int)($m * intdiv(101 * $u, 100)); $v[] = match ($how) { 0 => $b, 1 => -$b, 2 => ($i % 2 ? -$b : $b), default => mt_rand(-$b, $b) }; }
  return $v;
};
// operands whose sizes, in reduced limbs, multiply to at most 64; squares of up to 8, and sq2 of up to 5
$values = []; $bad = []; $n = 0;
foreach ([1, 2, 3, 4, 6, 8, 9, 16, 21, 32, 64] as $ma) foreach ([1, 2, 3, 4, 6, 8, 9, 16, 21, 32, 64] as $mb) {
  if ($ma * $mb > 64) continue;
  for ($k = 0; $k < 40; $k++) {
    $x = $wide($ma, $k < 4 ? $k : 9); $y = $wide($mb, $k < 4 ? ($k + ($k & 1)) % 4 : 9);
    $out = $C('mul', $x, $y); $n++;
    if (!$reduced($out)) $bad[] = "mul $ma·$mb";
    $values[] = ['mul', $x, $y, $out];
  }
}
foreach ([1, 2, 3, 4, 6, 8] as $m) for ($k = 0; $k < 60; $k++) {
  $x = $wide($m, $k < 4 ? $k : 9);
  $out = $C('sq', $x); $n++; if (!$reduced($out)) $bad[] = "sq $m"; $values[] = ['sq', $x, null, $out];
  if ($m <= 5) { $out = $C('sq2', $x); $n++; if (!$reduced($out)) $bad[] = "sq2 $m"; $values[] = ['sq2', $x, null, $out]; }
}
ok($bad === [], sprintf('%d products, squares and doubled squares at the widest the formulas allow: every limb an int, reduced%s',
   $n, $bad ? ': ' . implode(', ', array_slice(array_unique($bad), 0, 6)) : ''));
if (!extension_loaded('gmp')) {
  echo "  - the comparisons with gmp are skipped: this PHP has not loaded it. Never counted as passed.\n";
} else {
  $gp = gmp_init(P_HEX, 16); $gl = gmp_init(L_HEX, 16);
  $OFF = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230];
  $val = function (array $a) use ($OFF): GMP { $v = gmp_init(0); foreach ($a as $i => $l) $v = gmp_add($v, gmp_mul($l, gmp_pow(2, $OFF[$i]))); return $v; };
  $le = fn(GMP $v, int $len = 32): string => str_pad(strrev(gmp_sign($v) === 0 ? '' : gmp_export($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN)), $len, "\0");
  $gle = fn(string $b): GMP => gmp_import(strrev($b) === '' ? "\0" : strrev($b), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  $wrong = 0;
  foreach ($values as [$op, $x, $y, $out]) {
    $w = match ($op) { 'mul' => gmp_mul($val($x), $val($y)), 'sq' => gmp_mul($val($x), $val($x)), 'sq2' => gmp_mul(2, gmp_mul($val($x), $val($x))) };
    if (gmp_cmp(gmp_mod($val($out), $gp), gmp_mod($w, $gp)) !== 0) $wrong++;
  }
  ok($wrong === 0, sprintf('...and every one of the %d is the right value mod p (%d wrong)', count($values), $wrong));
  // canonical bytes, and the operations, on the edges and at random
  $edges = [gmp_init(0), gmp_init(1), gmp_init(2), gmp_init(18), gmp_init(19), gmp_sub($gp, 1), $gp, gmp_add($gp, 1), gmp_add($gp, 18),
            gmp_sub(gmp_pow(2, 255), 1), gmp_pow(2, 254), gmp_sub(gmp_pow(2, 255), 20)];
  $all = $edges;
  for ($i = 0; $i < 200; $i++) $all[] = gmp_mod(gmp_import(hash('sha256', "fe $seed $i", true), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), gmp_pow(2, 255));
  $bad = []; $nOps = 0;
  $bytesOf = fn(GMP $v): string => $le(gmp_mod($v, $gp));
  foreach ($all as $i => $a) {
    $fa = $C('fe', $le($a));
    $nOps += 7;
    if ($C('bytes', $fa) !== $bytesOf($a)) $bad[] = 'fe, bytes';
    if ($C('bytes', $C('neg', $fa)) !== $bytesOf(gmp_neg($a))) $bad[] = 'neg';
    if ($C('bytes', $C('add', $C('add', $fa, $fa), $fa)) !== $bytesOf(gmp_mul(3, $a))) $bad[] = 'bytes of 3 units';
    if ($C('bytes', $C('sub', $C('neg', $fa), $C('add', $fa, $fa))) !== $bytesOf(gmp_mul(-3, $a))) $bad[] = 'bytes of −3 units';
    if (gmp_sign(gmp_mod($a, $gp)) !== 0 && $C('bytes', $C('invert', $fa)) !== $bytesOf(gmp_invert($a, $gp))) $bad[] = 'invert';
    if ($C('bytes', $C('pow22523', $fa)) !== $bytesOf(gmp_powm($a, gmp_div_q(gmp_sub($gp, 5), 8), $gp))) $bad[] = 'pow22523';
    if ($C('isNegative', $fa) !== gmp_intval(gmp_mod(gmp_mod($a, $gp), 2))) $bad[] = 'isNegative';
    foreach ($i < count($edges) ? $all : array_slice($all, 0, count($edges)) as $b) {
      $fb = $C('fe', $le($b)); $nOps += 3;
      if ($C('bytes', $C('mul', $fa, $fb)) !== $bytesOf(gmp_mul($a, $b))) $bad[] = 'mul';
      if ($C('bytes', $C('sub', $fa, $fb)) !== $bytesOf(gmp_sub($a, $b))) $bad[] = 'sub';
      if ($C('isZero', $C('sub', $fa, $fb)) !== (gmp_cmp(gmp_mod($a, $gp), gmp_mod($b, $gp)) === 0)) $bad[] = 'isZero';
    }
  }
  // bytes() on limbs no fe() makes: every limb at its signed extreme
  foreach ([[-1, 0, 0, 0, 0, 0, 0, 0, 0, 0], $wide(3, 0), $wide(3, 1), $wide(3, 2), $wide(9, 0), $wide(9, 1)] as $v) {
    $nOps++;
    if ($C('bytes', $v) !== $bytesOf($val($v))) $bad[] = 'bytes of signed limbs';
  }
  ok($bad === [], sprintf('field: %d of fe, bytes, neg, add, sub, mul, invert, pow22523, isZero and isNegative on 0, 1, p − 1, p, p + 18, 2^255 − 1 and more%s',
     $nOps, $bad ? ': wrong ' . implode(', ', array_slice(array_unique($bad), 0, 6)) : ''));
  // scalars mod L
  $sedge = [gmp_init(0), gmp_init(1), gmp_sub($gl, 1), $gl, gmp_add($gl, 1), gmp_mul($gl, 8), gmp_pow(2, 252), gmp_pow(2, 253),
            gmp_sub(gmp_pow(2, 512), 1), gmp_mul(gmp_sub($gl, 1), gmp_sub($gl, 1)), gmp_sub(gmp_mul($gl, gmp_div_q(gmp_pow(2, 512), $gl)), 1)];
  for ($i = 0; $i < 500; $i++) $sedge[] = gmp_import(hash('sha512', "sc $seed $i", true), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  $sbad = 0;
  foreach ($sedge as $v) if ($C('scReduce', $le($v, 64)) !== $le(gmp_mod($v, $gl))) $sbad++;
  ok($sbad === 0, sprintf('scalars: %d reductions mod L of 0, L − 1, L, 8L, 2^512 − 1, (L − 1)² and more (%d wrong)', count($sedge), $sbad));
  // the signed window
  $wbad = 0; $wN = 0;
  $scal = ['', "\x01", $Z32, str_repeat("\xff", 32), str_repeat("\xff", 64), $L, str_repeat("\x21\x84\x10\x42", 8), str_repeat("\x55", 32)];
  for ($i = 0; $i < 400; $i++) $scal[] = hash('sha256', "w $i", true) . ($i % 3 === 0 ? hash('sha256', "v $i", true) : '');
  foreach ($scal as $k) {
    $wN++;
    $sum = gmp_init(0); $last = null; $good = true;
    foreach ($C('digits', $k) as $pos => $d) {
      if ($d % 2 === 0 || abs($d) >= 16 || ($last !== null && $pos - $last < 5)) $good = false;
      $sum = gmp_add($sum, gmp_mul($d, gmp_pow(2, $pos)));
      $last = $pos;
    }
    if (!$good || gmp_cmp($sum, $gle($k)) !== 0) $wbad++;
  }
  ok($wbad === 0, "the window: $wN scalars of up to 512 bits, each digit odd and below 16, 5 apart, summing to the scalar ($wbad wrong)");
}
// the constants, and B_ODD rebuilt from B by repeated addition of 2B
$fi = fn(int $v): array => $C('fe', pack('P', $v) . str_repeat("\0", 24));
$d = $C('fe', strrev(hex2bin((new ReflectionClassConstant(Ed25519::class, 'D'))->getValue())));
$d2 = $C('fe', strrev(hex2bin((new ReflectionClassConstant(Ed25519::class, 'D2'))->getValue())));
$i2 = $C('fe', strrev(hex2bin((new ReflectionClassConstant(Ed25519::class, 'SQRTM1'))->getValue())));
ok($C('isZero', $C('add', $C('mul', $d, $fi(121666)), $fi(121665))) && $C('isZero', $C('sub', $d2, $C('add', $d, $d)))
   && $C('isZero', $C('add', $C('sq', $i2), F1)),
   'the constants: d·121666 = −121665, 2d is twice d, and sqrt(−1) squares to −1');
$odd = (new ReflectionClassConstant(Ed25519::class, 'B_ODD'))->getValue();
[$bx, $by] = [$C('fe', strrev(hex2bin($odd[0][0]))), $C('fe', strrev(hex2bin($odd[0][1])))];
$xx = $C('sq', $bx); $yy = $C('sq', $by);
$onCurve = $C('isZero', $C('sub', $C('sub', $yy, $xx), $C('add', F1, $C('mul', $d, $C('mul', $xx, $yy)))));
$B = [$bx, $by, F1, $C('mul', $bx, $by)];
$rebuilt = $onCurve && $C('isZero', $C('sub', $C('mul', $by, $fi(5)), $fi(4))) && $C('isNegative', $bx) === 0
           && enc($B) === hex2bin('5866666666666666666666666666666666666666666666666666666666666666');
$B2 = padd($B, $B); $cur = $B;
foreach ($odd as $i => [$x, $y]) {
  $zi = $C('invert', $cur[2]);
  if (bin2hex(strrev($C('bytes', $C('mul', $cur[0], $zi)))) !== $x || bin2hex(strrev($C('bytes', $C('mul', $cur[1], $zi)))) !== $y) $rebuilt = false;
  $cur = padd($cur, $B2);
}
ok($rebuilt, "B is on the curve with y = 4/5 and x even, and B_ODD is B, 3B, ..., 15B rebuilt from it: all 8 entries match");
// the small-order points: 8 of them, [k]T of order 8 / gcd(k, 8), and their encodings the canonical ones of the 14
$orders = enc($tor[8]) === $torEnc[0];
foreach ([1, 8, 4, 8, 2, 8, 4, 8] as $k => $want) {
  $q = IDENTITY; $first = null;
  for ($j = 1; $j <= 8 && $first === null; $j++) { $q = padd($q, $tor[$k]); if (enc($q) === $torEnc[0]) $first = $j; }
  if ($first !== $want) $orders = false;
}
$canonicalSmall = array_values(array_filter($small, fn($e) => $isCanonical($e) && enc(pt($e)) === $e));
sort($canonicalSmall); $te = $torEnc; sort($te);
ok($orders && $canonicalSmall === $te && count(array_unique($torEnc)) === 8,
   'the 8 small-order points are [k]T, of orders 1, 8, 4, 8, 2, 8, 4, 8, and are the 8 canonical encodings among the 14');
// the double multiply against its parts: [a]A + [b]B is [a]A plus [b]B, for A of mixed order
$mbad = 0;
for ($i = 0; $i < 6; $i++) {
  [$a, $A] = $keyPair("parts $i", $i);
  $x = $scalar("parts x $i"); $y = $scalar("parts y $i");
  $Ap = pt($A);
  $both = enc(p3of($C('mulAdd', $x, $Ap, $y)));
  $parts = enc(padd(p3of($C('mulAdd', $x, $Ap, '')), base($y)));
  if ($both !== $parts) $mbad++;
}
ok($mbad === 0, "[a]A + [b]B in one pass is [a]A plus [b]B, for keys of every torsion ($mbad wrong)");

// ── 4. the edges ─────────────────────────────────────────────────────────────────────────────────────
echo "\n── edges: no exception for any input, and no dependency ──\n";
$threw = []; $trues = 0; $n = 0;
foreach ([0, 1, 31, 32, 33, 63, 64, 65, 96, 128] as $sl) foreach ([0, 1, 31, 32, 33, 64] as $pl) for ($k = 0; $k < 6; $k++) {
  $s = $bytes("g s $sl $pl $k", $sl); $p = $bytes("g p $sl $pl $k", $pl);
  if ($k === 1 && $pl === 32) $p = $small[$num("g small $sl", 14)];
  if ($k === 2 && $pl === 32) $p = str_repeat("\xff", 32);
  if ($k === 3 && $sl === 64) $s = str_repeat("\xff", 64);
  $n++;
  try { if (Ed25519::verify($s, $bytes("g m $k", $k * 7), $p)) $trues++; } catch (Throwable $e) { $threw[] = get_class($e) . ': ' . $e->getMessage(); }
}
ok($threw === [] && $trues === 0, sprintf('%d garbage signatures and keys of every length: false each time, nothing thrown%s', $n,
   $threw ? ': ' . implode('; ', array_slice(array_unique($threw), 0, 3)) : ''));
$names = [];
foreach (token_get_all((string)file_get_contents($file)) as $t)
  if (is_array($t) && in_array($t[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)
      && preg_match('/^\\\\?(sodium_|gmp_|bc[a-z]+$|openssl_|ParagonIE)/i', $t[1])) $names[] = $t[1];
$requires = preg_match_all('/^\s*(require|include)(_once)?\b/m', (string)file_get_contents($file));
ok($names === [] && $requires === 0, 'ed25519.php calls no sodium, gmp, bcmath or openssl function and loads no other file'
   . ($names ? ': ' . implode(', ', array_unique($names)) : ''));

// how long one verify takes, beside libsodium's
[$sig, $M, $A] = $signed($keyOf('timing'), 'a message');
$t0 = hrtime(true); for ($i = 0; $i < 100; $i++) Ed25519::verify($sig, $M, $A); $ours = (hrtime(true) - $t0) / 1e8;
$line = sprintf('  - one verify: %.2f ms by ed25519.php', $ours);
if ($sodium) { $t0 = hrtime(true); for ($i = 0; $i < 10000; $i++) sodium_crypto_sign_verify_detached($sig, $M, $A); $line .= sprintf(', %.3f ms by libsodium', (hrtime(true) - $t0) / 1e10); }
echo "$line\n";

printf("\n%s  %d passed, %d failed   [Ed25519 · against libsodium %s]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail, ORACLE_VERSION);
exit($fail === 0 ? 0 : 1);
