<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// secp256k1 and RFC 6979 on PHP ints, graded against the curve they replaced: server/secp256k1.php and rfc6979.php
// at f4f05d1, the last revision that computed with ext/gmp. On every case here the two must give the same verdict,
// the same bytes and the same error.
//
//   php server/verify-secp256k1-native.php [keys=400] [seed=20261025] [--curve=DIR]
//     keys     random keys in the sweep, about 60 cases each
//     --curve  grade the secp256k1.php and rfc6979.php in DIR instead of the ones beside this file
//
// The old files are read from git and loaded beside the new ones, their classes renamed. They compute with ext/gmp,
// so they are the oracle only where gmp is loaded and the revision is in this repository's history. Without them the
// case-by-case comparison is skipped, and says so, and the sweep and the branch cases are graded instead by
// SWEEP_DIGEST and BRANCH_DIGEST, the old files' results recorded below. With the oracle, both are re-checked.
//
// Four parts:
//   sweep     random keys and digests: the public key both ways, sign with and without low s, signRecoverable, and
//             verifyDigest on the signature and on its mutations: high s (no low-s rule, so it verifies), a wrong
//             digest or key, a flipped bit, r or s at 0, n and above, padded and negative integers, trailing and
//             truncated bytes, keys off the curve, past p, of the wrong length or prefix. decodeDer and decodePoint
//             on the same inputs, and RFC 6979's k, bits2int and int2octets on random orders and digests.
//   branches  signatures built to reach the multiply's rare branches: x(R) >= n, u1 = 0, and keys tG with u1 and u2
//             small or near n, where equal x meets equal x inside the interleaved loop as a double or as infinity.
//   layers    the field, scalar and point arithmetic against gmp, operands at the widest the point formulas allow
//             and wider, every limb checked to be an int; the signed windows; G_ODD rebuilt from G.
//   edges     keys as bytes, ints and GMP numbers; the errors and their order; signRecoverable's callback; and no gmp
//             call outside the two functions that read and make a caller's GMP number.
declare(strict_types=1);

const REV = 'f4f05d192bbd44e47f22447c9b4b51a1f8215abb';
const DEFAULT_KEYS = 400, DEFAULT_SEED = 20261025;
/** sha256 over the sweep and over the branch cases at the default keys and seed, as the old files ran them. */
const SWEEP_DIGEST  = '97527d199eee6571a372b7c6967db29fc11ae7fbbdf99a41a2ab33e7b55580c3';
const BRANCH_DIGEST = '580684c677b7639bbd4671552fd0e0678cb18b5dd38e1519957e0b6d9758041c';
const N_HEX = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
const P_HEX = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';

$plain = array_values(array_filter(array_slice($argv, 1), fn($a) => !str_starts_with($a, '--')));
$opt = function (string $name) use ($argv): ?string {
  foreach ($argv as $a) if (str_starts_with($a, "--$name=")) return substr($a, strlen($name) + 3);
  return null;
};
$keys = (int)($plain[0] ?? DEFAULT_KEYS);
$seed = (int)($plain[1] ?? DEFAULT_SEED);
$curve = $opt('curve') ?? __DIR__;
require_once "$curve/secp256k1.php";
$pinned = $keys === DEFAULT_KEYS && $seed === DEFAULT_SEED;

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── the oracle: the old files, from git ──────────────────────────────────────────────────────────────
function git_show(string $path): ?string {
  $p = @proc_open(['git', '-C', dirname(__DIR__), 'show', REV . ':' . $path], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
  if (!is_resource($p)) return null;
  $out = stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
  fclose($pipes[1]); fclose($pipes[2]);
  return proc_close($p) === 0 && $out !== '' ? $out : null;
}
$noOracle = null;                                       // why the old files cannot be run here, if they cannot
if (!extension_loaded('gmp')) $noOracle = 'the old curve computes with ext/gmp, which this PHP has not loaded';
elseif (($oldRfc = git_show('server/rfc6979.php')) === null || ($oldSec = git_show('server/secp256k1.php')) === null)
  $noOracle = 'revision ' . substr(REV, 0, 7) . ' is not in this repository';
else {
  $names = 0; $reqs = 0;
  foreach ([$oldRfc, $oldSec] as $src) {
    $src = preg_replace('/^<\?php\s*/', '', $src);
    $src = str_replace("require_once __DIR__ . '/rfc6979.php';", '', $src, $r);
    $src = preg_replace('/\b(Secp256k1|Rfc6979)\b/', 'Old$1', $src, -1, $k);
    $reqs += $r; $names += $k;
    eval($src);
  }
  ok($reqs === 1 && class_exists('OldSecp256k1', false) && class_exists('OldRfc6979', false),
     "the old curve loads beside the new one: $names names renamed");
}
$oracle = $noOracle === null;
if (!$oracle) echo "  - no oracle: $noOracle. The case-by-case comparison is skipped, never counted as passed.\n";

// ── byte helpers, independent of both curves ─────────────────────────────────────────────────────────
/** a + b or a − b, big-endian, the result as wide as the wider input (a − b needs a >= b). */
function badd(string $a, string $b): string {
  $n = max(strlen($a), strlen($b)); $a = str_pad($a, $n, "\0", STR_PAD_LEFT); $b = str_pad($b, $n, "\0", STR_PAD_LEFT);
  $out = ''; $c = 0;
  for ($i = $n - 1; $i >= 0; $i--) { $v = ord($a[$i]) + ord($b[$i]) + $c; $out = chr($v & 0xFF) . $out; $c = $v >> 8; }
  return $c ? chr($c) . $out : $out;
}
function bsub(string $a, string $b): string {
  $n = strlen($a); $b = str_pad($b, $n, "\0", STR_PAD_LEFT);
  $out = ''; $c = 0;
  for ($i = $n - 1; $i >= 0; $i--) { $v = ord($a[$i]) - ord($b[$i]) - $c; $out = chr($v & 0xFF) . $out; $c = $v < 0 ? 1 : 0; }
  return $out;
}
/** DER of two big-endian integers, minimal, written here so the cases do not depend on the encoder under test. */
function der(string $r, string $s): string {
  $int = function (string $v): string {
    $v = ltrim($v, "\0"); if ($v === '') $v = "\0";
    if (ord($v[0]) & 0x80) $v = "\0" . $v;
    return "\x02" . chr(strlen($v)) . $v;
  };
  $body = $int($r) . $int($s);
  return "\x30" . chr(strlen($body)) . $body;
}
/** [r, s] of a DER signature written by der() or by a signer: 30 L 02 lr r 02 ls s. */
function under(string $sig): array {
  $lr = ord($sig[3]);
  return [str_pad(ltrim(substr($sig, 4, $lr), "\0"), 32, "\0", STR_PAD_LEFT),
          str_pad(ltrim(substr($sig, 6 + $lr), "\0"), 32, "\0", STR_PAD_LEFT)];
}
function flipBit(string $b, int $bit): string { $i = intdiv($bit, 8) % strlen($b); $b[$i] = chr(ord($b[$i]) ^ (1 << ($bit % 8))); return $b; }
function in_range(string $v): bool { return $v !== str_repeat("\0", 32) && strcmp($v, hex2bin(N_HEX)) < 0; }

// ── what a curve did with a case, as one string ──────────────────────────────────────────────────────
function gi(string $b): GMP { return gmp_import($b === '' ? "\0" : $b, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN); }
/** A result integer as hex: a GMP number from the old files, 32 bytes or more; bytes from the new ones as they are. */
function hx(GMP|string $v): string {
  if (is_string($v)) return bin2hex($v);
  return bin2hex(str_pad(gmp_sign($v) === 0 ? '' : gmp_export($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), 32, "\0", STR_PAD_LEFT));
}
function said(Throwable $e): string { return get_class($e) . ': ' . $e->getMessage(); }
function rlen_of(string $q): int { $q = ltrim($q, "\0"); return $q === '' ? 0 : intdiv(8 * strlen($q) - 8 + strlen(decbin(ord($q[0]))) + 7, 8); }
/**
 * ['verify', sig, pub, digest, allowTrailing] · ['pub', d, compressed] · ['sign', d, digest, lowS] · ['rec', d, digest]
 * ['der', sig, allowTrailing] · ['point', pub] · ['k', q, x, h1, algo, attempt] · ['b2i', b, qlen] · ['i2o', x, rlen]
 * Keys and integers are bytes; the old files are handed them as GMP numbers.
 */
function outcome(bool $old, array $c): string {
  $S = $old ? 'OldSecp256k1' : 'Secp256k1';
  $R = $old ? 'OldRfc6979' : 'Rfc6979';
  $key = fn(string $b) => $old ? gi($b) : $b;
  try {
    switch ($c[0]) {
      case 'verify': return var_export($S::verifyDigest($c[1], $c[2], $c[3], $c[4]), true);
      case 'pub':    return bin2hex($S::publicKey($key($c[1]), $c[2]));
      case 'sign':   return bin2hex($S::sign($key($c[1]), $c[2], $c[3]));
      case 'rec':    [$r, $s, $v] = $S::signRecoverable($key($c[1]), $c[2]); return hx($r) . ' ' . hx($s) . " $v";
      case 'der':    $d = $S::decodeDer($c[1], $c[2]); return $d === null ? 'null' : hx($d[0]) . ' ' . hx($d[1]);
      case 'point':  $q = $S::decodePoint($c[1]); return $q === null ? 'null' : hx($q[0]) . ' ' . hx($q[1]);
      case 'k':
        if (!$old) return bin2hex(Rfc6979::k($c[1], $c[2], $c[3], $c[4], $c[5]));
        return bin2hex(OldRfc6979::int2octets(OldRfc6979::k(gi($c[1]), gi($c[2]), $c[3], $c[4], $c[5]), rlen_of($c[1])));
      case 'b2i':
        if (!$old) return bin2hex(Rfc6979::bits2int($c[1], $c[2]));
        return bin2hex(OldRfc6979::int2octets(OldRfc6979::bits2int($c[1], $c[2]), intdiv($c[2] + 7, 8)));
      case 'i2o':    return bin2hex($R::int2octets($old ? gi($c[1]) : $c[1], $c[2]));
    }
    return 'unknown case';
  } catch (Throwable $e) { return said($e); }
}
function caseKey(array $c): string {
  return implode("\0", array_map(fn($v) => is_string($v) ? bin2hex($v) : var_export($v, true), $c));
}

/** Both curves on every case, or the new one alone with no oracle. Returns the sha256 over each case and the old
 *  curve's result: with no oracle, the new curve's. */
function grade(string $part, iterable $cases, bool $oracle, ?array &$kinds = null): string {
  $h = hash_init('sha256'); $n = $same = 0; $diffs = []; $kinds = [];
  foreach ($cases as $c) {
    $new = outcome(false, $c);
    $old = $oracle ? outcome(true, $c) : $new;
    $n++;
    hash_update($h, caseKey($c) . "\0" . $old . "\n");
    $k = $c[0] . ($c[0] === 'verify' ? " $old" : '');
    $kinds[$k] = ($kinds[$k] ?? 0) + 1;
    if ($old === $new) { $same++; continue; }
    if (count($diffs) < 8) $diffs[] = [$c, $old, $new];
  }
  foreach ($diffs as [$c, $old, $new])
    printf("    differs: %s\n      old %s\n      new %s\n", substr(caseKey($c), 0, 200), $old, $new);
  ksort($kinds);
  $mix = implode(', ', array_map(fn($k, $v) => "$v $k", array_keys($kinds), $kinds));
  if ($oracle) ok($same === $n, "$part: $same of $n cases identical ($mix)");
  else echo "  - $part: $n cases run on the new curve alone ($mix)\n";
  return hash_final($h);
}
function pin(string $part, string $digest, string $want, bool $pinned, bool $oracle): void {
  if (!$pinned) { echo "  - $part: not the default keys and seed, so the pinned digest does not apply\n"; return; }
  ok($digest === $want, ($oracle ? "$part: the old curve still gives the pinned results" : "$part: the new curve gives the old curve's pinned results")
                        . " ($digest)");
}

// ── 1. the sweep ─────────────────────────────────────────────────────────────────────────────────────
echo "── sweep: random keys and digests, and their mutations ──\n";
$N = hex2bin(N_HEX); $P = hex2bin(P_HEX); $Z = str_repeat("\0", 32); $FF = str_repeat("\xff", 32);
$rnd = fn(string $tag): string => hash('sha256', "$seed:$tag", true);
$num = fn(string $tag, int $mod): int => unpack('N', $rnd($tag))[1] % $mod;
$E = $oracle ? 'OldSecp256k1' : 'Secp256k1';            // the curve whose signatures the mutations start from
$ek = fn(string $d) => $oracle ? gi($d) : $d;
$sweep = function () use ($keys, $rnd, $num, $E, $ek, $N, $P, $Z, $FF) {
  $prevPub = null;
  for ($i = 0; $i < $keys; $i++) {
    $d = $rnd("d$i");
    while (!in_range($d)) $d = hash('sha256', $d, true);
    $dig = $rnd("m$i");
    $pubC = $E::publicKey($ek($d)); $pubU = $E::publicKey($ek($d), false);
    $sig = $E::sign($ek($d), $dig);
    [$r, $s] = under($sig);
    $x = substr($pubU, 1, 32); $y = substr($pubU, 33, 32);
    $other = $prevPub ?? $E::publicKey($ek(hash('sha256', "other$d", true)));
    $prevPub = $pubC;
    yield ['pub', $d, true];
    yield ['pub', $d, false];
    yield ['sign', $d, $dig, false];
    yield ['sign', $d, $dig, true];
    yield ['rec', $d, $dig];
    $small = substr($rnd("k$i"), 0, 16);                                   // below 2^128 < 2^256 − n
    $padR = "\x30" . chr(ord($sig[1]) + 1) . "\x02" . chr(ord($sig[3]) + 1) . "\0" . substr($sig, 4);
    $negR = der("\x7f" . substr($r, 1), $s); $negR[4] = chr(ord($negR[4]) | 0x80);   // 02 20, top bit set: negative
    $zeroLen = "\x30" . chr(ord($sig[1]) - ord($sig[3])) . "\x02\x00" . substr($sig, 4 + ord($sig[3]));
    $junk = "\x30" . chr(ord($sig[1]) + 1) . substr($sig, 2) . "\x00";
    $flipAt = $num("f$i", strlen($sig));
    $badByte = $sig; $badByte[$flipAt] = chr(ord($sig[$flipAt]) ^ (1 + $num("g$i", 255)));
    $garbage = "\x30" . substr($rnd("x$i") . $rnd("y$i") . $rnd("z$i"), 0, 1 + $num("h$i", 80));
    $sigs = [
      $sig, der($r, bsub($N, $s)), der(flipBit($r, $num("r$i", 256)), $s), der($r, flipBit($s, $num("s$i", 256))), $badByte,
      $sig . "\x01", substr($sig, 0, -1), der($Z, $s), der($r, $Z), der($N, $s), der($r, $N), der(badd($N, $small), $s),
      der($r, badd($N, $small)), der("\x01" . $r, $s), der($FF, $s), der($r, $FF), $padR, $negR, $zeroLen, $junk,
      der(bsub($N, "\x01"), $s), der($r, bsub($N, "\x01")), der("\x01", "\x01"), $garbage,
      "\x30\x81" . substr($sig, 1), "\x31" . substr($sig, 1),
    ];
    foreach ($sigs as $k => $v) {
      yield ['verify', $v, $pubC, $dig, false];
      if ($k < 2) yield ['verify', $v, $pubU, $dig, false];
      if ($k === 5 || $k === 16) yield ['verify', $v, $pubC, $dig, true];
      if ($k < 6 || $k === 16 || $k === 17 || $k === 24) { yield ['der', $v, false]; yield ['der', $v, true]; }
    }
    $pubs = [
      $other, "\x04" . $x . flipBit($y, 0), chr(5 - ord($pubC[0])) . $x, "\x02" . flipBit($x, $num("p$i", 256)),
      "\x02" . $P, "\x03" . badd($P, "\x01"), "\x02" . $FF, "\x04" . $x . $P, "\x04" . $P . $y, "\x04" . $x,
      "\x02" . $x . $y, "\x05" . $x, "\x00" . $x, "\x06" . $x . $y, "\x07" . $x . $y,
      substr($pubC, 0, 32), $pubC . "\0", substr($pubU, 0, 64), $pubU . "\0", '',
    ];
    foreach ($pubs as $k => $v) {
      yield ['verify', $sig, $v, $dig, false];
      if ($k < 4) yield ['point', $v];
    }
    yield ['point', $pubC]; yield ['point', $pubU];
    foreach ([substr($dig, 0, 31), $dig . "\0", '', flipBit($dig, $num("d$i", 256))] as $v) yield ['verify', $sig, $pubC, $v, false];

    // RFC 6979 on an order of 2 to 600 bits, a key below it, and a digest of another hash
    $qlen = 2 + $num("q$i", 599); $rl = intdiv($qlen + 7, 8);
    $q = substr($rnd("qa$i") . $rnd("qb$i") . $rnd("qc$i"), 0, $rl);
    $top = ($qlen - 1) % 8;                                                   // the order's top bit, in its first byte
    $q[0] = chr((ord($q[0]) & ((1 << $top) - 1)) | (1 << $top));
    $xk = substr($rnd("xa$i") . $rnd("xb$i") . $rnd("xc$i"), 0, $rl);
    $xk[0] = chr(ord($xk[0]) & ((1 << $top) - 1));                            // below 2^(qlen − 1) <= q
    if (ltrim($xk, "\0") === '') $xk[$rl - 1] = "\x01";
    $algo = ['sha1', 'sha256', 'sha384', 'sha512'][$num("a$i", 4)];
    yield ['k', $q, $xk, hash($algo, "m$i", true), $algo, $num("t$i", 3)];
    $b = substr($rnd("ba$i") . $rnd("bb$i") . $rnd("bc$i"), 0, $num("bl$i", 81));
    yield ['b2i', $b, 1 + $num("bq$i", 640)];
    yield ['i2o', str_repeat("\0", $num("iz$i", 3)) . substr($rnd("ia$i"), 0, $num("il$i", 33)), $num("ir$i", 41)];
  }
  // RFC 6979 at its edges: no width, leading zeros, empty input, one bit, the curve's own order
  foreach ([0, 1, 31, 32, 33] as $rl)
    foreach (['', "\0", "\0\0\x05", "\x05", str_repeat("\xff", 33), "\0" . str_repeat("\xff", 32)] as $v) yield ['i2o', $v, $rl];
  foreach ([1, 7, 8, 9, 255, 256, 257, 512] as $ql)
    foreach (['', "\x80", "\x01\x23", str_repeat("\xff", 32), str_repeat("\xab", 64)] as $v) yield ['b2i', $v, $ql];
  foreach ([str_repeat("\0", 31) . "\x01", bsub($N, "\x01")] as $xk)
    foreach ([$Z, $FF, $N] as $h1) foreach ([0, 3] as $att) yield ['k', $N, $xk, $h1, 'sha256', $att];
  // the signing errors, and their order: the digest is checked before the key
  foreach ([[$Z, $Z], [$N, $Z], [$FF, $Z], [$Z, 'short'], [bsub($N, "\x01"), 'short'], [bsub($N, "\x01"), '']] as [$d, $dg]) {
    yield ['pub', $d, true];
    yield ['sign', $d, $dg, false];
    yield ['rec', $d, $dg];
  }
  yield ['pub', bsub($N, "\x01"), true];
  yield ['sign', bsub($N, "\x01"), $Z, false];
};
$t0 = microtime(true);
$digest = grade('sweep', $sweep(), $oracle, $kinds);
printf("    (%.1f s)\n", microtime(true) - $t0);
pin('sweep', $digest, SWEEP_DIGEST, $pinned, $oracle);
ok(($kinds['verify true'] ?? 0) >= 4 * $keys && ($kinds['verify false'] ?? 0) >= 40 * $keys,
   sprintf('the sweep reaches both verdicts: %d verify, %d refuse', $kinds['verify true'] ?? 0, $kinds['verify false'] ?? 0));

// ── 2. the branches ──────────────────────────────────────────────────────────────────────────────────
echo "\n── branches: signatures built to reach the multiply's rare cases ──\n";
// Built with the new curve's own arithmetic (the old one's is the oracle), so this part needs no gmp. A broken
// construction changes the cases, and the pinned digest catches it.
$C = Closure::bind(static fn(string $m, ...$a) => self::$m(...$a), null, Secp256k1::class);
$C('init');
$b32 = fn(int $v): string => str_pad(pack('J', $v), 32, "\0", STR_PAD_LEFT);
$built = [];                                            // [case, the verdict the construction aims at, what it is]
$sig3 = function (string $r, string $s, string $e, string $pub, bool $want, string $what) use (&$built) {
  $built[] = [['verify', der($r, $s), $pub, $e, false], $want, $what];
};
/** x(R) mod n, as 32 bytes, for an affine R from the new curve */
$xmodn = function (array $R) use ($C, $N): string {
  $x = $C('feBytes', $R[0]);
  return strcmp($x, $N) >= 0 ? bsub($x, $N) : $x;
};
// keys tG, with u1 and u2 small or near n: u1·G + u2·tG = (u1 + u2·t)·G, and equal x meets equal x inside the loop
foreach ([1, 2, 3, 17] as $t) {
  $pub = Secp256k1::publicKey($b32($t));
  foreach ([0, 1, 2, 3, $t, -$t, -1] as $a) {
    $u1 = $a >= 0 ? $b32($a) : bsub($N, $b32(-$a));
    foreach ([1, 2, -1, -2] as $b) {
      $u2 = $b > 0 ? $b32($b) : bsub($N, $b32(-$b));
      $k = $C('scAdd', $u1, $C('scMul', $u2, $b32($t)));
      if ($k === str_repeat("\0", 32)) { $r = $b32(1); $want = false; }               // R is the point at infinity
      else { $r = $xmodn($C('affine', $C('mulAdd', $k))); $want = true; }
      $s = $C('scMul', $r, $C('scInv', $u2));
      $sig3($r, $s, $C('scMul', $u1, $s), $pub, $want, "key {$t}G, u1 = $a, u2 = $b" . ($want ? '' : ', R at infinity'));
    }
  }
}
// u1 = 0: the digest is 0, or n itself
foreach ([1, 2, 3, 4] as $i) {
  $d = $rnd("u0$i");
  $pub = Secp256k1::publicKey($d);
  foreach ([str_repeat("\0", 32), $N] as $e) {
    [$r, $s] = under(Secp256k1::sign($d, $e));
    $sig3($r, $s, $e, $pub, true, 'u1 = 0, a real signature over a digest of ' . ($e === $N ? 'n' : '0'));
    $sig3($r, $s, $e, Secp256k1::publicKey(hash('sha256', $d, true)), false, 'u1 = 0, the wrong key');
  }
}
// R chosen first: x(R) >= n, so r = x − n and x mod n == r is found as x == r + n; and R with a small x, found as x == r
$found = ['high' => [], 'low' => []];
for ($j = 1; count($found['high']) < 3 && $j < 64; $j++) {                // x = n would make r = 0
  $x = badd($N, $b32($j));
  if (Secp256k1::decodePoint("\x02" . $x) !== null) $found['high'][] = $x;
}
for ($j = 1; count($found['low']) < 2 && $j < 64; $j++)
  if (Secp256k1::decodePoint("\x02" . $b32($j)) !== null) $found['low'][] = $b32($j);
ok(count($found['high']) === 3 && count($found['low']) === 2, 'points with x >= n and with a small x exist to build from');
foreach (['high', 'low'] as $kind) foreach ($found[$kind] as $x) foreach (["\x02", "\x03"] as $parity) {
  $R0 = $C('point', $parity . $x);
  $r = $kind === 'high' ? bsub($x, $N) : $x;
  foreach ([$b32(1), $b32(2), $rnd("s$kind" . bin2hex($x) . $parity)] as $j => $s) {
    $s = $C('scMod', $s);
    $e = $rnd("e$kind" . bin2hex($x) . $parity . $j);
    $w = $C('scInv', $s);
    $u1 = $C('scMul', $e, $w); $u2 = $C('scMul', $r, $w);
    // Q = (R0 − u1·G) / u2
    $mG = $C('affine', $C('mulAdd', $u1));
    $T = $C('affine', $C('pointAdd', [$R0[0], $R0[1], [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]], [$mG[0], $C('neg', $mG[1]), [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]]));
    $Q = $C('affine', $C('mulAdd', '', $T, $C('scInv', $u2)));
    $pub = chr(2 + ($Q[1][0] & 1)) . $C('feBytes', $Q[0]);
    $what = $kind === 'high' ? 'x(R) >= n' : 'x(R) small';
    $sig3($r, $s, $e, $pub, true, "$what, found as x == r" . ($kind === 'high' ? ' + n' : ''));
    $sig3($r, $s, flipBit($e, 0), $pub, false, "$what, the wrong digest");
    if ($kind === 'high') $sig3($x, $s, $e, $pub, false, 'x(R) >= n given as r itself: out of range');
  }
}
$aimed = 0; $missed = [];
foreach ($built as [$c, $want, $what]) {
  $got = outcome($oracle, $c) === var_export($want, true);
  $aimed += $got ? 1 : 0;
  if (!$got && count($missed) < 5) $missed[] = $what;
}
ok($aimed === count($built), sprintf('each branch case reaches the verdict it was built for (%d of %d, by the %s curve)%s',
   $aimed, count($built), $oracle ? 'old' : 'new', $missed ? ': ' . implode('; ', $missed) : ''));
$digest = grade('branches', array_column($built, 0), $oracle);
pin('branches', $digest, BRANCH_DIGEST, $pinned, $oracle);

// ── 3. the layers ────────────────────────────────────────────────────────────────────────────────────
echo "\n── layers: field, scalars and points against gmp ──\n";
$limbsOk = function ($a, int $lo, int $hi): bool {
  if (!is_array($a) || count($a) !== 10) return false;
  foreach ($a as $l) if (!is_int($l) || $l < $lo || $l > $hi) return false;
  return true;
};
$B = (1 << 26) + 128;                                        // a reduced limb is at most this, in magnitude
// the limbs of mul(), sqr() and norm() stay within [-65, 2^26 + 128]: the bound the point formulas are written against
$reduced = fn($a): bool => $limbsOk($a, -65, $B);
// 2a: a widest-operand fuzz, which runs without gmp too: the result must be an int in every limb, within the bound
mt_srand($seed);
$wide = function (int $m, int $how) use ($B): array {
  $v = []; for ($i = 0; $i < 10; $i++) $v[] = match ($how) { 0 => $m * $B, 1 => -$m * $B, 2 => ($i % 2 ? -1 : 1) * $m * $B, default => mt_rand(-$m * $B, $m * $B) };
  return $v;
};
$pairs = [];
foreach ([1, 2, 3, 4, 6, 7, 8, 11, 13, 16, 32, 64] as $ma) foreach ([1, 2, 3, 4, 6, 7, 8, 11, 13, 16, 32, 64] as $mb) if ($ma * $mb <= 128) $pairs[] = [$ma, $mb];
$fuzzN = 0; $fuzzBad = []; $values = [];
foreach ($pairs as [$ma, $mb]) for ($k = 0; $k < 60; $k++) {
  $a = $wide($ma, $k < 4 ? $k : 9); $b = $wide($mb, $k < 4 ? ($k + ($k & 1)) % 4 : 9);
  $m = $C('mul', $a, $b); $fuzzN++;
  if (!$reduced($m)) $fuzzBad[] = "mul $ma·$mb";
  $values[] = [$a, $b, $m];
  if ($ma === $mb) { $q = $C('sqr', $a); $fuzzN++; if (!$reduced($q)) $fuzzBad[] = "sqr $ma"; $values[] = [$a, $a, $q]; }
}
foreach ([1, 4, 13, 32, 64] as $m) for ($k = 0; $k < 60; $k++) {
  $a = $wide($m, $k < 4 ? $k : 9);
  $nr = $C('norm', $a); $cn = $C('canon', $a); $fuzzN += 2;
  if (!$reduced($nr)) $fuzzBad[] = "norm $m";
  if (!$limbsOk($cn, 0, (1 << 26) - 1) || $cn[9] >= 1 << 22) $fuzzBad[] = "canon $m";
  $values[] = [$a, null, $nr]; $values[] = [$a, null, $cn];
}
ok($fuzzBad === [], sprintf('%d multiplies, squares and reductions of operands up to 128 reduced limbs wide: every limb an int, within the bound%s',
   $fuzzN, $fuzzBad ? ': ' . implode(', ', array_slice(array_unique($fuzzBad), 0, 6)) : ''));
if (!extension_loaded('gmp')) {
  echo "  - the rest of this part compares with gmp, which this PHP has not loaded: skipped, never counted as passed\n";
} else {
  $gp = gmp_init(P_HEX, 16); $gn = gmp_init(N_HEX, 16);
  $val = function (array $a): GMP { $v = gmp_init(0); for ($i = 9; $i >= 0; $i--) $v = gmp_add(gmp_mul($v, gmp_pow(2, 26)), $a[$i]); return $v; };
  $mod = fn(GMP $v): GMP => gmp_mod($v, $gp);
  $bytes = fn(GMP $v): string => str_pad(gmp_sign($v) === 0 ? '' : gmp_export($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), 32, "\0", STR_PAD_LEFT);
  $wrong = 0;
  foreach ($values as [$a, $b, $out]) {
    $want = $b === null ? $mod($val($a)) : $mod(gmp_mul($val($a), $val($b)));
    if (gmp_cmp($mod($val($out)), $want) !== 0) $wrong++;
  }
  ok($wrong === 0, sprintf('...and every one of the %d is the right value mod p (%d wrong)', count($values), $wrong));
  // canon gives the unique value in [0, p), for the edge values
  $edges = [gmp_init(0), gmp_init(1), gmp_init(2), gmp_sub($gp, 2), gmp_sub($gp, 1), $gp, gmp_add($gp, 1),
            gmp_sub(gmp_pow(2, 256), 1), gmp_pow(2, 255), gmp_init(0x3D1), gmp_sub(gmp_pow(2, 256), gmp_init('1000003d1', 16))];
  $rand = []; for ($i = 0; $i < 300; $i++) $rand[] = gmp_import(hash('sha256', "fe$seed:$i", true), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  $all = array_merge($edges, $rand);
  $bad = []; $nOps = 0;
  $fe = fn(GMP $v): array => $C('fe', $bytes($v));
  $hex = fn(array $a): string => bin2hex($C('feBytes', $C('canon', $a)));
  $ghex = fn(GMP $v): string => bin2hex($bytes(gmp_mod($v, $gp)));
  foreach ($all as $i => $a) {
    $fa = $fe($a);
    foreach ($i < count($edges) ? $all : array_slice($all, 0, count($edges) + 20) as $b) {
      $fb = $fe($b); $nOps += 4;
      if ($hex($C('mul', $fa, $fb)) !== $ghex(gmp_mul($a, $b))) $bad[] = 'mul';
      if ($hex($C('add', $fa, $fb)) !== $ghex(gmp_add($a, $b))) $bad[] = 'add';
      if ($hex($C('sub', $fa, $fb)) !== $ghex(gmp_sub($a, $b))) $bad[] = 'sub';
      if ($C('isZero', $C('sub', $fa, $fb)) !== (gmp_cmp(gmp_mod($a, $gp), gmp_mod($b, $gp)) === 0)) $bad[] = 'isZero';
    }
    $nOps += 4;
    if ($hex($C('sqr', $fa)) !== $ghex(gmp_mul($a, $a))) $bad[] = 'sqr';
    if ($hex($C('neg', $fa)) !== $ghex(gmp_neg($a))) $bad[] = 'neg';
    if (gmp_sign(gmp_mod($a, $gp)) !== 0 && $hex($C('inv', $fa)) !== $ghex(gmp_invert($a, $gp))) $bad[] = 'inv';
    if ($hex($C('sqrt', $fa)) !== $ghex(gmp_powm($a, gmp_div_q(gmp_add($gp, 1), 4), $gp))) $bad[] = 'sqrt';
  }
  ok($bad === [], sprintf('field: %d mul, add, sub, isZero, sqr, neg, inv and sqrt on 0, 1, p − 1, p, p + 1, 2^256 − 1 and more%s',
     $nOps, $bad ? ': wrong ' . implode(', ', array_slice(array_unique($bad), 0, 6)) : ''));

  // scalars mod n, and the windows
  $sbad = []; $sN = 0;
  $sedges = [gmp_init(1), gmp_init(2), gmp_sub($gn, 1), gmp_sub($gn, 2), gmp_div_q($gn, 2), gmp_add(gmp_div_q($gn, 2), 1), gmp_pow(2, 128)];
  $srand = []; for ($i = 0; $i < 1000; $i++) $srand[] = gmp_mod(gmp_import(hash('sha256', "sc$seed:$i", true), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), $gn);
  $sb = fn(GMP $v): string => $bytes($v);
  foreach (array_merge($sedges, $srand) as $i => $a) {
    if (gmp_sign($a) === 0) continue;
    $b = $srand[($i * 7 + 3) % count($srand)];
    $sN += 5;
    if ($C('scInv', $sb($a)) !== $sb(gmp_invert($a, $gn))) $sbad[] = 'scInv';
    if ($C('scMul', $sb($a), $sb($b)) !== $sb(gmp_mod(gmp_mul($a, $b), $gn))) $sbad[] = 'scMul';
    if ($C('scAdd', $sb($a), $sb($b)) !== $sb(gmp_mod(gmp_add($a, $b), $gn))) $sbad[] = 'scAdd';
    if ($C('scNeg', $sb($a)) !== $sb(gmp_sub($gn, $a))) $sbad[] = 'scNeg';
    $wideA = hash('sha256', "w$i", true) . hash('sha256', "v$i", true) . substr(hash('sha256', "u$i", true), 0, $i % 17);
    if ($C('scMod', $wideA) !== $sb(gmp_mod(gmp_import($wideA, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), $gn))) $sbad[] = 'scMod';
  }
  foreach ([str_repeat("\xff", 32), str_repeat("\xff", 40), hex2bin(N_HEX), str_repeat("\0", 31) . "\x01"] as $v) {
    $sN++;
    if ($C('scMod', $v) !== $sb(gmp_mod(gmp_import($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), $gn))) $sbad[] = 'scMod edge';
  }
  $sN++;
  if ($C('scInv', str_repeat("\0", 32)) !== str_repeat("\0", 32)) $sbad[] = 'scInv of 0';   // no inverse, and no endless loop
  ok($sbad === [], sprintf('scalars: %d inverses, products, sums, negations and reductions mod n%s',
     $sN, $sbad ? ': wrong ' . implode(', ', array_slice(array_unique($sbad), 0, 6)) : ''));

  $wbad = 0; $wN = 0;
  $scal = [str_repeat("\0", 32), str_repeat("\0", 31) . "\x01", str_repeat("\xff", 32), hex2bin(N_HEX), str_repeat("\xff", 40),
           str_repeat("\x55", 32), str_repeat("\xaa", 32), str_repeat("\x84\x21", 16), str_repeat("\x82\x08\x20", 10) . "\x82\x08"];
  for ($i = 0; $i < 600; $i++) $scal[] = hash('sha256', "wn$i", true) . ($i % 3 === 0 ? substr(hash('sha256', "wm$i", true), 0, 8) : '');
  foreach ($scal as $k) foreach ([5, 6] as $w) {
    $wN++;
    $digits = $C('wnaf', $k, $w);
    $sum = gmp_init(0); $last = null; $good = true;
    foreach ($digits as $pos => $dgt) {
      if ($dgt % 2 === 0 || abs($dgt) >= 1 << ($w - 1) || ($last !== null && $pos - $last < $w)) $good = false;
      $sum = gmp_add($sum, gmp_mul($dgt, gmp_pow(2, $pos)));
      $last = $pos;
    }
    if (!$good || gmp_cmp($sum, gmp_import($k === '' ? "\0" : $k, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN)) !== 0) $wbad++;
  }
  ok($wbad === 0, "signed windows: $wN scalars, each digit odd and below 2^(w − 1), w apart, summing to the scalar ($wbad wrong)");

  // points: Jacobian sums and doubles against the old affine ones, with Z not 1
  if ($oracle) {
    $O = Closure::bind(static fn(string $m, ...$a) => self::$m(...$a), null, OldSecp256k1::class);
    $O('init');
    $pts = [];
    for ($i = 0; $i < 60; $i++) {
      $q = OldSecp256k1::decodePoint(Secp256k1::publicKey(hash('sha256', "pt$i", true), false));
      $pts[] = $q;
    }
    $jac = function (array $q, int $i) use ($C, $fe, $gp): array {      // (x·z², y·z³, z) for a z from i
      $z = gmp_add(gmp_import(hash('sha256', "z$i", true), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), 1);
      $z = gmp_mod($z, $gp);
      return [$fe(gmp_mod(gmp_mul($q[0], gmp_powm($z, 2, $gp)), $gp)), $fe(gmp_mod(gmp_mul($q[1], gmp_powm($z, 3, $gp)), $gp)), $fe($z)];
    };
    $aff = fn(array $q): array => [$fe($q[0]), $fe($q[1])];
    $same = fn(?array $new, ?array $old): bool => $new === null ? $old === null
      : $old !== null && $C('feBytes', $new[0]) === $bytes($old[0]) && $C('feBytes', $new[1]) === $bytes($old[1]);
    $pbad = []; $pN = 0;
    foreach ($pts as $i => $p) {
      $q = $pts[($i + 1) % count($pts)];
      $neg = [$p[0], gmp_sub($gp, $p[1])];
      $jp = $jac($p, $i); $jq = $jac($q, $i + 100); $jneg = $jac($neg, $i + 200); $jp2 = $jac($p, $i + 300);
      $checks = [
        'P + Q'         => [$C('affine', $C('pointAdd', $jp, $jq)), $O('add', $p, $q)],
        'P + Q affine'  => [$C('affine', $C('pointAddAffine', $jp, $aff($q))), $O('add', $p, $q)],
        '2P'            => [$C('affine', $C('pointDbl', $jp)), $O('dbl', $p)],
        'P + P'         => [$C('affine', $C('pointAdd', $jp, $jp2)), $O('dbl', $p)],
        'P + P affine'  => [$C('affine', $C('pointAddAffine', $jp, $aff($p))), $O('dbl', $p)],
        'P + −P'        => [$C('affine', $C('pointAdd', $jp, $jneg)), null],
        'P + −P affine' => [$C('affine', $C('pointAddAffine', $jp, $aff($neg))), null],
        'P + ∞'         => [$C('affine', $C('pointAdd', $jp, null)), $p],
        '∞ + P affine'  => [$C('affine', $C('pointAddAffine', null, $aff($p))), $p],
        '2∞'            => [$C('pointDbl', null), null],
      ];
      foreach ($checks as $what => [$new, $old]) { $pN++; if (!$same($new, $old)) $pbad[] = $what; }
    }
    ok($pbad === [], sprintf('points: %d sums and doubles in Jacobian form, Z not 1, equal to the old affine ones, P + P and P + −P included%s',
       $pN, $pbad ? ': wrong ' . implode(', ', array_slice(array_unique($pbad), 0, 6)) : ''));
    $tbl = true;
    foreach ((new ReflectionClassConstant(Secp256k1::class, 'G_ODD'))->getValue() as $i => [$x, $y]) {
      $u = OldSecp256k1::publicKey(gmp_init(2 * $i + 1), false);
      if (bin2hex(substr($u, 1, 32)) !== $x || bin2hex(substr($u, 33)) !== $y) $tbl = false;
    }
    ok($tbl, 'G_ODD is 1G, 3G, ..., 31G, as the old curve computes them');
  }
}
// G_ODD rebuilt with the new point arithmetic from G alone, which needs no gmp
$g1 = $C('point', hex2bin('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
$one = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
$rebuilt = $g1 !== null;
if ($rebuilt) {
  $j = [$g1[0], $g1[1], $one]; $g2 = $C('pointDbl', $j);
  foreach ((new ReflectionClassConstant(Secp256k1::class, 'G_ODD'))->getValue() as $i => [$x, $y]) {
    $a = $C('affine', $j);
    if ($a === null || bin2hex($C('feBytes', $a[0])) !== $x || bin2hex($C('feBytes', $a[1])) !== $y) { $rebuilt = false; break; }
    $j = $C('pointAdd', $j, $g2);
  }
}
ok($rebuilt, 'G_ODD rebuilt from G by repeated addition of 2G: all 16 entries match');

// ── 4. the edges ─────────────────────────────────────────────────────────────────────────────────────
echo "\n── edges: how a key may be given, and the errors ──\n";
$err = function (callable $f): string { try { $f(); return 'no error'; } catch (Throwable $e) { return said($e); } };
$d = hash('sha256', 'an edge key', true); $dig = hash('sha256', 'an edge message', true);
$range = 'InvalidArgumentException: private key out of range';
ok(Secp256k1::publicKey(str_repeat("\0", 31) . "\x05") === Secp256k1::publicKey(5)
   && Secp256k1::sign(str_repeat("\0", 31) . "\x05", $dig) === Secp256k1::sign(5, $dig)
   && Secp256k1::signRecoverable(str_repeat("\0", 31) . "\x05", $dig) === Secp256k1::signRecoverable(5, $dig),
   'a key as an int is the same key as its 32 bytes: publicKey, sign and signRecoverable');
ok(Secp256k1::publicKey(PHP_INT_MAX) === Secp256k1::publicKey(str_repeat("\0", 24) . "\x7f\xff\xff\xff\xff\xff\xff\xff"),
   'PHP_INT_MAX as a key');
$errs = [
  [fn() => Secp256k1::publicKey(0), $range], [fn() => Secp256k1::publicKey(-1), $range], [fn() => Secp256k1::publicKey(PHP_INT_MIN), $range],
  [fn() => Secp256k1::publicKey(str_repeat("\0", 32)), $range], [fn() => Secp256k1::publicKey(hex2bin(N_HEX)), $range],
  [fn() => Secp256k1::publicKey(substr($d, 1)), 'InvalidArgumentException: private key must be 32 bytes'],
  [fn() => Secp256k1::publicKey($d . "\0"), 'InvalidArgumentException: private key must be 32 bytes'],
  [fn() => Secp256k1::sign(0, 'short'), 'InvalidArgumentException: digest must be 32 bytes'],
  [fn() => Secp256k1::sign('short', 'short'), 'InvalidArgumentException: digest must be 32 bytes'],
  [fn() => Secp256k1::sign('short', $dig), 'InvalidArgumentException: private key must be 32 bytes'],
  [fn() => Secp256k1::signRecoverable(0, ''), 'InvalidArgumentException: digest must be 32 bytes'],
  [fn() => Secp256k1::signRecoverable(-5, $dig), $range],
];
$ebad = [];
foreach ($errs as $i => [$f, $want]) if (($got = $err($f)) !== $want) $ebad[] = "#$i: $got";
ok($ebad === [], 'bad keys and digests give the errors they always gave, the digest checked first' . ($ebad ? ': ' . implode('; ', $ebad) : ''));
// signRecoverable's callback: refusing steps the generator forward; r and s come as bytes for a key given as bytes
$calls = 0; $seen = [];
$refuse2 = function ($r, $s, int $v) use (&$calls, &$seen): bool { $seen[] = [$r, $s, $v]; return ++$calls > 2; };
$rec = Secp256k1::signRecoverable($d, $dig, $refuse2);
ok($calls === 3 && is_string($rec[0]) && strlen($rec[0]) === 32 && strlen($rec[1]) === 32 && $seen[2] === $rec
   && $seen[0] !== $rec && Secp256k1::verifyDigest(der($rec[0], $rec[1]), Secp256k1::publicKey($d), $dig),
   'signRecoverable with a key as bytes: the callback sees 32-byte r and s, two refusals step to a third signature, and it verifies');
ok(Secp256k1::encodeDer($rec[0], $rec[1]) === der($rec[0], $rec[1]) && Secp256k1::encodeDer("\0\0\x05", 7) === der("\x05", "\x07")
   && Secp256k1::encodeDer('', "\x80") === "\x30\x07\x02\x01\x00\x02\x02\x00\x80" && Secp256k1::encodeDer(-7, 7) === der("\x07", "\x07"),
   'encodeDer takes bytes and ints, pads a high bit, writes 0 as one zero byte and a negative number as its magnitude');
if (extension_loaded('gmp')) {
  $gd = gmp_import($d, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  ok(Secp256k1::publicKey($gd) === Secp256k1::publicKey($d) && Secp256k1::publicKey($gd, false) === Secp256k1::publicKey($d, false)
     && Secp256k1::sign($gd, $dig, true) === Secp256k1::sign($d, $dig, true),
     'a key as a GMP number is the same key as its 32 bytes');
  $gn = gmp_init(N_HEX, 16);
  $gerrs = [[gmp_init(0), $range], [gmp_init(-1), $range], [$gn, $range], [gmp_add($gn, 1), $range], [gmp_pow(2, 256), $range],
            [gmp_neg($gd), $range], [gmp_pow(2, 300), $range]];
  $gbad = [];
  foreach ($gerrs as $i => [$v, $want]) {
    $got = $err(fn() => Secp256k1::publicKey($v)) . ' | ' . $err(fn() => Secp256k1::sign($v, $dig)) . ' | ' . $err(fn() => Secp256k1::sign($v, 'x'));
    $exp = "$want | $want | InvalidArgumentException: digest must be 32 bytes";
    if ($oracle) $exp = $err(fn() => OldSecp256k1::publicKey($v)) . ' | ' . $err(fn() => OldSecp256k1::sign($v, $dig)) . ' | ' . $err(fn() => OldSecp256k1::sign($v, 'x'));
    if ($got !== $exp) $gbad[] = "#$i: $got";
  }
  ok($gbad === [], 'GMP keys out of range give ' . ($oracle ? "the old curve's errors" : 'the errors') . ($gbad ? ': ' . implode('; ', $gbad) : ''));
  $calls = 0; $types = true;
  $cb = function ($r, $s, int $v) use (&$calls, &$types): bool { if (!($r instanceof GMP) || !($s instanceof GMP)) $types = false; return ++$calls > 2; };
  $gr = Secp256k1::signRecoverable($gd, $dig, $cb);
  ok($types && $gr[0] instanceof GMP && hx($gr[0]) === bin2hex($rec[0]) && hx($gr[1]) === bin2hex($rec[1]) && $gr[2] === $rec[2],
     'signRecoverable with a GMP key: the callback and the result get GMP numbers, the same signature as with bytes');
  if ($oracle) {
    $calls = 0; $og = OldSecp256k1::signRecoverable($gd, $dig, function (GMP $r, GMP $s, int $v) use (&$calls): bool { return ++$calls > 2; });
    ok(gmp_cmp($og[0], $gr[0]) === 0 && gmp_cmp($og[1], $gr[1]) === 0 && $og[2] === $gr[2],
       'and the old curve, refusing the same two, gives the same r, s and recid');
    $pairs = [[gmp_init(0), gmp_init(0)], [gmp_init(5), gmp_init(-7)], [gmp_pow(2, 255), gmp_sub($gn, 1)], [gmp_init(0x80), gmp_pow(2, 300)]];
    $same = true;
    foreach ($pairs as [$a, $b]) if (Secp256k1::encodeDer($a, $b) !== OldSecp256k1::encodeDer($a, $b)) $same = false;
    ok($same, 'encodeDer of GMP numbers, zero, negative and wider than 32 bytes among them, is the old encoding');
  }
}
// Two guards no random case reaches, each held by a fixed vector that only its guard refuses: x(R) = r + n - p,
// which the inversion-free final check would take for r without 'r >= p - n gives false'; and a compressed key
// whose x is p + 1, which a reduction mod p would read as the key with x = 1.
$sig2 = '3045022100f6503cdb855e204c30a3b91bd1212055486e7eab2c8ae2ed9c761821fbc5d7be022072893b78aa5768e3bab08f073df71330e6a858b6dba23a55a9dace12318e223d';
$fixed = [
  ['30350211014551231950b75fc4402da1722fc9baef02203e7bd34fc0d174057dd9473b67d9d474c8be938a57a6ea3dea7604c07f056040',
   '0267e35e504d414bb1c148ef8338e8ba116a66d6ac170162b3b36a257338d68ec4',
   '970cd3614ebf965477448f3b7629f491d57021b5461c6c5f1028f0cce5d768e5', false, 'x(R) = r + n - p is refused'],
  [$sig2, '02' . str_repeat('00', 31) . '01', '855d328462979a8277eeb73456f46922babfceb4848e6674f617c050352ea88a', true,
   'a signature valid under the key with x = 1 verifies'],
  [$sig2, '02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30',
   '855d328462979a8277eeb73456f46922babfceb4848e6674f617c050352ea88a', false, 'and the same key written with x = p + 1 is refused'],
];
foreach ($fixed as [$s, $k, $g, $want, $what]) {
  $got = Secp256k1::verifyDigest(hex2bin($s), hex2bin($k), hex2bin($g));
  $old = $oracle ? OldSecp256k1::verifyDigest(hex2bin($s), hex2bin($k), hex2bin($g)) : $want;
  ok($got === $want && $old === $want, $what . ($oracle ? ', as by the old curve' : ''));
}

// no gmp outside the edge: every gmp_ name and GMP_ constant in the curve sits in magnitude() or toGmp()
$where = [];
foreach (['secp256k1.php', 'rfc6979.php'] as $f) {
  $fn = null; $depth = 0; $fnDepth = -1;
  foreach (token_get_all((string)file_get_contents("$curve/$f")) as $i => $t) {
    if ($t === '{' || (is_array($t) && in_array($t[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))) $depth++;
    if ($t === '}') { $depth--; if ($depth === $fnDepth) { $fn = null; $fnDepth = -1; } }
    if (!is_array($t)) continue;
    if ($t[0] === T_FUNCTION && $fn === null) $fn = '?';
    elseif ($fn === '?' && $t[0] === T_STRING) { $fn = $t[1]; $fnDepth = $depth; }
    elseif ($t[0] === T_STRING && preg_match('/^gmp_|^GMP_/', $t[1])) $where[] = "$f:" . ($fn ?? 'top') . ':' . $t[1];
  }
}
$outside = array_filter($where, fn($w) => !preg_match('/^secp256k1\.php:(magnitude|toGmp):/', $w));
ok($where !== [] && $outside === [], sprintf('%d gmp names in the curve, all in magnitude() and toGmp()%s', count($where),
   $outside ? ': ' . implode(', ', array_slice($outside, 0, 5)) : ''));

printf("\n%s  %d passed, %d failed   [secp256k1 on PHP ints · against the GMP curve at %s]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail, substr(REV, 0, 7));
exit($fail === 0 ? 0 : 1);
