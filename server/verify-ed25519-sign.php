<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// server/ed25519-sign.php graded against libsodium 1.0.22. ext/sodium at that version is the oracle, and every public
// key and every signature must be its bytes exactly: Ed25519 signing is deterministic, so a seed and a message have
// one right answer. The corpus is built the same way on every host, and the oracle's outputs over it are pinned below
// as SWEEP_DIGEST, so a PHP without sodium is graded by the digest instead.
//
//   php server/verify-ed25519-sign.php [n=2000] [seed=20261025] [--sign=FILE] [--emit-table]
//     n             random seeds and messages in the sweep
//     --sign        grade FILE instead of the ed25519-sign.php beside this file (FILE loads its own ed25519.php)
//     --emit-table  grade nothing: print BASE rebuilt from B, as the PHP ed25519-sign.php holds
//
// Five parts:
//   vectors  RFC 8032 section 7.1, its five Ed25519 tests (the empty message, one byte, two, 1023, and SHA-512 of
//            "abc"): the public key, and the signature from the seed and from the 64-byte secret key.
//   sweep    random seeds with messages of every length from 0 to 300 bytes, and of 64 KiB and 1 MiB; seeds all zero,
//            all 0xff and at other edges; each signed from the seed, half of them and every edge from libsodium's 64-byte
//            secret key too, and each signature verified by ed25519.php. Every clamped scalar is at least 2^254, above L (about 2^252), so every
//            seed here is one whose scalar exceeds L; the sweep checks the clamp on each.
//   secrets  a 64-byte secret key whose public half is not its seed's key is refused, and why: where gmp and sodium
//            are loaded, two libsodium signatures under two public halves are shown to give the secret scalar away.
//            Wrong lengths are refused. Each refusal is made with zend.exception_ignore_args = 0 and each string of a
//            trace shown whole, and fails if a run of 4 bytes of a seed, its a or its prefix (raw, in hex, or as a
//            printed trace writes it) is in the message, in the printed exception or in an argument getTrace() holds.
//   layers   [k]B against ed25519.php's variable-time multiply, for k at the edges and at random; the signed digits;
//            the conditional moves and the table selection; (h·a + r) mod L against gmp where it is loaded; BASE
//            rebuilt from B, entry by entry, and its odd multiples against ed25519.php's B_ODD.
//   shape    the tokens of sign() and publicKey(), the public methods Ed25519Sign declares, and of every function
//            either reaches by self::, in both files, each call resolved in its own class: the signing path.
//            ★ What it is for: it guards against an ACCIDENTAL edit that puts a secret-dependent branch, loop count,
//            index or one-byte string on the signing path. It cannot stop a deliberate saboteur, who would edit this
//            file too; it reads the source, not what the engine does with it; and PHP itself promises no constant
//            time. So each rule forbids a whole construct on the path rather than reason about where its value comes
//            from. It fails on:
//            - if, else, switch, match, ?:, ??, &&, ||, and, or, xor; while, do, foreach, break, continue, goto; throw,
//              try, yield, eval, include, require, exit; a comparison outside a for header, and !, isset, empty, unset
//              and instanceof, which make a bool of a value as a comparison does; /, %, **; a cast; a string with
//              variables in it, a heredoc or a backtick; echo, print, global, static, a static property
//            - but in sign(), publicKey() and host(): `if (C) throw new InvalidArgumentException or RuntimeException`,
//              C made of numbers, comparisons, &&, ||, !, PHP_INT_SIZE, a variable assigned once from strlen(), and
//              strlen(), substr() and hash_equals() of variables, hash_equals() with one argument a variable assigned
//              once from self::encode(); and addPrecomp()'s ?: on its flag, every call to it on the path passing false
//            - strlen() of anything but a parameter that the function never assigns: the length of an input is public
//            - a for header other than `$v = N; $v < M; $v++`, N and M each a number or a parameter that every call on
//              the path passes as numbers, arithmetic and the caller's loop counters
//            - an index other than numbers, arithmetic, loop counters, such parameters, and a closure's parameter in
//              the closure's body when every call of the closure passes numbers and loop counters
//            - a loop counter, or a parameter (a closure's too) that indexes or bounds a loop, assigned outside a for
//              header or the closure's parameter list
//            - an index on anything but an array parameter, an array constant of the class (an index of an index only
//              into one whose entries are arrays that deep), or a variable assigned only an array literal, unpack(),
//              array_fill(), an array constant or a self:: call declared to return array: so no string offset
//            - ord() and chr(), but in encode() and isNegative(), which are also spared the rule above. encode() may be
//              called only as `self::encode(self::mulBase($a))` and `self::encode(self::mulBase($r))`, from sign() and
//              publicKey(), and isNegative() only as encode() calls it: what they read is the public key and R
//            - a variable variable ($$v, ${...}); a reference of any kind (=&, [&$v], (&$v, use (&$v), fn&, and a
//              parameter taken or a value returned by reference: an & with no operand before it, so bitwise AND stays);
//              list(); a destructuring into anything but bare variables, `[$a, $b] = ...`; a => but an arrow function's, so no
//              key in an array literal or a destructuring; a closure but `$name = fn (int $x, ...) => ...` or `$name =
//              function (int $x, ...) {...}`; a named argument; a ... but into pack()
//            - a concatenation other than those in $CONCAT, `$R . $A` and `$R . self::scMulAdd($h, $a, $r)` in sign(),
//              and .=: . turns an int into a string through a table of them
//            - a shift by anything but a number; a float literal, a number of 2^32 or more, a left shift by 32 or more,
//              and a name but true, false, a guard's PHP_INT_SIZE, a closure's int and the class's own array and string
//              constants by self::. These keep out the plain ways to write an int multiply that overflows into a float;
//              that the honest products stay below 2^63 is ed25519.php's argument, not this scan's
//            - a call but by self::, of a closure the function defines, or of: unpack() with C, v or V and a count or
//              *, and an offset that is a number or none; pack() with v or V and a count of at least 2; hash();
//              substr() only as in $SUBSTR, the four calls that cut the secret key and the hash in halves (a one-byte
//              string is a load from a table indexed by the byte); array_fill(); and in the three above strlen(),
//              hash_init(), hash_update(), hash_final(), hash_equals(). A format or a flag of hash(), array_fill(),
//              hash_init() or hash_final() that is not numbers, strings and loop counters
//            - a parameter not marked #[\SensitiveParameter] but the four in $PUBLIC: the message, select()'s row,
//              addPrecomp()'s flag and sqMul()'s count. A trace, a fatal error's included, then shows none of the rest
//            - either file without declare(strict_types=1), which keeps an int passed to hash() or substr() from
//              becoming a string unseen
//            And [k]B timed for four classes of scalar, every digit 0, all but one 0, random, and every digit ±8:
//            the median of each over rounds that time each class once, the order turning, the slowest median held
//            below TIMING_BOUND.
declare(strict_types=1);

const DEFAULT_N = 2000, DEFAULT_SEED = 20261025;
const ORACLE_VERSION = '1.0.22';
/** sha256 over each sweep case and libsodium 1.0.22's public key and signature for it, at the default n and seed. */
const SWEEP_DIGEST = '63f2f37f6148cf219c2e547c9d5f04d664b26b56da0b04163d29b0288f3e939b';
const L_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';
/**
 * The most the slowest class of digits may take over the fastest, in median time per [k]B. The same work for every
 * digit measures about 1.01 here; a select() that moves |d| entries in place of 8 about 1.7. A smaller leak, such as
 * one move more when |d| = 8 (about 1.06), is the scan's to find: a bound that close to the noise would fail honest code.
 */
const TIMING_BOUND = 1.1;
const B_HEX = '5866666666666666666666666666666666666666666666666666666666666666';

$plain = array_values(array_filter(array_slice($argv, 1), fn($a) => !str_starts_with($a, '--')));
$opt = function (string $name) use ($argv): ?string {
  foreach ($argv as $a) if (str_starts_with($a, "--$name=")) return substr($a, strlen($name) + 3);
  return null;
};
$N = (int)($plain[0] ?? DEFAULT_N);
$seed = (int)($plain[1] ?? DEFAULT_SEED);
$file = $opt('sign') ?? __DIR__ . '/ed25519-sign.php';
require_once $file;                                     // and the ed25519.php beside it
$pinned = $N === DEFAULT_N && $seed === DEFAULT_SEED;

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── both files' own functions, for the layers ────────────────────────────────────────────────────────
$E = Closure::bind(static fn(string $m, ...$a) => self::$m(...$a), null, Ed25519::class);
$S = Closure::bind(static fn(string $m, ...$a) => self::$m(...$a), null, Ed25519Sign::class);
$E('init');
function E(string $m, mixed ...$a): mixed { return ($GLOBALS['E'])($m, ...$a); }
function S(string $m, mixed ...$a): mixed { return ($GLOBALS['S'])($m, ...$a); }
const F0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const F1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const IDENTITY = [F0, F1, F1, F0];
function pt(string $enc): array { $n = E('decodeNegated', $enc); return [E('neg', $n[0]), $n[1], $n[2], E('neg', $n[3])]; }
function padd(array $p, array $q): array { return E('p3', E('addCached', $p, E('cached', $q), false)); }
function enc(array $p): string { return E('encode', $p); }
/** The canonical limbs of an element: what fe() reads from its canonical bytes. */
function canon(array $f): array { return E('fe', E('bytes', $f)); }
/** [k]B by ed25519.php's variable-time double multiply, which verify-ed25519.php grades. */
function baseVartime(string $k): string { return enc(E('mulAdd', '', IDENTITY, $k)); }

/** BASE[i][j] = (j + 1)·256^i·B as [y + x, y − x, 2dxy], canonical limbs, from B's encoding by ed25519.php's point code. */
function rebuildBase(): array {
  $B = pt(hex2bin(B_HEX));
  $d2 = E('fe', strrev(hex2bin((new ReflectionClassConstant(Ed25519::class, 'D2'))->getValue())));
  $rows = []; $P = $B;
  for ($i = 0; $i < 32; $i++) {
    $Q = $P;
    for ($j = 0; $j < 8; $j++) {
      $zi = E('invert', $Q[2]);
      $x = E('mul', $Q[0], $zi); $y = E('mul', $Q[1], $zi);
      $rows[$i][$j] = [canon(E('add', $y, $x)), canon(E('sub', $y, $x)), canon(E('mul', E('mul', $x, $y), $d2))];
      $Q = padd($Q, $P);
    }
    for ($k = 0; $k < 8; $k++) $P = E('p3', E('dbl', $P));
  }
  return $rows;
}

if (in_array('--emit-table', $argv, true)) {
  foreach (rebuildBase() as $i => $row) {
    echo "    [ // 1 to 8 times 256^{$i}·B\n";
    foreach ($row as [$a, $b, $c]) echo '      [[', implode(', ', $a), '], [', implode(', ', $b), '], [', implode(', ', $c), "]],\n";
    echo "    ],\n";
  }
  exit(0);
}

// ── the oracle ───────────────────────────────────────────────────────────────────────────────────────
$sodium = extension_loaded('sodium');
$oracle = $sodium && SODIUM_LIBRARY_VERSION === ORACLE_VERSION;
printf("  - grading %s\n", realpath($file) ?: $file);
if ($oracle) echo "  - the oracle: ext/sodium, libsodium " . SODIUM_LIBRARY_VERSION . "\n";
elseif ($sodium) echo '  - no oracle: this PHP has libsodium ' . SODIUM_LIBRARY_VERSION . ', not ' . ORACLE_VERSION . ". Graded by the pinned digest.\n";
else echo "  - no oracle: ext/sodium is not loaded. Graded by the pinned digest.\n";
/** libsodium's [public key, 64-byte secret key, signature] for a seed and a message. */
function sodiumSign(string $seed, string $msg): array {
  $kp = sodium_crypto_sign_seed_keypair($seed);
  $sk = sodium_crypto_sign_secretkey($kp);
  return [sodium_crypto_sign_publickey($kp), $sk, sodium_crypto_sign_detached($msg, $sk)];
}

$rnd = fn(string $tag): string => hash('sha256', "$seed:$tag", true);
$bytes = function (string $tag, int $n) use ($rnd): string { $b = ''; for ($i = 0; strlen($b) < $n; $i++) $b .= $rnd("$tag/$i"); return substr($b, 0, $n); };
$L = strrev(hex2bin(L_HEX));                            // little-endian, as every scalar here
/** $f(), or null with the class of what it threw in $threw: a mutated signer is graded, never left to crash the run. */
function attempt(callable $f, ?string &$threw): ?string {
  try { return $f(); } catch (Throwable $e) { $threw ??= 'threw ' . get_class($e); return null; }
}

/**
 * One case: our public key and both signatures, against the oracle where there is one, and the signature verified by
 * ed25519.php. Returns [the line hashed into the digest, what went wrong or null].
 */
function signCase(string $seed, string $msg, bool $oracle, bool $both = true): array {
  $wrong = null;
  $pub = attempt(fn() => Ed25519Sign::publicKey($seed), $wrong);
  $sig = attempt(fn() => Ed25519Sign::sign($msg, $seed), $wrong);
  // the digest is over libsodium's bytes where it is loaded, and over ours where it is not
  [$opub, $sk, $osig] = $oracle ? sodiumSign($seed, $msg) : [(string)$pub, $seed . $pub, (string)$sig];
  if ($wrong === null && $pub !== $opub) $wrong = 'public key';
  if ($wrong === null && $sig !== $osig) $wrong = 'signature from the seed';
  if ($wrong === null && $both && attempt(fn() => Ed25519Sign::sign($msg, $sk), $wrong) !== $osig) $wrong ??= 'signature from the 64-byte secret key';
  if ($wrong === null && !Ed25519::verify($osig, $msg, $opub)) $wrong = 'ed25519.php refuses the signature';
  return [bin2hex($seed) . "\0" . hash('sha256', $msg) . "\0" . bin2hex($opub) . "\0" . bin2hex($osig) . "\n", $wrong];
}

// ── 1. RFC 8032 ──────────────────────────────────────────────────────────────────────────────────────
echo "\n── vectors: RFC 8032 section 7.1, Ed25519 ──\n";
$TEST1024 = '08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8'
          . '79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc'
          . '1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e'
          . '06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7'
          . 'aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2'
          . 'd17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270'
          . '88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07'
          . '07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a'
          . 'ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7'
          . '51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8'
          . 'ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08'
          . 'd78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4'
          . '88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e'
          . '6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5'
          . '0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d'
          . 'b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0';
$RFC = [
  ['TEST 1', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
   'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
  ['TEST 2', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
   '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
  ['TEST 3', 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
   '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
  ['TEST 1024', 'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5', '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e', $TEST1024,
   '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03'],
  ['TEST SHA(abc)', '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
   hash('sha512', 'abc'),
   'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704'],
];
foreach ($RFC as [$name, $sd, $pk, $m, $sg]) {
  [$sd, $pk, $m] = [hex2bin($sd), hex2bin($pk), hex2bin($m)];
  $threw = null;
  $pub = attempt(fn() => Ed25519Sign::publicKey($sd), $threw);
  $s32 = attempt(fn() => Ed25519Sign::sign($m, $sd), $threw);
  $s64 = attempt(fn() => Ed25519Sign::sign($m, $sd . $pk), $threw);
  $agree = !$oracle || sodiumSign($sd, $m) === [$pk, $sd . $pk, hex2bin($sg)];
  ok($pub === $pk && $s32 === hex2bin($sg) && $s64 === $s32 && $agree && Ed25519::verify(hex2bin($sg), $m, $pk),
     sprintf('%s, a message of %d byte%s: the public key and the signature, from the seed and from the secret key%s%s', $name, strlen($m),
             strlen($m) === 1 ? '' : 's', $oracle ? ', and libsodium gives the same' : '', $threw ? ": $threw" : ''));
}

// ── 2. the sweep ─────────────────────────────────────────────────────────────────────────────────────
echo "\n── sweep: random seeds and messages, and seeds at the edges ──\n";
$t0 = microtime(true);
$cases = [];                                            // [label, seed, message, sign from both forms]
foreach (['all zero' => str_repeat("\0", 32), 'all 0xff' => str_repeat("\xff", 32), 'one' => "\x01" . str_repeat("\0", 31),
          'the top bit only' => str_repeat("\0", 31) . "\x80", 'L' => $L, 'alternate bits' => str_repeat("\x55\xaa", 16)] as $what => $sd)
  foreach (['', "\0", 'a message', $bytes("edge $what", 300)] as $k => $m) $cases[] = ["seed $what, message $k", $sd, $m, true];
for ($i = 0; $i < $N; $i++) $cases[] = ["sweep $i", $rnd("seed $i"), $bytes("msg $i", $i % 301), $i % 2 === 0];
foreach (['64 KiB' => 65536, '1 MiB' => 1 << 20] as $what => $len)
  for ($k = 0; $k < 2; $k++) $cases[] = ["a message of $what, $k", $rnd("big seed $what $k"), str_repeat($bytes("big $what $k", 4096), $len >> 12), true];
$h = hash_init('sha256'); $wrong = []; $clamp = 0;
foreach ($cases as [$label, $sd, $m, $both]) {
  [$line, $w] = signCase($sd, $m, $oracle, $both);
  hash_update($h, $line);
  if ($w !== null && count($wrong) < 6) $wrong[] = "$label: $w";
  [$a] = S('expand', $sd);
  $ab = unpack('C32', $a);
  $full = hash('sha512', $sd, true);
  // the clamp, worked from the hash independently: bits 0 to 2 and 255 clear, 254 set, the rest as hashed
  $want = substr($full, 0, 32); $want[0] = chr(ord($want[0]) & 0xf8); $want[31] = chr((ord($want[31]) & 0x7f) | 0x40);
  if ($a === $want && ($ab[32] & 0x40) && strcmp(strrev($a), strrev($L)) > 0) $clamp++;
}
$digest = hash_final($h);
$big = count(array_filter($cases, fn($c) => strlen($c[2]) > 300));
ok($wrong === [], sprintf('%d cases, messages of 0 to 300 bytes and %d longer: %s, from the seed and %s from the 64-byte secret key, and ed25519.php verifies each%s',
   count($cases), $big, $oracle ? "libsodium's public key and signature byte for byte" : 'signed', 'half of them',
   $wrong ? ': ' . implode('; ', $wrong) : ''));
ok($clamp === count($cases), sprintf('the clamp on every seed: the low three bits and bit 255 cleared, bit 254 set, the rest as hashed, and the scalar above L (%d of %d)',
   $clamp, count($cases)));
if (!$pinned) echo "  - not the default n and seed, so the pinned digest does not apply\n";
else ok($digest === SWEEP_DIGEST, ($oracle ? 'libsodium still gives the pinned outputs' : "ed25519-sign.php gives libsodium's pinned outputs") . " ($digest)");
printf("    (%.1f s)\n", microtime(true) - $t0);

// ── 3. the secrets ───────────────────────────────────────────────────────────────────────────────────
echo "\n── secrets: what is refused, and what an exception and its trace carry ──\n";
$sdA = $rnd('secret A'); $sdB = $rnd('secret B');
$sdP = 'Qz7#Xv2!Kp9@Wm4$Jr6%Nt1^Bh8&Ld3*';                 // printable, so a trace would show it as it is
$pubA = Ed25519Sign::publicKey($sdA); $pubB = Ed25519Sign::publicKey($sdB);
// Every refusal below is made with the call arguments kept in its trace (PHP's built-in default, and
// php.ini-development's) and each string shown whole, not cut at 15 bytes, so that a secret cannot hide in a trace.
$ignoreArgs = (string)ini_get('zend.exception_ignore_args'); $maxLen = (string)ini_get('zend.exception_string_param_max_len');
ini_set('zend.exception_ignore_args', '0');
ini_set('zend.exception_string_param_max_len', '1000000');
// [what was refused, the exception or null]. Each call is made here, at the top level and not in a closure, so that
// its trace holds the signer's frames and nothing of this file's.
$caught = [];
foreach ([$sdA . $pubB, $sdB . $pubA, $sdP . $pubA, $sdA . substr($pubA, 0, 31) . chr(ord($pubA[31]) ^ 0x80)] as $secret) {
  try { Ed25519Sign::sign('a message', $secret); $caught[] = ['half', null]; }
  catch (InvalidArgumentException $e) { $caught[] = ['half', $e]; }
}
foreach ([0, 1, 31, 33, 63, 65, 96] as $n) foreach ([$sdA, $sdB, $sdP] as $sd) {
  try { Ed25519Sign::sign('a message', substr(str_repeat($sd, 4), 0, $n)); $caught[] = ['secret length', null]; }
  catch (InvalidArgumentException $e) { $caught[] = ['secret length', $e]; }
}
foreach ([0, 31, 33, 64] as $n) foreach ([$sdA, $sdB, $sdP] as $sd) {
  try { Ed25519Sign::publicKey(substr(str_repeat($sd, 4), 0, $n)); $caught[] = ['seed length', null]; }
  catch (InvalidArgumentException $e) { $caught[] = ['seed length', $e]; }
}
ini_set('zend.exception_ignore_args', $ignoreArgs); ini_set('zend.exception_string_param_max_len', $maxLen);
$msg = []; foreach ($caught as [$what, $e]) $msg[$what][] = $e?->getMessage();
ok(!in_array(null, $msg['half'], true) && count(array_unique($msg['half'])) === 1,
   "a 64-byte secret key whose public half is another key's, or its own with the sign bit flipped, is refused");
ok(!in_array(null, $msg['secret length'], true) && !in_array(null, $msg['seed length'], true),
   'a secret of 0, 1, 31, 33, 63, 65 or 96 bytes is refused, and a seed that is not 32 bytes');
/** $s as a printed trace writes a string: smart_str_append_escaped, a byte outside ASCII as \xNN. */
function traceEscaped(string $s): string {
  $named = ["\n" => '\\n', "\r" => '\\r', "\t" => '\\t', "\f" => '\\f', "\v" => '\\v', '\\' => '\\\\', "\e" => '\\e'];
  $out = '';
  foreach (str_split($s) as $c) $out .= $named[$c] ?? (ord($c) < 32 || ord($c) > 126 ? sprintf('\\x%02X', ord($c)) : $c);
  return $out;
}
// what a secret is made of here: each seed, its a and its prefix, as every run of 4 bytes, raw, in hex and as a
// printed trace would write it
$runs = [];
foreach ([$sdA, $sdB, $sdP] as $sd) {
  [$a, $prefix] = S('expand', $sd);
  foreach ([$sd, $a, $prefix] as $secret) for ($i = 0; $i + 4 <= 32; $i++) {
    $run = substr($secret, $i, 4);
    array_push($runs, $run, bin2hex($run), strtoupper(bin2hex($run)), traceEscaped($run));
  }
}
$texts = array_unique(array_filter(array_merge(...array_values($msg)), 'is_string'));
$leaks = [];
foreach ($texts as $text) {
  foreach ($runs as $run) if (str_contains($text, $run)) $leaks[] = $text;
  if (!preg_match('/^[ -~]+$/', $text)) $leaks[] = $text;
}
ok($leaks === [] && count(array_unique($msg['secret length'])) === 1 && count(array_unique($msg['seed length'])) === 1,
   sprintf('the %d messages are fixed text: the same for every seed, printable, with no run of 4 bytes of a seed, a scalar or a prefix in them', count($texts)));
/** Every string the arguments of a trace hold, at any depth, counting each SensitiveParameterValue in $hidden. */
function traceStrings(array $args, int &$hidden): array {
  $out = [];
  foreach ($args as $v) {
    if (is_array($v)) array_push($out, ...traceStrings($v, $hidden));
    elseif ($v instanceof SensitiveParameterValue) $hidden++;
    elseif (is_object($v)) $out[] = print_r($v, true);
    elseif (is_scalar($v)) $out[] = (string)$v;
  }
  return $out;
}
$hidden = 0; $frames = 0; $inTrace = [];
foreach ($caught as [$what, $e]) {
  if ($e === null) continue;
  $hay = [(string)$e];
  foreach ($e->getTrace() as $f) { $frames++; array_push($hay, ...traceStrings($f['args'] ?? [], $hidden)); }
  foreach ($hay as $h) foreach ($runs as $run) if (str_contains($h, $run)) { $inTrace[] = $what; break 2; }
}
$traced = sprintf('%d refusals, traced with every argument kept and each string whole: %d arguments in their %d frames are a SensitiveParameterValue; a run of 4 bytes of a seed, a or the prefix in an argument or the printed exception: %s',
                  count($caught), $hidden, $frames, $inTrace ? 'found, for ' . implode(', ', array_unique($inTrace)) : 'none');
if (PHP_VERSION_ID < 80200 && $ignoreArgs === '1')
  echo "  - PHP " . PHP_VERSION . " has no #[\\SensitiveParameter], and this host's zend.exception_ignore_args = 1 keeps arguments out of every trace. Not counted as passed:\n    $traced\n";
else ok($inTrace === [] && $hidden >= count($caught), $traced);
if ($oracle && extension_loaded('gmp')) {
  // libsodium signs with the public half it is given. Two signatures of one message under two halves share R, and
  // a = (S1 − S2) / (h1 − h2) mod L. Only the verdict is printed: the scalar is a test seed's, never shown.
  $m = 'one message';
  $s1 = sodium_crypto_sign_detached($m, $sdA . $pubA);
  $s2 = sodium_crypto_sign_detached($m, $sdA . $pubB);
  $gl = gmp_init(L_HEX, 16);
  $num = fn(string $le): GMP => gmp_import(strrev($le));
  $h1 = $num(hash('sha512', substr($s1, 0, 32) . $pubA . $m, true)); $h2 = $num(hash('sha512', substr($s2, 0, 32) . $pubB . $m, true));
  $got = gmp_mod(gmp_mul(gmp_sub($num(substr($s1, 32)), $num(substr($s2, 32))), gmp_invert(gmp_mod(gmp_sub($h1, $h2), $gl), $gl)), $gl);
  [$a] = S('expand', $sdA);
  ok(substr($s1, 0, 32) === substr($s2, 0, 32) && gmp_cmp($got, gmp_mod($num($a), $gl)) === 0,
     'why: libsodium signs under a public half that is not the seed\'s, and two such signatures of one message give the secret scalar away');
} else {
  echo "  - the demonstration of why is skipped: it needs ext/sodium " . ORACLE_VERSION . " and gmp. Never counted as passed.\n";
}

// ── 4. the layers ────────────────────────────────────────────────────────────────────────────────────
echo "\n── layers: [k]B, the digits, the moves, the scalars and the table ──\n";
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
$k32 = fn(string $le): string => substr(str_pad($le, 32, "\0"), 0, 32);
$Lm1 = $L; $Lm1[0] = chr(ord($L[0]) - 1);
$scal = ['0' => str_repeat("\0", 32), '1' => $k32("\x01"), '2' => $k32("\x02"), '7' => $k32("\x07"), '8' => $k32("\x08"), '9' => $k32("\x09"),
         '15' => $k32("\x0f"), '16' => $k32("\x10"), 'L - 1' => $Lm1, 'L' => $L, 'L + 1' => $k32(le_add($L, "\x01")), '8L' => $k32(le_mul($L, "\x08")),
         '7L, the largest multiple below 2^255' => $k32(le_mul($L, "\x07")), '2^252' => str_repeat("\0", 31) . "\x10", '2^253' => str_repeat("\0", 31) . "\x20",
         '2^254, the smallest clamped scalar' => str_repeat("\0", 31) . "\x40",
         '2^255 − 8, the largest clamped scalar' => "\xf8" . str_repeat("\xff", 30) . "\x7f", '2^255 − 1' => str_repeat("\xff", 31) . "\x7f",
         'every nibble 8' => str_repeat("\x88", 31) . "\x08", 'every nibble 7' => str_repeat("\x77", 32), 'every nibble 15' => str_repeat("\xff", 31) . "\x0f",
         'nibbles 8 and 0' => str_repeat("\x08", 32), 'nibbles 0 and 8' => str_repeat("\x80", 31) . "\x00"];
for ($i = 0; $i < 300; $i++) { $r = $rnd("k $i"); $r[31] = chr(ord($r[31]) & 0x7f); $scal["random $i"] = $r; }
$bad = []; $dbad = [];
foreach ($scal as $what => $k) {
  if (enc(S('mulBase', $k)) !== baseVartime($k)) $bad[] = $what;
  // the digits: each from −8 to 8, and Σ e[i]·16^i is k, worked back to nibbles here
  $e = S('radix16', $k); $carry = 0; $nib = '';
  $inRange = count($e) === 64 && min($e) >= -8 && max($e) <= 8;
  for ($i = 0; $i < 64; $i++) { $v = $e[$i] + $carry; $carry = $v >> 4; $nib .= dechex($v & 15); }
  $want = ''; foreach (str_split(bin2hex($k), 2) as $byte) $want .= $byte[1] . $byte[0];
  if (!$inRange || $carry !== 0 || $nib !== $want) $dbad[] = $what;
}
ok($bad === [], sprintf("[k]B is ed25519.php's variable-time [k]B for %d scalars: 0, 1, L − 1, L, 8L, 2^254, 2^255 − 8, 2^255 − 1, every nibble 8 and more%s",
   count($scal), $bad ? ': wrong for ' . implode(', ', array_slice($bad, 0, 5)) : ''));
ok($dbad === [], sprintf('the digits of the same %d: 64 of them, each from −8 to 8, summing to the scalar%s', count($scal), $dbad ? ': wrong for ' . implode(', ', array_slice($dbad, 0, 5)) : ''));
// the moves, and the selection of every row for every digit
$base = (new ReflectionClassConstant(Ed25519Sign::class, 'BASE'))->getValue();
$p0 = (new ReflectionClassConstant(Ed25519Sign::class, 'PRECOMP_0'))->getValue();
$u = [[1, -2, 3, -4, 5, -6, 7, -8, 9, -10], [11, 12, 13, 14, 15, 16, 17, 18, 19, 20], [-(1 << 26), 1 << 25, 0, 0, 0, 0, 0, 0, 0, -1]];
$moves = S('cmov', $p0, $u, 0) === $p0 && S('cmov', $p0, $u, -1) === $u && S('cmov', $u, $p0, -1) === $p0;
$sel = 0;
for ($pos = 0; $pos < 32; $pos++) for ($d = -8; $d <= 8; $d++) {
  $t = $d === 0 ? $p0 : $base[$pos][abs($d) - 1];
  $want = $d < 0 ? [$t[1], $t[0], E('neg', $t[2])] : $t;
  if (S('select', $pos, $d) === $want) $sel++;
}
ok($moves && $sel === 32 * 17, "the conditional move gives t for a zero mask and u for all ones; select() reads the right entry for each of the 32 rows and 17 digits, negated below 0 ($sel of 544)");
// (h·a + r) mod L
if (!extension_loaded('gmp')) {
  echo "  - (h·a + r) mod L against gmp is skipped: this PHP has not loaded it. Never counted as passed.\n";
} else {
  $gl = gmp_init(L_HEX, 16);
  $g = fn(string $le): GMP => gmp_import(strrev($le) === '' ? "\0" : strrev($le));
  $le = fn(GMP $v): string => str_pad(strrev(gmp_sign($v) === 0 ? '' : gmp_export($v)), 32, "\0");
  $edge = [str_repeat("\0", 32), $k32("\x01"), $Lm1, $L, str_repeat("\xff", 31) . "\x7f", "\xf8" . str_repeat("\xff", 30) . "\x7f", str_repeat("\xff", 32)];
  $sbad = 0; $sn = 0;
  foreach ($edge as $x) foreach ($edge as $y) foreach ([$edge[0], $edge[2], $edge[4]] as $z) {
    $sn++;
    if (S('scMulAdd', $x, $y, $z) !== $le(gmp_mod(gmp_add(gmp_mul($g($x), $g($y)), $g($z)), $gl))) $sbad++;
  }
  for ($i = 0; $i < 500; $i++) {
    [$x, $y, $z] = [$rnd("h $i"), $rnd("a $i"), $rnd("r $i")];
    $sn++;
    if (S('scMulAdd', $x, $y, $z) !== $le(gmp_mod(gmp_add(gmp_mul($g($x), $g($y)), $g($z)), $gl))) $sbad++;
  }
  ok($sbad === 0, "(h·a + r) mod L for $sn triples: each of h, a and r 0, 1, L − 1, L, 2^255 − 1, the largest clamped scalar and 2^256 − 1, and random ($sbad wrong)");
}
// BASE rebuilt from B, and its odd multiples against B_ODD, which ed25519.php holds and verify-ed25519.php rebuilds
$rebuilt = rebuildBase();
$diff = [];
for ($i = 0; $i < 32; $i++) for ($j = 0; $j < 8; $j++) if (($base[$i][$j] ?? null) !== $rebuilt[$i][$j]) $diff[] = ($j + 1) . "·256^$i·B";
$odd = (new ReflectionClassConstant(Ed25519::class, 'B_ODD'))->getValue();
$oddOk = true;
foreach ([0, 2, 4, 6] as $j) {
  [$x, $y] = [E('fe', strrev(hex2bin($odd[$j >> 1][0]))), E('fe', strrev(hex2bin($odd[$j >> 1][1])))];
  if ([canon(E('add', $y, $x)), canon(E('sub', $y, $x))] !== [$base[0][$j][0], $base[0][$j][1]]) $oddOk = false;
}
ok(count($base) === 32 && $diff === [] && enc(pt(hex2bin(B_HEX))) === hex2bin(B_HEX),
   sprintf('BASE rebuilt from B: all 256 entries match%s', $diff ? '; not ' . implode(', ', array_slice($diff, 0, 5)) : ''));
ok($oddOk, "BASE's B, 3B, 5B and 7B are ed25519.php's B_ODD, which is stored apart from it");

// ── 5. the shape ─────────────────────────────────────────────────────────────────────────────────────
echo "\n── shape: what the secret path is made of, and its timing ──\n";
/** A method's body as tokens, from its opening brace: no whitespace or comments, and \ord as ord. */
function bodyTokens(ReflectionMethod $m): array {
  $lines = file($m->getFileName());
  $src = implode('', array_slice($lines, $m->getStartLine() - 1, $m->getEndLine() - $m->getStartLine() + 1));
  $t = array_slice(token_get_all("<?php\n" . $src), 1);
  for ($i = 0; $i < count($t) && $t[$i] !== '{'; $i++);
  $out = [];
  foreach (array_slice($t, $i) as $x) {
    if (is_array($x) && in_array($x[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) continue;
    if (is_array($x) && in_array($x[0], [T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED, T_NAME_RELATIVE], true)) $x = [T_STRING, ltrim($x[1], '\\'), $x[2]];
    $out[] = $x;
  }
  return $out;
}
function tx(mixed $t): string { return is_array($t) ? $t[1] : (string)$t; }
function tid(mixed $t): ?int { return is_array($t) ? $t[0] : null; }
/** The index of the bracket that closes the one at $i, or that opens the one at $i when it is a closing one. */
function partner(array $t, int $i): int {
  $pairs = ['(' => ')', '[' => ']', '{' => '}'];
  $open = $t[$i]; $step = 1;
  if (!isset($pairs[$open])) { $step = -1; $open = array_search($open, $pairs, true); }
  $close = $pairs[$open]; $d = 0;
  for ($j = $i; $j >= 0 && $j < count($t); $j += $step) {
    if ($t[$j] === ($step > 0 ? $open : $close)) $d++;
    elseif ($t[$j] === ($step > 0 ? $close : $open) && --$d === 0) return $j;
  }
  return $step > 0 ? count($t) - 1 : 0;
}
/** The arguments of the call whose ( is at $i, each as its tokens. */
function argsOf(array $t, int $i): array {
  $end = partner($t, $i); $out = []; $cur = []; $d = 0;
  for ($j = $i + 1; $j < $end; $j++) {
    if (in_array($t[$j], ['(', '[', '{'], true)) $d++; elseif (in_array($t[$j], [')', ']', '}'], true)) $d--;
    if ($t[$j] === ',' && $d === 0) { $out[] = $cur; $cur = []; } else $cur[] = $t[$j];
  }
  if ($cur !== [] || $out !== []) $out[] = $cur;
  return $out;
}
/** The tokens from $i to the bracket that closes the one at $i + $open, as text without spaces: a call, as written. */
function callText(array $t, int $i, int $open): string {
  return implode('', array_map('tx', array_slice($t, $i, partner($t, $i + $open) - $i + 1)));
}
/**
 * The expression the operator at $i is part of, as text without spaces: out to the bracket, comma, statement end,
 * assignment or arrow on either side.
 */
function exprText(array $t, int $i, array $assign): string {
  $stop = fn($x) => in_array($x, [',', ';', '{', '}', '=', '?', ':'], true)
                 || in_array(tid($x), array_merge([T_RETURN, T_DOUBLE_ARROW, T_ECHO, T_PRINT], $assign), true);
  for ($a = $i - 1, $d = 0; $a >= 0; $a--) {
    if (in_array($t[$a], [')', ']'], true)) $d++;
    elseif (in_array($t[$a], ['(', '['], true)) { if ($d-- === 0) break; }
    elseif ($d === 0 && $stop($t[$a])) break;
  }
  for ($b = $i + 1, $d = 0; $b < count($t); $b++) {
    if (in_array($t[$b], ['(', '['], true)) $d++;
    elseif (in_array($t[$b], [')', ']'], true)) { if ($d-- === 0) break; }
    elseif ($d === 0 && $stop($t[$b])) break;
  }
  return implode('', array_map('tx', array_slice($t, $a + 1, $b - $a - 1)));
}
/** True when every token is a number, one of the variables in $vars, or arithmetic. */
function numeric(array $tokens, array $vars, bool $strings = false): bool {
  foreach ($tokens as $t) {
    $ok = in_array(tid($t), [T_LNUMBER, T_SL, T_SR], true) || in_array($t, ['+', '-', '*', '(', ')'], true)
       || (tid($t) === T_VARIABLE && in_array($t[1], $vars, true))
       || ($strings && (tid($t) === T_CONSTANT_ENCAPSED_STRING || in_array(strtolower(tx($t)), ['true', 'false'], true)));
    if (!$ok) return false;
  }
  return $tokens !== [];
}
/** True when $v, and everything $depth levels down in it, is an array. */
function arraysDown(mixed $v, int $depth): bool {
  if (!is_array($v)) return false;
  if ($depth === 0) return true;
  foreach ($v as $x) if (!arraysDown($x, $depth - 1)) return false;
  return true;
}

// the roots: the public methods Ed25519Sign declares. The walk follows every self:: call, each in its own class.
$cls = new ReflectionClass(Ed25519Sign::class);
$roots = [];
foreach ($cls->getMethods(ReflectionMethod::IS_PUBLIC) as $m) if ($m->getDeclaringClass()->getName() === Ed25519Sign::class) $roots[] = $m;
$fns = []; $sites = [];                                  // Class::name => [method, tokens]; callee => [[caller, index of its (]]
$todo = $roots;
while ($todo) {
  $m = array_pop($todo);
  $key = $m->getDeclaringClass()->getName() . '::' . $m->getName();
  if (isset($fns[$key])) continue;
  $bt = bodyTokens($m);
  $fns[$key] = [$m, $bt];
  foreach ($bt as $i => $t) if (tx($t) === 'self' && tx($bt[$i + 1] ?? '') === '::' && tid($bt[$i + 2] ?? '') === T_STRING && ($bt[$i + 3] ?? '') === '(') {
    $callee = new ReflectionMethod($m->getDeclaringClass()->getName(), tx($bt[$i + 2]));
    $sites[$callee->getDeclaringClass()->getName() . '::' . $callee->getName()][] = [$key, $i + 3];
    $todo[] = $callee;
  }
}
// May branch, into a throw only, on a length, PHP_INT_SIZE or hash_equals(): the two calls and host().
$GUARDS = array_merge(array_map(fn($m) => Ed25519Sign::class . '::' . $m->getName(), $roots), [Ed25519Sign::class . '::host']);
// May read bytes with ord(), chr() and offsets: each called only from these functions, by exactly these calls (written
// here without spaces). encode() is given [a]B or [r]B, whose encodings are the public key and R; isNegative() the x
// of the point encode() writes, which that encoding determines.
$BYTES = ['Ed25519::encode' => [Ed25519Sign::class . '::sign' => ['self::encode(self::mulBase($a))', 'self::encode(self::mulBase($r))'],
                                Ed25519Sign::class . '::publicKey' => ['self::encode(self::mulBase($a))']],
          'Ed25519::isNegative' => ['Ed25519::encode' => ['self::isNegative(self::mul($p[0],$zi))']]];
// The only substr() calls and concatenations on the path, each exactly as the honest code makes it: substr() of the
// secret into the seed and the public half, of the hash into a and the prefix, and R ‖ A and R ‖ S, all strings.
$SUBSTR = [Ed25519Sign::class . '::sign' => ['substr($secret,0,32)', 'substr($secret,32)'], Ed25519Sign::class . '::expand' => ['substr($h,0,32)', 'substr($h,32)']];
$CONCAT = [Ed25519Sign::class . '::sign' => ['$R.$A', '$R.self::scMulAdd($h,$a,$r)']];
// The parameters that hold public values, and so need no #[\SensitiveParameter]: the message, a row of BASE, a flag
// and a count. Every other parameter on the path must be marked.
$PUBLIC = [Ed25519Sign::class . '::sign' => ['$msg'], Ed25519Sign::class . '::select' => ['$pos'], 'Ed25519::addPrecomp' => ['$minus'], 'Ed25519::sqMul' => ['$n']];
// The calls allowed, each with the arguments that must be numbers, strings and loop counters: a format, a length, a
// flag. The rest of the arguments are data. substr() is held to $SUBSTR, and unpack()'s offset to a number.
$CALLS = ['unpack' => [0], 'pack' => [0], 'hash' => [0, 2], 'substr' => [], 'array_fill' => [0, 1, 2]];
$GUARD_CALLS = ['strlen' => [], 'hash_init' => [0], 'hash_update' => [], 'hash_final' => [1], 'hash_equals' => []];
$BYTE_CALLS = ['ord' => [], 'chr' => []];
$BRANCH = [T_IF, T_ELSEIF, T_ELSE, T_SWITCH, T_MATCH, T_COALESCE, T_COALESCE_EQUAL, T_BOOLEAN_AND, T_BOOLEAN_OR, T_LOGICAL_AND,
           T_LOGICAL_OR, T_LOGICAL_XOR, T_WHILE, T_DO, T_FOREACH, T_BREAK, T_CONTINUE, T_GOTO, T_MOD_EQUAL, T_DIV_EQUAL, T_POW,
           T_POW_EQUAL, T_THROW, T_TRY, T_CATCH, T_FINALLY, T_YIELD, T_YIELD_FROM, T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE,
           T_REQUIRE_ONCE, T_EXIT];
$COMPARE = [T_IS_EQUAL, T_IS_NOT_EQUAL, T_IS_IDENTICAL, T_IS_NOT_IDENTICAL, T_IS_SMALLER_OR_EQUAL, T_IS_GREATER_OR_EQUAL, T_SPACESHIP];
$ASSIGN = [T_PLUS_EQUAL, T_MINUS_EQUAL, T_MUL_EQUAL, T_DIV_EQUAL, T_CONCAT_EQUAL, T_MOD_EQUAL, T_AND_EQUAL, T_OR_EQUAL, T_XOR_EQUAL,
           T_SL_EQUAL, T_SR_EQUAL, T_POW_EQUAL, T_COALESCE_EQUAL, T_INC, T_DEC];

// first, each function's loop counters, its closures and the for headers
$info = [];
foreach ($fns as $key => [$m, $bt]) {
  $headers = []; $counters = []; $closures = [];
  foreach ($bt as $i => $t) {
    if (tid($t) === T_FOR) { $c = partner($bt, $i + 1); $headers[] = [$i, $c]; if (tid($bt[$i + 2] ?? null) === T_VARIABLE) $counters[] = $bt[$i + 2][1]; }
    // $name = fn (...) => ...; or $name = function (...) use (...) { ... }: its parameters, and where its body is
    if (tid($t) === T_VARIABLE && ($bt[$i + 1] ?? '') === '=' && in_array(tid($bt[$i + 2] ?? null), [T_FN, T_FUNCTION], true) && ($bt[$i + 3] ?? '') === '(') {
      $pe = partner($bt, $i + 3); $ps = [];
      for ($j = $i + 4; $j < $pe; $j++) if (tid($bt[$j]) === T_VARIABLE) $ps[] = $bt[$j][1];
      $arrow = null;
      if (tid($bt[$i + 2]) === T_FN) {
        for ($j = $pe; $j < count($bt) && tid($bt[$j]) !== T_DOUBLE_ARROW; $j++);
        for ($k = $j, $d = 0; $k < count($bt); $k++) {
          if (in_array($bt[$k], ['(', '[', '{'], true)) $d++; elseif (in_array($bt[$k], [')', ']', '}'], true)) $d--;
          if ($d < 0 || ($d === 0 && in_array($bt[$k], [';', ','], true))) break;
        }
        $body = [$j, $k]; $arrow = $j;
      } else {
        for ($j = $pe; $j < count($bt) && $bt[$j] !== '{'; $j++);
        $body = [$j, partner($bt, $j)];
      }
      // its parameters: `int $x, int $y`, and nothing else
      $plist = array_map('tx', array_slice($bt, $i + 4, $pe - $i - 4));
      $intParams = count($plist) % 3 === 2;
      foreach ($plist as $k => $x) $intParams = $intParams && match ($k % 3) { 0 => $x === 'int', 1 => in_array($x, $ps, true), 2 => $x === ',' };
      $closures[$t[1]] = ['params' => $ps, 'list' => [$i + 3, $pe], 'body' => $body, 'at' => $i + 2, 'arrow' => $arrow, 'ints' => $intParams || $plist === []];
    }
  }
  $params = array_map(fn($p) => '$' . $p->getName(), $m->getParameters());
  $info[$key] = ['headers' => $headers, 'counters' => array_values(array_unique($counters)), 'closures' => $closures, 'params' => $params];
}
$within = fn(int $i, array $ranges): bool => array_filter($ranges, fn($r) => $i >= $r[0] && $i <= $r[1]) !== [];
$found = [];
// A loop counter is a counter in the whole function, so it may not share a name with a parameter.
foreach ($info as $key => $in) foreach (array_intersect($in['counters'], $in['params']) as $v)
  $found[] = "$key: the parameter $v is also a loop counter";
// A parameter used as an index or a loop bound: every call on the path must pass it as numbers and loop counters.
$traced = [];                                            // "key $param" => what is wrong, or null
$trace = function (string $key, string $param) use (&$traced, $fns, $sites, $info): ?string {
  if (array_key_exists("$key $param", $traced)) return $traced["$key $param"];
  $pos = array_search($param, $info[$key]['params'], true);
  $why = null;
  if ($pos === false) $why = "$param is not a parameter";
  elseif (empty($sites[$key])) $why = "$param comes from outside the path";
  else foreach ($sites[$key] as [$caller, $at]) {
    $arg = argsOf($fns[$caller][1], $at)[$pos] ?? [];
    if (!numeric($arg, $info[$caller]['counters'])) { $why = "$caller passes $param as " . implode(' ', array_map('tx', $arg)); break; }
  }
  return $traced["$key $param"] = $why;
};
$CASTS = [T_INT_CAST, T_DOUBLE_CAST, T_STRING_CAST, T_ARRAY_CAST, T_OBJECT_CAST, T_BOOL_CAST, T_UNSET_CAST];
$OTHER = [T_ECHO, T_PRINT, T_GLOBAL, T_STATIC, T_START_HEREDOC, T_OPEN_TAG_WITH_ECHO, T_INLINE_HTML, T_CLOSE_TAG,
          ...(defined('T_PIPE') ? [T_PIPE] : [])];          // T_PIPE: PHP 8.5's |>, a call the walk cannot follow
foreach ($fns as $key => [$m, $bt]) {
  ['headers' => $headers, 'counters' => $counters, 'closures' => $closures, 'params' => $params] = $info[$key];
  $guard = in_array($key, $GUARDS, true); $readsBytes = isset($BYTES[$key]);
  $calls = $CALLS + ($guard ? $GUARD_CALLS : []) + ($readsBytes ? $BYTE_CALLS : []);
  $f = function (string $what) use (&$found, $key) { $found[] = "$key: $what"; };
  $kept = $counters;                                     // what indexes, or bounds a loop: assigned nowhere
  // no reference in or out, and every parameter but the public ones marked
  if ($m->returnsReference()) $f('returns a reference');
  foreach ($m->getParameters() as $p) {
    if ($p->isPassedByReference()) $f('takes $' . $p->getName() . ' by reference');
    if ($p->getAttributes('SensitiveParameter') === [] && !in_array('$' . $p->getName(), $PUBLIC[$key] ?? [], true))
      $f('$' . $p->getName() . ' is not marked #[\SensitiveParameter]');
  }
  // the for headers: $v = N; $v < M; $v++
  $hdr = [];
  foreach ($headers as [$i, $c]) {
    $h = array_slice($bt, $i + 2, $c - $i - 2);
    $bound = function (array $x) use ($params, $key, $trace, &$kept): bool {
      if (count($x) === 1 && tid($x[0]) === T_LNUMBER) return true;
      if (count($x) === 1 && tid($x[0]) === T_VARIABLE && in_array($x[0][1], $params, true) && $trace($key, $x[0][1]) === null) { $kept[] = $x[0][1]; return true; }
      return false;
    };
    $parts = [[]]; foreach ($h as $x) { if ($x === ';') $parts[] = []; else $parts[count($parts) - 1][] = $x; }
    $v = tx($h[0] ?? '');
    $shape = count($parts) === 3 && tid($h[0] ?? null) === T_VARIABLE
          && count($parts[0]) >= 3 && tx($parts[0][0]) === $v && $parts[0][1] === '=' && $bound(array_slice($parts[0], 2))
          && count($parts[1]) >= 3 && tx($parts[1][0]) === $v && $parts[1][1] === '<' && $bound(array_slice($parts[1], 2))
          && count($parts[2]) === 2 && tx($parts[2][0]) === $v && tid($parts[2][1]) === T_INC;
    if (!$shape) $f('for (' . implode(' ', array_map('tx', $h)) . ')');
    $hdr[] = [$i, $c];
  }
  // what is an array: an array parameter, and a variable assigned only an array literal, unpack(), array_fill(), an
  // array constant or a call declared to return an array; never one that is unpacked into or added to
  $assigns = []; $spoilt = [];
  foreach ($bt as $i => $t) {
    if (tid($t) !== T_VARIABLE) continue;
    $next = $bt[$i + 1] ?? null;
    if ($next === '=') $assigns[$t[1]][] = $i + 2;
    if (in_array(tid($next), $ASSIGN, true) || in_array(tid($bt[$i - 1] ?? null), [T_INC, T_DEC], true)) $spoilt[$t[1]] = true;
  }
  $destructured = [];                                    // [start, end] of each [...] = and list(...) =
  foreach ($bt as $i => $t) {
    $prev = $bt[$i - 1] ?? null;
    if (($t === '[' && !(in_array($prev, [']', ')', '}'], true) || in_array(tid($prev), [T_VARIABLE, T_STRING, T_CONSTANT_ENCAPSED_STRING], true))) || tid($t) === T_LIST) {
      $o = $t === '[' ? $i : $i + 1; $e = partner($bt, $o);
      if (($bt[$e + 1] ?? null) === '=') {
        $destructured[] = [$o, $e];
        for ($j = $o; $j < $e; $j++) if (tid($bt[$j]) === T_VARIABLE) $spoilt[$bt[$j][1]] = true;
        // [$a, $b, ...] =, and nothing else: no key, no index, no nesting, no gap
        $inner = array_slice($bt, $o + 1, $e - $o - 1); $bare = $t === '[' && count($inner) % 2 === 1;
        foreach ($inner as $k => $x) $bare = $bare && ($k % 2 === 0 ? tid($x) === T_VARIABLE : $x === ',');
        if (!$bare) $f('destructures into ' . tx($t) . ' ' . implode(' ', array_map('tx', $inner)));
      }
    }
  }
  $rhs = function (int $at, callable $is) use ($bt): bool {  // the right side at $at is one call or literal, then ;
    $t = $bt[$at] ?? null;
    if ($t === '[') return ($bt[partner($bt, $at) + 1] ?? null) === ';' && $is('[]', null);
    if (tid($t) === T_STRING && ($bt[$at + 1] ?? null) === '(') return ($bt[partner($bt, $at + 1) + 1] ?? null) === ';' && $is($t[1] . '()', null);
    if (tx($t) === 'self' && tx($bt[$at + 1] ?? '') === '::' && tid($bt[$at + 2] ?? null) === T_STRING) {
      if (($bt[$at + 3] ?? null) === '(') return ($bt[partner($bt, $at + 3) + 1] ?? null) === ';' && $is('self::()', $bt[$at + 2][1]);
      return ($bt[$at + 3] ?? null) === ';' && $is('self::', $bt[$at + 2][1]);
    }
    return false;
  };
  $c0 = $m->getDeclaringClass();
  $isArray = fn(int $at): bool => $rhs($at, fn(string $form, ?string $name): bool => match ($form) {
    '[]' => true, 'unpack()', 'array_fill()' => true,
    'self::()' => $c0->hasMethod($name) && (string)$c0->getMethod($name)->getReturnType() === 'array',
    'self::' => $c0->hasConstant($name) && is_array($c0->getConstant($name)),
    default => false });
  $arrays = [];
  foreach ($m->getParameters() as $p) if ((string)$p->getType() === 'array') $arrays['$' . $p->getName()] = true;
  foreach ($assigns as $v => $ats) $arrays[$v] = array_filter($ats, fn($at) => !$isArray($at)) === [];
  foreach ($spoilt as $v => $_) $arrays[$v] = false;
  // a guard's if: its condition reads a length, PHP_INT_SIZE, or hash_equals() of a public key against something,
  // and it throws
  $lengths = []; $encoded = [];
  foreach ($assigns as $v => $ats) if (count($ats) === 1 && !isset($spoilt[$v])) {
    if ($rhs($ats[0], fn($form) => $form === 'strlen()')) $lengths[] = $v;
    if ($rhs($ats[0], fn($form, $name) => $form === 'self::()' && $name === 'encode')) $encoded[] = $v;
  }
  $conds = []; $throws = [];
  foreach ($bt as $i => $t) {
    if (tid($t) !== T_IF || !$guard || ($bt[$i + 1] ?? null) !== '(') continue;
    $c = partner($bt, $i + 1); $ok = tid($bt[$c + 1] ?? null) === T_THROW;
    $data = [];                                          // what strlen() and hash_equals() read: data, not branched on
    for ($j = $i + 2; $j < $c; $j++) {
      $x = $bt[$j];
      if (tx($x) === 'strlen' && ($bt[$j + 1] ?? null) === '(') $data[] = [$j + 1, partner($bt, $j + 1)];
      if (tx($x) === 'hash_equals' && ($bt[$j + 1] ?? null) === '(') {
        $args = argsOf($bt, $j + 1);
        $ok = $ok && count($args) === 2 && array_filter($args, fn($g) => count($g) === 1 && tid($g[0]) === T_VARIABLE && in_array($g[0][1], $encoded, true)) !== [];
        $data[] = [$j + 1, partner($bt, $j + 1)];
      }
      $ok = $ok && (in_array(tid($x), array_merge([T_LNUMBER, T_BOOLEAN_AND, T_BOOLEAN_OR], $COMPARE), true) || in_array($x, ['!', '(', ')', ',', '<', '>'], true)
                    || in_array(tx($x), ['strlen', 'hash_equals', 'substr', 'PHP_INT_SIZE'], true)
                    || (tid($x) === T_VARIABLE && (in_array($x[1], $lengths, true) || $within($j, $data))));
    }
    if ($ok) { $conds[] = [$i, $c]; $throws[] = $c + 1; }
  }
  foreach ($bt as $i => $t) {
    $s = tx($t); $id = tid($t); $prev = $bt[$i - 1] ?? null; $next = $bt[$i + 1] ?? null;
    $inHdr = $within($i, $hdr); $inCond = $within($i, $conds);
    // branches, loops other than for, throws; a guard's if and its throw; && and || in a guard's condition
    if ($id === T_IF && in_array($i, array_column($conds, 0), true)) {}
    elseif ($id === T_THROW && in_array($i, $throws, true)) {}
    elseif (in_array($id, [T_BOOLEAN_AND, T_BOOLEAN_OR], true) && $inCond) {}
    elseif (($id !== null && in_array($id, $BRANCH, true)) || $s === '%' || $s === '/') $f($s);
    if ($s === '?' && !($key === 'Ed25519::addPrecomp' && tx($prev) === '$minus')) $f('?');
    if (!$inHdr && !$inCond && (($id !== null && in_array($id, $COMPARE, true)) || $s === '<' || $s === '>')) $f("$s outside a for header");
    // what makes a bool of a value, as a comparison does: ! outside a guard's condition, isset, empty, instanceof
    if ((!$inCond && $s === '!') || in_array($id, [T_ISSET, T_EMPTY, T_UNSET, T_INSTANCEOF], true)) $f($s);
    // casts and strings with variables in them, whose time depends on the value; output, globals and statics
    if (in_array($id, $CASTS, true) || $s === '"' || $s === '`') $f($id === null ? 'a string with variables in it' : "the cast $s");
    if (in_array($id, $OTHER, true) || (tx($prev) === '::' && $id === T_VARIABLE)) $f($id === T_VARIABLE ? "the static property $s" : $s);
    // a variable variable, which reads or writes a variable by a name worked out at run time: $$v, ${...}
    if ($s === '$' || $id === T_DOLLAR_OPEN_CURLY_BRACES) $f('a variable variable');
    // a reference: & where no operand comes before it, so not a bitwise AND (=&, [&$v], (&$v, use (&$v), fn&)
    if ($s === '&' && !(in_array(tid($prev), [T_VARIABLE, T_LNUMBER], true) || in_array($prev, [')', ']'], true))) $f('a reference');
    // => but an arrow function's: no key in an array literal or a destructuring; list(); .= and a concatenation but
    // those in $CONCAT, since . turns an int into a string
    if ($id === T_DOUBLE_ARROW && !in_array($i, array_column($closures, 'arrow'), true)) $f('=>');
    if ($id === T_LIST) $f('list()');
    if ($id === T_CONCAT_EQUAL) $f('.=');
    if ($s === '.' && !in_array(exprText($bt, $i, $ASSIGN), $CONCAT[$key] ?? [], true)) $f('concatenates ' . exprText($bt, $i, $ASSIGN));
    // a named argument, or ... but into pack(): every argument stands where its position says
    if ($s === ':' && is_array($prev) && preg_match('/^\w+$/', $prev[1]) && in_array($bt[$i - 2] ?? null, ['(', ','], true)) $f("the named argument {$prev[1]}:");
    if ($id === T_ELLIPSIS && !($prev === ',' && tid($bt[$i - 2] ?? null) === T_CONSTANT_ENCAPSED_STRING && ($bt[$i - 3] ?? null) === '(' && tx($bt[$i - 4] ?? '') === 'pack'))
      $f('...');
    // a closure but `$name = fn (int $x, ...)` or `$name = function (int $x, ...)`
    if (in_array($id, [T_FN, T_FUNCTION], true) && !in_array($i, array_column($closures, 'at'), true)) $f('a closure not assigned to a variable');
    // no float: no float literal, no integer literal of 2^32 or more, no left shift by 32 or more
    if ($id === T_DNUMBER) $f("the float $s");
    if ($id === T_LNUMBER && intval(str_replace('_', '', $s), 0) >= 1 << 32) $f("the number $s, of 2^32 or more");
    if (in_array($id, [T_SL, T_SL_EQUAL], true) && tid($next) === T_LNUMBER && intval($next[1], 0) >= 32) $f("$s {$next[1]}");
    // a name that is not a call or a member: true, false, a guard's PHP_INT_SIZE, a closure's int, the class's own
    // array and string constants, and self:: alone
    if ($id === T_STRING && $next !== '(') {
      // a type in a closure's parameter list, or its return type: `fn (int $i): int`
      $closureType = array_filter($closures, fn($cl) => ($i > $cl['list'][0] && $i < $cl['list'][1]) || $i === $cl['list'][1] + 2) !== [];
      if (tx($next) === '::') { if ($s !== 'self') $f("$s::"); }
      elseif (tx($prev) === '::') { if (!$c0->hasConstant($s) || !(is_array($c0->getConstant($s)) || is_string($c0->getConstant($s)))) $f("self::$s, not an array or string constant"); }
      elseif ($closureType) { if ($s !== 'int') $f("a closure's $s"); }
      elseif (!in_array($s, ['true', 'false'], true) && !($guard && $s === 'PHP_INT_SIZE') && tid($prev) !== T_NEW) $f("the constant $s");
    }
    if ($id === T_NEW && !($guard && in_array($i - 1, $throws, true) && in_array(tx($next), ['InvalidArgumentException', 'RuntimeException'], true)))
      $f('new ' . tx($next) . ', but an InvalidArgumentException or RuntimeException in a guard\'s throw');
    // shifts by a number
    if (in_array($id, [T_SL, T_SR, T_SL_EQUAL, T_SR_EQUAL], true) && tid($next) !== T_LNUMBER) $f("$s " . tx($next));
    // calls
    if ($id === T_STRING && $next === '(' && !in_array(tid($prev), [T_FUNCTION, T_FN], true)) {
      if (tx($prev) === '::') { if (tx($bt[$i - 2] ?? '') !== 'self') $f('calls ' . tx($bt[$i - 2] ?? '') . "::$s()"); }
      elseif (in_array(tid($prev), [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true)) $f("calls ->$s()");
      elseif (tid($prev) === T_NEW) { if (!($guard && in_array($i - 2, $throws, true) && in_array($s, ['InvalidArgumentException', 'RuntimeException'], true))) $f("new $s"); }
      elseif (!isset($calls[$s])) $f("calls $s()");
      elseif ($s === 'substr') {
        // only the calls in $SUBSTR: a one-byte string is a load from a table of them, indexed by the byte
        if (!in_array(callText($bt, $i, 1), $SUBSTR[$key] ?? [], true)) $f(callText($bt, $i, 1));
      }
      elseif ($s === 'strlen') {
        // of a parameter, which nothing here assigns: the length of an input is public
        $g = argsOf($bt, $i + 1); $v = tx($g[0][0] ?? '');
        if (!(count($g) === 1 && count($g[0]) === 1 && in_array($v, $params, true) && !isset($assigns[$v]) && !isset($spoilt[$v]))) $f(callText($bt, $i, 1) . ', not of a parameter');
      }
      elseif (in_array($s, ['pack', 'unpack'], true)) {
        // integers only, and pack() never one byte, for the same reason; unpack()'s offset a number
        $g = argsOf($bt, $i + 1); $fmt = $g[0] ?? [];
        $code = count($fmt) === 1 && tid($fmt[0]) === T_CONSTANT_ENCAPSED_STRING ? substr($fmt[0][1], 1, -1) : '';
        if (!preg_match($s === 'pack' ? '/^[vV]([2-9]|[1-9]\d+)$/' : '/^[CvV](\d+|\*)$/', $code)) $f("$s() given the format " . implode(' ', array_map('tx', $fmt)));
        if ($s === 'unpack' && (count($g) < 2 || count($g) > 3 || (isset($g[2]) && !(count($g[2]) === 1 && tid($g[2][0]) === T_LNUMBER))))
          $f(callText($bt, $i, 1) . ': not a format, the data and a number offset or none');
      }
      else foreach ($calls[$s] as $k) if (isset(argsOf($bt, $i + 1)[$k]) && !numeric(argsOf($bt, $i + 1)[$k], $counters, true)) $f("$s() given a variable format, offset or length");
    }
    if ($id === T_VARIABLE && $next === '(' && !isset($closures[$s])) $f("calls $s()");
    if (($s === ']' || ($s === ')' && !in_array(tid($bt[partner($bt, $i) - 1] ?? null), [T_IF, T_ELSEIF, T_FOR, T_WHILE, T_SWITCH], true))) && $next === '(')
      $f('calls what an expression gives');
    // an index
    $isIndex = $s === '[' && (in_array($prev, [']', ')', '}'], true) || in_array(tid($prev), [T_VARIABLE, T_STRING, T_CONSTANT_ENCAPSED_STRING], true));
    if (!$isIndex) continue;
    $c = partner($bt, $i);
    $content = array_slice($bt, $i + 1, $c - $i - 1);
    $vars = $counters;                                   // and a closure's parameter in its body, or a traced parameter
    foreach ($content as $x) if (tid($x) === T_VARIABLE && !in_array($x[1], $vars, true)) {
      $inClosure = array_filter($closures, fn($cl) => in_array($x[1], $cl['params'], true) && $i >= $cl['body'][0] && $i <= $cl['body'][1]) !== [];
      if ($inClosure) { $vars[] = $x[1]; $kept[] = $x[1]; }
      elseif (in_array($x[1], $params, true)) { $why = $trace($key, $x[1]); if ($why === null) { $vars[] = $x[1]; $kept[] = $x[1]; } else $f($why); }
    }
    if ($content !== [] && !numeric($content, $vars)) $f('indexes by ' . implode(' ', array_map('tx', $content)));
    if ($readsBytes) continue;
    if (tid($prev) === T_VARIABLE) { if (!($arrays[$prev[1]] ?? false)) $f("indexes {$prev[1]}, not known to be an array: a string offset?"); }
    elseif (tid($prev) === T_STRING && tx($bt[$i - 2] ?? '') === '::' && tx($bt[$i - 3] ?? '') === 'self') {
      if (!$c0->hasConstant($prev[1]) || !is_array($c0->getConstant($prev[1]))) $f("indexes {$prev[1]}, not an array constant");
    } elseif ($prev === ']') {
      $depth = 0; $j = $i - 1;
      while (($bt[$j] ?? null) === ']') { $j = partner($bt, $j) - 1; $depth++; }
      $root = $bt[$j] ?? null;
      if (!(tid($root) === T_STRING && tx($bt[$j - 1] ?? '') === '::' && tx($bt[$j - 2] ?? '') === 'self' && $c0->hasConstant($root[1]) && arraysDown($c0->getConstant($root[1]), $depth)))
        $f('indexes an index of ' . tx($root) . ', not an array constant');
    } else $f('indexes ' . tx($prev) . ', not an array of this class');
  }
  // closure parameters: each declared int, and each call of the closure passes numbers and loop counters
  foreach ($closures as $cl => $c) if (!$c['ints']) $f("$cl takes a parameter that is not `int \$x`");
  foreach ($closures as $cl => $_) foreach ($bt as $i => $t)
    if (tid($t) === T_VARIABLE && $t[1] === $cl && ($bt[$i + 1] ?? null) === '(')
      foreach (argsOf($bt, $i + 1) as $arg) if (!numeric($arg, $counters)) $f("calls $cl with " . implode(' ', array_map('tx', $arg)));
  // what indexes or bounds a loop is assigned nowhere: a counter only in its header, a closure's parameter only by its
  // calls, a parameter only by its callers
  $lists = array_column($closures, 'list');
  foreach ($bt as $i => $t)
    if (tid($t) === T_VARIABLE && in_array($t[1], $kept, true) && !$within($i, $hdr) && !$within($i, $lists)) {
      $next = $bt[$i + 1] ?? null; $prev = $bt[$i - 1] ?? null;
      if ($next === '=' || in_array(tid($next), $ASSIGN, true) || in_array(tid($prev), [T_INC, T_DEC], true) || $within($i, $destructured))
        $f("assigns {$t[1]}, which indexes or counts a loop");
    }
}
// the flag, and who may read bytes
foreach ($sites['Ed25519::addPrecomp'] ?? [] as [$caller, $at]) if (array_map('tx', argsOf($fns[$caller][1], $at)[2] ?? []) !== ['false']) $found[] = "$caller: addPrecomp() not given false";
foreach ($BYTES as $key => $callers) foreach ($sites[$key] ?? [] as [$caller, $at]) {
  $call = callText($fns[$caller][1], $at - 3, 3);
  if (!in_array($call, $callers[$caller] ?? [], true)) $found[] = "$caller: $call, where $key may be called only as " . implode(', ', array_unique(array_merge(...array_values($callers))));
}
// both files declare strict_types=1, without which an int passed to hash() or substr() becomes a string unseen
foreach (array_unique(array_map(fn($x) => $x[0]->getFileName(), $fns)) as $file) {
  $code = implode('', array_map('tx', array_filter(token_get_all(file_get_contents($file)), fn($x) => !in_array(tid($x), [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true))));
  if (!str_contains($code, 'declare(strict_types=1);')) $found[] = basename($file) . ' does not declare strict_types=1';
}
$names = array_keys($fns); sort($names);
echo '  - the secret path: ', implode(', ', $names), "\n";
$must = ['Ed25519Sign::sign', 'Ed25519Sign::publicKey', 'Ed25519Sign::mulBase', 'Ed25519Sign::select', 'Ed25519Sign::cmov', 'Ed25519Sign::radix16',
         'Ed25519Sign::scMulAdd', 'Ed25519::scReduce', 'Ed25519::encode', 'Ed25519::mul', 'Ed25519::carry'];
ok($found === [] && array_diff($must, $names) === [],
   sprintf('%d functions, from %s and all they reach: no branch but a guard\'s throw, no loop but `for ($v = N; $v < M; $v++)`, no counter assigned, no index but by counters and numbers into a known array, no ord(), chr() or offset outside encode() and isNegative(), no reference or variable variable, no concatenation, substr() or encode() but the listed ones, no shift but by a number, no float, no other call, every parameter marked but the public four%s',
           count($fns), implode(' and ', array_map(fn($m) => $m->getName() . '()', $roots)), $found ? ': ' . implode('; ', array_slice(array_unique($found), 0, 8)) : ''));
ok(array_intersect(['Ed25519::mulAdd', 'Ed25519::digits', 'Ed25519::decodeNegated'], $names) === [],
   "the secret path never reaches ed25519.php's variable-time mulAdd, digits or decodeNegated");
// [k]B timed for k whose digits are all 0, all but one 0, mixed, and all ±8: the same work for each. Median of each,
// over rounds in which each class is timed once, the order turning each round.
$timed = ['every digit 0 (k = 0)' => str_repeat("\0", 32), 'one digit not 0 (2^254)' => str_repeat("\0", 31) . "\x40",
          'random' => $scal['random 0'], 'every digit ±8' => "\x78" . str_repeat("\x77", 31)];
$digits = array_map(fn($k) => S('radix16', $k), $timed);
$count = fn(array $e, callable $c): int => count(array_filter($e, $c));
ok($count($digits['every digit 0 (k = 0)'], fn($d) => $d === 0) === 64 && $count($digits['one digit not 0 (2^254)'], fn($d) => $d === 0) === 63
   && $count($digits['every digit ±8'], fn($d) => abs($d) === 8) === 64 && $count($digits['random'], fn($d) => $d === 0) < 16,
   sprintf('the timed scalars have the digits they are named for: 64 zeros, 63, %d of 64 for random, and all 64 of the last ±8',
           $count($digits['random'], fn($d) => $d === 0)));
foreach ($timed as $k) S('mulBase', $k);
$ROUNDS = 41;
$classes = array_keys($timed); $ns = array_fill_keys($classes, []);
for ($round = 0; $round < $ROUNDS; $round++) for ($j = 0; $j < count($classes); $j++) {
  $what = $classes[($round + $j) % count($classes)];
  $t = hrtime(true); S('mulBase', $timed[$what]); $ns[$what][] = hrtime(true) - $t;
}
$median = array_map(function (array $v): float { sort($v); return $v[intdiv(count($v), 2)]; }, $ns);
$ratio = max($median) / min($median);
ok($ratio < TIMING_BOUND, sprintf('[k]B takes the same time whatever the digits: the slowest median over the fastest is %.3f, below %.2f (%s)', $ratio, TIMING_BOUND,
   implode(', ', array_map(fn($w, $t) => sprintf('%s %.3f ms', $w, $t / 1e6), array_keys($median), $median))));

// ── timings, beside libsodium's ──────────────────────────────────────────────────────────────────────
$time = function (callable $f, int $n): float { $t = hrtime(true); for ($i = 0; $i < $n; $i++) $f(); return (hrtime(true) - $t) / $n / 1e6; };
$sd = $rnd('timing'); $short = 'a message'; $long = $bytes('timing long', 65536);
$sk = $sd . Ed25519Sign::publicKey($sd);
$rows = [['publicKey', $time(fn() => Ed25519Sign::publicKey($sd), 40)],
         ['sign, 9 bytes', $time(fn() => Ed25519Sign::sign($short, $sd), 40)],
         ['sign, 64 KiB', $time(fn() => Ed25519Sign::sign($long, $sd), 20)],
         ['sign, 9 bytes, 64-byte secret key', $time(fn() => Ed25519Sign::sign($short, $sk), 40)]];
foreach ($rows as $i => [$what, $ms]) {
  $line = sprintf('  - %-34s %.2f ms by ed25519-sign.php', $what, $ms);
  if ($sodium) {
    $kp = sodium_crypto_sign_seed_keypair($sd); $osk = sodium_crypto_sign_secretkey($kp);
    $o = match ($i) { 0 => $time(fn() => sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($sd)), 2000),
                      1, 3 => $time(fn() => sodium_crypto_sign_detached($short, $osk), 2000),
                      2 => $time(fn() => sodium_crypto_sign_detached($long, $osk), 500) };
    $line .= sprintf(', %.3f ms by libsodium', $o);
  }
  echo "$line\n";
}

printf("\n%s  %d passed, %d failed   [Ed25519 signing · against libsodium %s]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail, ORACLE_VERSION);
exit($fail === 0 ? 0 : 1);
