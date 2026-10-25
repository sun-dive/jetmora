<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── secp256k1 ECDSA VERIFICATION — no dependencies ───────────────────────────────────────────────────
//
// ⚠ SHARED ON PURPOSE, unlike the interpreters. §10.9 isolates the SETS because an opcode fix for `SV`
// must not be able to reach `BT` — they disagree by design. **A curve does not disagree by design.**
// secp256k1 is secp256k1 in every set, so a fix here SHOULD reach all of them, and three copies would
// be three places for one bug to hide. ⇒ The chain core (`append.php`) uses it too.
//
// ⚠⚠ WHY THIS IS WRITTEN RATHER THAN IMPORTED, and it is a licence position, not a preference.
//
//   `@bsv/sdk` is Open BSV v6, whose clause 2 restricts FIELD OF USE to the BSV Blockchain. jetmora is
//   not the BSV Blockchain, so nothing derived from it may run here — and separately, it carries MIT
//   code with the licence and author names stripped off. This project's answer is the opposite: build
//   from clean sources and keep attribution intact.
//
//   ⚠ MEASURED, not assumed: **bitcoinX 0.9 (MIT, Neil Booth) does not implement the curve in Python.**
//   It binds to `electrumsv-secp256k1` — a build of libsecp256k1 in C. So there is no bitcoinX curve
//   code to port into PHP. ⇒ The remaining clean option is to implement the PUBLISHED ALGORITHM in our
//   own PHP: SEC1 §4.1.4 with SEC2 curve parameters, both public specifications. No dependency, nothing
//   to attribute, and nothing that can drag a field-of-use clause behind it.
//
//   ⛔ NOT PHP's openssl extension either. It would work, but it is a system dependency for the one
//   piece of this machine that must give the same answer on every host forever, and the point of the
//   exercise is to own the primitives.
//   ⛔ Nor ext/gmp or bcmath, for the same reason: an extension a shared host may not have.
//   The arithmetic below is PHP ints, and a 64-bit PHP is all it needs.
//
// ⚠⚠ NO LOW_S RULE. 0.1.3 has none, and enforcing it has already cost this project real spends: a
//    conformant covenant spend was refused by a broadcaster applying LOW_S after the rule was removed
//    from the node software. An entry is identified by its own hash; nothing here depends on a
//    signature being unique, so malleability is not a threat.
//
// ⚠ This is a verifier, never a signer. There is no private key in this file and there must never be.
// ★ Constant-time is NOT a goal here: every input is public (a signature and a key already published in
//   a script), and there is no secret to leak by timing. Saying so is better than implying otherwise.
//
// ⚠⚠⚠ AND THAT SENTENCE STOPS BEING TRUE THE MOMENT THIS FILE IS USED FOR A WALLET.
//   `mulAdd()` is fine with a PUBLIC scalar. Deriving a public key from a private one, or signing, feeds
//   it a SECRET scalar, and a multiply whose work depends on the bits of that scalar is the
//   textbook timing side channel. ⇒ **A signer MUST NOT simply reuse `mulAdd()` and inherit this note.**
//   ⚠ PHP cannot honestly promise constant time anyway (branches, GC, opcache), so the design
//     answer is not a clever loop: it is that **the jetmora wallet's SIGNING must not run where an
//     attacker can time it** — which is a real constraint on "runs on $2 shared hosting", and belongs
//     in the wallet design rather than being discovered later.
//   ★ Verification, which is what this file is for today, has no such problem and never will.
//
// ── THE ARITHMETIC, IN PHP INTS ──────────────────────────────────────────────────────────────────────
// A field element mod p is ten signed limbs of 26 bits, the low limb first; limb 9 holds 22 bits once
// reduced. mul() and sqr() return limbs in [−65, 2^26 + 128] ("reduced"). A product of two limbs is
// 52 bits and a column holds at most ten, so a column stays below 2^63 while the two operands' limbs, in
// units of a reduced limb, multiply to at most 128 (each point formula below says its own). Sums,
// differences and small multiples therefore go into a multiply without a carry pass.
// ⚠⚠ PHP turns an int multiply that overflows into a float without a word, and a shift that overflows
//    wraps. Either would give a wrong verdict, not an error, so every bound here is a correctness rule.
// Scalars mod n are big-endian byte strings at every boundary (DER integers, keys, digests), worked in
// 26-bit limbs for products and 52-bit limbs for the inverse. Byte strings compare with strcmp, never `<`,
// which compares numeric-looking strings as numbers. Points are Jacobian [X, Y, Z] standing for
// (X/Z², Y/Z³), null for the point at infinity, so an inversion is needed only for an affine result.
//
// ★ A caller's key may be 32 bytes, an int, or a GMP number when gmp happens to be loaded: GMP is read and
//   made only in magnitude() and toGmp(), and only when a caller passes one in.
declare(strict_types=1);
require_once __DIR__ . '/rfc6979.php';

final class Secp256k1
{
  // SEC2 curve parameters for secp256k1. y² = x³ + 7 over F_p.
  private const P  = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';
  private const N  = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

  /**
   * 1G, 3G, 5G, ..., 31G as affine [x, y]: the odd multiples a signed window of 6 bits reads. Fixed here rather
   * than built per call, since a PHP-FPM request starts with empty statics. verify-secp256k1-native.php
   * rebuilds them from G.
   */
  private const G_ODD = [
    ['79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'],   // 1G
    ['f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672'],   // 3G
    ['2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4', 'd8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6'],   // 5G
    ['5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc', '6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da'],   // 7G
    ['acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe', 'cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37'],   // 9G
    ['774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb', 'd984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b'],   // 11G
    ['f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8', '0ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81'],   // 13G
    ['d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e', '581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58'],   // 15G
    ['defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34', '4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77'],   // 17G
    ['2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c', '85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a'],   // 19G
    ['352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5', '321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c'],   // 21G
    ['2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f', '02de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67'],   // 23G
    ['9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714', '73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402'],   // 25G
    ['daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729', 'a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55'],   // 27G
    ['c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db', '2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482'],   // 29G
    ['6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4', 'e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82'],   // 31G
  ];

  private const ZERO  = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  private const ONE   = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  private const SEVEN = [7, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  private const Z32   = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  /** p, n, (n − 1) / 2 and p − n as 32 bytes. */
  private static ?string $pB = null, $nB = null, $halfB = null, $pnB = null;
  /** n in 26-bit and 52-bit limbs, 2^256 − n in 26-bit limbs, n as a field element. */
  private static array $nL = [], $n52 = [], $cL = [], $nF = [];
  /** G_ODD as field elements, and the same points negated. */
  private static array $gT = [], $gTn = [];

  private static function init(): void
  {
    if (self::$pB !== null) return;
    // the limbs are 26 bits and their products 52: a narrower int cannot hold one, so this host cannot answer
    if (PHP_INT_SIZE < 8) throw new RuntimeException('secp256k1 needs 64-bit integers on this host');
    $p = hex2bin(self::P); $n = hex2bin(self::N);
    self::$nL  = self::limbs($n, 26);
    self::$n52 = self::limbs($n, 52);
    self::$cL  = array_slice(self::bigSub([0, 0, 0, 0, 0, 0, 0, 0, 0, 1 << 22], self::$nL), 0, 5);   // 2^256 − n: 129 bits
    self::$nF  = self::fe($n);
    self::$nB  = $n;
    self::$halfB = self::unlimbs(self::half52(self::$n52), 52, 32);                     // n is odd: (n − 1) / 2 = n >> 1
    self::$pnB = self::unlimbs(self::bigSub(self::limbs($p, 26), self::$nL), 26, 32);
    foreach (self::G_ODD as $i => [$x, $y]) {
      self::$gT[$i]  = [self::fe(hex2bin($x)), self::fe(hex2bin($y))];
      self::$gTn[$i] = [self::$gT[$i][0], self::neg(self::$gT[$i][1])];
    }
    self::$pB = $p;
  }

  // ── the field: ten limbs of 26 bits ────────────────────────────────────────────────────────────────

  /** 32 big-endian bytes as limbs. */
  private static function fe(string $b): array
  {
    $w = unpack('N8', $b);                         // $w[1] is the most significant word
    return [
      $w[8] & 0x3FFFFFF,
      (($w[8] >> 26) | ($w[7] << 6)) & 0x3FFFFFF,
      (($w[7] >> 20) | ($w[6] << 12)) & 0x3FFFFFF,
      (($w[6] >> 14) | ($w[5] << 18)) & 0x3FFFFFF,
      (($w[5] >> 8) | ($w[4] << 24)) & 0x3FFFFFF,
      ($w[4] >> 2) & 0x3FFFFFF,
      (($w[4] >> 28) | ($w[3] << 4)) & 0x3FFFFFF,
      (($w[3] >> 22) | ($w[2] << 10)) & 0x3FFFFFF,
      (($w[2] >> 16) | ($w[1] << 16)) & 0x3FFFFFF,
      $w[1] >> 10,
    ];
  }

  /** A canonical element (from canon()) as 32 big-endian bytes. */
  private static function feBytes(array $a): string
  {
    [$a0, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9] = $a;
    return pack('N8',
      ($a9 << 10) | ($a8 >> 16),
      (($a8 & 0xFFFF) << 16) | ($a7 >> 10),
      (($a7 & 0x3FF) << 22) | ($a6 >> 4),
      (($a6 & 0xF) << 28) | ($a5 << 2) | ($a4 >> 24),
      (($a4 & 0xFFFFFF) << 8) | ($a3 >> 18),
      (($a3 & 0x3FFFF) << 14) | ($a2 >> 12),
      (($a2 & 0xFFF) << 20) | ($a1 >> 6),
      (($a1 & 0x3F) << 26) | $a0);
  }

  /**
   * a·b mod p, reduced. The 19 column sums, carried to 26 bits; then the columns from 10 up fold down, since
   * 2^260 = 2^36 + 0x3D10 (mod p): column i adds i·0x3D10 to column i − 10 and i·2^10 to column i − 9, from
   * the top down so column 10 folds last. Then a second carry, and what is left above bit 256 folds as
   * 2^256 = 2^32 + 0x3D1. The shifts are arithmetic, so a negative column carries as a negative number.
   */
  private static function mul(array $a, array $b): array
  {
    [$a0, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9] = $a;
    [$b0, $b1, $b2, $b3, $b4, $b5, $b6, $b7, $b8, $b9] = $b;
    $c0  = $a0 * $b0;
    $c1  = $a0 * $b1 + $a1 * $b0;
    $c2  = $a0 * $b2 + $a1 * $b1 + $a2 * $b0;
    $c3  = $a0 * $b3 + $a1 * $b2 + $a2 * $b1 + $a3 * $b0;
    $c4  = $a0 * $b4 + $a1 * $b3 + $a2 * $b2 + $a3 * $b1 + $a4 * $b0;
    $c5  = $a0 * $b5 + $a1 * $b4 + $a2 * $b3 + $a3 * $b2 + $a4 * $b1 + $a5 * $b0;
    $c6  = $a0 * $b6 + $a1 * $b5 + $a2 * $b4 + $a3 * $b3 + $a4 * $b2 + $a5 * $b1 + $a6 * $b0;
    $c7  = $a0 * $b7 + $a1 * $b6 + $a2 * $b5 + $a3 * $b4 + $a4 * $b3 + $a5 * $b2 + $a6 * $b1 + $a7 * $b0;
    $c8  = $a0 * $b8 + $a1 * $b7 + $a2 * $b6 + $a3 * $b5 + $a4 * $b4 + $a5 * $b3 + $a6 * $b2 + $a7 * $b1 + $a8 * $b0;
    $c9  = $a0 * $b9 + $a1 * $b8 + $a2 * $b7 + $a3 * $b6 + $a4 * $b5 + $a5 * $b4 + $a6 * $b3 + $a7 * $b2 + $a8 * $b1 + $a9 * $b0;
    $c10 = $a1 * $b9 + $a2 * $b8 + $a3 * $b7 + $a4 * $b6 + $a5 * $b5 + $a6 * $b4 + $a7 * $b3 + $a8 * $b2 + $a9 * $b1;
    $c11 = $a2 * $b9 + $a3 * $b8 + $a4 * $b7 + $a5 * $b6 + $a6 * $b5 + $a7 * $b4 + $a8 * $b3 + $a9 * $b2;
    $c12 = $a3 * $b9 + $a4 * $b8 + $a5 * $b7 + $a6 * $b6 + $a7 * $b5 + $a8 * $b4 + $a9 * $b3;
    $c13 = $a4 * $b9 + $a5 * $b8 + $a6 * $b7 + $a7 * $b6 + $a8 * $b5 + $a9 * $b4;
    $c14 = $a5 * $b9 + $a6 * $b8 + $a7 * $b7 + $a8 * $b6 + $a9 * $b5;
    $c15 = $a6 * $b9 + $a7 * $b8 + $a8 * $b7 + $a9 * $b6;
    $c16 = $a7 * $b9 + $a8 * $b8 + $a9 * $b7;
    $c17 = $a8 * $b9 + $a9 * $b8;
    $c18 = $a9 * $b9;

    $c1  += $c0 >> 26;  $c0  &= 0x3FFFFFF;
    $c2  += $c1 >> 26;  $c1  &= 0x3FFFFFF;
    $c3  += $c2 >> 26;  $c2  &= 0x3FFFFFF;
    $c4  += $c3 >> 26;  $c3  &= 0x3FFFFFF;
    $c5  += $c4 >> 26;  $c4  &= 0x3FFFFFF;
    $c6  += $c5 >> 26;  $c5  &= 0x3FFFFFF;
    $c7  += $c6 >> 26;  $c6  &= 0x3FFFFFF;
    $c8  += $c7 >> 26;  $c7  &= 0x3FFFFFF;
    $c9  += $c8 >> 26;  $c8  &= 0x3FFFFFF;
    $c10 += $c9 >> 26;  $c9  &= 0x3FFFFFF;
    $c11 += $c10 >> 26; $c10 &= 0x3FFFFFF;
    $c12 += $c11 >> 26; $c11 &= 0x3FFFFFF;
    $c13 += $c12 >> 26; $c12 &= 0x3FFFFFF;
    $c14 += $c13 >> 26; $c13 &= 0x3FFFFFF;
    $c15 += $c14 >> 26; $c14 &= 0x3FFFFFF;
    $c16 += $c15 >> 26; $c15 &= 0x3FFFFFF;
    $c17 += $c16 >> 26; $c16 &= 0x3FFFFFF;
    $c18 += $c17 >> 26; $c17 &= 0x3FFFFFF;
    $c19  = $c18 >> 26; $c18 &= 0x3FFFFFF;

    $c9 += $c19 * 0x3D10; $c10 += $c19 << 10;
    $c8 += $c18 * 0x3D10; $c9  += $c18 << 10;
    $c7 += $c17 * 0x3D10; $c8  += $c17 << 10;
    $c6 += $c16 * 0x3D10; $c7  += $c16 << 10;
    $c5 += $c15 * 0x3D10; $c6  += $c15 << 10;
    $c4 += $c14 * 0x3D10; $c5  += $c14 << 10;
    $c3 += $c13 * 0x3D10; $c4  += $c13 << 10;
    $c2 += $c12 * 0x3D10; $c3  += $c12 << 10;
    $c1 += $c11 * 0x3D10; $c2  += $c11 << 10;
    $c0 += $c10 * 0x3D10; $c1  += $c10 << 10;

    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    $c3 += $c2 >> 26; $c2 &= 0x3FFFFFF;
    $c4 += $c3 >> 26; $c3 &= 0x3FFFFFF;
    $c5 += $c4 >> 26; $c4 &= 0x3FFFFFF;
    $c6 += $c5 >> 26; $c5 &= 0x3FFFFFF;
    $c7 += $c6 >> 26; $c6 &= 0x3FFFFFF;
    $c8 += $c7 >> 26; $c7 &= 0x3FFFFFF;
    $c9 += $c8 >> 26; $c8 &= 0x3FFFFFF;
    $t = $c9 >> 22;   $c9 &= 0x3FFFFF;
    $c0 += $t * 0x3D1; $c1 += $t << 6;
    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    return [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9];
  }

  /** a² mod p: mul() with each cross product taken once and doubled, and the same reduction. */
  private static function sqr(array $a): array
  {
    [$a0, $a1, $a2, $a3, $a4, $a5, $a6, $a7, $a8, $a9] = $a;
    $d0 = $a0 * 2; $d1 = $a1 * 2; $d2 = $a2 * 2; $d3 = $a3 * 2; $d4 = $a4 * 2;
    $d5 = $a5 * 2; $d6 = $a6 * 2; $d7 = $a7 * 2; $d8 = $a8 * 2;
    $c0  = $a0 * $a0;
    $c1  = $d0 * $a1;
    $c2  = $d0 * $a2 + $a1 * $a1;
    $c3  = $d0 * $a3 + $d1 * $a2;
    $c4  = $d0 * $a4 + $d1 * $a3 + $a2 * $a2;
    $c5  = $d0 * $a5 + $d1 * $a4 + $d2 * $a3;
    $c6  = $d0 * $a6 + $d1 * $a5 + $d2 * $a4 + $a3 * $a3;
    $c7  = $d0 * $a7 + $d1 * $a6 + $d2 * $a5 + $d3 * $a4;
    $c8  = $d0 * $a8 + $d1 * $a7 + $d2 * $a6 + $d3 * $a5 + $a4 * $a4;
    $c9  = $d0 * $a9 + $d1 * $a8 + $d2 * $a7 + $d3 * $a6 + $d4 * $a5;
    $c10 = $d1 * $a9 + $d2 * $a8 + $d3 * $a7 + $d4 * $a6 + $a5 * $a5;
    $c11 = $d2 * $a9 + $d3 * $a8 + $d4 * $a7 + $d5 * $a6;
    $c12 = $d3 * $a9 + $d4 * $a8 + $d5 * $a7 + $a6 * $a6;
    $c13 = $d4 * $a9 + $d5 * $a8 + $d6 * $a7;
    $c14 = $d5 * $a9 + $d6 * $a8 + $a7 * $a7;
    $c15 = $d6 * $a9 + $d7 * $a8;
    $c16 = $d7 * $a9 + $a8 * $a8;
    $c17 = $d8 * $a9;
    $c18 = $a9 * $a9;

    $c1  += $c0 >> 26;  $c0  &= 0x3FFFFFF;
    $c2  += $c1 >> 26;  $c1  &= 0x3FFFFFF;
    $c3  += $c2 >> 26;  $c2  &= 0x3FFFFFF;
    $c4  += $c3 >> 26;  $c3  &= 0x3FFFFFF;
    $c5  += $c4 >> 26;  $c4  &= 0x3FFFFFF;
    $c6  += $c5 >> 26;  $c5  &= 0x3FFFFFF;
    $c7  += $c6 >> 26;  $c6  &= 0x3FFFFFF;
    $c8  += $c7 >> 26;  $c7  &= 0x3FFFFFF;
    $c9  += $c8 >> 26;  $c8  &= 0x3FFFFFF;
    $c10 += $c9 >> 26;  $c9  &= 0x3FFFFFF;
    $c11 += $c10 >> 26; $c10 &= 0x3FFFFFF;
    $c12 += $c11 >> 26; $c11 &= 0x3FFFFFF;
    $c13 += $c12 >> 26; $c12 &= 0x3FFFFFF;
    $c14 += $c13 >> 26; $c13 &= 0x3FFFFFF;
    $c15 += $c14 >> 26; $c14 &= 0x3FFFFFF;
    $c16 += $c15 >> 26; $c15 &= 0x3FFFFFF;
    $c17 += $c16 >> 26; $c16 &= 0x3FFFFFF;
    $c18 += $c17 >> 26; $c17 &= 0x3FFFFFF;
    $c19  = $c18 >> 26; $c18 &= 0x3FFFFFF;

    $c9 += $c19 * 0x3D10; $c10 += $c19 << 10;
    $c8 += $c18 * 0x3D10; $c9  += $c18 << 10;
    $c7 += $c17 * 0x3D10; $c8  += $c17 << 10;
    $c6 += $c16 * 0x3D10; $c7  += $c16 << 10;
    $c5 += $c15 * 0x3D10; $c6  += $c15 << 10;
    $c4 += $c14 * 0x3D10; $c5  += $c14 << 10;
    $c3 += $c13 * 0x3D10; $c4  += $c13 << 10;
    $c2 += $c12 * 0x3D10; $c3  += $c12 << 10;
    $c1 += $c11 * 0x3D10; $c2  += $c11 << 10;
    $c0 += $c10 * 0x3D10; $c1  += $c10 << 10;

    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    $c3 += $c2 >> 26; $c2 &= 0x3FFFFFF;
    $c4 += $c3 >> 26; $c3 &= 0x3FFFFFF;
    $c5 += $c4 >> 26; $c4 &= 0x3FFFFFF;
    $c6 += $c5 >> 26; $c5 &= 0x3FFFFFF;
    $c7 += $c6 >> 26; $c6 &= 0x3FFFFFF;
    $c8 += $c7 >> 26; $c7 &= 0x3FFFFFF;
    $c9 += $c8 >> 26; $c8 &= 0x3FFFFFF;
    $t = $c9 >> 22;   $c9 &= 0x3FFFFF;
    $c0 += $t * 0x3D1; $c1 += $t << 6;
    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    return [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9];
  }

  /** a² repeated n times. */
  private static function sqrN(array $a, int $n): array
  {
    for ($i = 0; $i < $n; $i++) $a = self::sqr($a);
    return $a;
  }

  // Limb by limb, with no carry: the caller keeps the result's limbs within what its next multiply allows.
  private static function add(array $a, array $b): array
  {
    return [$a[0] + $b[0], $a[1] + $b[1], $a[2] + $b[2], $a[3] + $b[3], $a[4] + $b[4],
            $a[5] + $b[5], $a[6] + $b[6], $a[7] + $b[7], $a[8] + $b[8], $a[9] + $b[9]];
  }

  private static function sub(array $a, array $b): array
  {
    return [$a[0] - $b[0], $a[1] - $b[1], $a[2] - $b[2], $a[3] - $b[3], $a[4] - $b[4],
            $a[5] - $b[5], $a[6] - $b[6], $a[7] - $b[7], $a[8] - $b[8], $a[9] - $b[9]];
  }

  private static function neg(array $a): array
  {
    return [-$a[0], -$a[1], -$a[2], -$a[3], -$a[4], -$a[5], -$a[6], -$a[7], -$a[8], -$a[9]];
  }

  private static function mulInt(array $a, int $k): array
  {
    return [$a[0] * $k, $a[1] * $k, $a[2] * $k, $a[3] * $k, $a[4] * $k,
            $a[5] * $k, $a[6] * $k, $a[7] * $k, $a[8] * $k, $a[9] * $k];
  }

  /** A sum of a few reduced elements, reduced again: mul()'s last carry and fold. */
  private static function norm(array $a): array
  {
    [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9] = $a;
    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    $c3 += $c2 >> 26; $c2 &= 0x3FFFFFF;
    $c4 += $c3 >> 26; $c3 &= 0x3FFFFFF;
    $c5 += $c4 >> 26; $c4 &= 0x3FFFFFF;
    $c6 += $c5 >> 26; $c5 &= 0x3FFFFFF;
    $c7 += $c6 >> 26; $c6 &= 0x3FFFFFF;
    $c8 += $c7 >> 26; $c7 &= 0x3FFFFFF;
    $c9 += $c8 >> 26; $c8 &= 0x3FFFFFF;
    $t = $c9 >> 22;   $c9 &= 0x3FFFFF;
    $c0 += $t * 0x3D1; $c1 += $t << 6;
    $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
    $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
    return [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9];
  }

  /**
   * The unique limbs of the value in [0, p). Carry and fold until nothing is left above bit 256, which also
   * brings a negative value up into [0, 2^256); then v ≥ p exactly when v + 2^32 + 0x3D1 reaches 2^256.
   */
  private static function canon(array $a): array
  {
    [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9] = $a;
    do {
      $c1 += $c0 >> 26; $c0 &= 0x3FFFFFF;
      $c2 += $c1 >> 26; $c1 &= 0x3FFFFFF;
      $c3 += $c2 >> 26; $c2 &= 0x3FFFFFF;
      $c4 += $c3 >> 26; $c3 &= 0x3FFFFFF;
      $c5 += $c4 >> 26; $c4 &= 0x3FFFFFF;
      $c6 += $c5 >> 26; $c5 &= 0x3FFFFFF;
      $c7 += $c6 >> 26; $c6 &= 0x3FFFFFF;
      $c8 += $c7 >> 26; $c7 &= 0x3FFFFFF;
      $c9 += $c8 >> 26; $c8 &= 0x3FFFFFF;
      $t = $c9 >> 22;   $c9 &= 0x3FFFFF;
      $c0 += $t * 0x3D1; $c1 += $t << 6;
    } while ($t !== 0);
    $d0 = $c0 + 0x3D1;
    $d1 = $c1 + 0x40 + ($d0 >> 26); $d0 &= 0x3FFFFFF;
    $d2 = $c2 + ($d1 >> 26); $d1 &= 0x3FFFFFF;
    $d3 = $c3 + ($d2 >> 26); $d2 &= 0x3FFFFFF;
    $d4 = $c4 + ($d3 >> 26); $d3 &= 0x3FFFFFF;
    $d5 = $c5 + ($d4 >> 26); $d4 &= 0x3FFFFFF;
    $d6 = $c6 + ($d5 >> 26); $d5 &= 0x3FFFFFF;
    $d7 = $c7 + ($d6 >> 26); $d6 &= 0x3FFFFFF;
    $d8 = $c8 + ($d7 >> 26); $d7 &= 0x3FFFFFF;
    $d9 = $c9 + ($d8 >> 26); $d8 &= 0x3FFFFFF;
    if ($d9 >> 22) return [$d0, $d1, $d2, $d3, $d4, $d5, $d6, $d7, $d8, $d9 & 0x3FFFFF];
    return [$c0, $c1, $c2, $c3, $c4, $c5, $c6, $c7, $c8, $c9];
  }

  private static function isZero(array $a): bool
  {
    return self::canon($a) === self::ZERO;
  }

  /**
   * a^(2^2 − 1), a^(2^22 − 1) and a^(2^223 − 1): the runs of ones in p − 2 and in (p + 1) / 4, by the addition
   * chain 1, 2, 3, 6, 9, 11, 22, 44, 88, 176, 220, 223.
   */
  private static function runs(array $a): array
  {
    $x2   = self::mul(self::sqr($a), $a);
    $x3   = self::mul(self::sqr($x2), $a);
    $x6   = self::mul(self::sqrN($x3, 3), $x3);
    $x9   = self::mul(self::sqrN($x6, 3), $x3);
    $x11  = self::mul(self::sqrN($x9, 2), $x2);
    $x22  = self::mul(self::sqrN($x11, 11), $x11);
    $x44  = self::mul(self::sqrN($x22, 22), $x22);
    $x88  = self::mul(self::sqrN($x44, 44), $x44);
    $x176 = self::mul(self::sqrN($x88, 88), $x88);
    $x220 = self::mul(self::sqrN($x176, 44), $x44);
    $x223 = self::mul(self::sqrN($x220, 3), $x3);
    return [$x2, $x22, $x223];
  }

  /** 1/a = a^(p − 2): p − 2 is 223 ones, a zero, 22 ones, then 0000101101. */
  private static function inv(array $a): array
  {
    [$x2, $x22, $x223] = self::runs($a);
    $t = self::mul(self::sqrN($x223, 23), $x22);
    $t = self::mul(self::sqrN($t, 5), $a);
    $t = self::mul(self::sqrN($t, 3), $x2);
    return self::mul(self::sqrN($t, 2), $a);
  }

  /**
   * a^((p + 1) / 4), a square root of a when a has one (p = 3 mod 4, so no Tonelli-Shanks is needed).
   * (p + 1) / 4 is 223 ones, a zero, 22 ones, then 00001100.
   */
  private static function sqrt(array $a): array
  {
    [$x2, $x22, $x223] = self::runs($a);
    $t = self::mul(self::sqrN($x223, 23), $x22);
    $t = self::mul(self::sqrN($t, 6), $x2);
    return self::sqrN($t, 2);
  }

  // ── point arithmetic, Jacobian, over F_p ───────────────────────────────────────────────────────────
  // A point is [X, Y, Z] of reduced elements, or null for the point at infinity. secp256k1 has prime order, so no
  // point other than infinity doubles to infinity, and Y is never 0. The comments give each multiply's operand sizes
  // in units of a reduced limb.

  /** 2P, by dbl-2009-l (a = 0). */
  private static function pointDbl(?array $p): ?array
  {
    if ($p === null) return null;
    [$x, $y, $z] = $p;
    $a  = self::sqr($x);
    $b  = self::sqr($y);
    $c  = self::sqr($b);
    $d  = self::mulInt(self::sub(self::sub(self::sqr(self::add($x, $b)), $a), $c), 2);   // (X + B)²: 2·2; D is 6
    $e  = self::mulInt($a, 3);
    $f  = self::sqr($e);                                                                  // 3·3
    $x3 = self::norm(self::sub($f, self::mulInt($d, 2)));                                 // 13 before norm
    $y3 = self::norm(self::sub(self::mul($e, self::sub($d, $x3)), self::mulInt($c, 8)));  // 3·7; then 9
    $z3 = self::mul(self::mulInt($y, 2), $z);                                             // 2·1
    return [$x3, $y3, $z3];
  }

  /**
   * P + Q, by add-2007-bl. Equal x (H = 0) is either a double (the same y) or a point and its negation (infinity):
   * the general formula gives 0/0 for both, so they are told apart here: a double, or infinity.
   */
  private static function pointAdd(?array $p, ?array $q): ?array
  {
    if ($p === null) return $q;
    if ($q === null) return $p;
    [$x1, $y1, $z1] = $p;
    [$x2, $y2, $z2] = $q;
    $z1z1 = self::sqr($z1);
    $z2z2 = self::sqr($z2);
    $u1 = self::mul($x1, $z2z2);
    $u2 = self::mul($x2, $z1z1);
    $s1 = self::mul($y1, self::mul($z2, $z2z2));
    $s2 = self::mul($y2, self::mul($z1, $z1z1));
    $h  = self::sub($u2, $u1);                                                            // 2
    $r  = self::mulInt(self::sub($s2, $s1), 2);                                           // 4
    if (self::isZero($h)) return self::isZero($r) ? self::pointDbl($p) : null;
    $i  = self::sqr(self::mulInt($h, 2));                                                 // 4·4
    $j  = self::mul($h, $i);                                                              // 2·1
    $v  = self::mul($u1, $i);
    $x3 = self::norm(self::sub(self::sub(self::sqr($r), $j), self::mulInt($v, 2)));       // 4·4; then 4
    $y3 = self::norm(self::sub(self::mul($r, self::sub($v, $x3)),                         // 4·2
                               self::mul(self::mulInt($s1, 2), $j)));                     // 2·1; then 2
    $z3 = self::mul(self::sub(self::sub(self::sqr(self::add($z1, $z2)), $z1z1), $z2z2), $h);   // 2·2; 3·2
    return [$x3, $y3, $z3];
  }

  /** P + Q for an affine Q = [x, y], by madd-2007-bl (Q's Z is 1). Equal x as in pointAdd(). */
  private static function pointAddAffine(?array $p, array $q): ?array
  {
    if ($p === null) return [$q[0], $q[1], self::ONE];
    [$x1, $y1, $z1] = $p;
    [$x2, $y2] = $q;
    $z1z1 = self::sqr($z1);
    $u2 = self::mul($x2, $z1z1);
    $s2 = self::mul($y2, self::mul($z1, $z1z1));
    $h  = self::sub($u2, $x1);                                                            // 2
    $r  = self::mulInt(self::sub($s2, $y1), 2);                                           // 4
    if (self::isZero($h)) return self::isZero($r) ? self::pointDbl($p) : null;
    $hh = self::sqr($h);                                                                  // 2·2
    $i  = self::mulInt($hh, 4);                                                           // 4
    $j  = self::mul($h, $i);                                                              // 2·4
    $v  = self::mul($x1, $i);                                                             // 1·4
    $x3 = self::norm(self::sub(self::sub(self::sqr($r), $j), self::mulInt($v, 2)));       // 4·4; then 4
    $y3 = self::norm(self::sub(self::mul($r, self::sub($v, $x3)),                         // 4·2
                               self::mul(self::mulInt($y1, 2), $j)));                     // 2·1; then 2
    $z3 = self::norm(self::sub(self::sub(self::sqr(self::add($z1, $h)), $z1z1), $hh));    // 3·3; then 3
    return [$x3, $y3, $z3];
  }

  /** The affine [x, y], canonical, of a Jacobian point: the one inversion. */
  private static function affine(?array $p): ?array
  {
    if ($p === null) return null;
    $zi  = self::inv($p[2]);
    $zi2 = self::sqr($zi);
    return [self::canon(self::mul($p[0], $zi2)), self::canon(self::mul($p[1], self::mul($zi2, $zi)))];
  }

  /**
   * The signed-window form of a scalar given as big-endian bytes: [bit position => digit], each digit odd with
   * |digit| < 2^(w − 1), any two at least w positions apart, and Σ digit·2^position equal to the scalar.
   */
  private static function wnaf(string $k, int $w): array
  {
    $bin = '';
    foreach (unpack('C*', $k) as $c) $bin .= sprintf('%08b', $c);
    $bits = array_map('intval', str_split(strrev($bin)));      // the low bit first
    $len = count($bits);
    $out = []; $carry = 0; $i = 0;
    while ($i < $len) {
      if ($bits[$i] === $carry) { $i++; continue; }            // this bit plus the carry is even: a zero digit
      $word = $carry;
      for ($j = 0; $j < $w && $i + $j < $len; $j++) $word += $bits[$i + $j] << $j;
      $carry = ($word >> ($w - 1)) & 1;                        // past half the window: a negative digit, and carry
      $out[$i] = $word - ($carry << $w);
      $i += $w;
    }
    if ($carry) $out[$i] = 1;
    return $out;
  }

  /**
   * u1·G + u2·Q, the scalars as big-endian bytes and Q affine, or u1·G alone when Q is null. Straus: one doubling
   * a bit shared by both, G's digits read from G_ODD (windows of 6 bits), Q's from Q, 3Q, ..., 15Q built here
   * (windows of 5). The group law gives one answer whatever the method.
   * ⚠ Variable time: in a verify every input is public, and a secret scalar comes here
   *   only blinded (mulBlinded).
   */
  private static function mulAdd(string $u1, ?array $q = null, string $u2 = ''): ?array
  {
    $dg = self::wnaf($u1, 6);
    $dq = [];
    $qt = [];
    if ($q !== null) {
      $dq = self::wnaf($u2, 5);
      $qt[0] = [$q[0], $q[1], self::ONE];
      $q2 = self::pointDbl($qt[0]);
      for ($i = 1; $i < 8; $i++) $qt[$i] = self::pointAdd($qt[$i - 1], $q2);
    }
    $top = max(array_key_last($dg) ?? -1, array_key_last($dq) ?? -1);
    $r = null;
    for ($i = $top; $i >= 0; $i--) {
      $r = self::pointDbl($r);
      if (isset($dg[$i])) {
        $d = $dg[$i];
        $r = self::pointAddAffine($r, $d > 0 ? self::$gT[$d >> 1] : self::$gTn[(-$d) >> 1]);
      }
      if (isset($dq[$i])) {
        $d = $dq[$i];
        $t = $qt[($d > 0 ? $d : -$d) >> 1];
        $r = self::pointAdd($r, $d > 0 ? $t : [$t[0], self::neg($t[1]), $t[2]]);
      }
    }
    return $r;
  }

  /**
   * ★★★ SECRET SCALAR — SCALAR BLINDING.
   * k·G for 1 <= k < n, as a Jacobian point.
   *
   * ⚠⚠⚠ WHY THIS EXISTS. The multiply does work that depends on the BITS OF ITS SCALAR, so its running
   *   time leaks them. That was tolerable while this file only verified (public inputs). It stops
   *   being tolerable the moment signing runs behind a web form: **the attacker then chooses the
   *   request and measures the response.**
   *
   * ★ THE FIX WORKS WITHOUT CONSTANT-TIME ARITHMETIC, which is what makes it usable in PHP at all:
   *   `n·P` is the identity, so `(k + b·n)·P == k·P` for any b. Choosing b at random per call means
   *   the bit pattern actually executed **changes every time while the RESULT does not.** Timing
   *   therefore correlates with b, which is random and worthless, instead of with k.
   *
   * ⚠ WHAT IT DOES NOT DO: it defeats TIMING analysis of the scalar. It does not protect against a
   *   host that can read process memory — nothing written in PHP can.
   * ⚠ And it does NOT disturb determinism: `k` still comes from RFC 6979 and the point is identical,
   *   so the signature bytes are unchanged and still reproducible.
   */
  private static function mulBlinded(string $k): ?array
  {
    $b = random_bytes(8);
    if ($b === "\0\0\0\0\0\0\0\0") $b = "\0\0\0\0\0\0\0\x01";
    // k + b·n < 2^64·n < 2^320: 40 bytes
    return self::mulAdd(self::unlimbs(self::bigAdd(self::limbs($k, 26), self::bigMul(self::limbs($b, 26), self::$nL)), 26, 40));
  }

  // ── scalars: integers of any size in limbs of 26 bits, the low limb first, every limb in [0, 2^26) ────

  /** Big-endian bytes as limbs of $w bits ($w <= 52). */
  private static function limbs(string $b, int $w): array
  {
    $l = []; $acc = 0; $n = 0; $m = (1 << $w) - 1;
    for ($i = strlen($b) - 1; $i >= 0; $i--) {
      $acc |= ord($b[$i]) << $n; $n += 8;
      if ($n >= $w) { $l[] = $acc & $m; $acc >>= $w; $n -= $w; }
    }
    if ($n > 0 || $l === []) $l[] = $acc;
    return $l;
  }

  /** Limbs of $w bits as exactly $len big-endian bytes; the value must fit. */
  private static function unlimbs(array $l, int $w, int $len): string
  {
    $out = ''; $acc = 0; $n = 0; $i = 0; $cnt = count($l);
    for ($k = 0; $k < $len; $k++) {
      if ($n < 8 && $i < $cnt) { $acc |= $l[$i++] << $n; $n += $w; }
      $out .= chr($acc & 0xFF); $acc >>= 8; $n -= 8;
    }
    return strrev($out);
  }

  private static function bigAdd(array $a, array $b): array
  {
    $out = []; $carry = 0;
    for ($i = 0, $len = max(count($a), count($b)); $i < $len; $i++) {
      $v = ($a[$i] ?? 0) + ($b[$i] ?? 0) + $carry;
      $out[] = $v & 0x3FFFFFF; $carry = $v >> 26;
    }
    if ($carry) $out[] = $carry;
    return $out;
  }

  /** a − b, for a >= b. */
  private static function bigSub(array $a, array $b): array
  {
    $out = []; $borrow = 0;
    for ($i = 0, $len = count($a); $i < $len; $i++) {
      $v = $a[$i] - ($b[$i] ?? 0) + $borrow;
      $out[] = $v & 0x3FFFFFF; $borrow = $v >> 26;
    }
    return $out;
  }

  /** Columns of up to 16 products of 52 bits stay below 2^56: operands of up to 416 bits. */
  private static function bigMul(array $a, array $b): array
  {
    $c = array_fill(0, count($a) + count($b), 0);
    foreach ($a as $i => $x) {
      if ($x === 0) continue;
      foreach ($b as $j => $y) $c[$i + $j] += $x * $y;
    }
    $carry = 0;
    foreach ($c as $k => $v) { $v += $carry; $c[$k] = $v & 0x3FFFFFF; $carry = $v >> 26; }
    return $c;
  }

  private static function bigCmp(array $a, array $b): int
  {
    for ($i = max(count($a), count($b)) - 1; $i >= 0; $i--) {
      $x = $a[$i] ?? 0; $y = $b[$i] ?? 0;
      if ($x !== $y) return $x < $y ? -1 : 1;
    }
    return 0;
  }

  /** a mod n: what is above bit 256 folds down as 2^256 = 2^256 − n (mod n) until nothing is, then n comes off. */
  private static function bigMod(array $a): array
  {
    while (count($a) > 10) {
      $lo = array_slice($a, 0, 10);
      $lo[9] &= 0x3FFFFF;
      $hi = [];
      for ($k = 9, $len = count($a); $k < $len; $k++) $hi[] = ($a[$k] >> 22) | ((($a[$k + 1] ?? 0) << 4) & 0x3FFFFFF);
      if (max($hi) === 0) { $a = $lo; break; }
      $a = self::bigAdd($lo, self::bigMul($hi, self::$cL));
    }
    $a = array_pad($a, 10, 0);
    if ($a[9] >> 22) {                                  // ten limbs can hold 2^256 and more: fold once more
      $h = $a[9] >> 22; $a[9] &= 0x3FFFFF;
      $a = array_pad(self::bigAdd($a, self::bigMul([$h], self::$cL)), 10, 0);
    }
    while (self::bigCmp($a, self::$nL) >= 0) $a = self::bigSub($a, self::$nL);
    return $a;
  }

  /** (a·b) mod n, as 32 bytes. */
  private static function scMul(string $a, string $b): string
  {
    return self::unlimbs(self::bigMod(self::bigMul(self::limbs($a, 26), self::limbs($b, 26))), 26, 32);
  }

  /** (a + b) mod n, as 32 bytes. */
  private static function scAdd(string $a, string $b): string
  {
    return self::unlimbs(self::bigMod(self::bigAdd(self::limbs($a, 26), self::limbs($b, 26))), 26, 32);
  }

  /** a mod n, as 32 bytes. */
  private static function scMod(string $a): string
  {
    return self::unlimbs(self::bigMod(self::limbs($a, 26)), 26, 32);
  }

  /** n − s, for 0 < s < n. */
  private static function scNeg(string $s): string
  {
    return self::unlimbs(self::bigSub(self::$nL, self::limbs($s, 26)), 26, 32);
  }

  /**
   * a⁻¹ mod n for 1 <= a < n (n is prime), by the binary extended Euclidean algorithm (Guide to Elliptic Curve
   * Cryptography, Algorithm 2.22), on five limbs of 52 bits: x1 and x2 stay in [0, n), so x + n fits in 260 bits.
   * Variable time: a verify inverts s, which is public, and signing inverts k·t, blinded by a random t.
   * 0 has no inverse and gives 0, which callers treat as no inverse: the loop below would never end on it.
   */
  private static function scInv(string $a): string
  {
    if ($a === self::Z32) return self::Z32;
    $n = self::$n52;
    $one = [1, 0, 0, 0, 0];
    $u = array_pad(self::limbs($a, 52), 5, 0);
    $v = $n;
    $x1 = $one; $x2 = [0, 0, 0, 0, 0];
    while ($u !== $one && $v !== $one) {
      while (($u[0] & 1) === 0) { $u = self::half52($u); $x1 = self::half52(($x1[0] & 1) ? self::add52($x1, $n) : $x1); }
      while (($v[0] & 1) === 0) { $v = self::half52($v); $x2 = self::half52(($x2[0] & 1) ? self::add52($x2, $n) : $x2); }
      if (self::cmp52($u, $v) >= 0) {
        $u = self::sub52($u, $v);
        $x1 = self::sub52($x1, $x2); if ($x1[4] < 0) $x1 = self::add52($x1, $n);
      } else {
        $v = self::sub52($v, $u);
        $x2 = self::sub52($x2, $x1); if ($x2[4] < 0) $x2 = self::add52($x2, $n);
      }
    }
    return self::unlimbs($u === $one ? $x1 : $x2, 52, 32);
  }

  private static function half52(array $a): array
  {
    return [($a[0] >> 1) | (($a[1] & 1) << 51), ($a[1] >> 1) | (($a[2] & 1) << 51),
            ($a[2] >> 1) | (($a[3] & 1) << 51), ($a[3] >> 1) | (($a[4] & 1) << 51), $a[4] >> 1];
  }

  private static function add52(array $a, array $b): array
  {
    $c0 = $a[0] + $b[0];
    $c1 = $a[1] + $b[1] + ($c0 >> 52); $c0 &= 0xFFFFFFFFFFFFF;
    $c2 = $a[2] + $b[2] + ($c1 >> 52); $c1 &= 0xFFFFFFFFFFFFF;
    $c3 = $a[3] + $b[3] + ($c2 >> 52); $c2 &= 0xFFFFFFFFFFFFF;
    $c4 = $a[4] + $b[4] + ($c3 >> 52); $c3 &= 0xFFFFFFFFFFFFF;
    return [$c0, $c1, $c2, $c3, $c4];
  }

  /** a − b; the top limb is negative when b > a. */
  private static function sub52(array $a, array $b): array
  {
    $c0 = $a[0] - $b[0];
    $c1 = $a[1] - $b[1] + ($c0 >> 52); $c0 &= 0xFFFFFFFFFFFFF;
    $c2 = $a[2] - $b[2] + ($c1 >> 52); $c1 &= 0xFFFFFFFFFFFFF;
    $c3 = $a[3] - $b[3] + ($c2 >> 52); $c2 &= 0xFFFFFFFFFFFFF;
    $c4 = $a[4] - $b[4] + ($c3 >> 52); $c3 &= 0xFFFFFFFFFFFFF;
    return [$c0, $c1, $c2, $c3, $c4];
  }

  private static function cmp52(array $a, array $b): int
  {
    for ($i = 4; $i >= 0; $i--) if ($a[$i] !== $b[$i]) return $a[$i] < $b[$i] ? -1 : 1;
    return 0;
  }

  // ── the edge: a caller's GMP number, read and made only here ───────────────────────────────────────

  /** |v| as big-endian bytes, and whether v is negative, for an int or a GMP number. */
  private static function magnitude(GMP|int $v): array
  {
    if (is_int($v)) return [$v === PHP_INT_MIN ? "\x80\0\0\0\0\0\0\0" : pack('J', abs($v)), $v < 0];
    $h = gmp_strval($v, 16);
    $neg = $h[0] === '-';
    $h = ltrim($h, '-');
    return [(string)hex2bin(strlen($h) % 2 === 1 ? "0$h" : $h), $neg];
  }

  private static function toGmp(string $b): GMP
  {
    return gmp_import($b, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  }

  /** A private key, 1 <= d < n, as 32 big-endian bytes: given as 32 bytes, an int, or a GMP number. */
  private static function secret(GMP|int|string $d): string
  {
    if (is_string($d)) {
      if (strlen($d) !== 32) throw new InvalidArgumentException('private key must be 32 bytes');
    } else {
      [$m, $neg] = self::magnitude($d);
      $m = ltrim($m, "\0");
      if ($neg || strlen($m) > 32) throw new InvalidArgumentException('private key out of range');
      $d = str_pad($m, 32, "\0", STR_PAD_LEFT);
    }
    if ($d === self::Z32 || strcmp($d, self::$nB) >= 0) throw new InvalidArgumentException('private key out of range');
    return $d;
  }

  // ── encodings ──────────────────────────────────────────────────────────────────────────────────────

  /** SEC1 point as canonical limbs [x, y], or null: 33-byte compressed (02/03) or 65-byte uncompressed (04). */
  private static function point(string $pub): ?array
  {
    $len = strlen($pub);
    if ($len === 65) {
      if (ord($pub[0]) !== 0x04) return null;
      $xb = substr($pub, 1, 32); $yb = substr($pub, 33, 32);
      if (strcmp($xb, self::$pB) >= 0 || strcmp($yb, self::$pB) >= 0) return null;
      $x = self::fe($xb); $y = self::fe($yb);
    } elseif ($len === 33) {
      $t = ord($pub[0]);
      if ($t !== 0x02 && $t !== 0x03) return null;
      $xb = substr($pub, 1, 32);
      if (strcmp($xb, self::$pB) >= 0) return null;
      $x = self::fe($xb);
      // y² = x³ + 7, and y = v^((p+1)/4)
      $v = self::canon(self::add(self::mul(self::sqr($x), $x), self::SEVEN));
      $y = self::canon(self::sqrt($v));
      // ⚠ That exponentiation always returns SOMETHING. If v was not a residue the result does not
      //   satisfy the curve, and skipping this check accepts points that are not on the curve at all.
      if (self::canon(self::sqr($y)) !== $v) return null;
      if (($y[0] & 1) !== ($t & 1)) $y = self::canon(self::neg($y));
    } else {
      return null;
    }
    // on-curve check, for the uncompressed path and as a belt for the compressed one
    return self::canon(self::sqr($y)) === self::canon(self::add(self::mul(self::sqr($x), $x), self::SEVEN))
      ? [$x, $y] : null;
  }

  /**
   * SEC1 point: 33-byte compressed (02/03) or 65-byte uncompressed (04).
   * @return array{string,string}|null x and y, 32 big-endian bytes each
   */
  public static function decodePoint(string $pub): ?array
  {
    self::init();
    $q = self::point($pub);
    return $q === null ? null : [self::feBytes($q[0]), self::feBytes($q[1])];
  }

  /**
   * DER SEQUENCE { INTEGER r, INTEGER s }.
   *
   * ⚠⚠⚠ STRICT BY DEFAULT: nothing may follow the sequence. An earlier version silently tolerated a
   * trailing byte so a Bitcoin sighash-type byte would "just work" — and a differential sweep against
   * openssl caught it on **200 of 200 keypairs**: openssl refused, we accepted.
   * ⇒ ★★ The tolerance is CORRECT for a Bitcoin signature and WRONG for a chain entry signature, where
   *   a trailing byte is simply malformed. **One function silently doing both is how a subtle
   *   acceptance difference ships.** So the caller says which it has, and `$allowTrailing` is the only
   *   way to get the lenient behaviour.
   * ⚠ A Bitcoin signature's sighash byte is NOT part of the signature — it says which preimage to
   *   build — so it must be stripped before DER parsing or the DER is malformed for the wrong reason.
   * @return array{string,string}|null r and s as big-endian bytes: 32 bytes, or longer for a value of more than 32
   *                                   significant bytes. A needlessly padded integer is read as its value.
   */
  public static function decodeDer(string $sig, bool $allowTrailing = false): ?array
  {
    $n = strlen($sig);
    if ($n < 8 || ord($sig[0]) !== 0x30) return null;
    $len = ord($sig[1]);
    if (2 + $len > $n) return null;                          // truncated
    if (!$allowTrailing && 2 + $len !== $n) return null;     // ⛔ trailing bytes: malformed, not lenient
    $i = 2;
    $rd = self::derInt($sig, $i, 2 + $len);   if ($rd === null) return null;
    $sd = self::derInt($sig, $i, 2 + $len);   if ($sd === null) return null;
    if ($i !== 2 + $len) return null;            // trailing junk INSIDE the sequence
    return [$rd, $sd];
  }

  private static function derInt(string $b, int &$i, int $end): ?string
  {
    if ($i + 2 > $end || ord($b[$i]) !== 0x02) return null;
    $l = ord($b[$i + 1]);
    if ($l === 0 || $i + 2 + $l > $end) return null;
    $v = substr($b, $i + 2, $l);
    if (ord($v[0]) & 0x80) return null;          // negative: not a valid ECDSA component
    $i += 2 + $l;
    return str_pad(ltrim($v, "\0"), 32, "\0", STR_PAD_LEFT);
  }

  /** 1 <= v < n, for an integer as decodeDer() gives it. */
  private static function inRange(string $v): bool
  {
    return strlen($v) === 32 && $v !== self::Z32 && strcmp($v, self::$nB) < 0;
  }

  // ── the public key from a private one ──────────────────────────────────────────────────────────────
  /**
   * @param GMP|int|string $d private key, 0 < d < n: 32 big-endian bytes, an int, or a GMP number
   * @param bool $compressed  33-byte SEC1 (the default everywhere modern) or 65-byte
   * ⚠⚠ SECRET SCALAR: see the header note. The multiply is not constant time and cannot honestly be
   *    made so in PHP. This is safe where the host is not shared with an adversary who can time it.
   */
  public static function publicKey(GMP|int|string $d, bool $compressed = true): string
  {
    self::init();
    $q = self::affine(self::mulBlinded(self::secret($d)));   // ⚠ secret scalar
    if ($q === null) throw new RuntimeException('degenerate public key');
    $x = self::feBytes($q[0]);
    return $compressed ? chr(2 + ($q[1][0] & 1)) . $x : "\x04" . $x . self::feBytes($q[1]);
  }

  // ── signing ────────────────────────────────────────────────────────────────────────────────────────

  /**
   * One RFC 6979 candidate: [r, s, R's y is odd, R's x >= n], r and s as 32 bytes, or null when r or s is 0.
   * ⚠ r or s hitting zero is astronomically unlikely and MUST still be handled: RFC 6979 says step
   *   the generator forward, NOT pick a fresh random k, because a random retry reintroduces the RNG.
   */
  private static function signWith(string $d, string $digest32, int $attempt): ?array
  {
    $k = Rfc6979::k(self::$nB, $d, $digest32, 'sha256', $attempt);
    $R = self::affine(self::mulBlinded($k));          // ⚠ secret scalar
    if ($R === null) return null;
    $x = self::feBytes($R[0]);
    $high = strcmp($x, self::$nB) >= 0;
    $r = $high ? self::unlimbs(self::bigSub(self::limbs($x, 26), self::$nL), 26, 32) : $x;   // x mod n: x < p < 2n
    if ($r === self::Z32) return null;
    // ★ The INVERSION leaks too, so blind it multiplicatively: (k·t)⁻¹·t == k⁻¹, and the inverse
    //   then operates on a value the attacker cannot predict. Same answer, different work.
    $t = self::scMod(random_bytes(32));
    if ($t === self::Z32) $t = str_repeat("\0", 31) . "\x01";
    $kt = self::scInv(self::scMul($k, $t));
    if ($kt === self::Z32) return null;
    $kinv = self::scMul($kt, $t);
    $e = Rfc6979::bits2int($digest32, 256);
    $s = self::scMul($kinv, self::scAdd($e, self::scMul($r, $d)));
    if ($s === self::Z32) return null;
    return [$r, $s, $R[1][0] & 1, $high];
  }

  /**
   * Deterministic ECDSA (RFC 6979). Returns DER `SEQUENCE { INTEGER r, INTEGER s }`.
   *
   * ⚠⚠⚠ There is NO random number generator in this path. See rfc6979.php for why that is the whole
   *   point: a repeated or biased `k` hands over the private key, and an RNG is the thing that goes
   *   wrong quietly on a cheap host, in a VM snapshot, or in a container that starts with the same seed.
   *
   * @param GMP|int|string $d the private key, as publicKey() takes it
   * @param string $digest32 the 32-byte digest, ALREADY hashed by the caller — as with verifyDigest(),
   *                         so the choice of single or double SHA-256 is visible at the call site.
   * @param bool   $lowS     ⚠ NOT a protocol rule. jetmora does not inherit LOW_S and 0.1.3 has none;
   *                         Chronicle removed it. But a BROADCASTER can still refuse a high-S signature
   *                         — this project has had a conformant spend refused by exactly that — so a
   *                         wallet broadcasting to BSV passes true. Negating s is deterministic, so the
   *                         signature stays reproducible either way.
   */
  public static function sign(GMP|int|string $d, string $digest32, bool $lowS = false): string
  {
    self::init();
    if (strlen($digest32) !== 32) throw new InvalidArgumentException('digest must be 32 bytes');
    $d = self::secret($d);
    for ($attempt = 0; $attempt < 16; $attempt++) {
      $c = self::signWith($d, $digest32, $attempt);
      if ($c === null) continue;
      [$r, $s] = $c;
      if ($lowS && strcmp($s, self::$halfB) > 0) $s = self::scNeg($s);
      return self::encodeDer($r, $s);
    }
    throw new RuntimeException('no usable k after 16 attempts');   // unreachable in practice
  }

  /**
   * RECOVERABLE deterministic ECDSA, low-s: `[r, s, recid]` where recid (0..3) says which point R was, so a verifier
   * holding only the signature can recover the key (Antelope/WAX, and Bitcoin message signatures, need it).
   * `$accept` may refuse a result (WAX refuses "non-canonical" r or s): the RFC 6979 generator then steps forward,
   * exactly as for r or s = 0 - never a fresh random k.
   * r and s, to `$accept` and in the result, are GMP numbers when `$d` is one, and 32 big-endian bytes otherwise.
   */
  public static function signRecoverable(GMP|int|string $d, string $digest32, ?callable $accept = null): array
  {
    self::init();
    if (strlen($digest32) !== 32) throw new InvalidArgumentException('digest must be 32 bytes');
    $gmp = $d instanceof GMP;
    $d = self::secret($d);
    for ($attempt = 0; $attempt < 256; $attempt++) {
      $c = self::signWith($d, $digest32, $attempt);
      if ($c === null) continue;
      [$r, $s, $odd, $high] = $c;
      $recid = $odd | ($high ? 2 : 0);
      if (strcmp($s, self::$halfB) > 0) { $s = self::scNeg($s); $recid ^= 1; }   // low-s flips R's parity
      if ($gmp) { $r = self::toGmp($r); $s = self::toGmp($s); }
      if ($accept !== null && !$accept($r, $s, $recid)) continue;
      return [$r, $s, $recid];
    }
    throw new RuntimeException('no acceptable signature after 256 attempts');
  }

  /**
   * DER, with the leading-zero rule that a naive encoder gets wrong. r and s as big-endian bytes of any length, an
   * int, or a GMP number; a negative number is encoded as its magnitude.
   */
  public static function encodeDer(GMP|int|string $r, GMP|int|string $s): string
  {
    $enc = function (GMP|int|string $v): string {
      $b = ltrim(is_string($v) ? $v : self::magnitude($v)[0], "\0");
      if ($b === '') $b = "\x00";
      // ⚠ DER INTEGERs are SIGNED: a high top bit needs a 0x00 in front or the value reads negative.
      if (ord($b[0]) & 0x80) $b = "\x00" . $b;
      return "\x02" . chr(strlen($b)) . $b;
    };
    $body = $enc($r) . $enc($s);
    return "\x30" . chr(strlen($body)) . $body;
  }

  // ── verification ───────────────────────────────────────────────────────────────────────────────────
  /**
   * SEC1 §4.1.4. `$msg32` is the 32-byte digest ALREADY COMPUTED by the caller.
   * ★ Taking the digest rather than the message is deliberate: Bitcoin signs a DOUBLE sha256, and a
   *   verifier that hashes once internally silently disagrees with it. Making the caller hash makes
   *   the choice visible at the call site instead of hidden in here.
   * ⚠ `$allowTrailing` permits ONE thing: bytes after the DER sequence, which is what a Bitcoin
   *   signature's appended sighash-type byte looks like. ⛔ Default is STRICT — see decodeDer().
   */
  public static function verifyDigest(string $sig, string $pub, string $msg32,
                                      bool $allowTrailing = false): bool
  {
    self::init();
    if (strlen($msg32) !== 32) return false;
    $der = self::decodeDer($sig, $allowTrailing);   if ($der === null) return false;
    $q   = self::point($pub);                       if ($q === null)   return false;
    [$r, $s] = $der;
    if (!self::inRange($r) || !self::inRange($s)) return false;

    $w  = self::scInv($s);
    if ($w === self::Z32) return false;
    $u1 = self::scMul($msg32, $w);                   // 256-bit curve: the digest is e, no truncation
    $u2 = self::scMul($r, $w);
    $pt = self::mulAdd($u1, $q, $u2);
    if ($pt === null) return false;
    // x(R) mod n == r without an inversion: x = X/Z², and x < p < 2n, so x mod n == r means x == r, or x == r + n
    // when r + n < p.
    [$x, , $z] = $pt;
    $zz = self::sqr($z);
    $rf = self::fe($r);
    if (self::isZero(self::sub($x, self::mul($rf, $zz)))) return true;
    if (strcmp($r, self::$pnB) >= 0) return false;
    return self::isZero(self::sub($x, self::mul(self::add($rf, self::$nF), $zz)));
  }
}
