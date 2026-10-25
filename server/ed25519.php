<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── Ed25519 VERIFICATION BY LIBSODIUM 1.0.22's RULES, NO DEPENDENCIES ───────────────────────────────
//
// One verdict on every host. A tick's ED25519-CHECKSIG and a 32-byte append key are checked here, and never by
// ext/sodium, even where it is loaded: libsodium has tightened its rules from version to version, so a verdict that
// followed the host's library would differ from one host to the next. This file fixes the rules to the ones
// libsodium 1.0.22 applies (src/libsodium/crypto_sign/ed25519/ref10/open.c), in its order, and verify-ed25519.php
// holds it to them: ext/sodium 1.0.22 is the oracle, case by case, and its verdicts are pinned as a digest for a host
// that has no sodium.
//
// A signature is R ‖ S, 64 bytes; a key A is 32 bytes. The signature verifies when
//   1  S < L                                                        sc25519_is_canonical
//   2  R is none of the small-order encodings                       ge25519_has_small_order
//   3  A is canonical: its y, the sign bit cleared, is below p      ge25519_is_canonical
//   4  A is none of the small-order encodings                       ge25519_has_small_order
//   5  A is a point of the curve                                    ge25519_frombytes_negate_vartime
//   6  [S]B − [h]A, encoded, is R byte for byte, h = SHA-512(R ‖ A ‖ M) mod L
// The small-order encodings are the 14 that decode to a point of order 1, 2, 4 or 8: seven y values (0, 1, the two of
// order 8, p − 1, and p and p + 1, which read as 0 and 1), each with either sign bit. The equation is the cofactorless
// one, so a key with a small-order component (mixed order) verifies exactly when the equation holds. R is never
// decoded: an R that is not the canonical encoding of a point (y ≥ p, x = 0 with the sign bit set, a y off the curve)
// can never equal the encoding rule 6 computes.
// Any other input gives false, a wrong length included. Nothing here throws for bad input.
//
// ⚠ No signature anyone can build shows rule 3 in a verdict. The non-canonical keys that rule 4 lets through are those
//   whose y mod p is 2 to 18, and a signature that passes rule 6 under one of them needs the discrete logarithm of a point
//   with that y. The rule is here because libsodium applies it; verify-ed25519.php checks that it is the rule that
//   refuses those keys.
//
// ── THE ARITHMETIC ───────────────────────────────────────────────────────────────────────────────────
// ref10's (Bernstein, Duif, Lange, Schwabe and Yang), as libsodium and sodium_compat carry it. A field element mod
// p = 2^255 − 19 is ten signed limbs at bits 0, 26, 51, 77, 102, 128, 153, 179, 204 and 230, alternately 26 and 25 bits
// wide. Points are extended twisted Edwards coordinates, and the addition law is complete on this curve (d is not a
// square), so no input meets an exceptional case: a double, the identity and a point of small order all go through
// the same formulas. The formulas and the field code are ported from sodium_compat with PHP's own int multiply.
//
// mul(), sq() and sq2() return limbs within 2^25 and 2^24, give or take one percent ("reduced"). A column of mul()
// is at most 249·2^51 times the product of its operands' largest limbs in units of 2^26 and 2^25, so it stays below
// 2^63 while the two operands, in units of a reduced limb, multiply to at most 64. Each point formula below gives its
// operands' sizes; the largest product is 9. Sums and differences therefore go into a multiply without a carry.
// ⚠⚠ PHP turns an int multiply that overflows into a float without a word, and a shift that overflows wraps. Either
//    would give a wrong verdict, not an error, so every bound here is a correctness rule.
// Bytes are little-endian, as Ed25519 writes them. Scalars compare as reversed bytes with strcmp, never `<`, which
// compares numeric-looking strings as numbers.
//
// ★ Constant time is not a goal: a signature, a key and a message are public, and there is no secret here to leak by
//   timing. This is a verifier, never a signer; signing stays with sodium.
//
// The field and point code is ported from sodium_compat (src/Core/Curve25519.php, src/Core/Ed25519.php), and the
// rules and the small-order list from libsodium (open.c, crypto_core/ed25519/ref10/ed25519_ref10.c at 1.0.22-RELEASE).
// Both are ISC, and both ask that their notice be kept:
//
//   ISC License
//
//   Copyright (c) 2016-2023, Paragon Initiative Enterprises <security at paragonie dot com>
//   Copyright (c) 2013-2019, Frank Denis <j at pureftpd dot org>
//
//   Permission to use, copy, modify, and/or distribute this software for any
//   purpose with or without fee is hereby granted, provided that the above
//   copyright notice and this permission notice appear in all copies.
//
//   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//   ISC License
//
//   Copyright (c) 2013-2026
//   Frank Denis <j at pureftpd dot org>
//
//   Permission to use, copy, modify, and/or distribute this software for any
//   purpose with or without fee is hereby granted, provided that the above
//   copyright notice and this permission notice appear in all copies.
//
//   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
declare(strict_types=1);

final class Ed25519
{
  /** p = 2^255 − 19 and L = 2^252 + 27742317777372353535851937790883648493, big-endian. */
  private const P = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed';
  private const L = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';
  /** d = −121665/121666 and 2d, and sqrt(−1) = 2^((p − 1)/4), canonical, big-endian. */
  private const D      = '52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3';
  private const D2     = '2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159';
  private const SQRTM1 = '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0';

  /**
   * B, 3B, 5B, ..., 15B as affine [x, y], big-endian: the odd multiples a signed window of 5 bits reads. Fixed here
   * rather than built per call, since a PHP-FPM request starts with empty statics. verify-ed25519.php rebuilds them
   * from B.
   */
  private const B_ODD = [
    ['216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a', '6666666666666666666666666666666666666666666666666666666666666658'],   // B
    ['67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25c', '1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4'],   // 3B
    ['49fda73eade3587bfcef7cf7d12da5de5c2819f93e1be1a591409cc0322ef233', '5f4825b298feae6fe02c6e148992466631282eca89430b5d10d21f83d676c8ed'],   // 5B
    ['14568685fcf4bd4ee9e3ee194b1d810783e809f3bbf1ce955855981af50e4107', '31c563e32b47d52f87ce6468dd36ad41f0882b46f7abf23d12c4c4b59f4062b8'],   // 7B
    ['357cc970c80071651bf336e06f9422b886d80e5c2e4e0294d3e023065185715c', '7f3d23c2c2dd0df4b2befce956f2d2fd1f789013236e4430c74e44845522f1c0'],   // 9B
    ['14e528b1154be417b6cf078dd6712438d381a5b2c593d552ff2fd2c1207cf3cb', '2d9082313f21ab975a6f7ce340ff0fce1258591c3c9c58d4308f2dc36a033713'],   // 11B
    ['107427e0d5f366ccdb33adf0282d304f8843e3e88d22b7b83780e073b7c05fed', '12dbb00ded538b7478466022d2da89b83740cfb2289a272387efe1aeea401f80'],   // 13B
    ['4f162deaec2ec435dc5ac6f95d20419ed9631374770189cb90617f3e66a18dc1', '12cbfb2d04ff22f55162f70164d29331ace5af18a19a9aa1946d4cc4ad2e5cdf'],   // 15B
  ];

  /**
   * The seven y values of the small-order points, little-endian with the sign bit cleared, as libsodium lists them:
   * 0 (order 4), 1 (order 1), the two of order 8, p − 1 (order 2), and p and p + 1, which read as 0 and 1.
   */
  private const SMALL_ORDER = [
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  ];

  private const ZERO = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  private const ONE  = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  private const Z32  = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

  /** p and L as 32 big-endian bytes; the small-order y values as keys. */
  private static ?string $pB = null, $lB = null;
  private static array $small = [];
  /** d, 2d and sqrt(−1) as field elements; B_ODD as precomputed points [y + x, y − x, 2dxy]. */
  private static array $d = [], $d2 = [], $sqrtm1 = [], $bi = [];

  private static function init(): void
  {
    if (self::$pB !== null) return;
    // the limbs' products are 52 bits: a narrower int cannot hold one, so this host cannot answer
    if (PHP_INT_SIZE < 8) throw new RuntimeException('Ed25519 needs 64-bit integers on this host');
    foreach (self::SMALL_ORDER as $y) self::$small[hex2bin($y)] = true;
    self::$d = self::fe(strrev(hex2bin(self::D)));
    self::$d2 = self::fe(strrev(hex2bin(self::D2)));
    self::$sqrtm1 = self::fe(strrev(hex2bin(self::SQRTM1)));
    foreach (self::B_ODD as $i => [$x, $y]) {
      $x = self::fe(strrev(hex2bin($x))); $y = self::fe(strrev(hex2bin($y)));
      self::$bi[$i] = [self::add($y, $x), self::sub($y, $x), self::mul(self::mul($x, $y), self::$d2)];
    }
    self::$lB = hex2bin(self::L);
    self::$pB = hex2bin(self::P);
  }

  // ── the verdict ────────────────────────────────────────────────────────────────────────────────────

  /**
   * RFC 8032 Ed25519 over the message as given, with libsodium 1.0.22's verdict: true when $sig is a valid signature
   * of $msg under the key $pub. False for anything else, and for a signature that is not 64 bytes or a key that is
   * not 32.
   */
  public static function verify(string $sig, string $msg, string $pub): bool
  {
    return self::refusal($sig, $msg, $pub) === null;
  }

  /** The rule that refuses the signature, by the header's numbering, or null when it verifies. */
  private static function refusal(string $sig, string $msg, string $pub): ?string
  {
    if (strlen($sig) !== 64 || strlen($pub) !== 32) return 'lengths';
    self::init();
    $r = substr($sig, 0, 32);
    $s = substr($sig, 32);
    if (strcmp(strrev($s), self::$lB) >= 0) return '1 S < L';
    if (self::smallOrder($r)) return '2 R small order';
    if (!self::canonical($pub)) return '3 A canonical';
    if (self::smallOrder($pub)) return '4 A small order';
    $a = self::decodeNegated($pub);
    if ($a === null) return '5 A on the curve';
    $h = self::scReduce(hash('sha512', $r . $pub . $msg, true));
    if (self::encode(self::mulAdd($h, $a, $s)) !== $r) return '6 the equation';
    return null;
  }

  /** One of the 14 small-order encodings: its y, the sign bit cleared, is one of the seven. */
  private static function smallOrder(string $b): bool
  {
    return isset(self::$small[substr($b, 0, 31) . chr(ord($b[31]) & 0x7f)]);
  }

  /** y, the sign bit cleared, is below p. */
  private static function canonical(string $b): bool
  {
    return strcmp(strrev(substr($b, 0, 31) . chr(ord($b[31]) & 0x7f)), self::$pB) < 0;
  }

  // ── the field: ten limbs, 26 and 25 bits ───────────────────────────────────────────────────────────

  /** 32 little-endian bytes as limbs, the top bit dropped, as fe25519_frombytes reads them. Limbs in [0, 2^26). */
  private static function fe(string $s): array
  {
    $w = unpack('V8', $s);
    return [
      $w[1] & 0x3FFFFFF,
      (($w[1] >> 26) | ($w[2] << 6)) & 0x1FFFFFF,
      (($w[2] >> 19) | ($w[3] << 13)) & 0x3FFFFFF,
      (($w[3] >> 13) | ($w[4] << 19)) & 0x1FFFFFF,
      ($w[4] >> 6) & 0x3FFFFFF,
      $w[5] & 0x1FFFFFF,
      (($w[5] >> 25) | ($w[6] << 7)) & 0x3FFFFFF,
      (($w[6] >> 19) | ($w[7] << 13)) & 0x1FFFFFF,
      (($w[7] >> 12) | ($w[8] << 20)) & 0x3FFFFFF,
      ($w[8] >> 6) & 0x1FFFFFF,
    ];
  }

  /**
   * The canonical 32 bytes of an element, fe25519_tobytes: q = floor((h + 19·h9/2^25 rounded) / 2^255) is how many
   * times p comes off, then a carry from the bottom drops q·2^255. Exact for any limbs far below 2^40.
   */
  private static function bytes(array $h): string
  {
    [$h0, $h1, $h2, $h3, $h4, $h5, $h6, $h7, $h8, $h9] = $h;
    $q = (19 * $h9 + (1 << 24)) >> 25;
    $q = ($h0 + $q) >> 26;
    $q = ($h1 + $q) >> 25;
    $q = ($h2 + $q) >> 26;
    $q = ($h3 + $q) >> 25;
    $q = ($h4 + $q) >> 26;
    $q = ($h5 + $q) >> 25;
    $q = ($h6 + $q) >> 26;
    $q = ($h7 + $q) >> 25;
    $q = ($h8 + $q) >> 26;
    $q = ($h9 + $q) >> 25;
    $h0 += 19 * $q;
    $h1 += $h0 >> 26; $h0 &= 0x3FFFFFF;
    $h2 += $h1 >> 25; $h1 &= 0x1FFFFFF;
    $h3 += $h2 >> 26; $h2 &= 0x3FFFFFF;
    $h4 += $h3 >> 25; $h3 &= 0x1FFFFFF;
    $h5 += $h4 >> 26; $h4 &= 0x3FFFFFF;
    $h6 += $h5 >> 25; $h5 &= 0x1FFFFFF;
    $h7 += $h6 >> 26; $h6 &= 0x3FFFFFF;
    $h8 += $h7 >> 25; $h7 &= 0x1FFFFFF;
    $h9 += $h8 >> 26; $h8 &= 0x3FFFFFF;
    $h9 &= 0x1FFFFFF;                                  // what is above bit 255 is q, and comes off
    return pack('V8',
      $h0 | (($h1 << 26) & 0xFFFFFFFF),
      ($h1 >> 6) | (($h2 << 19) & 0xFFFFFFFF),
      ($h2 >> 13) | (($h3 << 13) & 0xFFFFFFFF),
      ($h3 >> 19) | ($h4 << 6),
      $h5 | (($h6 << 25) & 0xFFFFFFFF),
      ($h6 >> 7) | (($h7 << 19) & 0xFFFFFFFF),
      ($h7 >> 13) | (($h8 << 12) & 0xFFFFFFFF),
      ($h8 >> 20) | ($h9 << 6));
  }

  private static function isZero(array $f): bool
  {
    return self::bytes($f) === self::Z32;
  }

  /** The low bit of the canonical value: the sign of x in an encoding. */
  private static function isNegative(array $f): int
  {
    return ord(self::bytes($f)[0]) & 1;
  }

  /**
   * f·g mod p, reduced: fe25519_mul. Products that land at 2^255 and above come down times 19, and a product of two
   * odd limbs (both 25 bits) is doubled, since 25 + 25 is one bit short of the column it lands in. The carries round
   * to the nearest, so each limb ends signed and centred on 0.
   */
  private static function mul(array $f, array $g): array
  {
    [$f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9] = $f;
    [$g0, $g1, $g2, $g3, $g4, $g5, $g6, $g7, $g8, $g9] = $g;
    $g1_19 = 19 * $g1; $g2_19 = 19 * $g2; $g3_19 = 19 * $g3; $g4_19 = 19 * $g4; $g5_19 = 19 * $g5;
    $g6_19 = 19 * $g6; $g7_19 = 19 * $g7; $g8_19 = 19 * $g8; $g9_19 = 19 * $g9;
    $f1_2 = 2 * $f1; $f3_2 = 2 * $f3; $f5_2 = 2 * $f5; $f7_2 = 2 * $f7; $f9_2 = 2 * $f9;
    $h0 = $f0 * $g0 + $f1_2 * $g9_19 + $f2 * $g8_19 + $f3_2 * $g7_19 + $f4 * $g6_19 + $f5_2 * $g5_19 + $f6 * $g4_19 + $f7_2 * $g3_19 + $f8 * $g2_19 + $f9_2 * $g1_19;
    $h1 = $f0 * $g1 + $f1 * $g0 + $f2 * $g9_19 + $f3 * $g8_19 + $f4 * $g7_19 + $f5 * $g6_19 + $f6 * $g5_19 + $f7 * $g4_19 + $f8 * $g3_19 + $f9 * $g2_19;
    $h2 = $f0 * $g2 + $f1_2 * $g1 + $f2 * $g0 + $f3_2 * $g9_19 + $f4 * $g8_19 + $f5_2 * $g7_19 + $f6 * $g6_19 + $f7_2 * $g5_19 + $f8 * $g4_19 + $f9_2 * $g3_19;
    $h3 = $f0 * $g3 + $f1 * $g2 + $f2 * $g1 + $f3 * $g0 + $f4 * $g9_19 + $f5 * $g8_19 + $f6 * $g7_19 + $f7 * $g6_19 + $f8 * $g5_19 + $f9 * $g4_19;
    $h4 = $f0 * $g4 + $f1_2 * $g3 + $f2 * $g2 + $f3_2 * $g1 + $f4 * $g0 + $f5_2 * $g9_19 + $f6 * $g8_19 + $f7_2 * $g7_19 + $f8 * $g6_19 + $f9_2 * $g5_19;
    $h5 = $f0 * $g5 + $f1 * $g4 + $f2 * $g3 + $f3 * $g2 + $f4 * $g1 + $f5 * $g0 + $f6 * $g9_19 + $f7 * $g8_19 + $f8 * $g7_19 + $f9 * $g6_19;
    $h6 = $f0 * $g6 + $f1_2 * $g5 + $f2 * $g4 + $f3_2 * $g3 + $f4 * $g2 + $f5_2 * $g1 + $f6 * $g0 + $f7_2 * $g9_19 + $f8 * $g8_19 + $f9_2 * $g7_19;
    $h7 = $f0 * $g7 + $f1 * $g6 + $f2 * $g5 + $f3 * $g4 + $f4 * $g3 + $f5 * $g2 + $f6 * $g1 + $f7 * $g0 + $f8 * $g9_19 + $f9 * $g8_19;
    $h8 = $f0 * $g8 + $f1_2 * $g7 + $f2 * $g6 + $f3_2 * $g5 + $f4 * $g4 + $f5_2 * $g3 + $f6 * $g2 + $f7_2 * $g1 + $f8 * $g0 + $f9_2 * $g9_19;
    $h9 = $f0 * $g9 + $f1 * $g8 + $f2 * $g7 + $f3 * $g6 + $f4 * $g5 + $f5 * $g4 + $f6 * $g3 + $f7 * $g2 + $f8 * $g1 + $f9 * $g0;
    return self::carry($h0, $h1, $h2, $h3, $h4, $h5, $h6, $h7, $h8, $h9);
  }

  /** f² mod p: fe25519_sq, mul() with each cross product taken once and doubled. */
  private static function sq(array $f): array
  {
    [$f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9] = $f;
    $f0_2 = 2 * $f0; $f1_2 = 2 * $f1; $f2_2 = 2 * $f2; $f3_2 = 2 * $f3; $f4_2 = 2 * $f4;
    $f5_2 = 2 * $f5; $f6_2 = 2 * $f6; $f7_2 = 2 * $f7;
    $f5_38 = 38 * $f5; $f6_19 = 19 * $f6; $f7_38 = 38 * $f7; $f8_19 = 19 * $f8; $f9_38 = 38 * $f9;
    $h0 = $f0 * $f0 + $f1_2 * $f9_38 + $f2_2 * $f8_19 + $f3_2 * $f7_38 + $f4_2 * $f6_19 + $f5 * $f5_38;
    $h1 = $f0_2 * $f1 + $f2 * $f9_38 + $f3_2 * $f8_19 + $f4 * $f7_38 + $f5_2 * $f6_19;
    $h2 = $f0_2 * $f2 + $f1_2 * $f1 + $f3_2 * $f9_38 + $f4_2 * $f8_19 + $f5_2 * $f7_38 + $f6 * $f6_19;
    $h3 = $f0_2 * $f3 + $f1_2 * $f2 + $f4 * $f9_38 + $f5_2 * $f8_19 + $f6 * $f7_38;
    $h4 = $f0_2 * $f4 + $f1_2 * $f3_2 + $f2 * $f2 + $f5_2 * $f9_38 + $f6_2 * $f8_19 + $f7 * $f7_38;
    $h5 = $f0_2 * $f5 + $f1_2 * $f4 + $f2_2 * $f3 + $f6 * $f9_38 + $f7_2 * $f8_19;
    $h6 = $f0_2 * $f6 + $f1_2 * $f5_2 + $f2_2 * $f4 + $f3_2 * $f3 + $f7_2 * $f9_38 + $f8 * $f8_19;
    $h7 = $f0_2 * $f7 + $f1_2 * $f6 + $f2_2 * $f5 + $f3_2 * $f4 + $f8 * $f9_38;
    $h8 = $f0_2 * $f8 + $f1_2 * $f7_2 + $f2_2 * $f6 + $f3_2 * $f5_2 + $f4 * $f4 + $f9 * $f9_38;
    $h9 = $f0_2 * $f9 + $f1_2 * $f8 + $f2_2 * $f7 + $f3_2 * $f6 + $f4_2 * $f5;
    return self::carry($h0, $h1, $h2, $h3, $h4, $h5, $h6, $h7, $h8, $h9);
  }

  /** 2f² mod p: fe25519_sq2, sq()'s columns doubled before the carry. A column is then twice sq()'s, so the operand
   *  may be at most 5 reduced limbs; the one caller squares a Z, which is 1. */
  private static function sq2(array $f): array
  {
    [$f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9] = $f;
    $f0_2 = 2 * $f0; $f1_2 = 2 * $f1; $f2_2 = 2 * $f2; $f3_2 = 2 * $f3; $f4_2 = 2 * $f4;
    $f5_2 = 2 * $f5; $f6_2 = 2 * $f6; $f7_2 = 2 * $f7;
    $f5_38 = 38 * $f5; $f6_19 = 19 * $f6; $f7_38 = 38 * $f7; $f8_19 = 19 * $f8; $f9_38 = 38 * $f9;
    $h0 = $f0 * $f0 + $f1_2 * $f9_38 + $f2_2 * $f8_19 + $f3_2 * $f7_38 + $f4_2 * $f6_19 + $f5 * $f5_38;
    $h1 = $f0_2 * $f1 + $f2 * $f9_38 + $f3_2 * $f8_19 + $f4 * $f7_38 + $f5_2 * $f6_19;
    $h2 = $f0_2 * $f2 + $f1_2 * $f1 + $f3_2 * $f9_38 + $f4_2 * $f8_19 + $f5_2 * $f7_38 + $f6 * $f6_19;
    $h3 = $f0_2 * $f3 + $f1_2 * $f2 + $f4 * $f9_38 + $f5_2 * $f8_19 + $f6 * $f7_38;
    $h4 = $f0_2 * $f4 + $f1_2 * $f3_2 + $f2 * $f2 + $f5_2 * $f9_38 + $f6_2 * $f8_19 + $f7 * $f7_38;
    $h5 = $f0_2 * $f5 + $f1_2 * $f4 + $f2_2 * $f3 + $f6 * $f9_38 + $f7_2 * $f8_19;
    $h6 = $f0_2 * $f6 + $f1_2 * $f5_2 + $f2_2 * $f4 + $f3_2 * $f3 + $f7_2 * $f9_38 + $f8 * $f8_19;
    $h7 = $f0_2 * $f7 + $f1_2 * $f6 + $f2_2 * $f5 + $f3_2 * $f4 + $f8 * $f9_38;
    $h8 = $f0_2 * $f8 + $f1_2 * $f7_2 + $f2_2 * $f6 + $f3_2 * $f5_2 + $f4 * $f4 + $f9 * $f9_38;
    $h9 = $f0_2 * $f9 + $f1_2 * $f8 + $f2_2 * $f7 + $f3_2 * $f6 + $f4_2 * $f5;
    return self::carry(2 * $h0, 2 * $h1, 2 * $h2, 2 * $h3, 2 * $h4, 2 * $h5, 2 * $h6, 2 * $h7, 2 * $h8, 2 * $h9);
  }

  /**
   * ref10's carry for columns below 2^63: each limb rounded to its width, the carry into the next; what leaves the top
   * limb comes back into the bottom times 19, then the bottom carries once more. The shifts are arithmetic, so a
   * negative column carries as a negative number.
   */
  private static function carry(int $h0, int $h1, int $h2, int $h3, int $h4, int $h5, int $h6, int $h7, int $h8, int $h9): array
  {
    $c = ($h0 + (1 << 25)) >> 26; $h1 += $c; $h0 -= $c << 26;
    $c = ($h4 + (1 << 25)) >> 26; $h5 += $c; $h4 -= $c << 26;
    $c = ($h1 + (1 << 24)) >> 25; $h2 += $c; $h1 -= $c << 25;
    $c = ($h5 + (1 << 24)) >> 25; $h6 += $c; $h5 -= $c << 25;
    $c = ($h2 + (1 << 25)) >> 26; $h3 += $c; $h2 -= $c << 26;
    $c = ($h6 + (1 << 25)) >> 26; $h7 += $c; $h6 -= $c << 26;
    $c = ($h3 + (1 << 24)) >> 25; $h4 += $c; $h3 -= $c << 25;
    $c = ($h7 + (1 << 24)) >> 25; $h8 += $c; $h7 -= $c << 25;
    $c = ($h4 + (1 << 25)) >> 26; $h5 += $c; $h4 -= $c << 26;
    $c = ($h8 + (1 << 25)) >> 26; $h9 += $c; $h8 -= $c << 26;
    $c = ($h9 + (1 << 24)) >> 25; $h0 += 19 * $c; $h9 -= $c << 25;
    $c = ($h0 + (1 << 25)) >> 26; $h1 += $c; $h0 -= $c << 26;
    return [$h0, $h1, $h2, $h3, $h4, $h5, $h6, $h7, $h8, $h9];
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

  /** f squared n times, then times g. */
  private static function sqMul(array $f, int $n, array $g): array
  {
    for ($i = 0; $i < $n; $i++) $f = self::sq($f);
    return self::mul($f, $g);
  }

  /**
   * z^(2^250 − 1) and z^11: the squarings fe25519_invert and fe25519_pow22523 share, by the runs of ones
   * 2^5 − 1, 2^10 − 1, 2^20 − 1, 2^40 − 1, 2^50 − 1, 2^100 − 1, 2^200 − 1 and 2^250 − 1.
   */
  private static function pow250(array $z): array
  {
    $z2   = self::sq($z);
    $z9   = self::mul($z, self::sq(self::sq($z2)));
    $z11  = self::mul($z2, $z9);
    $t5   = self::mul($z9, self::sq($z11));             // 2^5 − 1
    $t10  = self::sqMul($t5, 5, $t5);
    $t20  = self::sqMul($t10, 10, $t10);
    $t40  = self::sqMul($t20, 20, $t20);
    $t50  = self::sqMul($t40, 10, $t10);
    $t100 = self::sqMul($t50, 50, $t50);
    $t200 = self::sqMul($t100, 100, $t100);
    $t250 = self::sqMul($t200, 50, $t50);
    return [$t250, $z11];
  }

  /** 1/z = z^(p − 2) = z^(2^255 − 21): 2^250 − 1, five squarings, times z^11. */
  private static function invert(array $z): array
  {
    [$t250, $z11] = self::pow250($z);
    return self::sqMul($t250, 5, $z11);
  }

  /** z^((p − 5)/8) = z^(2^252 − 3): 2^250 − 1, two squarings, times z. */
  private static function pow22523(array $z): array
  {
    [$t250] = self::pow250($z);
    return self::sqMul($t250, 2, $z);
  }

  // ── points, extended twisted Edwards: −x² + y² = 1 + d·x²·y² ───────────────────────────────────────
  // As ref10 names them:  p2 [X, Y, Z], (X/Z, Y/Z) · p3 [X, Y, Z, T], with T = XY/Z · p1p1 [X, Y, Z, T], (X/Z, Y/T),
  // what a sum or a double gives before its last multiply · cached [Y + X, Y − X, Z, 2dT] · precomp [y + x, y − x, 2dxy],
  // affine. The comments give each multiply's operand sizes in units of a reduced limb.

  /** 2P for a p2 or p3 point, as p1p1: ge25519_p2_dbl. */
  private static function dbl(array $p): array
  {
    $xx = self::sq($p[0]);
    $yy = self::sq($p[1]);                                                    // 2·2: a decoded y is 2
    $zz = self::sq2($p[2]);
    $s  = self::sq(self::add($p[0], $p[1]));                                  // 3·3
    $y  = self::add($yy, $xx);
    $z  = self::sub($yy, $xx);
    return [self::sub($s, $y), $y, $z, self::sub($zz, $z)];                   // 3, 2, 2, 3
  }

  /** p1p1 as p2. */
  private static function p2(array $p): array
  {
    return [self::mul($p[0], $p[3]), self::mul($p[1], $p[2]), self::mul($p[2], $p[3])];   // 3·3, 2·3, 3·3
  }

  /** p1p1 as p3. */
  private static function p3(array $p): array
  {
    return [self::mul($p[0], $p[3]), self::mul($p[1], $p[2]), self::mul($p[2], $p[3]), self::mul($p[0], $p[1])];
  }

  /** p3 as cached. */
  private static function cached(array $p): array
  {
    return [self::add($p[1], $p[0]), self::sub($p[1], $p[0]), $p[2], self::mul($p[3], self::$d2)];   // 3, 3 for a decoded key
  }

  /** p + q for a p3 p and a cached q, as p1p1: ge25519_add. q negated, ge25519_sub, when $minus. */
  private static function addCached(array $p, array $q, bool $minus): array
  {
    $a = self::mul(self::add($p[1], $p[0]), $minus ? $q[1] : $q[0]);          // 2·3
    $b = self::mul(self::sub($p[1], $p[0]), $minus ? $q[0] : $q[1]);
    $t = self::mul($q[3], $p[3]);
    $z = self::mul($p[2], $q[2]);
    $z = self::add($z, $z);
    return $minus ? [self::sub($a, $b), self::add($a, $b), self::sub($z, $t), self::add($z, $t)]
                  : [self::sub($a, $b), self::add($a, $b), self::add($z, $t), self::sub($z, $t)];    // 2, 2, 3, 3
  }

  /** p + q for a p3 p and a precomp q, as p1p1: ge25519_madd. q negated, ge25519_msub, when $minus. */
  private static function addPrecomp(array $p, array $q, bool $minus): array
  {
    $a = self::mul(self::add($p[1], $p[0]), $minus ? $q[1] : $q[0]);          // 2·4: y ± x of B_ODD, read from bytes
    $b = self::mul(self::sub($p[1], $p[0]), $minus ? $q[0] : $q[1]);
    $t = self::mul($q[2], $p[3]);
    $z = self::add($p[2], $p[2]);
    return $minus ? [self::sub($a, $b), self::add($a, $b), self::sub($z, $t), self::add($z, $t)]
                  : [self::sub($a, $b), self::add($a, $b), self::add($z, $t), self::sub($z, $t)];
  }

  /**
   * −A as p3 for the encoding of A, or null when its y has no x on the curve: ge25519_frombytes_negate_vartime.
   * x = u·v³·(u·v⁷)^((p − 5)/8) with u = y² − 1 and v = d·y² + 1 is a square root of u/v when v·x² = u, and becomes one
   * times sqrt(−1) when v·x² = −u; otherwise u/v has none. Then the root whose low bit is NOT the sign bit is kept,
   * which negates A. The same root when x = 0 and the sign bit is set: no such A reaches here (rule 4).
   */
  private static function decodeNegated(string $s): ?array
  {
    $y = self::fe($s);                                                        // 2
    $u = self::sq($y);
    $v = self::add(self::mul($u, self::$d), self::ONE);                       // 1·2
    $u = self::sub($u, self::ONE);
    $v3 = self::mul(self::sq($v), $v);
    $x = self::mul(self::mul(self::sq($v3), $v), $u);
    $x = self::mul(self::mul(self::pow22523($x), $v3), $u);
    $vxx = self::mul(self::sq($x), $v);
    if (!self::isZero(self::sub($vxx, $u))) {
      if (!self::isZero(self::add($vxx, $u))) return null;
      $x = self::mul($x, self::$sqrtm1);
    }
    if (self::isNegative($x) === ord($s[31]) >> 7) $x = self::neg($x);
    return [$x, $y, self::ONE, self::mul($x, $y)];
  }

  /** The encoding of a p2 point: y canonical, the sign of x in the top bit. The one inversion. */
  private static function encode(array $p): string
  {
    $zi = self::invert($p[2]);
    $b = self::bytes(self::mul($p[1], $zi));
    $b[31] = chr(ord($b[31]) | (self::isNegative(self::mul($p[0], $zi)) << 7));
    return $b;
  }

  /**
   * [a]A + [b]B as p2, a and b little-endian of any length and A as p3: ge25519_double_scalarmult_vartime. One
   * doubling a bit shared by both, A's digits read from A, 3A, ..., 15A built here and B's from B_ODD.
   * The group law gives one answer whatever the method.
   */
  private static function mulAdd(string $a, array $A, string $b): array
  {
    $da = self::digits($a);
    $db = self::digits($b);
    $ai = [self::cached($A)];
    $a2 = self::p3(self::dbl($A));
    for ($i = 1; $i < 8; $i++) $ai[$i] = self::cached(self::p3(self::addCached($a2, $ai[$i - 1], false)));
    $r = [self::ZERO, self::ONE, self::ONE];
    for ($i = max(array_key_last($da) ?? -1, array_key_last($db) ?? -1); $i >= 0; $i--) {
      $t = self::dbl($r);
      if (isset($da[$i])) {
        $d = $da[$i];
        $t = self::addCached(self::p3($t), $ai[($d > 0 ? $d : -$d) >> 1], $d < 0);
      }
      if (isset($db[$i])) {
        $d = $db[$i];
        $t = self::addPrecomp(self::p3($t), self::$bi[($d > 0 ? $d : -$d) >> 1], $d < 0);
      }
      $r = self::p2($t);
    }
    return $r;
  }

  /**
   * The signed-window form of a little-endian scalar: [bit position => digit], each digit odd with |digit| < 16,
   * any two at least 5 positions apart, and Σ digit·2^position equal to the scalar.
   */
  private static function digits(string $k): array
  {
    $bits = [];
    foreach (unpack('C*', $k) as $c)
      array_push($bits, $c & 1, ($c >> 1) & 1, ($c >> 2) & 1, ($c >> 3) & 1, ($c >> 4) & 1, ($c >> 5) & 1, ($c >> 6) & 1, $c >> 7);
    $len = count($bits);
    $out = []; $carry = 0; $i = 0;
    while ($i < $len) {
      if ($bits[$i] === $carry) { $i++; continue; }           // this bit plus the carry is even: a zero digit
      $word = $carry;
      for ($j = 0; $j < 5 && $i + $j < $len; $j++) $word += $bits[$i + $j] << $j;
      $carry = ($word >> 4) & 1;                               // past half the window: a negative digit, and carry
      $out[$i] = $word - ($carry << 5);
      $i += 5;
    }
    if ($carry) $out[$i] = 1;
    return $out;
  }

  // ── scalars mod L ──────────────────────────────────────────────────────────────────────────────────

  /**
   * A 64-byte little-endian number mod L, as 32 bytes: sc25519_reduce. Limbs of 21 bits; what is above 2^252 folds
   * down as 2^252 = −(L − 2^252) (mod L), whose limbs are 666643, 470296, 654183, −997805, 136657 and −683901 times
   * 2^21 apart, from the top limb down, with carries between.
   */
  private static function scReduce(string $s): string
  {
    $b = unpack('C*', $s);
    $l3 = fn(int $i): int => $b[$i + 1] | ($b[$i + 2] << 8) | ($b[$i + 3] << 16);
    $l4 = fn(int $i): int => $b[$i + 1] | ($b[$i + 2] << 8) | ($b[$i + 3] << 16) | ($b[$i + 4] << 24);
    $s0  = 2097151 & $l3(0);
    $s1  = 2097151 & ($l4(2) >> 5);
    $s2  = 2097151 & ($l3(5) >> 2);
    $s3  = 2097151 & ($l4(7) >> 7);
    $s4  = 2097151 & ($l4(10) >> 4);
    $s5  = 2097151 & ($l3(13) >> 1);
    $s6  = 2097151 & ($l4(15) >> 6);
    $s7  = 2097151 & ($l3(18) >> 3);
    $s8  = 2097151 & $l3(21);
    $s9  = 2097151 & ($l4(23) >> 5);
    $s10 = 2097151 & ($l3(26) >> 2);
    $s11 = 2097151 & ($l4(28) >> 7);
    $s12 = 2097151 & ($l4(31) >> 4);
    $s13 = 2097151 & ($l3(34) >> 1);
    $s14 = 2097151 & ($l4(36) >> 6);
    $s15 = 2097151 & ($l3(39) >> 3);
    $s16 = 2097151 & $l3(42);
    $s17 = 2097151 & ($l4(44) >> 5);
    $s18 = 2097151 & ($l3(47) >> 2);
    $s19 = 2097151 & ($l4(49) >> 7);
    $s20 = 2097151 & ($l4(52) >> 4);
    $s21 = 2097151 & ($l3(55) >> 1);
    $s22 = 2097151 & ($l4(57) >> 6);
    $s23 = $l4(60) >> 3;

    $s11 += $s23 * 666643; $s12 += $s23 * 470296; $s13 += $s23 * 654183; $s14 -= $s23 * 997805; $s15 += $s23 * 136657; $s16 -= $s23 * 683901;
    $s10 += $s22 * 666643; $s11 += $s22 * 470296; $s12 += $s22 * 654183; $s13 -= $s22 * 997805; $s14 += $s22 * 136657; $s15 -= $s22 * 683901;
    $s9  += $s21 * 666643; $s10 += $s21 * 470296; $s11 += $s21 * 654183; $s12 -= $s21 * 997805; $s13 += $s21 * 136657; $s14 -= $s21 * 683901;
    $s8  += $s20 * 666643; $s9  += $s20 * 470296; $s10 += $s20 * 654183; $s11 -= $s20 * 997805; $s12 += $s20 * 136657; $s13 -= $s20 * 683901;
    $s7  += $s19 * 666643; $s8  += $s19 * 470296; $s9  += $s19 * 654183; $s10 -= $s19 * 997805; $s11 += $s19 * 136657; $s12 -= $s19 * 683901;
    $s6  += $s18 * 666643; $s7  += $s18 * 470296; $s8  += $s18 * 654183; $s9  -= $s18 * 997805; $s10 += $s18 * 136657; $s11 -= $s18 * 683901;

    $c = ($s6 + (1 << 20)) >> 21;  $s7  += $c; $s6  -= $c << 21;
    $c = ($s8 + (1 << 20)) >> 21;  $s9  += $c; $s8  -= $c << 21;
    $c = ($s10 + (1 << 20)) >> 21; $s11 += $c; $s10 -= $c << 21;
    $c = ($s12 + (1 << 20)) >> 21; $s13 += $c; $s12 -= $c << 21;
    $c = ($s14 + (1 << 20)) >> 21; $s15 += $c; $s14 -= $c << 21;
    $c = ($s16 + (1 << 20)) >> 21; $s17 += $c; $s16 -= $c << 21;
    $c = ($s7 + (1 << 20)) >> 21;  $s8  += $c; $s7  -= $c << 21;
    $c = ($s9 + (1 << 20)) >> 21;  $s10 += $c; $s9  -= $c << 21;
    $c = ($s11 + (1 << 20)) >> 21; $s12 += $c; $s11 -= $c << 21;
    $c = ($s13 + (1 << 20)) >> 21; $s14 += $c; $s13 -= $c << 21;
    $c = ($s15 + (1 << 20)) >> 21; $s16 += $c; $s15 -= $c << 21;

    $s5 += $s17 * 666643; $s6 += $s17 * 470296; $s7 += $s17 * 654183; $s8 -= $s17 * 997805; $s9 += $s17 * 136657; $s10 -= $s17 * 683901;
    $s4 += $s16 * 666643; $s5 += $s16 * 470296; $s6 += $s16 * 654183; $s7 -= $s16 * 997805; $s8 += $s16 * 136657; $s9  -= $s16 * 683901;
    $s3 += $s15 * 666643; $s4 += $s15 * 470296; $s5 += $s15 * 654183; $s6 -= $s15 * 997805; $s7 += $s15 * 136657; $s8  -= $s15 * 683901;
    $s2 += $s14 * 666643; $s3 += $s14 * 470296; $s4 += $s14 * 654183; $s5 -= $s14 * 997805; $s6 += $s14 * 136657; $s7  -= $s14 * 683901;
    $s1 += $s13 * 666643; $s2 += $s13 * 470296; $s3 += $s13 * 654183; $s4 -= $s13 * 997805; $s5 += $s13 * 136657; $s6  -= $s13 * 683901;
    $s0 += $s12 * 666643; $s1 += $s12 * 470296; $s2 += $s12 * 654183; $s3 -= $s12 * 997805; $s4 += $s12 * 136657; $s5  -= $s12 * 683901;
    $s12 = 0;

    $c = ($s0 + (1 << 20)) >> 21;  $s1  += $c; $s0  -= $c << 21;
    $c = ($s2 + (1 << 20)) >> 21;  $s3  += $c; $s2  -= $c << 21;
    $c = ($s4 + (1 << 20)) >> 21;  $s5  += $c; $s4  -= $c << 21;
    $c = ($s6 + (1 << 20)) >> 21;  $s7  += $c; $s6  -= $c << 21;
    $c = ($s8 + (1 << 20)) >> 21;  $s9  += $c; $s8  -= $c << 21;
    $c = ($s10 + (1 << 20)) >> 21; $s11 += $c; $s10 -= $c << 21;
    $c = ($s1 + (1 << 20)) >> 21;  $s2  += $c; $s1  -= $c << 21;
    $c = ($s3 + (1 << 20)) >> 21;  $s4  += $c; $s3  -= $c << 21;
    $c = ($s5 + (1 << 20)) >> 21;  $s6  += $c; $s5  -= $c << 21;
    $c = ($s7 + (1 << 20)) >> 21;  $s8  += $c; $s7  -= $c << 21;
    $c = ($s9 + (1 << 20)) >> 21;  $s10 += $c; $s9  -= $c << 21;
    $c = ($s11 + (1 << 20)) >> 21; $s12 += $c; $s11 -= $c << 21;

    $s0 += $s12 * 666643; $s1 += $s12 * 470296; $s2 += $s12 * 654183; $s3 -= $s12 * 997805; $s4 += $s12 * 136657; $s5 -= $s12 * 683901;
    $s12 = 0;

    $c = $s0 >> 21;  $s1  += $c; $s0  -= $c << 21;
    $c = $s1 >> 21;  $s2  += $c; $s1  -= $c << 21;
    $c = $s2 >> 21;  $s3  += $c; $s2  -= $c << 21;
    $c = $s3 >> 21;  $s4  += $c; $s3  -= $c << 21;
    $c = $s4 >> 21;  $s5  += $c; $s4  -= $c << 21;
    $c = $s5 >> 21;  $s6  += $c; $s5  -= $c << 21;
    $c = $s6 >> 21;  $s7  += $c; $s6  -= $c << 21;
    $c = $s7 >> 21;  $s8  += $c; $s7  -= $c << 21;
    $c = $s8 >> 21;  $s9  += $c; $s8  -= $c << 21;
    $c = $s9 >> 21;  $s10 += $c; $s9  -= $c << 21;
    $c = $s10 >> 21; $s11 += $c; $s10 -= $c << 21;
    $c = $s11 >> 21; $s12 += $c; $s11 -= $c << 21;

    $s0 += $s12 * 666643; $s1 += $s12 * 470296; $s2 += $s12 * 654183; $s3 -= $s12 * 997805; $s4 += $s12 * 136657; $s5 -= $s12 * 683901;

    $c = $s0 >> 21;  $s1  += $c; $s0  -= $c << 21;
    $c = $s1 >> 21;  $s2  += $c; $s1  -= $c << 21;
    $c = $s2 >> 21;  $s3  += $c; $s2  -= $c << 21;
    $c = $s3 >> 21;  $s4  += $c; $s3  -= $c << 21;
    $c = $s4 >> 21;  $s5  += $c; $s4  -= $c << 21;
    $c = $s5 >> 21;  $s6  += $c; $s5  -= $c << 21;
    $c = $s6 >> 21;  $s7  += $c; $s6  -= $c << 21;
    $c = $s7 >> 21;  $s8  += $c; $s7  -= $c << 21;
    $c = $s8 >> 21;  $s9  += $c; $s8  -= $c << 21;
    $c = $s9 >> 21;  $s10 += $c; $s9  -= $c << 21;
    $c = $s10 >> 21; $s11 += $c; $s10 -= $c << 21;

    // eleven limbs of 21 bits and one of 21 at the top: 252 bits, written as 32 bytes
    return pack('V8',
      $s0 | (($s1 << 21) & 0xFFFFFFFF),
      ($s1 >> 11) | (($s2 << 10) & 0xFFFFFFFF) | (($s3 << 31) & 0xFFFFFFFF),
      ($s3 >> 1) | (($s4 << 20) & 0xFFFFFFFF),
      ($s4 >> 12) | (($s5 << 9) & 0xFFFFFFFF) | (($s6 << 30) & 0xFFFFFFFF),
      ($s6 >> 2) | (($s7 << 19) & 0xFFFFFFFF),
      ($s7 >> 13) | (($s8 << 8) & 0xFFFFFFFF) | (($s9 << 29) & 0xFFFFFFFF),
      ($s9 >> 3) | (($s10 << 18) & 0xFFFFFFFF),
      ($s10 >> 14) | ($s11 << 7));
  }
}
