<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
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
//   code to port into PHP. ⇒ The remaining clean option is to implement the PUBLISHED ALGORITHM over
//   GMP: SEC1 §4.1.4 with SEC2 curve parameters, both public specifications. No dependency, nothing to
//   attribute, and nothing that can drag a field-of-use clause behind it.
//
//   ⛔ NOT PHP's openssl extension either. It would work, but it is a system dependency for the one
//   piece of this machine that must give the same answer on every host forever, and the point of the
//   exercise is to own the primitives.
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
//   `mul()` is fine with a PUBLIC scalar. Deriving a public key from a private one, or signing, feeds
//   it a SECRET scalar — and a double-and-add whose work depends on the bits of that scalar is the
//   textbook timing side channel. ⇒ **A signer MUST NOT simply reuse `mul()` and inherit this note.**
//   ⚠ PHP cannot honestly promise constant time anyway (GMP branches, GC, opcache), so the design
//     answer is not a clever loop: it is that **the jetmora wallet's SIGNING must not run where an
//     attacker can time it** — which is a real constraint on "runs on $2 shared hosting", and belongs
//     in the wallet design rather than being discovered later.
//   ★ Verification, which is what this file is for today, has no such problem and never will.
declare(strict_types=1);
require_once __DIR__ . '/rfc6979.php';

final class Secp256k1
{
  // SEC2 curve parameters for secp256k1. y² = x³ + 7 over F_p.
  private const P  = '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';
  private const N  = '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
  private const GX = '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  private const GY = '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

  private static ?GMP $p = null, $n = null;
  private static ?array $g = null;

  private static function init(): void
  {
    if (self::$p !== null) return;
    self::$p = gmp_init(self::P, 16);
    self::$n = gmp_init(self::N, 16);
    self::$g = [gmp_init(self::GX, 16), gmp_init(self::GY, 16)];
  }

  // ── point arithmetic, affine, over F_p ─────────────────────────────────────────────────────────────
  // A point is [x, y] as GMP, or null for the point at infinity.

  private static function add(?array $a, ?array $b): ?array
  {
    if ($a === null) return $b;
    if ($b === null) return $a;
    $p = self::$p;
    if (gmp_cmp($a[0], $b[0]) === 0) {
      // x equal: either a double, or the two points are inverses and sum to infinity
      if (gmp_cmp(gmp_mod(gmp_add($a[1], $b[1]), $p), 0) === 0) return null;
      return self::dbl($a);
    }
    $lam = gmp_mod(gmp_mul(gmp_sub($b[1], $a[1]),
                           gmp_invert(gmp_sub($b[0], $a[0]), $p)), $p);
    $x   = gmp_mod(gmp_sub(gmp_sub(gmp_mul($lam, $lam), $a[0]), $b[0]), $p);
    $y   = gmp_mod(gmp_sub(gmp_mul($lam, gmp_sub($a[0], $x)), $a[1]), $p);
    return [$x, $y];
  }

  private static function dbl(?array $a): ?array
  {
    if ($a === null || gmp_cmp($a[1], 0) === 0) return null;
    $p   = self::$p;
    // λ = 3x² / 2y   (a = 0 for secp256k1, so no +a term)
    $lam = gmp_mod(gmp_mul(gmp_mul(gmp_mul($a[0], $a[0]), 3),
                           gmp_invert(gmp_mul($a[1], 2), $p)), $p);
    $x   = gmp_mod(gmp_sub(gmp_mul($lam, $lam), gmp_mul($a[0], 2)), $p);
    $y   = gmp_mod(gmp_sub(gmp_mul($lam, gmp_sub($a[0], $x)), $a[1]), $p);
    return [$x, $y];
  }

  /**
   * double-and-add over a scalar taken AS GIVEN — no reduction mod n.
   * ⚠ Not constant time, and cannot be made so in PHP. For a PUBLIC scalar that is fine; for a SECRET
   *   one, go through mulBlinded() instead.
   */
  private static function mulRaw(?array $pt, GMP $k): ?array
  {
    if (gmp_cmp($k, 0) <= 0 || $pt === null) return null;
    $r = null;
    for ($i = strlen(gmp_strval($k, 2)) - 1; $i >= 0; $i--) {
      $r = self::dbl($r);
      if (gmp_testbit($k, $i)) $r = self::add($r, $pt);
    }
    return $r;
  }

  /** Public scalar: reduce and go. */
  private static function mul(?array $pt, GMP $k): ?array
  {
    return self::mulRaw($pt, gmp_mod($k, self::$n));
  }

  /**
   * ★★★ SECRET SCALAR — SCALAR BLINDING.
   *
   * ⚠⚠⚠ WHY THIS EXISTS. `mulRaw` does work proportional to the BITS OF ITS SCALAR, so its running
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
  private static function mulBlinded(?array $pt, GMP $k): ?array
  {
    $k = gmp_mod($k, self::$n);
    if (gmp_cmp($k, 0) === 0) return null;
    $b = gmp_import(random_bytes(8), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if (gmp_cmp($b, 0) === 0) $b = gmp_init(1);
    return self::mulRaw($pt, gmp_add($k, gmp_mul($b, self::$n)));
  }

  // ── encodings ──────────────────────────────────────────────────────────────────────────────────────
  /** SEC1 point: 33-byte compressed (02/03) or 65-byte uncompressed (04). */
  public static function decodePoint(string $pub): ?array
  {
    self::init();
    $n = strlen($pub);
    if ($n === 65) {
      if (ord($pub[0]) !== 0x04) return null;
      $x = gmp_import(substr($pub, 1, 32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
      $y = gmp_import(substr($pub, 33, 32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    } elseif ($n === 33) {
      $t = ord($pub[0]);
      if ($t !== 0x02 && $t !== 0x03) return null;
      $x = gmp_import(substr($pub, 1, 32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
      if (gmp_cmp($x, self::$p) >= 0) return null;
      // y² = x³ + 7. ★ p ≡ 3 (mod 4), so the square root is v^((p+1)/4) — no Tonelli-Shanks needed.
      $v = gmp_mod(gmp_add(gmp_powm($x, 3, self::$p), 7), self::$p);
      $y = gmp_powm($v, gmp_div_q(gmp_add(self::$p, 1), 4), self::$p);
      // ⚠ That exponentiation always returns SOMETHING. If v was not a residue the result does not
      //   satisfy the curve, and skipping this check accepts points that are not on the curve at all.
      if (gmp_cmp(gmp_mod(gmp_mul($y, $y), self::$p), $v) !== 0) return null;
      if (gmp_intval(gmp_mod($y, 2)) !== ($t & 1)) $y = gmp_sub(self::$p, $y);
    } else {
      return null;
    }
    if (gmp_cmp($x, self::$p) >= 0 || gmp_cmp($y, self::$p) >= 0) return null;
    // on-curve check, for the uncompressed path and as a belt for the compressed one
    $lhs = gmp_mod(gmp_mul($y, $y), self::$p);
    $rhs = gmp_mod(gmp_add(gmp_powm($x, 3, self::$p), 7), self::$p);
    return gmp_cmp($lhs, $rhs) === 0 ? [$x, $y] : null;
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
   * @return array{GMP,GMP}|null
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

  private static function derInt(string $b, int &$i, int $end): ?GMP
  {
    if ($i + 2 > $end || ord($b[$i]) !== 0x02) return null;
    $l = ord($b[$i + 1]);
    if ($l === 0 || $i + 2 + $l > $end) return null;
    $v = substr($b, $i + 2, $l);
    if (ord($v[0]) & 0x80) return null;          // negative: not a valid ECDSA component
    $i += 2 + $l;
    return gmp_import($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
  }

  // ── the public key from a private one ──────────────────────────────────────────────────────────────
  /**
   * @param GMP  $d          private key, 0 < d < n
   * @param bool $compressed 33-byte SEC1 (the default everywhere modern) or 65-byte
   * ⚠⚠ SECRET SCALAR — see the header note. `mul()` is not constant time and cannot honestly be made so
   *    in PHP. This is safe where the host is not shared with an adversary who can time it.
   */
  public static function publicKey(GMP $d, bool $compressed = true): string
  {
    self::init();
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, self::$n) >= 0)
      throw new InvalidArgumentException('private key out of range');
    $q = self::mulBlinded(self::$g, $d);          // ⚠ secret scalar
    if ($q === null) throw new RuntimeException('degenerate public key');
    $x = Rfc6979::int2octets($q[0], 32);
    $y = Rfc6979::int2octets($q[1], 32);
    return $compressed ? chr(2 + (gmp_intval(gmp_mod($q[1], 2)))) . $x : "\x04" . $x . $y;
  }

  // ── signing ────────────────────────────────────────────────────────────────────────────────────────
  /**
   * Deterministic ECDSA (RFC 6979). Returns DER `SEQUENCE { INTEGER r, INTEGER s }`.
   *
   * ⚠⚠⚠ There is NO random number generator in this path. See rfc6979.php for why that is the whole
   *   point: a repeated or biased `k` hands over the private key, and an RNG is the thing that goes
   *   wrong quietly on a cheap host, in a VM snapshot, or in a container that starts with the same seed.
   *
   * @param string $digest32 the 32-byte digest, ALREADY hashed by the caller — as with verifyDigest(),
   *                         so the choice of single or double SHA-256 is visible at the call site.
   * @param bool   $lowS     ⚠ NOT a protocol rule. jetmora does not inherit LOW_S and 0.1.3 has none;
   *                         Chronicle removed it. But a BROADCASTER can still refuse a high-S signature
   *                         — this project has had a conformant spend refused by exactly that — so a
   *                         wallet broadcasting to BSV passes true. Negating s is deterministic, so the
   *                         signature stays reproducible either way.
   */
  public static function sign(GMP $d, string $digest32, bool $lowS = false): string
  {
    self::init();
    if (strlen($digest32) !== 32) throw new InvalidArgumentException('digest must be 32 bytes');
    if (gmp_cmp($d, 1) < 0 || gmp_cmp($d, self::$n) >= 0)
      throw new InvalidArgumentException('private key out of range');
    $n = self::$n;
    $e = Rfc6979::bits2int($digest32, 256);

    // ⚠ r or s hitting zero is astronomically unlikely and MUST still be handled: RFC 6979 says step
    //   the generator forward, NOT pick a fresh random k, because a random retry reintroduces the RNG.
    for ($attempt = 0; $attempt < 16; $attempt++) {
      $k = Rfc6979::k($n, $d, $digest32, 'sha256', $attempt);
      $R = self::mulBlinded(self::$g, $k);          // ⚠ secret scalar
      if ($R === null) continue;
      $r = gmp_mod($R[0], $n);
      if (gmp_sign($r) === 0) continue;
      // ★ The INVERSION leaks too, so blind it multiplicatively: (k·t)⁻¹·t == k⁻¹, and gmp_invert
      //   then operates on a value the attacker cannot predict. Same answer, different work.
      $t = gmp_mod(gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), $n);
      if (gmp_sign($t) === 0) $t = gmp_init(1);
      $kt = gmp_invert(gmp_mod(gmp_mul($k, $t), $n), $n);
      if ($kt === false) continue;
      $kinv = gmp_mod(gmp_mul($kt, $t), $n);
      $s = gmp_mod(gmp_mul($kinv, gmp_add($e, gmp_mul($r, $d))), $n);
      if (gmp_sign($s) === 0) continue;
      if ($lowS && gmp_cmp(gmp_mul($s, 2), $n) > 0) $s = gmp_sub($n, $s);
      return self::encodeDer($r, $s);
    }
    throw new RuntimeException('no usable k after 16 attempts');   // unreachable in practice
  }

  /** DER, with the leading-zero rule that a naive encoder gets wrong. */
  public static function encodeDer(GMP $r, GMP $s): string
  {
    $enc = function (GMP $v): string {
      $b = gmp_sign($v) === 0 ? "\x00" : gmp_export($v, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
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
    $q   = self::decodePoint($pub);       if ($q === null)   return false;
    [$r, $s] = $der;
    $n = self::$n;
    if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, $n) >= 0) return false;
    if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, $n) >= 0) return false;

    $e  = gmp_import($msg32, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);   // 256-bit curve: no truncation
    $w  = gmp_invert($s, $n);
    if ($w === false) return false;
    $u1 = gmp_mod(gmp_mul($e, $w), $n);
    $u2 = gmp_mod(gmp_mul($r, $w), $n);
    $pt = self::add(self::mul(self::$g, $u1), self::mul($q, $u2));
    if ($pt === null) return false;
    return gmp_cmp(gmp_mod($pt[0], $n), gmp_mod($r, $n)) === 0;
  }
}
