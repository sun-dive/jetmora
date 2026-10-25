<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── RFC 6979 — DETERMINISTIC `k` FOR (EC)DSA ─────────────────────────────────────────────────────────
//
// ⚠⚠⚠ THIS IS THE MOST DANGEROUS NUMBER IN A WALLET.
//   ECDSA leaks the private key outright if `k` is ever repeated across two signatures, and leaks it to
//   lattice attacks if `k` is merely BIASED. It is not a theoretical failure: it took Sony's PS3 signing
//   key (a CONSTANT k) and it emptied Android Bitcoin wallets in 2013 (a broken SecureRandom).
//   ⇒ ★★★ RFC 6979 derives `k` from the private key and the message digest through HMAC, so **there is
//     no random number generator in the signing path at all** — nothing to seed badly, nothing to
//     repeat after a VM snapshot, nothing that behaves differently on a $2 shared host.
//   ★★ And the property that matters most to THIS project: a deterministic signature can be checked
//     against PUBLISHED VECTORS. A random one cannot be checked against anything.
//
// ⚠ CURVE-AGNOSTIC BY DESIGN, and that is what makes it gradeable: `k` depends only on the group order
//   `q`, the private key and the digest — never on the curve's points. ⇒ So this file is tested with
//   **P-256's order against RFC 6979's own Appendix A.2.5 vectors**, which is an authoritative external
//   grade, and then used with secp256k1's order for real signing.
//   ⛔ I could not find an authoritative RFC 6979 vector FOR secp256k1. One widely-quoted "secp256k1"
//     value is byte-identical to the P-256 one, which cannot be correct because the orders differ.
//     **A plausible vector is worse than no vector**, so signature validity is graded by openssl
//     instead (see server/verify-rfc6979.php).
//
// Every integer here is a big-endian byte string, so the file needs no big-number library: HMAC does the work,
// and the arithmetic is a shift, a comparison and one subtraction.
declare(strict_types=1);

final class Rfc6979
{
  /**
   * Deterministic `k` per RFC 6979 §3.2.
   *
   * @param string $q       the group order, q > 0, big-endian
   * @param string $x       the private key, 0 < x < q, big-endian
   * @param string $h1      the message DIGEST, raw bytes (already hashed by the caller)
   * @param string $algo    HMAC hash, matching the digest that produced $h1
   * @param int    $attempt 0 for the first candidate; higher values step the generator forward, which
   *                        is what a caller does if it must reject a k for its own reasons
   * @return string k, 1 <= k < q, as rlen big-endian bytes (rlen = the order's length in bytes)
   */
  public static function k(string $q, string $x, string $h1, string $algo = 'sha256', int $attempt = 0): string
  {
    $qlen = self::bitlen($q);
    $rlen = intdiv($qlen + 7, 8);
    $hlen = strlen(hash($algo, '', true));
    $q = self::int2octets($q, $rlen);

    // ⚠ int2octets is FIXED WIDTH (rlen), and bits2octets reduces mod q FIRST. Getting either wrong
    //   produces a k that is perfectly usable — the signature verifies — but does not match anyone
    //   else's, which is the silent failure this whole file exists to avoid.
    // ★ bits2int's value is below 2^qlen, and 2^qlen <= 2q, so "mod q" is one conditional subtraction.
    $bx = self::int2octets($x, $rlen);
    $z  = self::bits2int($h1, $qlen);
    $bh = strcmp($z, $q) >= 0 ? self::sub($z, $q) : $z;

    $V = str_repeat("\x01", $hlen);
    $K = str_repeat("\x00", $hlen);
    $K = hash_hmac($algo, $V . "\x00" . $bx . $bh, $K, true);
    $V = hash_hmac($algo, $V, $K, true);
    $K = hash_hmac($algo, $V . "\x01" . $bx . $bh, $K, true);
    $V = hash_hmac($algo, $V, $K, true);

    $zero = str_repeat("\0", $rlen);
    $skip = $attempt;
    while (true) {
      $T = '';
      while (strlen($T) * 8 < $qlen) {
        $V  = hash_hmac($algo, $V, $K, true);
        $T .= $V;
      }
      $k = self::bits2int($T, $qlen);
      if ($k !== $zero && strcmp($k, $q) < 0) {      // ⚠ strcmp, equal widths: `<` would compare numeric strings as numbers
        if ($skip === 0) return $k;
        $skip--;                                  // caller asked for a later candidate
      }
      // ⚠ this step happens on REJECTION, and only then — not once per loop unconditionally
      $K = hash_hmac($algo, $V . "\x00", $K, true);
      $V = hash_hmac($algo, $V, $K, true);
    }
  }

  /** RFC 6979 §2.3.2: the leftmost qlen bits of $b as an integer.
   *  It comes back as rlen big-endian bytes. */
  public static function bits2int(string $b, int $qlen): string
  {
    $rlen = intdiv($qlen + 7, 8);
    $shift = strlen($b) * 8 - $qlen;
    // ⚠ SHIFT RIGHT when the input is longer than the order, never truncate bytes: the discarded bits
    //   are the LOW ones. Cutting bytes instead happens to agree when both are a whole 32 bytes, and
    //   disagrees the moment a digest is wider than the curve — which is exactly the case nobody tests.
    if ($shift > 0) {
      $b = substr($b, 0, strlen($b) - ($shift >> 3));          // whole bytes off the low end
      $s = $shift & 7;
      if ($s > 0) {                                           // then the bits left over, across the bytes
        $out = ''; $carry = 0;
        for ($i = 0, $n = strlen($b); $i < $n; $i++) {
          $c = ord($b[$i]);
          $out .= chr(($carry << (8 - $s)) | ($c >> $s));
          $carry = $c & ((1 << $s) - 1);
        }
        $b = $out;
      }
    }
    return self::int2octets($b, $rlen);
  }

  /** RFC 6979 §2.3.3: an integer as exactly $rlen big-endian bytes.
   *  $x is big-endian bytes too, and a longer one keeps its low $rlen bytes. */
  public static function int2octets(string $x, int $rlen): string
  {
    $x = ltrim($x, "\0");
    if (strlen($x) > $rlen) return substr($x, -$rlen);
    return str_pad($x, $rlen, "\x00", STR_PAD_LEFT);
  }

  private static function bitlen(string $n): int
  {
    $n = ltrim($n, "\0");
    return $n === '' ? 0 : 8 * strlen($n) - 8 + strlen(decbin(ord($n[0])));
  }

  /** a − b for two big-endian integers of one width, a >= b. */
  private static function sub(string $a, string $b): string
  {
    $out = ''; $borrow = 0;
    for ($i = strlen($a) - 1; $i >= 0; $i--) {
      $d = ord($a[$i]) - ord($b[$i]) - $borrow;
      $borrow = $d < 0 ? 1 : 0;
      $out = chr($d & 0xFF) . $out;
    }
    return $out;
  }
}
