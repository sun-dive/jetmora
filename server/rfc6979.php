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
declare(strict_types=1);

final class Rfc6979
{
  /**
   * Deterministic `k` per RFC 6979 §3.2.
   *
   * @param GMP    $q       the group order
   * @param GMP    $x       the private key, 0 < x < q
   * @param string $h1      the message DIGEST, raw bytes (already hashed by the caller)
   * @param string $algo    HMAC hash, matching the digest that produced $h1
   * @param int    $attempt 0 for the first candidate; higher values step the generator forward, which
   *                        is what a caller does if it must reject a k for its own reasons
   */
  public static function k(GMP $q, GMP $x, string $h1, string $algo = 'sha256', int $attempt = 0): GMP
  {
    $qlen = self::bitlen($q);
    $rlen = intdiv($qlen + 7, 8);
    $hlen = strlen(hash($algo, '', true));

    // ⚠ int2octets is FIXED WIDTH (rlen), and bits2octets reduces mod q FIRST. Getting either wrong
    //   produces a k that is perfectly usable — the signature verifies — but does not match anyone
    //   else's, which is the silent failure this whole file exists to avoid.
    $bx = self::int2octets($x, $rlen);
    $bh = self::int2octets(gmp_mod(self::bits2int($h1, $qlen), $q), $rlen);

    $V = str_repeat("\x01", $hlen);
    $K = str_repeat("\x00", $hlen);
    $K = hash_hmac($algo, $V . "\x00" . $bx . $bh, $K, true);
    $V = hash_hmac($algo, $V, $K, true);
    $K = hash_hmac($algo, $V . "\x01" . $bx . $bh, $K, true);
    $V = hash_hmac($algo, $V, $K, true);

    $skip = $attempt;
    while (true) {
      $T = '';
      while (strlen($T) * 8 < $qlen) {
        $V  = hash_hmac($algo, $V, $K, true);
        $T .= $V;
      }
      $k = self::bits2int($T, $qlen);
      if (gmp_cmp($k, 1) >= 0 && gmp_cmp($k, $q) < 0) {
        if ($skip === 0) return $k;
        $skip--;                                  // caller asked for a later candidate
      }
      // ⚠ this step happens on REJECTION, and only then — not once per loop unconditionally
      $K = hash_hmac($algo, $V . "\x00", $K, true);
      $V = hash_hmac($algo, $V, $K, true);
    }
  }

  /** RFC 6979 §2.3.2 — the leftmost qlen bits of $b as an integer. */
  public static function bits2int(string $b, int $qlen): GMP
  {
    $v = gmp_import($b, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $blen = strlen($b) * 8;
    // ⚠ SHIFT RIGHT when the input is longer than the order, never truncate bytes: the discarded bits
    //   are the LOW ones. Cutting bytes instead happens to agree when both are a whole 32 bytes, and
    //   disagrees the moment a digest is wider than the curve — which is exactly the case nobody tests.
    return $blen > $qlen ? gmp_div_q($v, gmp_pow(2, $blen - $qlen)) : $v;
  }

  /** RFC 6979 §2.3.3 — an integer as exactly $rlen big-endian bytes. */
  public static function int2octets(GMP $x, int $rlen): string
  {
    $be = gmp_sign($x) === 0 ? '' : gmp_export($x, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if (strlen($be) > $rlen) $be = substr($be, -$rlen);
    return str_pad($be, $rlen, "\x00", STR_PAD_LEFT);
  }

  private static function bitlen(GMP $n): int
  {
    return strlen(gmp_strval($n, 2));
  }
}
