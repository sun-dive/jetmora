<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ⚠⚠⚠ THE WALLET IS TWO ISOLATED CODE SETS, ONE PER CHAIN (his call, 7 Sept).
//   `server/wallet/jetmora/` · `server/wallet/bsv/` · `server/wallet/shared/`
//
// ★★★ THE RULE THAT DECIDES WHAT GOES WHERE: **share what CANNOT disagree; isolate what CAN.**
//   A curve cannot disagree by design — secp256k1 is secp256k1 on both chains, so one copy is right
//   and three would be three places for one bug to hide. An ADDRESS FORMAT can disagree. So can a
//   transaction format, and so can a key-derivation path.
//
// ⇒ AND THE ISOLATION IS LOAD-BEARING THREE TIMES OVER, not once:
//   1. ⚖ **LICENCE.** Open BSV v6 clause 2 restricts field of use to the BSV Blockchain, so nothing
//      derived from it may run on jetmora. `own-wallet-sdk-position`: *"the hazard is one codebase
//      mixing them — 'derived from' goes murky the moment a helper crosses."* **The directory boundary
//      is what keeps that question ANSWERABLE.**
//   2. 💥 **BLAST RADIUS.** A BSV fix must not be able to reach jetmora — §10.9 and page-script-isolation.
//   3. ✅ **CORRECTNESS.** They genuinely differ: jetmora entries are ed25519 (every live genesis
//      authorises a 32-byte key); BSV is secp256k1. ⚠ Even HD derivation differs — BIP-32 is
//      secp256k1-specific and ed25519 needs SLIP-0010, a different algorithm.
//
// ── THIS FILE IS THE JETMORA SIDE ────────────────────────────────────────────────────────────────────
// ⛔⛔ §2c-i: a jetmora address MUST NOT be parseable as a Bitcoin address, and MUST NOT be emitted as
//   one. jetmora has no COIN, so nothing is ever transferred TO a jetmora address — value in a covenant
//   thread is ADVANCED by its authorised key, never paid into one. ⇒ One pasted into a Bitcoin wallet
//   is a TRAP WITH NO UPSIDE: the coin is lost, and nothing here was ever going to receive it.
//   ⚠⚠ NOT "jetmora is value-free". §3's `value MUST NOT be interpreted as money` is about THE FIELD,
//   for legal reasons. **Covenants on this chain can and will hold value**, so key handling here is
//   not lower-stakes than on the BSV side.
//   ⚠ Not hypothetical: BTC and BCH shared base58 P2PKH and people lost real money; BCH fixed it by
//   CHANGING THE FORMAT, not the leading character.
//   ⚠ MEASURED: base58check 0x69 is the unique byte giving a leading `j`, and such an address STILL
//   PARSES as valid base58check. **A first character protects the reader, not the software.**
// ⚠⚠ bech32m, NOT bech32 — DEMONSTRATED: a valid bech32 string ending in `p` still verifies after
//   inserting `q`s before that `p`. bech32m rejects every such mutation.
declare(strict_types=1);

final class Bech32
{
  private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  public  const BECH32  = 1;                 // BIP-173 — ⚠ has the length-extension weakness
  public  const BECH32M = 0x2bc830a3;        // BIP-350 — use this
  private const MAXLEN  = 90;

  /** Largest payload (in bytes) that fits 90 chars for this HRP, allowing one version symbol. */
  public static function payloadMax(string $hrp): int
  {
    return intdiv((self::MAXLEN - strlen($hrp) - 1 - 6 - 1) * 5, 8);
  }

  private static function polymod(array $v): int
  {
    $gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    $chk = 1;
    foreach ($v as $d) {
      $b = $chk >> 25;
      $chk = (($chk & 0x1ffffff) << 5) ^ $d;
      for ($i = 0; $i < 5; $i++) if (($b >> $i) & 1) $chk ^= $gen[$i];
    }
    return $chk;
  }

  /** ⚠ The HRP is expanded as high bits, a zero, then low bits — not simply appended. */
  private static function hrpExpand(string $hrp): array
  {
    $out = [];
    for ($i = 0, $n = strlen($hrp); $i < $n; $i++) $out[] = ord($hrp[$i]) >> 5;
    $out[] = 0;
    for ($i = 0, $n = strlen($hrp); $i < $n; $i++) $out[] = ord($hrp[$i]) & 31;
    return $out;
  }

  /**
   * @param int[] $data5 five-bit groups
   * @param int   $spec  self::BECH32M (default) or self::BECH32
   */
  public static function encode(string $hrp, array $data5, int $spec = self::BECH32M): string
  {
    $chk = self::polymod(array_merge(self::hrpExpand($hrp), $data5, [0, 0, 0, 0, 0, 0])) ^ $spec;
    $out = $hrp . '1';
    foreach ($data5 as $d) $out .= self::CHARSET[$d];
    for ($i = 0; $i < 6; $i++) $out .= self::CHARSET[($chk >> 5 * (5 - $i)) & 31];
    // ⚠⚠ THE 90-CHARACTER LIMIT IS NOT ARBITRARY AND MUST NOT BE RAISED. bech32's error-detection
    //   guarantee (any 4 errors detected, and better than 10^-9 beyond that) holds within it; past 90
    //   characters the guarantee weakens. Raising the cap to fit a longer payload would trade the
    //   thing the format is FOR against convenience.
    if (strlen($out) > self::MAXLEN)
      throw new InvalidArgumentException(sprintf(
        'bech32 string is %d chars, over the %d limit — with HRP "%s" the payload ceiling is %d bytes',
        strlen($out), self::MAXLEN, $hrp, self::payloadMax($hrp)));
    return $out;
  }

  /**
   * @return array{hrp:string,data:int[],spec:int}|null  null on ANY malformity — never a partial parse.
   */
  public static function decode(string $s): ?array
  {
    $n = strlen($s);
    if ($n < 8 || $n > self::MAXLEN) return null;
    // ⚠ MIXED CASE IS INVALID, and it is a real vector: a string may be all-upper or all-lower, never
    //   both. Lowercasing first and forgetting this check silently accepts a forbidden form.
    $hasU = $s !== strtolower($s);
    $hasL = $s !== strtoupper($s);
    if ($hasU && $hasL) return null;
    $s = strtolower($s);

    $sep = strrpos($s, '1');
    if ($sep === false || $sep === 0 || $sep + 7 > $n) return null;   // empty HRP, or checksum too short
    $hrp = substr($s, 0, $sep);
    for ($i = 0; $i < $sep; $i++) {
      $c = ord($hrp[$i]);
      if ($c < 33 || $c > 126) return null;                          // HRP character out of range
    }
    $data = [];
    for ($i = $sep + 1; $i < $n; $i++) {
      $p = strpos(self::CHARSET, $s[$i]);
      if ($p === false) return null;                                 // invalid data character
      $data[] = $p;
    }
    $chk = self::polymod(array_merge(self::hrpExpand($hrp), $data));
    $spec = $chk === self::BECH32M ? self::BECH32M : ($chk === self::BECH32 ? self::BECH32 : 0);
    if ($spec === 0) return null;
    return ['hrp' => $hrp, 'data' => array_slice($data, 0, -6), 'spec' => $spec];
  }

  /**
   * General base conversion.
   * ⚠⚠ THE PADDING RULES ARE WHERE IMPLEMENTATIONS DIVERGE, and BIP-350 tests both: when UNPACKING
   *   (5→8) any leftover bits MUST be fewer than the source group AND MUST be zero. Skipping either
   *   check accepts addresses that other software rejects — which for an address format means funds
   *   sent somewhere the sender did not intend.
   * @param int[] $data
   * @return int[]|null
   */
  public static function convertBits(array $data, int $from, int $to, bool $pad): ?array
  {
    $acc = 0; $bits = 0; $out = []; $maxv = (1 << $to) - 1;
    foreach ($data as $d) {
      if ($d < 0 || $d >> $from) return null;
      $acc = ($acc << $from) | $d;
      $bits += $from;
      while ($bits >= $to) { $bits -= $to; $out[] = ($acc >> $bits) & $maxv; }
    }
    if ($pad) {
      if ($bits) $out[] = ($acc << ($to - $bits)) & $maxv;
    } elseif ($bits >= $from || (($acc << ($to - $bits)) & $maxv)) {
      return null;                                                   // over-long or non-zero padding
    }
    return $out;
  }
}

/**
 * A jetmora address: `j1…`, bech32m, a version byte then a payload.
 *
 * ⏭ **The PAYLOAD is not settled by §2c-i** — that rule fixes the FORMAT, which is what protects
 *   people. What a jetmora address names (a 32-byte ed25519 key, as every live genesis authorises
 *   today; or a hash of one) is a separate question, deliberately left open here rather than guessed.
 */
final class JetAddress
{
  public const HRP = 'j';

  public static function encode(string $payload, int $version = 0, string $hrp = self::HRP): string
  {
    if ($version < 0 || $version > 31) throw new InvalidArgumentException('version must be 0..31');
    if ($payload === '') throw new InvalidArgumentException('empty payload');
    // ★ Named up front rather than discovered as a checksum-length error further down. With HRP 'j'
    //   the ceiling is 50 bytes — which covers a hash160 (20), an ed25519 key (32, what every live
    //   genesis authorises today) and a compressed pubkey (33). ⛔ A 65-byte UNCOMPRESSED key does not
    //   fit, and jetmora has no reason to address one.
    $max = Bech32::payloadMax($hrp);
    if (strlen($payload) > $max)
      throw new InvalidArgumentException(sprintf(
        'payload is %d bytes; the ceiling for HRP "%s" is %d', strlen($payload), $hrp, $max));
    $five = Bech32::convertBits(array_values(unpack('C*', $payload)), 8, 5, true);
    if ($five === null) throw new RuntimeException('bit conversion failed');
    return Bech32::encode($hrp, array_merge([$version], $five), Bech32::BECH32M);
  }

  /** @return array{version:int,payload:string}|null */
  public static function decode(string $addr, string $hrp = self::HRP): ?array
  {
    $d = Bech32::decode($addr);
    if ($d === null || $d['hrp'] !== $hrp) return null;
    // ⛔ bech32 (not -m) must be REFUSED even though its checksum is valid: accepting both would
    //    reinstate exactly the length-extension weakness bech32m was defined to remove.
    if ($d['spec'] !== Bech32::BECH32M) return null;
    if (count($d['data']) < 2) return null;
    $ver = $d['data'][0];
    $bytes = Bech32::convertBits(array_slice($d['data'], 1), 5, 8, false);
    if ($bytes === null || $bytes === []) return null;
    return ['version' => $ver, 'payload' => pack('C*', ...$bytes)];
  }
}

