<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE SIGHASH PREIMAGE, COMPUTED OVER A COVENANT ENTRY (spec §3) ───────────────────────────────────
//
// ★★★ THIS IS THE PIECE THAT LETS `OP_PUSH_TX` EXIST WITH NO TRANSACTION. The technique works because a
// verifier RECOMPUTES the preimage from what actually happened, and `CHECKSIG` fails if the pushed one
// differs. Here the verifier serializes the entry and computes this. **Same mechanism, same bytes.**
//
// ⚠ THE LAYOUT IS BIP143's — a published specification, so implementing it from the BIP carries no
//   licence exposure. ⛔ It is NOT 0.1.3's sighash: the original is O(n²) and has no hashPrevouts or
//   hashOutputs, so `OP_PUSH_TX` could not be built on it. **jetmora is therefore not "pure 0.1.3" on
//   sighash, and says so rather than pretending otherwise.**
//
// ⚠⚠ FORKID IS NOT SET AND MUST NOT BE (§5.0c): replay protection makes a signed transition valid in
//   exactly one place, which would rebuild the censorship freeze that portability exists to prevent.
//
// ★ NOTE WHAT IS **NOT** IN HERE: this entry's own unlocking script. `scriptCode` is the locking script
//   of the entry being CONSUMED. ⇒ So the preimage is computable BEFORE the unlocking script exists,
//   which is what makes ticking a thread possible at all rather than circular.
declare(strict_types=1);
require_once __DIR__ . '/covenant-entry.php';

final class PreimageError extends RuntimeException {}

final class Preimage
{
  public const SIGHASH_ALL           = 0x01;
  public const SIGHASH_NONE          = 0x02;
  public const SIGHASH_SINGLE        = 0x03;
  public const SIGHASH_ANYONECANPAY  = 0x80;

  private const ZERO32 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                       . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

  /**
   * @param array  $entry      a decoded covenant entry
   * @param int    $inputIndex which input is being signed
   * @param string $scriptCode the locking script of the entry being CONSUMED
   * @param string $value      8 raw bytes — an application-defined quantity (§3), and MAY be zero
   */
  public static function build(array $entry, int $inputIndex, string $scriptCode, string $value,
                               int $sighashType = self::SIGHASH_ALL): string
  {
    if (!isset($entry['inputs'][$inputIndex])) throw new PreimageError("no input at index $inputIndex");
    if ($sighashType & 0x40) throw new PreimageError('FORKID must not be set (§5.0c)');
    if ($sighashType !== self::SIGHASH_ALL)
      throw new PreimageError('jetmora v1 supports SIGHASH_ALL only; other flags are unassigned');
    if (strlen($value) !== 8) throw new PreimageError('value must be 8 raw bytes');
    $in = $entry['inputs'][$inputIndex];

    $outpoints = ''; $sequences = ''; $outputs = '';
    foreach ($entry['inputs'] as $i) {
      $outpoints .= $i['prevEntry'] . pack('V', $i['index']);
      $sequences .= pack('V', $i['sequence']);
    }
    foreach ($entry['outputs'] as $o) {
      $v = is_int($o['value']) ? pack('P', $o['value']) : $o['value'];
      $outputs .= $v . self::varint(strlen($o['locking'])) . $o['locking'];
    }

    return pack('V', $entry['version'])
         . self::dsha256($outpoints)
         . self::dsha256($sequences)
         . $in['prevEntry'] . pack('V', $in['index'])
         . self::varint(strlen($scriptCode)) . $scriptCode
         . $value
         . pack('V', $in['sequence'])
         . self::dsha256($outputs)
         . pack('V', $entry['locktime'])
         . pack('V', $sighashType);
  }

  /** What a signature is actually over. */
  public static function sighash(array $entry, int $inputIndex, string $scriptCode, string $value,
                                 int $sighashType = self::SIGHASH_ALL): string
  {
    return self::dsha256(self::build($entry, $inputIndex, $scriptCode, $value, $sighashType));
  }

  /**
   * ⚠ The varint prefixed to `scriptCode` makes the preimage's own length depend on the script's
   * length, which is why a covenant that PEELS ITS OWN STATE must be built, measured and rebuilt.
   * Exposed so a compiler can resolve that circularity rather than rediscovering it.
   */
  public static function scriptCodeVarintSize(int $len): int { return strlen(self::varint($len)); }

  private static function dsha256(string $b): string
  {
    return hash('sha256', hash('sha256', $b, true), true);
  }

  private static function varint(int $n): string
  {
    if ($n < 0xfd)        return chr($n);
    if ($n <= 0xffff)     return "\xfd" . pack('v', $n);
    if ($n <= 0xffffffff) return "\xfe" . pack('V', $n);
    throw new PreimageError('length beyond a 4-byte varint');
  }
}
