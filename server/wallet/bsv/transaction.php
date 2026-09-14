<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ BSV TRANSACTIONS · SERIALIZE · PARSE · BIP143 SIGHASH ════════════════════════════════════════════
//
// ⚠⚠⚠ WHY THIS IS ON THE BSV SIDE AND NOT SHARED WITH `server/preimage.php`.
//   The layout is the same BIP143 layout. **The rules are not, and they conflict outright:**
//
//   | | jetmora (`preimage.php`) | BSV (here) |
//   |---|---|---|
//   | FORKID | ⛔ **must NOT be set** (§5.0c) — it would rebuild the censorship freeze portability exists to prevent | ★ **always set** — `0x41` in every live covenant, `0xc1` in the battery |
//   | flags | SIGHASH_ALL only; everything else unassigned | ALL · NONE · SINGLE · ANYONECANPAY |
//   | value | 8 raw bytes, application-defined, **may be zero** | satoshis, and a wrong one is a burnt fee |
//
//   ⇒ **"Share what cannot disagree; isolate what can."** These disagree at the first byte, so sharing
//     one class would mean a flag either side refuses. ⛔ `preimage.php` is NOT reused, NOT modified,
//     and NOT imported — it was READ. → [[port-dont-reinvent]]
//
// ★ FORKID changes nothing about the arithmetic: with a fork id of 0 (BSV's), `nHashType` serializes as
//   the plain 4-byte little-endian type — `0x41` → `41000000`. ⇒ Which is exactly why BIP-143's OWN
//   vectors, which have FORKID clear, grade this code's layout end to end.
//
// ⚠⚠ THE SILENT FAILURES THIS FILE EXISTS TO AVOID, every one of which produces a well-formed result:
//   · an **8-byte amount packed as 4** — identical below 42.9 BTC, wrong above it
//   · a **varint written as one byte** past 0xfc — shifts every following field
//   · **scriptCode double-prefixed** with its length — BIP-143 prints it WITH the prefix already
//   · **SIGHASH_SINGLE past the last output** — Bitcoin's `uint256(1)` bug; here it is zeros, matching
//     BIP-143 rather than the legacy algorithm
//   · a **txid not reversed** — the wire order and the display order are opposites, always
declare(strict_types=1);

final class BsvTxError extends RuntimeException {}

/** Reading and writing the primitives every Bitcoin structure is built from. */
final class BsvBytes
{
  /** ⚠ Bitcoin's compact size. Writing 0xfd as one byte shifts every subsequent field. */
  public static function varint(int $n): string
  {
    if ($n < 0)           throw new BsvTxError('a length cannot be negative');
    if ($n < 0xfd)        return chr($n);
    if ($n <= 0xffff)     return "\xfd" . pack('v', $n);
    if ($n <= 0xffffffff) return "\xfe" . pack('V', $n);
    return "\xff" . pack('P', $n);
  }

  /** @return array{0:int,1:int} the value and the new offset */
  public static function readVarint(string $b, int $o): array
  {
    if ($o >= strlen($b)) throw new BsvTxError("varint runs past the end at offset $o");
    $f = ord($b[$o]);
    if ($f < 0xfd)   return [$f, $o + 1];
    if ($f === 0xfd) return [unpack('v', self::take($b, $o + 1, 2))[1], $o + 3];
    if ($f === 0xfe) return [unpack('V', self::take($b, $o + 1, 4))[1], $o + 5];
    $v = unpack('P', self::take($b, $o + 1, 8))[1];
    if ($v < 0) throw new BsvTxError('varint exceeds PHP\'s signed 64-bit range');
    return [$v, $o + 9];
  }

  public static function take(string $b, int $o, int $n): string
  {
    if ($o + $n > strlen($b)) throw new BsvTxError("need $n bytes at offset $o; the data ends first");
    return substr($b, $o, $n);
  }

  public static function dsha256(string $b): string
  {
    return hash('sha256', hash('sha256', $b, true), true);
  }
}

final class BsvTx
{
  /** @param array<int,array{txid:string,vout:int,script:string,sequence:int}> $inputs
   *  @param array<int,array{value:int,script:string}> $outputs
   *  ⚠ `txid` is stored in WIRE order (little-endian, as it appears in the bytes), never display order. */
  public function __construct(
    public int   $version  = 1,
    public array $inputs   = [],
    public array $outputs  = [],
    public int   $locktime = 0,
  ) {}

  public static function parse(string $raw): self
  {
    if (ctype_xdigit($raw) && strlen($raw) % 2 === 0) $raw = (string)hex2bin($raw);
    $o  = 0;
    $tx = new self(unpack('V', BsvBytes::take($raw, 0, 4))[1]);
    $o  = 4;
    [$nIn, $o] = BsvBytes::readVarint($raw, $o);
    for ($i = 0; $i < $nIn; $i++) {
      $txid = BsvBytes::take($raw, $o, 32);           $o += 32;
      $vout = unpack('V', BsvBytes::take($raw, $o, 4))[1]; $o += 4;
      [$len, $o] = BsvBytes::readVarint($raw, $o);
      $script = BsvBytes::take($raw, $o, $len);       $o += $len;
      $seq  = unpack('V', BsvBytes::take($raw, $o, 4))[1]; $o += 4;
      $tx->inputs[] = ['txid' => $txid, 'vout' => $vout, 'script' => $script, 'sequence' => $seq];
    }
    [$nOut, $o] = BsvBytes::readVarint($raw, $o);
    for ($i = 0; $i < $nOut; $i++) {
      // ⚠ 8 BYTES, not 4. A 4-byte read is identical below 42.9 BTC and silently wrong above it.
      $v = unpack('P', BsvBytes::take($raw, $o, 8))[1]; $o += 8;
      [$len, $o] = BsvBytes::readVarint($raw, $o);
      $tx->outputs[] = ['value' => $v, 'script' => BsvBytes::take($raw, $o, $len)];
      $o += $len;
    }
    $tx->locktime = unpack('V', BsvBytes::take($raw, $o, 4))[1];
    $o += 4;
    // ⛔ TRAILING BYTES ARE AN ERROR. A parser that ignores them accepts two different transactions as
    //   the same one, and the txid it reports belongs to neither.
    if ($o !== strlen($raw))
      throw new BsvTxError(sprintf('%d trailing byte(s) after the transaction', strlen($raw) - $o));
    return $tx;
  }

  public function serialize(): string
  {
    $b = pack('V', $this->version) . BsvBytes::varint(count($this->inputs));
    foreach ($this->inputs as $i)
      $b .= $i['txid'] . pack('V', $i['vout'])
          . BsvBytes::varint(strlen($i['script'])) . $i['script'] . pack('V', $i['sequence']);
    $b .= BsvBytes::varint(count($this->outputs));
    foreach ($this->outputs as $o)
      $b .= pack('P', $o['value']) . BsvBytes::varint(strlen($o['script'])) . $o['script'];
    return $b . pack('V', $this->locktime);
  }

  public function hex(): string { return bin2hex($this->serialize()); }

  /** ⚠ The txid a person reads is the hash REVERSED. The wire order and the display order are opposites. */
  public function txid(): string { return bin2hex(strrev(BsvBytes::dsha256($this->serialize()))); }

  /** ★ 100 sat/KB, and never ARC's suggestion. ⚠ Rounded UP: a fee below the floor is a stuck tx. */
  public function fee(int $satPerKb = 100): int
  {
    return (int)ceil(strlen($this->serialize()) * $satPerKb / 1000);
  }
}

final class BsvSighash
{
  public const ALL           = 0x01;
  public const NONE          = 0x02;
  public const SINGLE        = 0x03;
  public const FORKID        = 0x40;
  public const ANYONECANPAY  = 0x80;
  /** ★ What every live covenant in this project signs under: SIGHASH_ALL | FORKID. */
  public const ALL_FORKID    = 0x41;

  private const ZERO32 = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                       . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

  /**
   * The BIP-143 preimage.
   *
   * @param string $scriptCode the locking script being spent, RAW — its varint length is added here.
   *   ⚠⚠ BIP-143's published examples print it WITH the prefix; passing one of those in unchanged
   *     double-prefixes it and yields a preimage that is wrong and looks entirely plausible.
   * @param int $amount satoshis in the output being spent. ⚠ Wrong value, invalid signature, and
   *   nothing in the transaction reveals which one was assumed.
   */
  public static function preimage(BsvTx $tx, int $inputIndex, string $scriptCode, int $amount,
                                  int $sighashType = self::ALL_FORKID): string
  {
    if (!isset($tx->inputs[$inputIndex])) throw new BsvTxError("no input at index $inputIndex");
    if ($amount < 0) throw new BsvTxError('an amount cannot be negative');
    $in   = $tx->inputs[$inputIndex];
    $base = $sighashType & 0x1f;                 // ⚠ masks off FORKID (0x40) AND ANYONECANPAY (0x80)
    $acp  = ($sighashType & self::ANYONECANPAY) !== 0;

    // ⚠⚠ ANYONECANPAY zeroes BOTH prevouts and sequences: the signature stops committing to the other
    //   inputs, which is exactly what lets a sponsor fund the battery without invalidating it.
    $hashPrevouts = self::ZERO32;
    $hashSequence = self::ZERO32;
    if (!$acp) {
      $p = '';
      foreach ($tx->inputs as $i) $p .= $i['txid'] . pack('V', $i['vout']);
      $hashPrevouts = BsvBytes::dsha256($p);
      // ⚠ sequences are committed ONLY for ALL — NONE and SINGLE leave them free to change
      if ($base !== self::SINGLE && $base !== self::NONE) {
        $s = '';
        foreach ($tx->inputs as $i) $s .= pack('V', $i['sequence']);
        $hashSequence = BsvBytes::dsha256($s);
      }
    }

    $hashOutputs = self::ZERO32;
    if ($base !== self::SINGLE && $base !== self::NONE) {
      $o = '';
      foreach ($tx->outputs as $out)
        $o .= pack('P', $out['value']) . BsvBytes::varint(strlen($out['script'])) . $out['script'];
      $hashOutputs = BsvBytes::dsha256($o);
    } elseif ($base === self::SINGLE && isset($tx->outputs[$inputIndex])) {
      // ★ SINGLE commits to the ONE output at this input's index. ⛔ And past the last output it is
      //   ZEROS here, not Bitcoin's legacy `uint256(1)` bug — BIP-143 fixed that, and copying the old
      //   behaviour would produce a signature no BSV node accepts.
      $out = $tx->outputs[$inputIndex];
      $hashOutputs = BsvBytes::dsha256(
        pack('P', $out['value']) . BsvBytes::varint(strlen($out['script'])) . $out['script']);
    }

    return pack('V', $tx->version)
         . $hashPrevouts
         . $hashSequence
         . $in['txid'] . pack('V', $in['vout'])
         . BsvBytes::varint(strlen($scriptCode)) . $scriptCode
         . pack('P', $amount)
         . pack('V', $in['sequence'])
         . $hashOutputs
         . pack('V', $tx->locktime)
         . pack('V', $sighashType);         // ★ fork id 0 ⇒ 0x41 serializes as 41000000
  }

  /** The 32 bytes a signature is actually over. */
  public static function hash(BsvTx $tx, int $inputIndex, string $scriptCode, int $amount,
                              int $sighashType = self::ALL_FORKID): string
  {
    return BsvBytes::dsha256(self::preimage($tx, $inputIndex, $scriptCode, $amount, $sighashType));
  }
}
