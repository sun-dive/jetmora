<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ LAYER 2 of 2 — THE LOG RECORD. The STORAGE object. ═══════════════════════════════════════════════
//
// ★★★ HIS DESIGN, 31 Aug, and *this is where "log" is the CORRECT word*:
//
//   | **covenant chain** | the DESIGN object — a tip, ticked forward, only valid links |
//   | **log record**     | the STORAGE object — immutable, append-only, holds inputs, outputs AND errors |
//
//   > *"A full log record is itself an immutable chain that contains all inputs, outputs and errors."*
//
// ⚠⚠ **SECONDARY, NEVER PRIMARY.** The first test chain built THIS layer, competently, and called it
//   the covenant chain. Nothing was wrong with the layer; the claim about it was wrong. ⇒ Keeping the
//   two in separate files with different names is the cheapest guard against repeating that, because
//   the confusion was never a bug — it was a WORD.
//
// ★★ Errors live HERE, and that is the resolution of §4.3: a refusal is a fact worth keeping, but it is
//   **not a link in the chain.** ⇒ Nothing has to be deleted; it has somewhere to go.
//
// ⏱ ON THE TIMESTAMP (his words, 4 Sept): it is **a RECORD, not proof** — the writer's claim, per entry.
//   ★ It is what gives the log an order AT ALL, since the log holds errors and conflicts that no tick
//   sequence orders. ⚠⚠ **Nothing depends on it being honest, and a covenant MUST NOT read it.** §6.3
//   stays absolute: a covenant derives time from `nSequence` and never from a clock.
//
// ⛔ A LOG RECORD IS NOT A SPEND. It has no unlocking script, carries no signature, and proves nothing
//   about validity. That is not a shortcoming — it is the definition. Anything that needs proving
//   belongs in `covenant-entry.php`.
declare(strict_types=1);

final class LogRecordError extends RuntimeException {}

final class LogRecord
{
  /**
   * ⚠⚠ THE MAGIC EXISTS SO THE TWO LAYERS CANNOT BE CONFUSED AT THE BYTE LEVEL.
   * A covenant entry opens with a 4-byte `nVersion`. `JLR\x01` read as one is `0x014C524A`, whose
   * family bytes are `0x52 0x01` — and `0x01` is not in the legal family alphabet (§10.6: A-Z, 0-9),
   * while the high half being non-zero rules out a legacy version too. ⇒ **It can never be a valid
   * nVersion under either rule**, so a decoder handed the wrong object refuses immediately instead of
   * parsing it as the other. That is the guard the first chain did not have.
   */
  public const MAGIC = "JLR\x01";

  public const KIND_INPUT  = 0x01;
  public const KIND_OUTPUT = 0x02;
  public const KIND_ERROR  = 0x03;

  private const KINDS = [self::KIND_INPUT => 'input', self::KIND_OUTPUT => 'output',
                         self::KIND_ERROR => 'error'];

  /**
   * @param string $chainId   32 bytes — `HASH256(genesis ‖ branch)`. ★ His index id, 31 Aug: inputs and
   *                          outputs share it, so a covenant's records retrieve in one lookup. A static
   *                          covenant is `branch = zeroes`; a fork takes a new branch ⇒ new id, shared
   *                          genesis. One scheme, both cases.
   * @param string $prev      32 bytes — the previous record's hash, or 32 zero bytes for the first.
   *                          ⇒ *"a full log record is itself an immutable chain"*.
   * @param int    $timestamp the writer's claim. ⚠ NOT proof. See the header.
   */
  public static function encode(string $chainId, string $prev, int $seq, int $timestamp,
                                int $kind, string $payload): string
  {
    if (strlen($chainId) !== 32) throw new LogRecordError('chainId must be 32 bytes');
    if (strlen($prev) !== 32)    throw new LogRecordError('prev must be 32 bytes (zeroes for the first)');
    if (!isset(self::KINDS[$kind])) throw new LogRecordError('kind must be input, output or error');
    if ($seq < 0 || $timestamp < 0) throw new LogRecordError('seq and timestamp must be non-negative');
    if (strlen($payload) > 0xffffffff) throw new LogRecordError('payload too large');
    return self::MAGIC . $chainId . $prev . pack('P', $seq) . pack('P', $timestamp)
         . chr($kind) . pack('V', strlen($payload)) . $payload;
  }

  /** @return array{chainId:string,prev:string,seq:int,timestamp:int,kind:int,kindName:string,payload:string} */
  public static function decode(string $b): array
  {
    if (strlen($b) < 4 || substr($b, 0, 4) !== self::MAGIC)
      throw new LogRecordError(
        'not a log record: missing the JLR magic. ⚠ If these bytes came from a covenant chain they are '
      . 'a COVENANT ENTRY — use covenant-entry.php');
    if (strlen($b) < 4 + 32 + 32 + 8 + 8 + 1 + 4) throw new LogRecordError('log record truncated');
    $p = 4;
    $chainId = substr($b, $p, 32); $p += 32;
    $prev    = substr($b, $p, 32); $p += 32;
    $seq     = unpack('P', substr($b, $p, 8))[1]; $p += 8;
    $ts      = unpack('P', substr($b, $p, 8))[1]; $p += 8;
    $kind    = ord($b[$p]); $p++;
    if (!isset(self::KINDS[$kind])) throw new LogRecordError(sprintf('unknown kind 0x%02x', $kind));
    $len     = unpack('V', substr($b, $p, 4))[1]; $p += 4;
    if ($p + $len !== strlen($b))
      throw new LogRecordError('payload length does not match the record — trailing or truncated');
    return ['chainId' => $chainId, 'prev' => $prev, 'seq' => $seq, 'timestamp' => $ts,
            'kind' => $kind, 'kindName' => self::KINDS[$kind], 'payload' => substr($b, $p, $len)];
  }

  public static function hash(string $recordBytes): string
  {
    return hash('sha256', hash('sha256', $recordBytes, true), true);
  }

  /** ★ The index id both layers share, so a covenant's records retrieve in one lookup. */
  public static function chainId(string $genesis, string $branch): string
  {
    if (strlen($genesis) !== 32 || strlen($branch) !== 32)
      throw new LogRecordError('genesis and branch must each be 32 bytes');
    return hash('sha256', hash('sha256', $genesis . $branch, true), true);
  }
}
