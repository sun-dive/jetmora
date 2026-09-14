<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ LAYER 1 of 2 — THE COVENANT ENTRY. The DESIGN object. ════════════════════════════════════════════
//
// His words, 31 Aug: a covenant chain is *"a tip, ticked forward, only valid links"*.
//
// ⚠⚠⚠ WHY THIS FILE EXISTS SEPARATELY FROM `log-record.php`, AND IT IS THE LESSON OF THE FIRST CHAIN.
//   One serializer was used for BOTH layers. It permitted `unlocking = 0 bytes`, because a LOG RECORD
//   has no unlocking script and never needed one. ⇒ **528 log rows were therefore serialized as
//   covenant entries and called a chain.** Parsed from the live database, every entry read:
//
//       version 103 · inputs 1 · unlocking 0 BYTES · outputs 1 · locking 24 bytes of STATE
//
//   No signature. No `OP_PUSH_TX` preimage. No proof the transition was permitted. **A previous hash,
//   a counter, a value and some state — which is a log row, and a perfectly good one.** The defect was
//   never that a log exists; it is the SECONDARY layer and it is needed. The defect was one format
//   serving two layers, so the secondary could pass as the primary.
//
// ⇒ ★★★ THEREFORE: **a covenant entry without an unlocking script is not a covenant entry.** That is
//   enforced here on encode AND decode, so the shape that produced the first chain is now
//   unrepresentable rather than merely discouraged.
//
// ⛔ NEVER put a log record through this file, and never put a covenant entry through `log-record.php`.
//   They are different objects. The two decoders refuse each other's bytes by construction.
declare(strict_types=1);

final class CovenantEntryError extends RuntimeException {}

/**
 * An entry IS a transaction (spec §3): it serializes so the sighash preimage computed over it has the
 * same shape Bitcoin's does. ⚠ CANONICAL: exactly one byte string per entry — `OP_PUSH_TX` is secure
 * only because a verifier RECOMPUTES the preimage and compares, and two encodings would let a signer
 * push a preimage that does not describe what they did.
 */
final class CovenantEntry
{
  /**
   * @param array{version:int,inputs:array,outputs:array,locktime:int} $e
   *   inputs:  [{prevEntry: 32 raw bytes, index: int, unlocking: raw, sequence: int}, ...]
   *   outputs: [{value: raw 8 bytes|int, locking: raw}, ...]
   */
  public static function encode(array $e): string
  {
    if (($e['locktime'] ?? 0) !== 0) throw new CovenantEntryError('§3: nLocktime MUST be 0 in version 1');
    if (empty($e['inputs']))  throw new CovenantEntryError('an entry must consume at least one previous entry');
    if (empty($e['outputs'])) throw new CovenantEntryError('an entry must produce at least one successor');

    $out = pack('V', $e['version']) . self::varint(count($e['inputs']));
    foreach ($e['inputs'] as $i) {
      if (strlen($i['prevEntry']) !== 32) throw new CovenantEntryError('prevEntry must be 32 bytes');
      // ⛔⛔ THE GUARD. This one line is what the first chain lacked.
      if (($i['unlocking'] ?? '') === '')
        throw new CovenantEntryError(
          'an input with NO UNLOCKING SCRIPT is not a spend — it proves nothing about whether the '
        . 'transition was permitted. That is a LOG RECORD; use log-record.php');
      $out .= $i['prevEntry'] . pack('V', $i['index'])
            . self::varint(strlen($i['unlocking'])) . $i['unlocking'] . pack('V', $i['sequence']);
    }
    $out .= self::varint(count($e['outputs']));
    foreach ($e['outputs'] as $o) {
      // ⚠ A successor with no locking script is a state blob, not a covenant. Same defect, other end.
      if (($o['locking'] ?? '') === '')
        throw new CovenantEntryError(
          'an output with NO LOCKING SCRIPT carries state, not a covenant — that is a LOG RECORD');
      $v = is_int($o['value']) ? pack('P', $o['value']) : $o['value'];
      if (strlen($v) !== 8) throw new CovenantEntryError('value must be 8 bytes');
      $out .= $v . self::varint(strlen($o['locking'])) . $o['locking'];
    }
    return $out . pack('V', $e['locktime']);
  }

  /** @return array{version:int,inputs:array,outputs:array,locktime:int} */
  public static function decode(string $b): array
  {
    $p = 0;
    $u32 = function () use (&$p, $b) {
      if ($p + 4 > strlen($b)) throw new CovenantEntryError('entry truncated');
      $v = unpack('V', substr($b, $p, 4))[1]; $p += 4; return $v;
    };
    $take = function (int $n) use (&$p, $b) {
      if ($p + $n > strlen($b)) throw new CovenantEntryError('entry truncated');
      $s = substr($b, $p, $n); $p += $n; return $s;
    };
    $vi = function () use (&$p, $b) { return self::readVarint($b, $p); };

    $version = $u32();
    $inputs = [];
    for ($n = $vi(), $i = 0; $i < $n; $i++) {
      $prev = $take(32); $idx = $u32(); $ul = $vi(); $unlock = $take($ul); $seq = $u32();
      // ⛔ refused on DECODE too: the first chain's entries must not round-trip through this file
      if ($ul === 0)
        throw new CovenantEntryError(
          'input has no unlocking script — this is a LOG RECORD, not a covenant entry');
      $inputs[] = ['prevEntry' => $prev, 'index' => $idx, 'unlocking' => $unlock, 'sequence' => $seq];
    }
    $outputs = [];
    for ($n = $vi(), $i = 0; $i < $n; $i++) {
      $val = $take(8); $ll = $vi(); $lock = $take($ll);
      if ($ll === 0) throw new CovenantEntryError('output has no locking script — this is a LOG RECORD');
      $outputs[] = ['value' => $val, 'locking' => $lock];
    }
    $locktime = $u32();
    if ($p !== strlen($b)) throw new CovenantEntryError('trailing bytes: ' . (strlen($b) - $p));
    return ['version' => $version, 'inputs' => $inputs, 'outputs' => $outputs, 'locktime' => $locktime];
  }

  public static function hash(string $entryBytes): string
  {
    return hash('sha256', hash('sha256', $entryBytes, true), true);
  }

  private static function varint(int $n): string
  {
    if ($n < 0xfd)        return chr($n);
    if ($n <= 0xffff)     return "\xfd" . pack('v', $n);
    if ($n <= 0xffffffff) return "\xfe" . pack('V', $n);
    throw new CovenantEntryError('length beyond a 4-byte varint');
  }

  /** ⚠ REFUSES a non-minimal varint — accepting one would give an entry two encodings. */
  private static function readVarint(string $b, int &$p): int
  {
    if ($p >= strlen($b)) throw new CovenantEntryError('varint truncated');
    $c = ord($b[$p]); $p++;
    if ($c < 0xfd) return $c;
    if ($c === 0xfd) {
      if ($p + 2 > strlen($b)) throw new CovenantEntryError('varint truncated');
      $v = unpack('v', substr($b, $p, 2))[1]; $p += 2;
      if ($v < 0xfd) throw new CovenantEntryError('non-minimal varint');
      return $v;
    }
    if ($c === 0xfe) {
      if ($p + 4 > strlen($b)) throw new CovenantEntryError('varint truncated');
      $v = unpack('V', substr($b, $p, 4))[1]; $p += 4;
      if ($v <= 0xffff) throw new CovenantEntryError('non-minimal varint');
      return $v;
    }
    throw new CovenantEntryError('8-byte varint is not a length here');
  }
}
