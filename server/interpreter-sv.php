<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE `SV` SET: the interpreter ────────────────────────────────────────────────────────────────────
// BSV + Chronicle semantics. Written from the specification and the conformance vectors, NOT ported
// from `tools/interpreter.mjs` — ⚠ a port is a second copy, not an independent implementation, and the
// point of writing it is to become a FOURTH implementation the acid test can disagree with.
//
// ⚠⚠ ISOLATION (gaps §10.9). This file is the `SV` set and nothing else. A bug fix here MUST NOT be
// able to reach `BT` or `JF`. The only thing shared across sets is the conformance vector file.
//
// ── THE ARITHMETIC RULE, AND IT IS NOT NEGOTIABLE ────────────────────────────────────────────────────
// ⚠⚠⚠ NEVER touch PHP's native int for a stack value. `PHP_INT_MAX + 1` silently becomes a float:
// precision gone, NO error raised. Fatal for a machine whose product is the same answer every time.
// Everything numeric goes through GMP.
// ★ And NEVER convert to decimal. Script numbers are little-endian binary; `gmp_import`/`gmp_export`
//   speak binary directly. Decimal stringification dominated every timing it appeared in.
declare(strict_types=1);
require_once __DIR__ . '/ops-sv.php';

final class SvScriptError extends RuntimeException {}

final class InterpreterSV
{
  /** @var string[] main stack — raw binary strings, bottom first */
  private array $stack = [];
  /** @var string[] alt stack */
  private array $alt = [];
  /** @var bool[] conditional execution stack, one entry per open IF */
  private array $cond = [];
  private int $opCount = 0;

  /** Operator policy, never a protocol constant (§4.5). Past the budget there is simply no proof. */
  public function __construct(private int $maxOps = 200000) {}

  // ── script numbers ─────────────────────────────────────────────────────────────────────────────────
  // Little-endian sign-magnitude, sign in the HIGH BIT OF THE LAST BYTE.
  // ⚠ BSV applies no minimal-encoding rule on decode, so non-minimal forms are accepted, exactly as
  //   0.1.3 accepted them. Encoding is always minimal.

  /** bytes → GMP integer. */
  public static function toInt(string $b): GMP {
    $n = strlen($b);
    if ($n === 0) return gmp_init(0);
    $le = strrev($b);                                  // gmp_import wants big-endian
    $neg = (ord($b[$n - 1]) & 0x80) !== 0;
    if ($neg) $le[0] = chr(ord($le[0]) & 0x7f);        // clear the sign bit, big-endian first byte
    $v = gmp_import($le, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    return $neg ? gmp_neg($v) : $v;
  }

  /** GMP integer → minimal script-number bytes. */
  public static function fromInt(GMP $v): string {
    if (gmp_sign($v) === 0) return '';
    $neg = gmp_sign($v) < 0;
    $mag = gmp_abs($v);
    $be  = gmp_export($mag, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $le  = strrev($be);
    // ⚠ If the top bit of the most significant byte is taken, the sign needs a byte of its own.
    if (ord($le[strlen($le) - 1]) & 0x80) $le .= $neg ? "\x80" : "\x00";
    elseif ($neg) $le[strlen($le) - 1] = chr(ord($le[strlen($le) - 1]) | 0x80);
    return $le;
  }

  /** ⚠ Negative zero (0x80) is DATA and survives on the stack; only truth-casting treats it as false. */
  public static function toBool(string $b): bool {
    $n = strlen($b);
    for ($i = 0; $i < $n; $i++) {
      if ($b[$i] !== "\x00") {
        // a lone sign bit in the final byte is negative zero
        return !($i === $n - 1 && ord($b[$i]) === 0x80);
      }
    }
    return false;
  }

  // ── stack helpers ──────────────────────────────────────────────────────────────────────────────────
  private function need(int $n): void {
    if (count($this->stack) < $n) throw new SvScriptError("stack underflow: need $n");
  }
  private function pop(): string {
    if (!$this->stack) throw new SvScriptError('stack underflow');
    return array_pop($this->stack);
  }
  private function push(string $b): void { $this->stack[] = $b; }
  private function popInt(): GMP { return self::toInt($this->pop()); }
  private function pushInt(GMP $v): void { $this->push(self::fromInt($v)); }
  private function executing(): bool {
    foreach ($this->cond as $c) if (!$c) return false;
    return true;
  }

  /**
   * Run a script. Returns the final main stack as an array of raw binary strings.
   * @throws SvScriptError on any failure — a failed script has no stack, not a partial one.
   */
  public function run(string $script): array
  {
    $this->stack = $this->alt = $this->cond = [];
    $this->opCount = 0;
    $len = strlen($script);
    $i = 0;

    while ($i < $len) {
      if (++$this->opCount > $this->maxOps) throw new SvScriptError('op budget exhausted');
      $op = ord($script[$i]); $i++;

      // ── pushes ───────────────────────────────────────────────────────────────────────────────────
      if ($op >= 1 && $op <= 0x4b) {
        if ($i + $op > $len) throw new SvScriptError('push past end of script');
        if ($this->executing()) $this->push(substr($script, $i, $op));
        $i += $op;
        continue;
      }
      if ($op === 0x4c || $op === 0x4d || $op === 0x4e) {
        $w = $op === 0x4c ? 1 : ($op === 0x4d ? 2 : 4);
        if ($i + $w > $len) throw new SvScriptError('truncated pushdata length');
        $n = 0;
        for ($k = 0; $k < $w; $k++) $n |= ord($script[$i + $k]) << (8 * $k);  // little-endian
        $i += $w;
        if ($i + $n > $len) throw new SvScriptError('pushdata past end of script');
        if ($this->executing()) $this->push(substr($script, $i, $n));
        $i += $n;
        continue;
      }

      // ── conditionals run even when not executing; everything else does not ───────────────────────
      switch ($op) {
        case 0x63: case 0x64:                                   // OP_IF / OP_NOTIF
          if (!$this->executing()) { $this->cond[] = false; break; }
          $v = self::toBool($this->pop());
          $this->cond[] = ($op === 0x63) ? $v : !$v;
          break;
        case 0x67:                                              // OP_ELSE
          if (!$this->cond) throw new SvScriptError('OP_ELSE without OP_IF');
          $this->cond[count($this->cond) - 1] = !$this->cond[count($this->cond) - 1];
          break;
        case 0x68:                                              // OP_ENDIF
          if (!$this->cond) throw new SvScriptError('OP_ENDIF without OP_IF');
          array_pop($this->cond);
          break;

        // ⚠ 0.1.3 semantics, which the `bsv` vectors confirm: OP_RETURN does NOT fail. It jumps to the
        //   end of the script and the stack SURVIVES. `return.dropsRest` proves the tail is ignored.
        case 0x6a:
          if ($this->executing()) { $i = $len; }
          break;

        default:
          if (!$this->executing()) break;
          $this->step($op);
      }
    }

    if ($this->cond) throw new SvScriptError('unbalanced OP_IF');
    return $this->stack;
  }

  /** One opcode, executing. */
  private function step(int $op): void
  {
    switch ($op) {
      case 0x00: $this->push(''); return;                                     // OP_0
      case 0x4f: $this->push("\x81"); return;                                 // OP_1NEGATE
      case 0x61: return;                                                      // OP_NOP

      // ── constants 1..16 ───────────────────────────────────────────────────────────────────────────
      case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
      case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: case 0x60:
        $this->push(chr($op - 0x50)); return;

      // ── stack ─────────────────────────────────────────────────────────────────────────────────────
      case 0x6b: $this->alt[] = $this->pop(); return;                          // OP_TOALTSTACK
      case 0x6c:                                                              // OP_FROMALTSTACK
        if (!$this->alt) throw new SvScriptError('altstack underflow');
        $this->push(array_pop($this->alt)); return;
      case 0x6d: $this->need(2); array_pop($this->stack); array_pop($this->stack); return;   // 2DROP
      case 0x6e: $this->need(2);                                              // OP_2DUP
        $n = count($this->stack);
        $this->push($this->stack[$n - 2]); $this->push($this->stack[$n - 1]); return;
      case 0x6f: $this->need(3);                                              // OP_3DUP
        $n = count($this->stack);
        $a = $this->stack[$n - 3]; $b = $this->stack[$n - 2]; $c = $this->stack[$n - 1];
        $this->push($a); $this->push($b); $this->push($c); return;
      case 0x70: $this->need(4);                                              // OP_2OVER
        $n = count($this->stack);
        $this->push($this->stack[$n - 4]); $this->push($this->stack[$n - 3]); return;
      case 0x71: $this->need(6);                                              // OP_2ROT
        $x = array_splice($this->stack, count($this->stack) - 6, 2);
        $this->stack = array_merge($this->stack, $x); return;
      case 0x72: $this->need(4);                                              // OP_2SWAP
        $x = array_splice($this->stack, count($this->stack) - 4, 2);
        $this->stack = array_merge($this->stack, $x); return;
      case 0x73: $this->need(1);                                              // OP_IFDUP
        $t = $this->stack[count($this->stack) - 1];
        if (self::toBool($t)) $this->push($t); return;
      case 0x74: $this->pushInt(gmp_init(count($this->stack))); return;        // OP_DEPTH
      case 0x75: $this->pop(); return;                                        // OP_DROP
      case 0x76: $this->need(1); $this->push($this->stack[count($this->stack) - 1]); return; // OP_DUP
      case 0x77: $this->need(2); array_splice($this->stack, count($this->stack) - 2, 1); return; // NIP
      case 0x78: $this->need(2); $this->push($this->stack[count($this->stack) - 2]); return; // OP_OVER
      case 0x79: {                                                            // OP_PICK
        $n = gmp_intval($this->popInt());
        if ($n < 0 || $n >= count($this->stack)) throw new SvScriptError('OP_PICK out of range');
        $this->push($this->stack[count($this->stack) - 1 - $n]); return;
      }
      case 0x7a: {                                                            // OP_ROLL
        $n = gmp_intval($this->popInt());
        if ($n < 0 || $n >= count($this->stack)) throw new SvScriptError('OP_ROLL out of range');
        $v = array_splice($this->stack, count($this->stack) - 1 - $n, 1);
        $this->push($v[0]); return;
      }
      case 0x7b: $this->need(3);                                              // OP_ROT
        $v = array_splice($this->stack, count($this->stack) - 3, 1);
        $this->push($v[0]); return;
      case 0x7c: $this->need(2);                                              // OP_SWAP
        $v = array_splice($this->stack, count($this->stack) - 2, 1);
        $this->push($v[0]); return;
      case 0x7d: $this->need(2);                                              // OP_TUCK
        $t = $this->stack[count($this->stack) - 1];
        array_splice($this->stack, count($this->stack) - 2, 0, [$t]); return;

      // ── byte strings ──────────────────────────────────────────────────────────────────────────────
      case 0x7e: { $b = $this->pop(); $a = $this->pop(); $this->push($a . $b); return; }   // OP_CAT
      case 0x82: $this->need(1);                                              // OP_SIZE
        $this->pushInt(gmp_init(strlen($this->stack[count($this->stack) - 1]))); return;

      case 0x83: {                                                            // OP_INVERT
        $a = $this->pop(); $o = '';
        for ($k = 0; $k < strlen($a); $k++) $o .= chr(~ord($a[$k]) & 0xff);
        $this->push($o); return;
      }
      // ⚠ BSV requires EQUAL LENGTH for the bitwise words and fails otherwise.
      //   0.1.3 pads the shorter operand — that difference is why `and.padshort` is oracle=013 and
      //   lives in the `BT` set's contract, not this one.
      case 0x84: case 0x85: case 0x86: {
        $b = $this->pop(); $a = $this->pop();
        if (strlen($a) !== strlen($b)) throw new SvScriptError('bitwise operands differ in length');
        $o = '';
        for ($k = 0; $k < strlen($a); $k++) {
          $x = ord($a[$k]); $y = ord($b[$k]);
          $o .= chr($op === 0x84 ? ($x & $y) : ($op === 0x85 ? ($x | $y) : ($x ^ $y)));
        }
        $this->push($o); return;
      }

      case 0x87: case 0x88: {                                                 // OP_EQUAL / EQUALVERIFY
        $b = $this->pop(); $a = $this->pop();
        $eq = ($a === $b);                                                    // ⚠ BYTE STRING compare
        if ($op === 0x88) { if (!$eq) throw new SvScriptError('OP_EQUALVERIFY failed'); return; }
        $this->push($eq ? "\x01" : ''); return;
      }

      // ── arithmetic ────────────────────────────────────────────────────────────────────────────────
      case 0x8b: $this->pushInt(gmp_add($this->popInt(), 1)); return;          // OP_1ADD
      case 0x8c: $this->pushInt(gmp_sub($this->popInt(), 1)); return;          // OP_1SUB
      case 0x8d: $this->pushInt(gmp_mul($this->popInt(), 2)); return;          // OP_2MUL
      case 0x8e: $this->pushInt(self::divTrunc($this->popInt(), gmp_init(2))); return;  // OP_2DIV
      case 0x8f: $this->pushInt(gmp_neg($this->popInt())); return;            // OP_NEGATE
      case 0x90: $this->pushInt(gmp_abs($this->popInt())); return;            // OP_ABS
      case 0x91: $this->push(self::toBool($this->pop()) ? '' : "\x01"); return;   // OP_NOT
      case 0x92: $this->push(self::toBool($this->pop()) ? "\x01" : ''); return;   // OP_0NOTEQUAL

      case 0x93: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_add($a, $b)); return; }
      case 0x94: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_sub($a, $b)); return; }
      case 0x95: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_mul($a, $b)); return; }
      case 0x96: {                                                            // OP_DIV
        $b = $this->popInt(); $a = $this->popInt();
        if (gmp_sign($b) === 0) throw new SvScriptError('division by zero');
        $this->pushInt(self::divTrunc($a, $b)); return;
      }
      case 0x97: {                                                            // OP_MOD
        $b = $this->popInt(); $a = $this->popInt();
        if (gmp_sign($b) === 0) throw new SvScriptError('modulo by zero');
        $this->pushInt(self::modTrunc($a, $b)); return;
      }

      case 0x9a: { $b = $this->pop(); $a = $this->pop();                      // OP_BOOLAND
        $this->push((self::toBool($a) && self::toBool($b)) ? "\x01" : ''); return; }
      case 0x9b: { $b = $this->pop(); $a = $this->pop();                      // OP_BOOLOR
        $this->push((self::toBool($a) || self::toBool($b)) ? "\x01" : ''); return; }

      case 0x9c: case 0x9d: {                                                 // NUMEQUAL / VERIFY
        $b = $this->popInt(); $a = $this->popInt();
        $eq = gmp_cmp($a, $b) === 0;
        if ($op === 0x9d) { if (!$eq) throw new SvScriptError('OP_NUMEQUALVERIFY failed'); return; }
        $this->push($eq ? "\x01" : ''); return;
      }
      case 0x9e: { $b = $this->popInt(); $a = $this->popInt();
        $this->push(gmp_cmp($a, $b) !== 0 ? "\x01" : ''); return; }
      case 0x9f: { $b = $this->popInt(); $a = $this->popInt();
        $this->push(gmp_cmp($a, $b) < 0 ? "\x01" : ''); return; }
      case 0xa0: { $b = $this->popInt(); $a = $this->popInt();
        $this->push(gmp_cmp($a, $b) > 0 ? "\x01" : ''); return; }
      case 0xa1: { $b = $this->popInt(); $a = $this->popInt();
        $this->push(gmp_cmp($a, $b) <= 0 ? "\x01" : ''); return; }
      case 0xa2: { $b = $this->popInt(); $a = $this->popInt();
        $this->push(gmp_cmp($a, $b) >= 0 ? "\x01" : ''); return; }
      case 0xa3: { $b = $this->popInt(); $a = $this->popInt();
        $this->pushInt(gmp_cmp($a, $b) < 0 ? $a : $b); return; }
      case 0xa4: { $b = $this->popInt(); $a = $this->popInt();
        $this->pushInt(gmp_cmp($a, $b) > 0 ? $a : $b); return; }
      case 0xa5: {                                                            // OP_WITHIN — min <= x < max
        $max = $this->popInt(); $min = $this->popInt(); $x = $this->popInt();
        $in = gmp_cmp($x, $min) >= 0 && gmp_cmp($x, $max) < 0;
        $this->push($in ? "\x01" : ''); return;
      }

      case 0x69:                                                              // OP_VERIFY
        if (!self::toBool($this->pop())) throw new SvScriptError('OP_VERIFY failed');
        return;

      // ── digests ───────────────────────────────────────────────────────────────────────────────────
      case 0xa6: $this->push(hash('ripemd160', $this->pop(), true)); return;
      case 0xa7: $this->push(hash('sha1',      $this->pop(), true)); return;
      case 0xa8: $this->push(hash('sha256',    $this->pop(), true)); return;
      case 0xa9: $this->push(hash('ripemd160', hash('sha256', $this->pop(), true), true)); return;
      case 0xaa: $this->push(hash('sha256',    hash('sha256', $this->pop(), true), true)); return;

      default:
        throw new SvScriptError('unimplemented opcode ' . sv_op_name($op));
    }
  }

  // ⚠⚠ TRUNCATION TOWARD ZERO, NOT FLOOR: -7/2 = -3, NOT -4. And the remainder takes the sign of the
  //    DIVIDEND: -7 % 2 = -1.
  // ★ MEASURED, not assumed: GMP's defaults are already both of these — gmp_div_q(-7,2) = -3 and
  //   gmp_div_r(-7,2) = -1. An earlier version wrapped them in abs-and-restore, which was redundant and
  //   read as though GMP needed correcting. It does not.
  // ⛔ gmp_mod is the WRONG function here: it returns a non-negative remainder (gmp_mod(-7,2) = 1).
  private static function divTrunc(GMP $a, GMP $b): GMP { return gmp_div_q($a, $b); }
  private static function modTrunc(GMP $a, GMP $b): GMP { return gmp_div_r($a, $b); }
}

/**
 * H(result) = sha256( for each stack item: varint(len) ‖ bytes ) — the §2b comparison hash.
 * ⚠ Canonical by construction: one byte string per stack, no optional fields.
 */
function sv_stack_hash(array $items): string {
  $b = '';
  foreach ($items as $d) {
    $n = strlen($d);
    if ($n < 0xfd)        $b .= chr($n);
    elseif ($n <= 0xffff) $b .= "\xfd" . chr($n & 0xff) . chr($n >> 8);
    else                  $b .= "\xfe" . pack('V', $n);
    $b .= $d;
  }
  return hash('sha256', $b);
}
