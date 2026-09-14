<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE `BT` SET: the interpreter ────────────────────────────────────────────────────────────────────
// **Bitcoin 0.1.3.** Its purpose is one thing: so that script from 2009 and 2010 executes AS WRITTEN.
// ⇒ §5b.1a — BTC disabled those opcodes and cannot run such a script at all; BSV re-enabled them but
//   renumbered 0x7f–0x81, so a 2009 OP_SUBSTR executes there as OP_SPLIT. **Not an error. A different
//   answer**, which is worse. An implementation keeping 0.1.3's positions may be the only environment
//   able to execute early Bitcoin script correctly, and that is checkable: find such an output, run it.
//
// ⚠⚠ ISOLATION (gaps §10.9). This file is `BT` and nothing else. It shares no code with `interpreter-sv.php`
// — deliberately. The stack machine looks similar because both are Bitcoin; the SEMANTICS differ in six
// places and each one is marked below. A fix here MUST NOT be able to reach `SV` or `JF`.
//
// ⛔ NOTHING ABOVE 0xaf EXISTS IN THIS SET. jetmora's 0xb0–0xb2 are refused, not silently ignored.
declare(strict_types=1);
require_once __DIR__ . '/ops-bt.php';

final class BtScriptError extends RuntimeException {}

final class InterpreterBT
{
  /** @var string[] */ private array $stack = [];
  /** @var string[] */ private array $alt = [];
  /** @var bool[]   */ private array $cond = [];
  private int $opCount = 0;

  /** Operator policy, never a protocol constant (§4.5). */
  public function __construct(private int $maxOps = 200000) {}

  // ── script numbers — little-endian sign-magnitude, sign in the high bit of the LAST byte ───────────
  // ⚠ 0.1.3 applies NO size limit and NO minimal-encoding rule: operands are OpenSSL BIGNUMs
  //   (`CBigNum bn1(stacktop(-2))`, script.cpp:567). Non-minimal forms decode; encoding is minimal.
  // ⚠⚠ NEVER PHP's native int — PHP_INT_MAX + 1 silently becomes a float, no error raised.

  public static function toInt(string $b): GMP {
    $n = strlen($b);
    if ($n === 0) return gmp_init(0);
    $le = strrev($b);
    $neg = (ord($b[$n - 1]) & 0x80) !== 0;
    if ($neg) $le[0] = chr(ord($le[0]) & 0x7f);
    $v = gmp_import($le, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    return $neg ? gmp_neg($v) : $v;
  }

  public static function fromInt(GMP $v): string {
    if (gmp_sign($v) === 0) return '';
    $neg = gmp_sign($v) < 0;
    $be  = gmp_export(gmp_abs($v), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $le  = strrev($be);
    if (ord($le[strlen($le) - 1]) & 0x80) $le .= $neg ? "\x80" : "\x00";
    elseif ($neg) $le[strlen($le) - 1] = chr(ord($le[strlen($le) - 1]) | 0x80);
    return $le;
  }

  /** ⚠ Negative zero (0x80) survives as DATA; only truth-casting treats it as false. */
  public static function toBool(string $b): bool {
    $n = strlen($b);
    for ($i = 0; $i < $n; $i++) {
      if ($b[$i] !== "\x00") return !($i === $n - 1 && ord($b[$i]) === 0x80);
    }
    return false;
  }

  private function need(int $n): void {
    if (count($this->stack) < $n) throw new BtScriptError("stack underflow: need $n");
  }
  private function pop(): string {
    if (!$this->stack) throw new BtScriptError('stack underflow');
    return array_pop($this->stack);
  }
  private function push(string $b): void { $this->stack[] = $b; }
  private function popInt(): GMP { return self::toInt($this->pop()); }
  private function pushInt(GMP $v): void { $this->push(self::fromInt($v)); }
  private function executing(): bool {
    foreach ($this->cond as $c) if (!$c) return false;
    return true;
  }

  public function run(string $script): array
  {
    $this->stack = $this->alt = $this->cond = [];
    $this->opCount = 0;
    $len = strlen($script);
    $i = 0;

    while ($i < $len) {
      if (++$this->opCount > $this->maxOps) throw new BtScriptError('op budget exhausted');
      $op = ord($script[$i]); $i++;

      // ── ★ DIVERGENCE 1 · THE TWO-BYTE SPACE ────────────────────────────────────────────────────
      // 0.1.3's reader takes the next byte when it sees 0xf0. It defines no occupants, so nothing
      // behind the prefix is valid. ⇒ Reading it and then failing IS the faithful behaviour.
      if ($op === BT_SINGLEBYTE_END) {
        if ($i >= $len) throw new BtScriptError('truncated two-byte opcode');
        $second = ord($script[$i]); $i++;
        if ($this->executing()) {
          throw new BtScriptError(sprintf(
            'no two-byte opcode 0x%02x%02x exists in Bitcoin 0.1.3 — the space is declared and empty',
            $op, $second));
        }
        continue;
      }

      if ($op >= 1 && $op <= 0x4b) {
        if ($i + $op > $len) throw new BtScriptError('push past end of script');
        if ($this->executing()) $this->push(substr($script, $i, $op));
        $i += $op;
        continue;
      }
      if ($op === 0x4c || $op === 0x4d || $op === 0x4e) {
        $w = $op === 0x4c ? 1 : ($op === 0x4d ? 2 : 4);
        if ($i + $w > $len) throw new BtScriptError('truncated pushdata length');
        $n = 0;
        for ($k = 0; $k < $w; $k++) $n |= ord($script[$i + $k]) << (8 * $k);
        $i += $w;
        if ($i + $n > $len) throw new BtScriptError('pushdata past end of script');
        if ($this->executing()) $this->push(substr($script, $i, $n));
        $i += $n;
        continue;
      }

      switch ($op) {
        case 0x63: case 0x64:
          if (!$this->executing()) { $this->cond[] = false; break; }
          $v = self::toBool($this->pop());
          $this->cond[] = ($op === 0x63) ? $v : !$v;
          break;
        case 0x67:
          if (!$this->cond) throw new BtScriptError('OP_ELSE without OP_IF');
          $this->cond[count($this->cond) - 1] = !$this->cond[count($this->cond) - 1];
          break;
        case 0x68:
          if (!$this->cond) throw new BtScriptError('OP_ENDIF without OP_IF');
          array_pop($this->cond);
          break;
        case 0x6a:                                    // OP_RETURN: `pc = pend` — jumps, does NOT fail
          if ($this->executing()) { $i = $len; }
          break;
        default:
          if (!$this->executing()) break;
          $this->step($op);
      }
    }

    // ── ★★★ DIVERGENCE 2 · AN UNBALANCED OP_IF IS NOT AN ERROR ─────────────────────────────────────
    // 0.1.3's EvalScript does NOT check that the conditional stack is empty when the script ends. It
    // simply ends. ⚠ The JS interpreter failed exactly here, having imported a modern rule by habit;
    // `if.unbalanced` and `if.unbalanced.f` exist because of it. The unclosed branch never executes,
    // and whatever is on the stack is the result.
    return $this->stack;
  }

  private function step(int $op): void
  {
    // ⛔ jetmora's own range does not exist here. Refuse it loudly rather than reach the default.
    if ($op >= 0xb0) {
      throw new BtScriptError(sprintf(
        'opcode 0x%02x is above 0xaf — Bitcoin 0.1.3 defines nothing there', $op));
    }

    switch ($op) {
      case 0x00: $this->push(''); return;
      case 0x4f: $this->push("\x81"); return;
      case 0x61: return;

      case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
      case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: case 0x60:
        $this->push(chr($op - 0x50)); return;

      // ── stack ─────────────────────────────────────────────────────────────────────────────────────
      case 0x6b: $this->alt[] = $this->pop(); return;
      case 0x6c:
        if (!$this->alt) throw new BtScriptError('altstack underflow');
        $this->push(array_pop($this->alt)); return;
      case 0x6d: $this->need(2); array_pop($this->stack); array_pop($this->stack); return;
      case 0x6e: $this->need(2); $n = count($this->stack);
        $this->push($this->stack[$n - 2]); $this->push($this->stack[$n - 1]); return;
      case 0x6f: $this->need(3); $n = count($this->stack);
        $a = $this->stack[$n - 3]; $b = $this->stack[$n - 2]; $c = $this->stack[$n - 1];
        $this->push($a); $this->push($b); $this->push($c); return;
      case 0x70: $this->need(4); $n = count($this->stack);
        $this->push($this->stack[$n - 4]); $this->push($this->stack[$n - 3]); return;
      case 0x71: $this->need(6);
        $x = array_splice($this->stack, count($this->stack) - 6, 2);
        $this->stack = array_merge($this->stack, $x); return;
      case 0x72: $this->need(4);
        $x = array_splice($this->stack, count($this->stack) - 4, 2);
        $this->stack = array_merge($this->stack, $x); return;
      case 0x73: $this->need(1);
        $t = $this->stack[count($this->stack) - 1];
        if (self::toBool($t)) $this->push($t); return;
      case 0x74: $this->pushInt(gmp_init(count($this->stack))); return;
      case 0x75: $this->pop(); return;
      case 0x76: $this->need(1); $this->push($this->stack[count($this->stack) - 1]); return;
      case 0x77: $this->need(2); array_splice($this->stack, count($this->stack) - 2, 1); return;
      case 0x78: $this->need(2); $this->push($this->stack[count($this->stack) - 2]); return;
      case 0x79: {
        $n = gmp_intval($this->popInt());
        if ($n < 0 || $n >= count($this->stack)) throw new BtScriptError('OP_PICK out of range');
        $this->push($this->stack[count($this->stack) - 1 - $n]); return;
      }
      case 0x7a: {
        $n = gmp_intval($this->popInt());
        if ($n < 0 || $n >= count($this->stack)) throw new BtScriptError('OP_ROLL out of range');
        $v = array_splice($this->stack, count($this->stack) - 1 - $n, 1);
        $this->push($v[0]); return;
      }
      case 0x7b: $this->need(3);
        $v = array_splice($this->stack, count($this->stack) - 3, 1); $this->push($v[0]); return;
      case 0x7c: $this->need(2);
        $v = array_splice($this->stack, count($this->stack) - 2, 1); $this->push($v[0]); return;
      case 0x7d: $this->need(2);
        $t = $this->stack[count($this->stack) - 1];
        array_splice($this->stack, count($this->stack) - 2, 0, [$t]); return;

      case 0x7e: { $b = $this->pop(); $a = $this->pop(); $this->push($a . $b); return; }

      // ── ★★★ DIVERGENCE 3 · STRING OPS AT 0x7f–0x81 ─────────────────────────────────────────────────
      // ⚠⚠ BSV has SPLIT/NUM2BIN/BIN2NUM at these numbers. This is the single most consequential
      //    difference between the two sets, and the reason a 2009 script must declare `BT`.
      case 0x7f: {                                  // OP_SUBSTR (data, begin, count)
        $this->need(3);
        $count = gmp_intval($this->popInt());
        $begin = gmp_intval($this->popInt());
        $data  = $this->pop();
        // ⚠ ONE expression, checked and used. An earlier version validated `$begin + $count` but
        //   extracted with `substr($data, $begin, $count)` — two expressions for one intent, so a
        //   mutation to the check left the extraction untouched and produced a SHORT READ.
        //   ⇒ `substr.overrun` is the vector; this is the shape that makes it impossible.
        if ($begin < 0 || $count < 0 || $begin + $count > strlen($data)) {
          throw new BtScriptError('OP_SUBSTR out of range');
        }
        $out = substr($data, $begin, $count);
        if (strlen($out) !== $count) throw new BtScriptError('OP_SUBSTR short read');   // belt
        $this->push($out); return;
      }
      case 0x80: {                                  // OP_LEFT (data, size) — keep the FIRST size bytes
        $this->need(2);
        $size = gmp_intval($this->popInt());
        $data = $this->pop();
        if ($size < 0 || $size > strlen($data)) throw new BtScriptError('OP_LEFT out of range');
        $this->push(substr($data, 0, $size)); return;
      }
      case 0x81: {                                  // OP_RIGHT (data, start) — drop the FIRST start bytes
        $this->need(2);
        $start = gmp_intval($this->popInt());
        $data  = $this->pop();
        if ($start < 0 || $start > strlen($data)) throw new BtScriptError('OP_RIGHT out of range');
        $this->push(substr($data, $start)); return;
      }
      case 0x82: $this->need(1);
        $this->pushInt(gmp_init(strlen($this->stack[count($this->stack) - 1]))); return;

      case 0x83: {                                                            // OP_INVERT — bytewise
        $a = $this->pop(); $o = '';
        for ($k = 0; $k < strlen($a); $k++) $o .= chr(~ord($a[$k]) & 0xff);
        $this->push($o); return;
      }

      // ── ★★★ DIVERGENCE 4 · BITWISE PADS, IT DOES NOT REFUSE ────────────────────────────────────────
      // 0.1.3 calls MakeSameSize() and ZERO-PADS the shorter operand to the longer (script.cpp:26); the
      // result takes the LONGER length. ⚠ BSV REFUSES mismatched sizes.
      // ⚠⚠ Found by differential fuzzing 24 Aug: an earlier implementation TRUNCATED to the shorter —
      //    a THIRD behaviour, matching neither, and no curated vector exercised unequal lengths.
      case 0x84: case 0x85: case 0x86: {
        $b = $this->pop(); $a = $this->pop();
        $n = max(strlen($a), strlen($b));
        $a = str_pad($a, $n, "\x00", STR_PAD_RIGHT);
        $b = str_pad($b, $n, "\x00", STR_PAD_RIGHT);
        $o = '';
        for ($k = 0; $k < $n; $k++) {
          $x = ord($a[$k]); $y = ord($b[$k]);
          $o .= chr($op === 0x84 ? ($x & $y) : ($op === 0x85 ? ($x | $y) : ($x ^ $y)));
        }
        $this->push($o); return;
      }

      case 0x87: case 0x88: {
        $b = $this->pop(); $a = $this->pop();
        $eq = ($a === $b);                                                    // BYTE STRING compare
        if ($op === 0x88) { if (!$eq) throw new BtScriptError('OP_EQUALVERIFY failed'); return; }
        $this->push($eq ? "\x01" : ''); return;
      }

      // ── arithmetic ────────────────────────────────────────────────────────────────────────────────
      case 0x8b: $this->pushInt(gmp_add($this->popInt(), 1)); return;
      case 0x8c: $this->pushInt(gmp_sub($this->popInt(), 1)); return;
      case 0x8d: $this->pushInt(gmp_mul($this->popInt(), 2)); return;
      case 0x8e: $this->pushInt(gmp_div_q($this->popInt(), gmp_init(2))); return;
      case 0x8f: $this->pushInt(gmp_neg($this->popInt())); return;
      case 0x90: $this->pushInt(gmp_abs($this->popInt())); return;
      case 0x91: $this->push(self::toBool($this->pop()) ? '' : "\x01"); return;
      case 0x92: $this->push(self::toBool($this->pop()) ? "\x01" : ''); return;

      case 0x93: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_add($a, $b)); return; }
      case 0x94: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_sub($a, $b)); return; }
      case 0x95: { $b = $this->popInt(); $a = $this->popInt(); $this->pushInt(gmp_mul($a, $b)); return; }
      // ⚠ TRUNCATION TOWARD ZERO (-7/2 = -3) and the remainder takes the DIVIDEND's sign (-7 % 2 = -1).
      //   ★ Measured: GMP's defaults are already both. ⛔ gmp_mod is WRONG here — it returns non-negative.
      case 0x96: {
        $b = $this->popInt(); $a = $this->popInt();
        if (gmp_sign($b) === 0) throw new BtScriptError('division by zero');
        $this->pushInt(gmp_div_q($a, $b)); return;
      }
      case 0x97: {
        $b = $this->popInt(); $a = $this->popInt();
        if (gmp_sign($b) === 0) throw new BtScriptError('modulo by zero');
        $this->pushInt(gmp_div_r($a, $b)); return;
      }

      // ── ★★★ DIVERGENCE 5 · SHIFTS ARE NUMERIC, NOT BYTEWISE ────────────────────────────────────────
      // `bn = bn1 << bn2.getulong()` (script.cpp). ⚠ BSV's LSHIFT is a BYTEWISE shift of a string:
      //    same opcode, different meaning. A negative shift count has no meaning and fails.
      case 0x98: case 0x99: {
        $n = $this->popInt(); $v = $this->popInt();
        if (gmp_sign($n) < 0) throw new BtScriptError('negative shift');
        $k = gmp_intval($n);
        $this->pushInt($op === 0x98 ? gmp_mul($v, gmp_pow(2, $k)) : gmp_div_q($v, gmp_pow(2, $k)));
        return;
      }

      case 0x9a: { $b = $this->pop(); $a = $this->pop();
        $this->push((self::toBool($a) && self::toBool($b)) ? "\x01" : ''); return; }
      case 0x9b: { $b = $this->pop(); $a = $this->pop();
        $this->push((self::toBool($a) || self::toBool($b)) ? "\x01" : ''); return; }

      case 0x9c: case 0x9d: {
        $b = $this->popInt(); $a = $this->popInt();
        $eq = gmp_cmp($a, $b) === 0;
        if ($op === 0x9d) { if (!$eq) throw new BtScriptError('OP_NUMEQUALVERIFY failed'); return; }
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
      case 0xa5: {
        $max = $this->popInt(); $min = $this->popInt(); $x = $this->popInt();
        $this->push((gmp_cmp($x, $min) >= 0 && gmp_cmp($x, $max) < 0) ? "\x01" : ''); return;
      }

      case 0x69:
        if (!self::toBool($this->pop())) throw new BtScriptError('OP_VERIFY failed');
        return;

      case 0xa6: $this->push(hash('ripemd160', $this->pop(), true)); return;
      case 0xa7: $this->push(hash('sha1',      $this->pop(), true)); return;
      case 0xa8: $this->push(hash('sha256',    $this->pop(), true)); return;
      case 0xa9: $this->push(hash('ripemd160', hash('sha256', $this->pop(), true), true)); return;
      case 0xaa: $this->push(hash('sha256',    hash('sha256', $this->pop(), true), true)); return;

      default:
        throw new BtScriptError('unimplemented opcode ' . bt_op_name($op));
    }
  }
}

/** H(result) = sha256( for each stack item: varint(len) ‖ bytes ) — the §2b comparison hash. */
function bt_stack_hash(array $items): string {
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
