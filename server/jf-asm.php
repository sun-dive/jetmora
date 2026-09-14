<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE `JF` ASSEMBLER — text to bytecode ────────────────────────────────────────────────────────────
//
// ★ §10.5c: `JF` needs no COMPILER, only an ASSEMBLER — *"a table lookup"*. Forth IS the stack machine
//   written down, so there is no language to translate, only names to resolve to bytes.
//
// ⚠ Extracted from `verify-jf.php` on 7 Sept because the WALLET needs it too: a covenant has to be
//   assembled before it can be minted, and an assembler that lives inside a test file is not available
//   to the thing it exists to serve.
//
// ⚠⚠ THIS IS NOT THE READABLE SOURCE FORM. §10.5h settled that readability comes from **named locals**
//   (`{: a b -- c :}`, LOCAL EXT) and short definitions in stdForth source. This is the layer beneath
//   that: opcode names, labels and operands. A person writes stdForth; this writes bytes.
declare(strict_types=1);
require_once __DIR__ . '/ops-jf.php';

// ── a very small assembler, so the tests read as something a person can check ────────────────────────
// tokens:  DUP            a jetForth word
//          5   -1  1000   an integer literal (smallest form that fits)
//          $aabb          a direct push of those bytes  → ( c-addr u )
//          name:          a label
//          BRANCH>name    a branch to a label
//          INVOKE#0       an opcode with a u8 operand
//          [FLOATING:3]   a bank escape and selector, to prove refusal
function jf_asm(string $src): string
{
  $toks = preg_split('/\s+/', trim($src), -1, PREG_SPLIT_NO_EMPTY);
  // pass 1: sizes, to place labels
  $labels = []; $at = 0; $sized = [];
  foreach ($toks as $t) {
    if (str_ends_with($t, ':') && !isset(JF_WORD[$t])) { $labels[substr($t, 0, -1)] = $at; continue; }
    $n = jf_asm_size($t); $sized[] = [$t, $at]; $at += $n;
  }
  // pass 2: emit
  $out = '';
  foreach ($sized as [$t, $pos]) $out .= jf_asm_emit($t, $pos, $labels);
  return $out;
}
function jf_asm_size(string $t): int {
  // ⚠ EXACT WORD MATCH FIRST. `>R`, `2R>`, `S>D`, `U>` all contain '>' and are not branches.
  if (isset(JF_WORD[$t]) || isset(JF_LIT[$t])) return 1;
  if ($t[0] === '$') { $n = intdiv(strlen($t) - 1, 2);
                       return ($n <= JF_PUSH_MAX ? 1 : 2) + $n; }        // over 72 B needs STR8
  if ($t[0] === '[')                       return 2;
  if (str_starts_with($t, '(ABORT")$'))    return 2 + intdiv(strlen($t) - 9, 2);
  if (str_contains($t, '>'))               return 3;                       // branch + i16
  if (str_contains($t, '#'))               return 2;                       // op + u8
  if (preg_match('/^-?\d+$/', $t)) {
    $v = (int)$t;
    if ($v >= 0 && $v <= 8) return 1;                                   // small ints are 0..8
    if ($v === -1)          return 1;
    if ($v >= -128 && $v <= 127)     return 2;
    if ($v >= -32768 && $v <= 32767) return 3;
    return 5;
  }
  throw new RuntimeException("asm: unknown token '$t'");
}
function jf_asm_emit(string $t, int $pos, array $labels): string {
  if (isset(JF_WORD[$t])) return chr(JF_WORD[$t]);          // ⚠ exact match first, as in jf_asm_size
  if (isset(JF_LIT[$t]))  return chr(JF_LIT[$t]);
  if ($t[0] === '$') { $b = hex2bin(substr($t, 1));
    // ⚠ A DER signature is 70-73 B and an uncompressed key is 65 — both DIRECT now. Longer than 72
    //   (a sighash preimage, say) takes STR8, which is one byte more and says so.
    return strlen($b) <= JF_PUSH_MAX ? chr(strlen($b)) . $b
                                     : chr(JF_LIT['STR8']) . chr(strlen($b)) . $b; }
  if ($t[0] === '[') { [$set, $sel] = explode(':', trim($t, '[]'));
                       $esc = array_search($set, JF_BANK, true);
                       if ($esc === false) throw new RuntimeException("asm: no bank $set");
                       return chr($esc) . chr((int)$sel); }
  if (str_contains($t, '>')) {
    [$w, $lab] = explode('>', $t);
    if (!isset(JF_WORD[$w])) throw new RuntimeException("asm: unknown branch word $w");
    if (!isset($labels[$lab])) throw new RuntimeException("asm: no label $lab");
    $off = $labels[$lab] - ($pos + 3);
    return chr(JF_WORD[$w]) . pack('v', $off & 0xffff);
  }
  // (ABORT")$<hex> — an INLINE literal message, never a stack span
  if (str_starts_with($t, '(ABORT")$')) {
    $b = hex2bin(substr($t, 9));
    return chr(JF_WORD['(ABORT")']) . chr(strlen($b)) . $b;
  }
  if (str_contains($t, '#')) {
    [$w, $n] = explode('#', $t);
    if (!isset(JF_WORD[$w])) throw new RuntimeException("asm: unknown word $w");
    return chr(JF_WORD[$w]) . chr((int)$n);
  }
  $v = (int)$t;
  if ($v >= 0 && $v <= 8) return chr(JF_SMALL0 + $v);
  if ($v === -1)           return chr(JF_SMALL_NEG1);
  if ($v >= -128 && $v <= 127)     return chr(JF_LIT['LIT8'])  . pack('c', $v);
  if ($v >= -32768 && $v <= 32767) return chr(JF_LIT['LIT16']) . pack('v', $v & 0xffff);
  return chr(JF_LIT['LIT32']) . pack('V', $v & 0xffffffff);
}

/**
 * Build a DEFS header from [[n_in, n_out, asm], ...] or [[n_in, n_out, asm, in_max, out_max], ...].
 * ★ in_max / out_max are the DECLARED CHANNELS — zero means the function has none.
 */
function jf_defs(array $ds): string {
  $vi = fn(int $n) => $n < 0xfd ? chr($n) : "\xfd" . pack('v', $n);
  $b = chr(JF_RESERVED0) . chr(count($ds));
  foreach ($ds as $d) {
    [$in, $out, $src] = $d;
    $inMax  = $d[3] ?? 0;
    $outMax = $d[4] ?? 0;
    $body = jf_asm($src);
    $b .= chr($in) . chr($out) . $vi($inMax) . $vi($outMax) . $vi(strlen($body)) . $body;
  }
  return $b;
}
