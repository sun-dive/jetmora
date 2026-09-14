<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── THE `JF` SET: the interpreter ────────────────────────────────────────────────────────────────────
// jetmora Forth. TWO TIERS, and the tier boundary is a PRIVILEGE boundary (design notes §10.5e–§10.5j):
//
//   jetForth   one byte   — CONTROLS the covenant. Owns carried state. Decides valid / invalid.
//   stdForth   two bytes  — standard Forth, unmodified. A PURE FUNCTION: values in, values out.
//
// ⚠⚠ ISOLATION (gaps §10.9). This file is the `JF` set and nothing else. A fix here MUST NOT be able to
// reach `SV` or `BT`. The only thing shared across sets is the conformance vector file.
//
// ── THE ARITHMETIC RULE, AND IT IS NOT NEGOTIABLE ────────────────────────────────────────────────────
// ⚠⚠⚠ NEVER touch PHP's native int for a cell. `PHP_INT_MAX + 1` silently becomes a float: precision
// gone, NO error raised. Fatal for a machine whose product is the same answer every time. And a cell
// must WRAP at 64 bits, which a float cannot do. Everything numeric goes through GMP, masked on store.
//
// ── CELLS AND STRINGS ────────────────────────────────────────────────────────────────────────────────
// §10.4: the version names the set and THE SET FIXES THE WIDTH. `JF` is 64-bit cells.
// ★ So a string is what it is in every Forth: AN ADDRESS AND A LENGTH (§10.5c). Byte-string and crypto
//   words take `( c-addr u ... )` and write to a destination the CALLER supplies — no hidden allocator,
//   because an allocator is a source of divergence between implementations.
declare(strict_types=1);
require_once __DIR__ . '/ops-jf.php';
require_once __DIR__ . '/secp256k1.php';

class JfScriptError extends RuntimeException
{
  /**
   * ★★★ THE DIAGNOSTIC A REFUSAL CARRIES OUT.
   * A BSV covenant fails with *"the top stack element must be true"* and nothing else. A covenant that
   * can say WHY it refused is a real improvement — and because the message is bytes the script chose,
   * it is part of the recorded execution, so **the reason is PROVABLE and not the wallet's claim.**
   * ⚠ Null for an ordinary machine fault (underflow, bad opcode): those are not the script speaking.
   */
  public ?string $diagnostic = null;

  public static function aborted(string $msg): self
  {
    $e = new self($msg === '' ? 'ABORT' : "ABORT: $msg");
    $e->diagnostic = $msg;
    return $e;
  }
}

/** ⚠ Distinct on purpose: the bank design exists so an unimplemented wordset is refused BY NAME. */
final class JfBankUnsupported extends JfScriptError
{
  public function __construct(public readonly string $wordset, public readonly ?string $word = null)
  {
    parent::__construct($word === null
      ? "stdForth wordset not implemented: $wordset"
      : "stdForth wordset not implemented: $wordset (word $word)");
  }
}

final class InterpreterJF
{
  /** @var GMP[] data stack   */ private array $ds = [];
  /** @var GMP[] return stack */ private array $rs = [];
  /** @var array<int,array{n_in:int,n_out:int,body:string}> */ private array $defs = [];
  /** @var GMP[][] locals frames */ private array $frames = [];
  private string $mem = '';
  /** @var array<int,array{in:string,pos:int,out:string,max:int}> one frame per active INVOKE */
  private array $chan = [];
  private int $opCount = 0;
  private int $depth = 0;

  /** Signature/preimage context. ⚠ Optional: a bare script has no transaction. */
  private ?string $preimage = null;

  private static ?GMP $M64 = null;   // 2^64
  private static ?GMP $H64 = null;   // 2^63

  /**
   * Every limit here is OPERATOR POLICY (§4.5), never a protocol constant. Past the budget there is
   * simply no proof — which is a different thing from the program being invalid.
   */
  public function __construct(
    private int $maxOps = 200000,
    private int $memSize = 65536,
    private int $maxDepth = 64,
  ) {
    self::$M64 ??= gmp_pow(2, 64);
    self::$H64 ??= gmp_pow(2, 63);
  }

  public function setPreimage(?string $p): void { $this->preimage = $p; }

  // ── cells ──────────────────────────────────────────────────────────────────────────────────────────
  /** Wrap into a signed 64-bit cell. ⚠ Two's complement WRAPPING, which is what a fixed cell means. */
  private static function cell(GMP $v): GMP {
    $u = gmp_mod($v, self::$M64);                       // gmp_mod is non-negative: what we want here
    return gmp_cmp($u, self::$H64) >= 0 ? gmp_sub($u, self::$M64) : $u;
  }
  /** Unsigned view of a cell, for U< U> and shifts. */
  private static function u(GMP $v): GMP {
    return gmp_sign($v) < 0 ? gmp_add($v, self::$M64) : $v;
  }

  // ── stacks ─────────────────────────────────────────────────────────────────────────────────────────
  private function need(int $n): void {
    if (count($this->ds) < $n) throw new JfScriptError("stack underflow: need $n, have " . count($this->ds));
  }
  private function pop(): GMP {
    if (!$this->ds) throw new JfScriptError('stack underflow');
    return array_pop($this->ds);
  }
  private function push(GMP $v): void { $this->ds[] = self::cell($v); }
  private function pushI(int $v): void { $this->ds[] = self::cell(gmp_init($v)); }
  private function popInt(): int {
    $v = $this->pop();
    if (gmp_cmp($v, PHP_INT_MAX) > 0 || gmp_cmp($v, PHP_INT_MIN) < 0)
      throw new JfScriptError('cell out of host int range');
    return gmp_intval($v);
  }
  private function flag(bool $b): void { $this->pushI($b ? -1 : 0); }   // Forth TRUE is all bits set

  // ── memory ─────────────────────────────────────────────────────────────────────────────────────────
  private function bounds(int $addr, int $len): void {
    if ($addr < 0 || $len < 0 || $addr + $len > strlen($this->mem))
      throw new JfScriptError("memory out of range: addr=$addr len=$len size=" . strlen($this->mem));
  }
  private function fetch(int $addr): GMP {
    $this->bounds($addr, 8);
    $le = substr($this->mem, $addr, 8);
    return self::cell(gmp_import(strrev($le), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN));
  }
  private function store(int $addr, GMP $v): void {
    $this->bounds($addr, 8);
    $u  = self::u(self::cell($v));
    $be = gmp_sign($u) === 0 ? '' : gmp_export($u, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $le = strrev(str_pad($be, 8, "\x00", STR_PAD_LEFT));
    for ($k = 0; $k < 8; $k++) $this->mem[$addr + $k] = $le[$k];
  }
  private function read(int $addr, int $len): string {
    $this->bounds($addr, $len);
    return substr($this->mem, $addr, $len);
  }
  private function write(int $addr, string $b): void {
    $this->bounds($addr, strlen($b));
    for ($k = 0, $n = strlen($b); $k < $n; $k++) $this->mem[$addr + $k] = $b[$k];
  }
  /** `( c-addr u -- )` popped as a pair, u on top. */
  private function popSpan(): string { $u = $this->popInt(); $a = $this->popInt(); return $this->read($a, $u); }

  // ── operands, read from the instruction stream ─────────────────────────────────────────────────────
  private static function i16(string $s, int $i): int {
    if ($i + 2 > strlen($s)) throw new JfScriptError('truncated operand');
    $v = ord($s[$i]) | (ord($s[$i + 1]) << 8);
    return $v >= 0x8000 ? $v - 0x10000 : $v;
  }
  private static function u16(string $s, int $i): int {
    if ($i + 2 > strlen($s)) throw new JfScriptError('truncated operand');
    return ord($s[$i]) | (ord($s[$i + 1]) << 8);
  }
  private static function u8(string $s, int $i): int {
    if ($i + 1 > strlen($s)) throw new JfScriptError('truncated operand');
    return ord($s[$i]);
  }

  // ── the DEFS header ────────────────────────────────────────────────────────────────────────────────
  /**
   * `[ DEFS <count:u8> { <n_in:u8> <n_out:u8> <in_max:varint> <out_max:varint> <len:varint> <body> }`
   * `x count ]? <covenant code>`
   *
   * ★★★ `in_max` AND `out_max` ARE THE DECLARED CHANNELS — his call, 7 Sept: *"EMIT can return its
   * contents and must be able to"*, and *"just as ACCEPT should be able to receive values from the
   * function that called the stdForth."* Zero means the channel does not exist and its words are
   * refused in that function. Above zero:
   *
   *   `<n_in cells> [<c-addr u> if in_max]  <index> INVOKE  ->  <n_out cells> [<c-addr u> if out_max]`
   *
   * ⇒ ★★ **Both channels are DECLARED, therefore COUNTED**, which is the whole reason they are allowed.
   *   The objection to `EMIT` was never that a proved execution cannot produce output — §10.5d already
   *   settled that it can, if the input is recorded — it was that an UNDECLARED channel cannot be
   *   checked, and the arity check being checkable is what the tier boundary rests on.
   *
   * ⚠ Definitions come FIRST so a verifier scans the script once, and **no header means every bank
   * escape in the script is illegal** — checkable before a single opcode runs.
   */
  private function parseDefs(string $script, int &$i): void
  {
    $this->defs = [];
    // The header is present iff the script opens with the reserved DEFS marker.
    if ($i >= strlen($script) || ord($script[$i]) !== self::DEFS_MARK) return;
    $i++;
    $count = self::u8($script, $i); $i++;
    for ($k = 0; $k < $count; $k++) {
      $nin  = self::u8($script, $i); $i++;
      $nout = self::u8($script, $i); $i++;
      $inm  = $this->varint($script, $i);
      $outm = $this->varint($script, $i);
      $len  = $this->varint($script, $i);
      if ($i + $len > strlen($script)) throw new JfScriptError("DEFS $k body past end of script");
      $this->defs[] = ['n_in' => $nin, 'n_out' => $nout, 'in_max' => $inm, 'out_max' => $outm,
                       'body' => substr($script, $i, $len)];
      $i += $len;
    }
  }
  /** ⚠ The reserved slot the compiler emits for the header. Reserved region, append-only. */
  private const DEFS_MARK = JF_RESERVED0;

  private function varint(string $s, int &$i): int {
    $b = self::u8($s, $i); $i++;
    if ($b < 0xfd) return $b;
    if ($b === 0xfd) { $v = self::u16($s, $i); $i += 2; return $v; }
    if ($b === 0xfe) {
      if ($i + 4 > strlen($s)) throw new JfScriptError('truncated varint');
      $v = unpack('V', substr($s, $i, 4))[1]; $i += 4; return $v;
    }
    throw new JfScriptError('8-byte varint is not a script length');
  }

  // ── run ────────────────────────────────────────────────────────────────────────────────────────────
  /** @return GMP[] the final data stack, bottom first. @throws JfScriptError */
  public function run(string $script): array
  {
    $this->ds = $this->rs = $this->frames = $this->chan = [];
    $this->opCount = 0; $this->depth = 0;
    $this->mem = str_repeat("\x00", $this->memSize);
    $i = 0;
    $this->parseDefs($script, $i);
    $this->exec($script, $i, /* covenant tier */ true);
    if ($this->frames) throw new JfScriptError('unbalanced locals frame');
    return $this->ds;
  }

  /**
   * Execute from $i to the end of $code.
   * @param bool $covenant true in the jetForth tier, where a bank escape is ILLEGAL.
   */
  private function exec(string $code, int $i, bool $covenant): void
  {
    $len = strlen($code);
    while ($i < $len) {
      if (++$this->opCount > $this->maxOps) throw new JfScriptError('op budget exhausted');
      $op = ord($code[$i]); $i++;

      // ── direct push: the opcode IS the length ───────────────────────────────────────────────────
      // ⚠ A push puts (c-addr u) on the stack — the bytes are copied into working memory at the
      //   scratch pointer, because a cell cannot hold 32 bytes and Forth strings are addr+len.
      if ($op <= JF_PUSH_MAX) {
        if ($i + $op > $len) throw new JfScriptError('push past end of script');
        $this->pushSpan(substr($code, $i, $op));
        $i += $op;
        continue;
      }
      // ── small integers ──────────────────────────────────────────────────────────────────────────
      if ($op >= JF_SMALL0 && $op <= JF_SMALL_NEG1) {
        $this->pushI($op === JF_SMALL_NEG1 ? -1 : $op - JF_SMALL0);
        continue;
      }
      // ── bank escape ─────────────────────────────────────────────────────────────────────────────
      if ($op >= JF_ESC0) {
        if ($covenant)
          throw new JfScriptError(sprintf(
            'bank escape 0x%02x is illegal in jetForth — stdForth is entered only through INVOKE', $op));
        if ($op === JF_PLANE) throw new JfScriptError('plane escape 0xff is unassigned');
        $set = jf_bank_name($op) ?? sprintf('unassigned bank 0x%02x', $op);
        $sel = self::u8($code, $i); $i++;
        $names = JF_BANK_WORD[$set] ?? [];
        $word  = array_search($sel, $names, true);
        // ⚠ ONE WORD, ONE ENCODING: a promoted word's two-byte form is reserved-illegal, because
        //   execution is proved by hashing the bytecode and two encodings would mean two hashes.
        if ($word !== false && isset(JF_PROMOTED[$word]))
          throw new JfScriptError("$word is jetForth-only: its two-byte form is reserved-illegal");
        // ⚠⚠ MEASURED: of the 98 CORE words left in the bank, ZERO are runtime data operations —
        //    the 84 promoted words ARE the complete runtime CORE. So the CORE bank is an ENCODING
        //    RESERVATION, and refusing it as "not implemented yet" would be a lie: it is not work
        //    outstanding, it is a word the COMPILER executes.
        // ★ The output words RUN when the function declared a channel. `TYPE` `CR` `SPACE` `SPACES`
        //   are EMIT loops in every Forth, so refusing them while allowing EMIT would be arbitrary.
        if ($word !== false && isset(self::CHANNEL_WORDS[$word]) && $this->chan) {
          $this->channel($word);
          continue;                      // ⚠ exec() drives $i itself; step() is not on this path
        }
        if ($word !== false && isset(JF_CORE_KIND[$word])) {
          // ⚠ The reason differs by kind, and saying the wrong one is worse than saying nothing:
          //   a compiling word is consumed by the compiler, but `EMIT` is not — it simply has no
          //   output device to write to inside a proved execution.
          $why = [
            'compile-time'        => 'the compiler executes it, bytecode never contains it',
            'text interpretation' => 'it parses source text, which the compiler has already done',
            // ★★★ THESE NOW RUN. The DEFS header declares in_max and out_max, so the channel is
            //   COUNTED and the arity contract survives. This message is only reached OUTSIDE a
            //   function — in jetForth a bank escape is already illegal, so it means the covenant
            //   tier tried to reach a channel word directly.
            'output channel'      => 'it writes to a declared output channel, which exists only inside '
                                   . 'a stdForth function whose DEFS entry sets out_max',
            'input channel'       => 'it reads a declared input channel, which exists only inside '
                                   . 'a stdForth function whose DEFS entry sets in_max',
            // ⚠ HONEST WORK OUTSTANDING, unlike everything else in this table: these need `BASE` as
            //   live state plus pictured numeric output. Saying "not built" is the truthful answer.
            'number formatting'   => 'NOT BUILT — it needs BASE as live state and pictured numeric '
                                   . 'output (<# # #S #>)',
            'system'              => 'it abandons or restarts the interpreter, which a declared '
                                   . 'arity cannot describe',
          ][JF_CORE_KIND[$word]] ?? null;
          // ⛔ `EVALUATE` interprets text at RUNTIME, which is OP_EVAL. §6 sets out why OP_EVAL is
          //    correctly absent, and that reasoning does not lapse because the spelling changed.
          throw new JfScriptError($why === null
            ? sprintf('%s — refused: %s', $word, JF_CORE_KIND[$word])
            : sprintf('%s — %s word: %s', $word, JF_CORE_KIND[$word], $why));
        }
        throw new JfBankUnsupported($set, $word === false ? null : $word);
      }

      $i = $this->step($op, $code, $i, $covenant);
    }
  }

  /** Copy bytes into scratch memory and leave `( c-addr u )`. */
  private function pushSpan(string $b): void {
    $at = $this->scratch(strlen($b));
    $this->write($at, $b);
    $this->pushI($at); $this->pushI(strlen($b));
  }
  /**
   * Scratch allocation for literals only, growing DOWN from the top of memory.
   * ⚠ Deterministic by construction: it depends on nothing but the sequence of literals executed.
   */
  private int $scratchTop = 0;
  private function scratch(int $n): int {
    if ($this->scratchTop === 0) $this->scratchTop = strlen($this->mem);
    $this->scratchTop -= $n;
    if ($this->scratchTop < 0) throw new JfScriptError('literal scratch exhausted');
    return $this->scratchTop;
  }

  /** One opcode. Returns the new instruction pointer. */
  private function step(int $op, string $code, int $i, bool $covenant): int
  {
    $W = JF_WORD; $L = JF_LIT;
    switch ($op) {

      // ── literal forms ─────────────────────────────────────────────────────────────────────────────
      case $L['LIT8']:  case $L['LIT16']: case $L['LIT32']: case $L['LIT64']: {
        $w = [$L['LIT8'] => 1, $L['LIT16'] => 2, $L['LIT32'] => 4, $L['LIT64'] => 8][$op];
        if ($i + $w > strlen($code)) throw new JfScriptError('truncated literal');
        $le = substr($code, $i, $w);
        $v  = gmp_import(strrev($le), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        if (ord($le[$w - 1]) & 0x80) $v = gmp_sub($v, gmp_pow(2, 8 * $w));   // sign-extend
        $this->push($v);
        return $i + $w;
      }
      case $L['LITBIG']: {
        $n = $this->varint($code, $i);
        if ($i + $n > strlen($code)) throw new JfScriptError('truncated LITBIG');
        // ⚠ A bignum does not fit a cell. It goes to memory and arrives as (c-addr u), like any string.
        $this->pushSpan(substr($code, $i, $n));
        return $i + $n;
      }
      case $L['STR8']: case $L['STR16']: case $L['STR32']: {
        $w = [$L['STR8'] => 1, $L['STR16'] => 2, $L['STR32'] => 4][$op];
        if ($i + $w > strlen($code)) throw new JfScriptError('truncated string length');
        $n = 0; for ($k = 0; $k < $w; $k++) $n |= ord($code[$i + $k]) << (8 * $k);
        $i += $w;
        if ($i + $n > strlen($code)) throw new JfScriptError('string past end of script');
        $this->pushSpan(substr($code, $i, $n));
        return $i + $n;
      }

      // ── stack ─────────────────────────────────────────────────────────────────────────────────────
      case $W['DUP']:   $this->need(1); $this->ds[] = $this->ds[count($this->ds) - 1]; return $i;
      case $W['DROP']:  $this->pop(); return $i;
      case $W['SWAP']:  $this->need(2); $n = count($this->ds);
                        [$this->ds[$n-2], $this->ds[$n-1]] = [$this->ds[$n-1], $this->ds[$n-2]]; return $i;
      case $W['OVER']:  $this->need(2); $this->ds[] = $this->ds[count($this->ds) - 2]; return $i;
      case $W['ROT']:   $this->need(3); $n = count($this->ds);
                        $x = $this->ds[$n-3]; array_splice($this->ds, $n-3, 1); $this->ds[] = $x; return $i;
      case $W['?DUP']:  $this->need(1); $t = $this->ds[count($this->ds) - 1];
                        if (gmp_sign($t) !== 0) $this->ds[] = $t; return $i;
      case $W['NIP']:   $this->need(2); array_splice($this->ds, count($this->ds) - 2, 1); return $i;
      case $W['TUCK']:  $this->need(2); $n = count($this->ds);
                        array_splice($this->ds, $n - 2, 0, [$this->ds[$n-1]]); return $i;
      case $W['DEPTH']: $this->pushI(count($this->ds)); return $i;
      case $W['PICK']:  $n = $this->popInt(); $this->need($n + 1);
                        $this->ds[] = $this->ds[count($this->ds) - 1 - $n]; return $i;
      case $W['ROLL']:  $n = $this->popInt(); $this->need($n + 1);
                        $x = array_splice($this->ds, count($this->ds) - 1 - $n, 1);
                        $this->ds[] = $x[0]; return $i;
      case $W['2DUP']:  $this->need(2); $n = count($this->ds);
                        $this->ds[] = $this->ds[$n-2]; $this->ds[] = $this->ds[$n-1]; return $i;
      case $W['2DROP']: $this->need(2); $this->pop(); $this->pop(); return $i;
      case $W['2SWAP']: $this->need(4); $n = count($this->ds);
                        $x = array_splice($this->ds, $n - 4, 2);
                        array_splice($this->ds, count($this->ds), 0, $x); return $i;
      case $W['2OVER']: $this->need(4); $n = count($this->ds);
                        $this->ds[] = $this->ds[$n-4]; $this->ds[] = $this->ds[$n-3]; return $i;
      case $W['>R']:    $this->rs[] = $this->pop(); return $i;
      case $W['R>']:    if (!$this->rs) throw new JfScriptError('return stack underflow');
                        $this->ds[] = array_pop($this->rs); return $i;
      case $W['R@']:    if (!$this->rs) throw new JfScriptError('return stack underflow');
                        $this->ds[] = $this->rs[count($this->rs) - 1]; return $i;
      case $W['2>R']:   $this->need(2); $b = $this->pop(); $a = $this->pop();
                        $this->rs[] = $a; $this->rs[] = $b; return $i;
      case $W['2R>']:   if (count($this->rs) < 2) throw new JfScriptError('return stack underflow');
                        $b = array_pop($this->rs); $a = array_pop($this->rs);
                        $this->ds[] = $a; $this->ds[] = $b; return $i;
      case $W['2R@']:   if (count($this->rs) < 2) throw new JfScriptError('return stack underflow');
                        $n = count($this->rs);
                        $this->ds[] = $this->rs[$n-2]; $this->ds[] = $this->rs[$n-1]; return $i;

      // ── arithmetic ────────────────────────────────────────────────────────────────────────────────
      case $W['+']:  $b = $this->pop(); $this->push(gmp_add($this->pop(), $b)); return $i;
      case $W['-']:  $b = $this->pop(); $this->push(gmp_sub($this->pop(), $b)); return $i;
      case $W['*']:  $b = $this->pop(); $this->push(gmp_mul($this->pop(), $b)); return $i;
      case $W['/']:  $b = $this->pop(); $a = $this->pop(); $this->push(self::divT($a, $b)); return $i;
      case $W['MOD']: $b = $this->pop(); $a = $this->pop(); $this->push(self::modT($a, $b)); return $i;
      case $W['/MOD']: $b = $this->pop(); $a = $this->pop();
                       $this->push(self::modT($a, $b)); $this->push(self::divT($a, $b)); return $i;
      // ★ */ and */MOD keep the intermediate at DOUBLE width — that is the whole point of them, and
      //   GMP gives it for free. Rounding down to a cell first would be a different word.
      case $W['*/']:  $c = $this->pop(); $b = $this->pop(); $a = $this->pop();
                      $this->push(self::divT(gmp_mul($a, $b), $c)); return $i;
      case $W['*/MOD']: $c = $this->pop(); $b = $this->pop(); $a = $this->pop();
                      $p = gmp_mul($a, $b);
                      $this->push(self::modT($p, $c)); $this->push(self::divT($p, $c)); return $i;
      case $W['1+']: $this->push(gmp_add($this->pop(), 1)); return $i;
      case $W['1-']: $this->push(gmp_sub($this->pop(), 1)); return $i;
      case $W['2*']: $this->push(gmp_mul($this->pop(), 2)); return $i;
      case $W['2/']: $this->push(gmp_div_q($this->pop(), 2, GMP_ROUND_MINUSINF)); return $i;  // arithmetic shift
      case $W['ABS']: $this->push(gmp_abs($this->pop())); return $i;
      case $W['NEGATE']: $this->push(gmp_neg($this->pop())); return $i;
      case $W['MIN']: $b = $this->pop(); $a = $this->pop(); $this->push(gmp_cmp($a,$b) <= 0 ? $a : $b); return $i;
      case $W['MAX']: $b = $this->pop(); $a = $this->pop(); $this->push(gmp_cmp($a,$b) >= 0 ? $a : $b); return $i;
      // ⚠ FM/MOD is FLOORED, SM/REM is SYMMETRIC. They are two words BECAUSE they differ; collapsing
      //   them onto one division is the classic Forth implementation bug.
      case $W['FM/MOD']: $b = $this->pop(); $a = $this->pop();
                         if (gmp_sign($b) === 0) throw new JfScriptError('FM/MOD by zero');
                         $q = gmp_div_q($a, $b, GMP_ROUND_MINUSINF);
                         $this->push(gmp_sub($a, gmp_mul($q, $b))); $this->push($q); return $i;
      case $W['SM/REM']: $b = $this->pop(); $a = $this->pop();
                         $this->push(self::modT($a, $b)); $this->push(self::divT($a, $b)); return $i;
      case $W['UM*']:  $b = self::u($this->pop()); $a = self::u($this->pop());
                       $p = gmp_mul($a, $b);
                       $this->push(gmp_mod($p, self::$M64));
                       $this->push(gmp_div_q($p, self::$M64)); return $i;
      case $W['UM/MOD']: $b = self::u($this->pop()); $hi = self::u($this->pop()); $lo = self::u($this->pop());
                       if (gmp_sign($b) === 0) throw new JfScriptError('UM/MOD by zero');
                       $d = gmp_add(gmp_mul($hi, self::$M64), $lo);
                       $this->push(gmp_mod($d, $b)); $this->push(gmp_div_q($d, $b)); return $i;
      case $W['M*']:   $b = $this->pop(); $a = $this->pop(); $p = gmp_mul($a, $b);
                       $this->push(gmp_mod(self::u2($p), self::$M64));
                       $this->push(gmp_div_q($p, self::$M64, GMP_ROUND_MINUSINF)); return $i;
      case $W['S>D']:  $this->need(1); $a = $this->ds[count($this->ds) - 1];
                       $this->pushI(gmp_sign($a) < 0 ? -1 : 0); return $i;

      // ── logic ─────────────────────────────────────────────────────────────────────────────────────
      case $W['AND']:    $b = $this->pop(); $this->push(gmp_and(self::u($this->pop()), self::u($b))); return $i;
      case $W['OR']:     $b = $this->pop(); $this->push(gmp_or (self::u($this->pop()), self::u($b))); return $i;
      case $W['XOR']:    $b = $this->pop(); $this->push(gmp_xor(self::u($this->pop()), self::u($b))); return $i;
      case $W['INVERT']: $this->push(gmp_sub(gmp_neg($this->pop()), 1)); return $i;   // ~x == -x-1
      case $W['LSHIFT']: $n = $this->popInt(); $a = self::u($this->pop());
                         $this->push($n >= 64 ? gmp_init(0) : gmp_mul($a, gmp_pow(2, $n))); return $i;
      case $W['RSHIFT']: $n = $this->popInt(); $a = self::u($this->pop());   // ⚠ LOGICAL, not arithmetic
                         $this->push($n >= 64 ? gmp_init(0) : gmp_div_q($a, gmp_pow(2, $n))); return $i;

      // ── comparison ────────────────────────────────────────────────────────────────────────────────
      case $W['=']:   $b = $this->pop(); $this->flag(gmp_cmp($this->pop(), $b) === 0); return $i;
      case $W['<>']:  $b = $this->pop(); $this->flag(gmp_cmp($this->pop(), $b) !== 0); return $i;
      case $W['<']:   $b = $this->pop(); $this->flag(gmp_cmp($this->pop(), $b) <  0); return $i;
      case $W['>']:   $b = $this->pop(); $this->flag(gmp_cmp($this->pop(), $b) >  0); return $i;
      case $W['U<']:  $b = self::u($this->pop()); $this->flag(gmp_cmp(self::u($this->pop()), $b) < 0); return $i;
      case $W['U>']:  $b = self::u($this->pop()); $this->flag(gmp_cmp(self::u($this->pop()), $b) > 0); return $i;
      case $W['0=']:  $this->flag(gmp_sign($this->pop()) === 0); return $i;
      case $W['0<>']: $this->flag(gmp_sign($this->pop()) !== 0); return $i;
      case $W['0<']:  $this->flag(gmp_sign($this->pop()) <  0); return $i;
      case $W['0>']:  $this->flag(gmp_sign($this->pop()) >  0); return $i;
      case $W['WITHIN']: $hi = self::u($this->pop()); $lo = self::u($this->pop()); $t = self::u($this->pop());
                         // Forth's WITHIN is circular: ( test lo hi -- flag ), lo inclusive, hi exclusive
                         $this->flag(gmp_cmp(gmp_mod(gmp_sub($t, $lo), self::$M64),
                                             gmp_mod(gmp_sub($hi, $lo), self::$M64)) < 0); return $i;

      // ── constants ─────────────────────────────────────────────────────────────────────────────────
      case $W['TRUE']:  $this->pushI(-1); return $i;
      case $W['FALSE']: $this->pushI(0);  return $i;
      case $W['BL']:    $this->pushI(32); return $i;

      // ── memory ────────────────────────────────────────────────────────────────────────────────────
      case $W['@']:  $this->push($this->fetch($this->popInt())); return $i;
      case $W['!']:  $a = $this->popInt(); $this->store($a, $this->pop()); return $i;
      case $W['C@']: $this->pushI(ord($this->read($this->popInt(), 1))); return $i;
      case $W['C!']: $a = $this->popInt(); $v = $this->popInt();
                     $this->write($a, chr($v & 0xff)); return $i;
      case $W['+!']: $a = $this->popInt(); $this->store($a, gmp_add($this->fetch($a), $this->pop())); return $i;
      case $W['2@']: $a = $this->popInt();
                     $this->push($this->fetch($a + 8)); $this->push($this->fetch($a)); return $i;
      case $W['2!']: $a = $this->popInt(); $lo = $this->pop(); $hi = $this->pop();
                     $this->store($a, $lo); $this->store($a + 8, $hi); return $i;
      case $W['MOVE']: $u = $this->popInt(); $to = $this->popInt(); $from = $this->popInt();
                       $this->write($to, $this->read($from, $u)); return $i;
      case $W['FILL']: $ch = $this->popInt(); $u = $this->popInt(); $a = $this->popInt();
                       if ($u > 0) $this->write($a, str_repeat(chr($ch & 0xff), $u)); return $i;
      case $W['ERASE']: $u = $this->popInt(); $a = $this->popInt();
                        if ($u > 0) $this->write($a, str_repeat("\x00", $u)); return $i;
      case $W['CELLS']: $this->push(gmp_mul($this->pop(), 8)); return $i;
      case $W['CELL+']: $this->push(gmp_add($this->pop(), 8)); return $i;
      case $W['CHARS']: return $i;                                  // a char is one address unit
      case $W['CHAR+']: $this->push(gmp_add($this->pop(), 1)); return $i;
      case $W['ALIGNED']: $a = $this->popInt(); $this->pushI(intdiv($a + 7, 8) * 8); return $i;

      // ── loop runtime ──────────────────────────────────────────────────────────────────────────────
      // ⚠ DO pushes (limit, index) on the RETURN stack, as standard Forth does, so I / J / UNLOOP are
      //   the standard words and not a private mechanism.
      case $W['I']: if (count($this->rs) < 2) throw new JfScriptError('I outside a loop');
                    $this->ds[] = $this->rs[count($this->rs) - 1]; return $i;
      case $W['J']: if (count($this->rs) < 4) throw new JfScriptError('J outside two loops');
                    $this->ds[] = $this->rs[count($this->rs) - 3]; return $i;
      case $W['UNLOOP']: if (count($this->rs) < 2) throw new JfScriptError('UNLOOP outside a loop');
                    array_pop($this->rs); array_pop($this->rs); return $i;
      case $W['LEAVE']: { $off = self::i16($code, $i);
                    if (count($this->rs) < 2) throw new JfScriptError('LEAVE outside a loop');
                    array_pop($this->rs); array_pop($this->rs);
                    return $this->jump($code, $i + 2, $off); }
      case $W['EXIT']: return strlen($code);
      case $W['EXECUTE']: { $xt = $this->popInt();
                    $this->call($code, $xt, $covenant); return $i; }

      // ── branch primitives (jetmora) ───────────────────────────────────────────────────────────────
      case $W['BRANCH']:  { $off = self::i16($code, $i); return $this->jump($code, $i + 2, $off); }
      case $W['0BRANCH']: { $off = self::i16($code, $i); $i += 2;
                    return gmp_sign($this->pop()) === 0 ? $this->jump($code, $i, $off) : $i; }
      case $W['(DO)']:  { $ix = $this->pop(); $lim = $this->pop();
                    $this->rs[] = $lim; $this->rs[] = $ix; return $i; }
      case $W['(?DO)']: { $off = self::i16($code, $i); $i += 2;
                    $ix = $this->pop(); $lim = $this->pop();
                    if (gmp_cmp($ix, $lim) === 0) return $this->jump($code, $i, $off);
                    $this->rs[] = $lim; $this->rs[] = $ix; return $i; }
      case $W['(LOOP)']: case $W['(+LOOP)']: {
                    $off = self::i16($code, $i); $i += 2;
                    if (count($this->rs) < 2) throw new JfScriptError('LOOP outside a loop');
                    $step = $op === $W['(+LOOP)'] ? $this->pop() : gmp_init(1);
                    $ix   = array_pop($this->rs); $lim = $this->rs[count($this->rs) - 1];
                    $nx   = self::cell(gmp_add($ix, $step));
                    // ★ Forth's rule: terminate when the index CROSSES the limit, which is a different
                    //   test from equality and is why a +LOOP with a negative step terminates at all.
                    $done = gmp_sign($step) >= 0
                          ? (gmp_cmp($ix, $lim) < 0 && gmp_cmp($nx, $lim) >= 0) || gmp_cmp($ix,$lim) >= 0
                          : (gmp_cmp($ix, $lim) > 0 && gmp_cmp($nx, $lim) <= 0) || gmp_cmp($ix,$lim) <= 0;
                    if ($done) { array_pop($this->rs); return $i; }
                    $this->rs[] = $nx;
                    return $this->jump($code, $i, $off); }
      case $W['CALL']: { $to = self::u16($code, $i); $i += 2;
                    $this->call($code, $to, $covenant); return $i; }
      case $W['RET']: return strlen($code);

      // ── locals (jetmora runtime for `{:` and `LOCALS|`) ───────────────────────────────────────────
      case $W['(FRAME)']: { $n = self::u8($code, $i); $i++;
                    $this->need($n);
                    $this->frames[] = $n === 0 ? [] : array_splice($this->ds, count($this->ds) - $n);
                    return $i; }
      case $W['(LOCAL@)']: { $k = self::u8($code, $i); $i++;
                    $f = $this->frame(); if (!array_key_exists($k, $f)) throw new JfScriptError("local $k unset");
                    $this->ds[] = $f[$k]; return $i; }
      case $W['(LOCAL!)']: { $k = self::u8($code, $i); $i++;
                    $this->frames[count($this->frames) - 1][$k] = $this->pop(); return $i; }
      case $W['(UNFRAME)']: if (!$this->frames) throw new JfScriptError('(UNFRAME) with no frame');
                    array_pop($this->frames); return $i;

      // ── byte strings ──────────────────────────────────────────────────────────────────────────────
      case $W['SIZE']:  $this->need(2); $this->ds[] = $this->ds[count($this->ds) - 1]; return $i;
      case $W['SPLIT']: { $n = $this->popInt(); $u = $this->popInt(); $a = $this->popInt();
                    if ($n < 0 || $n > $u) throw new JfScriptError('SPLIT out of range');
                    // ★ No copy: a split of (addr,len) is two spans of the SAME bytes.
                    $this->pushI($a); $this->pushI($n); $this->pushI($a + $n); $this->pushI($u - $n); return $i; }
      case $W['CAT']:   { $d = $this->popInt(); $s2 = $this->popSpan(); $s1 = $this->popSpan();
                    $this->write($d, $s1 . $s2);
                    $this->pushI($d); $this->pushI(strlen($s1) + strlen($s2)); return $i; }
      case $W['SUBSTR']:{ $d = $this->popInt(); $cnt = $this->popInt(); $beg = $this->popInt();
                    $s = $this->popSpan();
                    if ($beg < 0 || $cnt < 0 || $beg + $cnt > strlen($s))
                      throw new JfScriptError('SUBSTR out of range');
                    $this->write($d, substr($s, $beg, $cnt));
                    $this->pushI($d); $this->pushI($cnt); return $i; }
      case $W['LEFT']:  { $d = $this->popInt(); $n = $this->popInt(); $s = $this->popSpan();
                    if ($n < 0 || $n > strlen($s)) throw new JfScriptError('LEFT out of range');
                    $this->write($d, substr($s, 0, $n)); $this->pushI($d); $this->pushI($n); return $i; }
      case $W['RIGHT']: { $d = $this->popInt(); $n = $this->popInt(); $s = $this->popSpan();
                    if ($n < 0 || $n > strlen($s)) throw new JfScriptError('RIGHT out of range');
                    $this->write($d, substr($s, strlen($s) - $n)); $this->pushI($d); $this->pushI($n); return $i; }
      case $W['NUM2BIN']: { $d = $this->popInt(); $sz = $this->popInt(); $v = $this->pop();
                    if ($sz < 0 || $sz > 0x10000) throw new JfScriptError('NUM2BIN size out of range');
                    $u  = self::u($v);
                    $be = gmp_sign($u) === 0 ? '' : gmp_export($u, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
                    if (strlen($be) > $sz) throw new JfScriptError('NUM2BIN does not fit');
                    $this->write($d, strrev(str_pad($be, $sz, "\x00", STR_PAD_LEFT)));
                    $this->pushI($d); $this->pushI($sz); return $i; }
      // ★★★ ( a1 u1 a2 u2 -- flag ) — THE COVENANT'S CENTRAL OPERATION.
      //   Comparing a computed hash against one from the preimage is what every covenant does, and
      //   nothing else could do it: `=` compares cells, and BIN2NUM on 32 bytes truncates to 64 bits.
      // ⚠ CONSTANT TIME over the compared bytes: hash_equals, never `===`. A byte-at-a-time compare
      //   leaks WHERE two hashes first differ, which is enough to forge one a byte at a time.
      case $W['BYTES=']: { $b = $this->popSpan(); $a = $this->popSpan();
                    $this->flag(strlen($a) === strlen($b) && hash_equals($a, $b)); return $i; }

      case $W['BIN2NUM']: { $s = $this->popSpan();
                    $this->push($s === '' ? gmp_init(0)
                      : gmp_import(strrev($s), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN)); return $i; }

      // ── crypto ────────────────────────────────────────────────────────────────────────────────────
      // `( c-addr u dest -- )` — the CALLER supplies the destination. No hidden allocator, because an
      // allocator is a source of divergence between implementations.
      case $W['SHA256']:    return $this->hashTo($code, $i, fn($b) => hash('sha256', $b, true));
      case $W['SHA1']:      return $this->hashTo($code, $i, fn($b) => hash('sha1', $b, true));
      case $W['RIPEMD160']: return $this->hashTo($code, $i, fn($b) => hash('ripemd160', $b, true));
      case $W['HASH160']:   return $this->hashTo($code, $i,
                              fn($b) => hash('ripemd160', hash('sha256', $b, true), true));
      case $W['HASH256']:   return $this->hashTo($code, $i,
                              fn($b) => hash('sha256', hash('sha256', $b, true), true));

      // `( a-sig u-sig a-pub u-pub a-digest 32 -- flag )`
      // ★ EXPLICIT DIGEST, twice over. Bitcoin's CHECKSIG reaches for a preimage the script cannot see
      //   AND hashes it twice behind your back; here `PREIMAGE` is a word and the hashing is written
      //   down, so `PREIMAGE d HASH256 ... CHECKSIG` says exactly what it signs.
      case $W['CHECKSIG']: case $W['CHECKSIGVERIFY']: {
        $msg = $this->popSpan(); $pub = $this->popSpan(); $sig = $this->popSpan();
        $ok  = self::ecdsaVerify($sig, $pub, $msg);
        if ($op === $W['CHECKSIGVERIFY']) {
          if (!$ok) throw new JfScriptError('CHECKSIGVERIFY failed');
        } else $this->flag($ok);
        return $i; }

      // `( a-msg u-msg n a-pub u-pub ... m a-sig u-sig ... -- flag )` — m sigs, n keys, sigs in key order.
      // ⛔ NO dummy element. BTC's off-by-one is a bug `BT` carries for fidelity; `JF` is not trying to
      //    be Bitcoin, and reproducing a known bug in a new set would be an amputation in reverse.
      case $W['CHECKMULTISIG']: case $W['CHECKMULTISIGVERIFY']: {
        $m = $this->popInt();
        if ($m < 0 || $m > 32) throw new JfScriptError('CHECKMULTISIG: bad signature count');
        $sigs = [];
        for ($k = 0; $k < $m; $k++) array_unshift($sigs, $this->popSpan());
        $n = $this->popInt();
        if ($n < 0 || $n > 32 || $m > $n) throw new JfScriptError('CHECKMULTISIG: bad key count');
        $keys = [];
        for ($k = 0; $k < $n; $k++) array_unshift($keys, $this->popSpan());
        $msg = $this->popSpan();
        // signatures must appear in the same order as their keys — one pass, no backtracking
        $ki = 0; $matched = 0;
        foreach ($sigs as $s) {
          while ($ki < $n && !self::ecdsaVerify($s, $keys[$ki], $msg)) $ki++;
          if ($ki >= $n) break;
          $matched++; $ki++;
        }
        $ok = $matched === $m;
        if ($op === $W['CHECKMULTISIGVERIFY']) {
          if (!$ok) throw new JfScriptError('CHECKMULTISIGVERIFY failed');
        } else $this->flag($ok);
        return $i; }

      // ── transaction ───────────────────────────────────────────────────────────────────────────────
      case $W['PREIMAGE']: { $this->covenantOnly('PREIMAGE', $covenant); $d = $this->popInt();
        if ($this->preimage === null) throw new JfScriptError('PREIMAGE: no transaction context');
        $this->write($d, $this->preimage);
        $this->pushI($d); $this->pushI(strlen($this->preimage)); return $i; }
      // ⏭ The field accessors are slices of the preimage and are not built yet — see verify-jf.php.
      case $W['TXVERSION']: case $W['PREVOUTS-HASH']: case $W['SEQUENCES-HASH']: case $W['OUTPOINT']:
      case $W['SCRIPTCODE']: case $W['TXVALUE']: case $W['NSEQUENCE']: case $W['OUTPUTS-HASH']:
      case $W['LOCKTIME']:
        // ⚠ The guard goes on FIRST, so it is already in place the day these are built rather than
        //   being something to remember later.
        $this->covenantOnly(jf_op_name($op), $covenant);
        throw new JfScriptError(jf_op_name($op) . ': not built yet — derive it from PREIMAGE with SUBSTR');
      case $W['VER']: case $W['VERIF']: case $W['VERNOTIF']:
        throw new JfScriptError(jf_op_name($op) . ': version words are §6b and not built yet');

      // ── INVOKE: the tier boundary ─────────────────────────────────────────────────────────────────
      case $W['INVOKE']: { $ix = self::u8($code, $i); $i++; $this->invoke($ix); return $i; }

      // ── abort ─────────────────────────────────────────────────────────────────────────────────────
      // ★ `ABORT` is Forth's own word, promoted to jetForth because refusing is the commonest thing a
      //   covenant does. `(ABORT")` is what `ABORT"` compiles to, as BRANCH is what IF compiles to.
      case $W['ABORT']: throw JfScriptError::aborted('');
      case $W['(ABORT")']: {                    // ( flag -- )  with an INLINE <len:u8> <bytes>
        // ⛔⛔⛔ THE MESSAGE IS A COMPILE-TIME LITERAL, NOT A STACK SPAN, AND THAT IS THE SECURITY
        //    PROPERTY. The diagnostic leaves the machine — it reaches a wallet, a UI, a log, possibly
        //    a server. A version taking `( flag c-addr u -- )` let a covenant abort carrying COMPUTED
        //    bytes, and it was measured doing exactly that: `PREIMAGE (ABORT")` handed the whole
        //    transaction context out. ⇒ An inline literal is in the script, so it is public by
        //    construction and can carry nothing derived from a key, a preimage or memory.
        //  ★ And this is Forth's OWN semantics: `ABORT" msg"` compiles its string in. The stack-span
        //    version was my generalisation, and the standard was right.
        $n = self::u8($code, $i); $i++;
        if ($i + $n > strlen($code)) throw new JfScriptError('truncated ABORT" message');
        $msg = substr($code, $i, $n); $i += $n;
        if (gmp_sign($this->pop()) !== 0) throw JfScriptError::aborted($msg);
        return $i; }
    }

    if ($op >= JF_RESERVED0 && $op < JF_ESC0)
      throw new JfScriptError(sprintf('0x%02x is reserved and must not appear', $op));
    throw new JfScriptError(sprintf('unknown opcode 0x%02x', $op));
  }

  // ★ `TYPE` `CR` `SPACE` `SPACES` are EMIT loops in every Forth, and `KEY` is what `ACCEPT` reads
  //   with, so allowing one of each pair and refusing the rest would be arbitrary.
  private const CHANNEL_WORDS = ['EMIT' => 'o', 'CR' => 'o', 'SPACE' => 'o', 'SPACES' => 'o',
                                 'TYPE' => 'o', 'KEY' => 'i', 'ACCEPT' => 'i', 'EMIT?' => 'o'];

  private function channel(string $word): void
  {
    $t = count($this->chan) - 1;
    if (self::CHANNEL_WORDS[$word] === 'o') {
      if ($this->chan[$t]['max'] === 0)
        throw new JfScriptError("$word: this function declared no output channel (out_max is 0)");
      $b = match ($word) {
        'EMIT'   => chr($this->popInt() & 0xff),
        'CR'     => "\n",
        'SPACE'  => ' ',
        'SPACES' => str_repeat(' ', max(0, $this->popInt())),
        'TYPE'   => $this->popSpan(),
        'EMIT?'  => '',
      };
      if ($word === 'EMIT?') {                       // ( -- flag ) is there room for one more?
        $this->flag(strlen($this->chan[$t]['out']) < $this->chan[$t]['max']);
        return;
      }
      if (strlen($this->chan[$t]['out']) + strlen($b) > $this->chan[$t]['max'])
        throw new JfScriptError(sprintf('output exceeds the declared out_max of %d',
                                        $this->chan[$t]['max']));
      $this->chan[$t]['out'] .= $b;
      return;
    }
    // ── input ────────────────────────────────────────────────────────────────────────────────────
    // ⚠ Check the DECLARED size, not whether bytes happen to be present: a function that declared a
    //   channel and was handed an empty one is legal (ACCEPT returns 0). A function that declared
    //   none is not, and conflating the two is how ACCEPT slipped past this check first time.
    if ($this->chan[$t]['inmax'] === 0)
      throw new JfScriptError("$word: this function declared no input channel (in_max is 0)");
    $in = $this->chan[$t]['in'];
    if ($word === 'KEY') {                           // ( -- char )
      if ($this->chan[$t]['pos'] >= strlen($in)) throw new JfScriptError('KEY: input exhausted');
      $this->pushI(ord($in[$this->chan[$t]['pos']++]));
      return;
    }
    // ACCEPT ( c-addr +n1 -- +n2 ) — a LINE, as the standard says: up to n1 bytes, stopping at \n,
    // ⚠ and the newline is CONSUMED but NOT stored, which is the part that is easy to get wrong.
    $n1 = $this->popInt(); $addr = $this->popInt();
    if ($n1 < 0) throw new JfScriptError('ACCEPT: negative length');
    $got = '';
    while (strlen($got) < $n1 && $this->chan[$t]['pos'] < strlen($in)) {
      $c = $in[$this->chan[$t]['pos']++];
      if ($c === "\n") break;
      $got .= $c;
    }
    if ($got !== '') $this->write($addr, $got);
    $this->pushI(strlen($got));
  }

  /**
   * ⛔⛔ THE COVENANT'S OWN WORDS ARE NOT THE FUNCTION'S.
   * *"The function computes. The covenant decides."* was stated from the start and was NOT enforced:
   * a stdForth function could call `PREIMAGE` and read transaction context it was never handed.
   * ⇒ Anything that reaches for context the caller did not pass as an argument is covenant-tier only.
   */
  private function covenantOnly(string $word, bool $covenant): void
  {
    if (!$covenant)
      throw new JfScriptError("$word is covenant-tier only: a stdForth function computes from what it "
                            . 'was given, and reaches for nothing else');
  }

  private function frame(): array {
    if (!$this->frames) throw new JfScriptError('local access with no frame');
    return $this->frames[count($this->frames) - 1];
  }

  private function jump(string $code, int $from, int $off): int {
    $to = $from + $off;
    if ($to < 0 || $to > strlen($code)) throw new JfScriptError('branch out of range');
    return $to;
  }

  private function call(string $code, int $to, bool $covenant): void {
    if (++$this->depth > $this->maxDepth) { $this->depth--; throw new JfScriptError('call depth exceeded'); }
    try {
      if ($to < 0 || $to > strlen($code)) throw new JfScriptError('call out of range');
      $this->exec($code, $to, $covenant);
    } finally { $this->depth--; }
  }

  private function hashTo(string $code, int $i, callable $h): int {
    $d = $this->popInt(); $s = $this->popSpan();
    $this->write($d, $h($s));
    return $i;
  }

  /**
   * ⛔⛔ THE TIER BOUNDARY, AND IT IS ENFORCED RATHER THAN DECLARED.
   *
   * A declared arity is NOT a sandbox: a function would otherwise reach past its arguments with PICK or
   * ROLL and read the covenant's stack. So the function gets a FRESH data stack holding exactly n_in
   * items, a FRESH return stack, fresh locals — and stdForth has no word that reaches back.
   * ⇒ The arity check then becomes a CHECK rather than a hope: n_out items sit on a stack that started
   *   empty and could hold nothing else.
   * ⚠⚠⚠ MEMORY IS FRESH TOO, and an earlier version of this file got that WRONG. I reasoned that
   *   working memory was "how (c-addr u) arguments are passed at all" and left it shared — which
   *   meant **a function could read the caller's entire memory with a bare `@`**, measured and
   *   confirmed. The fresh stack was real; the memory boundary did not exist.
   * ⇒ ★★★ The resolution makes the design cleaner rather than costing anything: **a function takes
   *   CELLS and its declared input channel, never addresses.** An address is meaningless across the
   *   boundary anyway, so nothing is lost by refusing to carry one.
   */
  private function invoke(int $ix): void
  {
    if (!isset($this->defs[$ix])) throw new JfScriptError("INVOKE $ix: no such definition");
    $d = $this->defs[$ix];
    $inMax = $d['in_max'] ?? 0; $outMax = $d['out_max'] ?? 0;
    // ⚠ The input span sits ABOVE the cell arguments — pushed last, so popped first.
    $this->need($d['n_in'] + ($inMax > 0 ? 2 : 0));
    if (++$this->depth > $this->maxDepth) { $this->depth--; throw new JfScriptError('call depth exceeded'); }

    $savedDs = $this->ds; $savedRs = $this->rs; $savedFr = $this->frames;
    $chanDepth = count($this->chan);
    try {
      $inBytes = '';
      if ($inMax > 0) {
        $inBytes = $this->popSpan();
        if (strlen($inBytes) > $inMax)
          throw new JfScriptError(sprintf('INVOKE %d: input is %d bytes, declared in_max %d',
                                          $ix, strlen($inBytes), $inMax));
      }
      $args = $d['n_in'] === 0 ? [] : array_splice($this->ds, count($this->ds) - $d['n_in']);
      $callerDs = $this->ds;
      $this->ds = $args; $this->rs = []; $this->frames = [];
      $savedMem = $this->mem; $savedTop = $this->scratchTop;
      $this->mem = str_repeat("\x00", strlen($this->mem));   // ⛔ zeroed: no residue from the caller
      $this->scratchTop = 0;
      $this->chan[] = ['in' => $inBytes, 'pos' => 0, 'inmax' => $inMax,
                       'out' => '', 'max' => $outMax];

      $this->exec($d['body'], 0, /* covenant */ false);
      if (count($this->ds) !== $d['n_out'])
        throw new JfScriptError(sprintf('INVOKE %d: declared %d out, produced %d',
                                        $ix, $d['n_out'], count($this->ds)));
      if ($this->frames) throw new JfScriptError("INVOKE $ix: unbalanced locals frame");
      $results = $this->ds;
      $emitted = array_pop($this->chan)['out'];
      $this->mem = $savedMem; $this->scratchTop = $savedTop;
    } catch (Throwable $e) {
      // ⚠ A failed call leaves NOTHING behind — not a partial stack, not a half-written channel,
      //   and not a scribbled-on arena.
      array_splice($this->chan, $chanDepth);
      if (isset($savedMem)) { $this->mem = $savedMem; $this->scratchTop = $savedTop; }
      $this->ds = $savedDs; $this->rs = $savedRs; $this->frames = $savedFr;
      throw $e;
    } finally { $this->depth--; }

    $this->ds = array_merge($callerDs, $results);
    $this->rs = $savedRs; $this->frames = $savedFr;
    // ⇒ THE CHANNEL COMES BACK AS ( c-addr u ), ABOVE the declared outputs. Declared, therefore
    //   counted — which is the whole reason it is allowed at all.
    if ($outMax > 0) $this->pushSpan($emitted);
  }

  // ── division ───────────────────────────────────────────────────────────────────────────────────────
  // ⚠⚠ SYMMETRIC (truncate toward zero): -7/2 = -3, and the remainder takes the sign of the DIVIDEND.
  // ★ Forth 2012 §3.2.2.1 PERMITS either floored or symmetric as a documented choice — this is not a
  //   deviation from the standard, it is one of the two answers the standard hands you.
  // ⛔ gmp_mod is the WRONG function here: it returns a NON-NEGATIVE remainder (gmp_mod(-7,2) = 1).
  private static function divT(GMP $a, GMP $b): GMP {
    if (gmp_sign($b) === 0) throw new JfScriptError('division by zero');
    return gmp_div_q($a, $b);
  }
  private static function modT(GMP $a, GMP $b): GMP {
    if (gmp_sign($b) === 0) throw new JfScriptError('division by zero');
    return gmp_div_r($a, $b);
  }
  /** two's-complement view of a possibly-negative double-width product */
  private static function u2(GMP $p): GMP {
    return gmp_sign($p) < 0 ? gmp_add($p, gmp_pow(2, 128)) : $p;
  }

  // ── secp256k1 ──────────────────────────────────────────────────────────────────────────────────────
  /**
   * ⚠ THE ONE PIECE OF PACKAGING THAT FAILS SILENTLY: a Bitcoin signature is DER with the SIGHASH TYPE
   *   BYTE APPENDED. That byte is not part of the signature — it says which preimage to build — and
   *   leaving it on makes the DER malformed, so verification fails for the WRONG REASON.
   * ★ `JF` signs an explicit digest, so there is no sighash byte to strip here. A caller handing over a
   *   Bitcoin signature strips it at the call site, where it is visible.
   * ⚠⚠ The curve lives in `secp256k1.php` — WRITTEN, NOT IMPORTED, and that is a licence position.
   *   See that file's header: bitcoinX has no Python curve to port, and a system crypto library is not
   *   something this machine should depend on for its one unforgeable answer.
   */
  public static function ecdsaVerify(string $sig, string $pub, string $digest32): bool
  {
    return Secp256k1::verifyDigest($sig, $pub, $digest32);
  }
}

/**
 * H(result) = sha256( for each cell: 8 bytes little-endian ) — the §2b comparison hash for `JF`.
 * ⚠ Canonical by construction: cells are fixed width, so there is no length prefix to disagree about.
 */
function jf_stack_hash(array $cells): string
{
  $b = '';
  foreach ($cells as $c) {
    $u  = gmp_sign($c) < 0 ? gmp_add($c, gmp_pow(2, 64)) : $c;
    $be = gmp_sign($u) === 0 ? '' : gmp_export($u, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $b .= strrev(str_pad($be, 8, "\x00", STR_PAD_LEFT));
  }
  return hash('sha256', $b);
}
