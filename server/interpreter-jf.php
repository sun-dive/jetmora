<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
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
// A cell is a PHP int: 64 bits, two's complement. The constructor refuses a host whose int is narrower, so
// no extension is needed for a cell. ⚠⚠⚠ But `PHP_INT_MAX + 1` silently becomes a float: precision gone,
// NO error raised. Fatal for a machine whose product is the same answer every time, and a cell must WRAP at
// 64 bits, which a float cannot do. ⇒ No cell is made by a bare `+`, `-` or `*` that can overflow: add(),
// sub(), mul() and the double-width helpers below wrap mod 2^64. Under strict_types a float can never sit on
// a stack: push(int) refuses one.
//
// ── CELLS AND STRINGS ────────────────────────────────────────────────────────────────────────────────
// §10.4: the version names the set and THE SET FIXES THE WIDTH. `JF` is 64-bit cells.
// ★ So a string is what it is in every Forth: AN ADDRESS AND A LENGTH (§10.5c). Byte-string and crypto
//   words take `( c-addr u ... )` and write to a destination the CALLER supplies — no hidden allocator,
//   because an allocator is a source of divergence between implementations.
declare(strict_types=1);
require_once __DIR__ . '/ops-jf.php';
require_once __DIR__ . '/secp256k1.php';
require_once __DIR__ . '/ed25519.php';

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

/**
 * THE HOST CANNOT JUDGE: a capability it lacks (a 64-bit int, which every cell is and secp256k1.php and
 * ed25519.php compute CHECKSIG and ED25519-CHECKSIG with). It is not a refusal, and verifyTick
 * passes it on rather than turn it into one: a tick is never refused here and accepted there because one
 * host is missing a library.
 */
final class JfHostError extends RuntimeException {}

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
  /** @var int[] data stack   */ private array $ds = [];
  /** @var int[] return stack */ private array $rs = [];
  /** @var array<int,array{n_in:int,n_out:int,body:string}> */ private array $defs = [];
  /** @var int[][] locals frames */ private array $frames = [];
  private string $mem = '';
  /** @var array<int,array{in:string,pos:int,inmax:int,out:string,max:int,room:int}> one frame per active INVOKE */
  private array $chan = [];
  private int $opCount = 0;
  private int $depth = 0;
  /** Cells in the locals frames, and cells an active INVOKE has set aside: both count as items held. */
  private int $frameCells = 0;
  private int $held = 0;
  /** Every pushed byte, in order: read-only, and never at a program-memory address (his call, 23 Oct). */
  private string $pmem = '';
  private int $sigOps = 0;
  /** Where the push space starts. Program memory is below it, so the two can never overlap. A function at INVOKE
   *  depth d (the INVOKEs active: the lock is 0) has its own from PUSH_BASE × (d + 1), so a push address it returns
   *  is out of range in its caller. */
  public const PUSH_BASE = 16777216;
  private int $pbase = self::PUSH_BASE;
  /** The lock's program memory is at 0. A function's is at its push space + MEM_OFFSET, so a memory address it
   *  returns is out of range in its caller too (his call, 23 Oct). A function finds its memory with HERE. */
  public const MEM_OFFSET = 8388608;
  private int $mbase = 0;

  /** Signature/preimage context. ⚠ Optional: a bare script has no transaction. */
  private ?string $preimage = null;

  /**
   * These limits are for run(), the interpreter as a tool. A tick is judged by verifyTick(), with JF
   * revision 3's own limits (the TICK_ constants), the same for every host.
   */
  public function __construct(
    private int $maxOps = 200000,
    private int $memSize = 65536,
    private int $maxDepth = 64,
    private int $maxItems = 1000,
    private int $pushSize = 65536,
    private int $maxSigOps = 100,
  ) {
    // every cell is a 64-bit int: a host with a narrower one cannot run a single instruction, so it cannot judge
    if (PHP_INT_SIZE < 8) throw new JfHostError('JF needs 64-bit integers on this host');
  }

  public function setPreimage(?string $p): void { $this->preimage = $p; }

  // ── cells ──────────────────────────────────────────────────────────────────────────────────────────
  // Each helper gives what a cell holds: the true result mod 2^64, read as two's complement. An "unsigned"
  // argument is the same 64 bits read from 0 to 2^64 - 1.
  /** a + b. On overflow a and b have the same sign: flipping the top bit of one keeps the low 64 bits of the
   *  sum, and that sum cannot overflow. */
  private static function add(int $a, int $b): int {
    $r = $a + $b;
    return is_int($r) ? $r : (($a ^ PHP_INT_MIN) + $b) ^ PHP_INT_MIN;
  }
  /** a - b. On overflow a and b differ in sign, and the same flip applies. */
  private static function sub(int $a, int $b): int {
    $r = $a - $b;
    return is_int($r) ? $r : (($a ^ PHP_INT_MIN) - $b) ^ PHP_INT_MIN;
  }
  /** -a. The most negative cell is its own negation: 2^63 wraps back to it. */
  private static function neg(int $a): int { return $a === PHP_INT_MIN ? $a : -$a; }
  /** a × b: the low 64 bits of the product. */
  private static function mul(int $a, int $b): int {
    $r = $a * $b;
    return is_int($r) ? $r : self::umul($a, $b)[1];
  }
  /** a < b, both unsigned. */
  private static function ult(int $a, int $b): bool { return ($a ^ PHP_INT_MIN) < ($b ^ PHP_INT_MIN); }
  /** a >> n, logical: the top n bits are zeros. */
  private static function lshr(int $a, int $n): int {
    return $n === 0 ? $a : ($n >= 64 ? 0 : ($a >> $n) & (PHP_INT_MAX >> ($n - 1)));
  }
  /** A cell written as unsigned decimal, for a message about a value past PHP_INT_MAX. */
  private static function udec(int $a): string { return sprintf('%u', $a); }
  /**
   * The 128-bit product of a and b, both unsigned, as [hi, lo]. In 16-bit limbs, so no partial product reaches
   * 2^32 and no column 2^35: 32-bit halves would not do, as 0xffffffff × 0xffffffff is past PHP_INT_MAX.
   */
  private static function umul(int $a, int $b): array {
    $x = [$a & 0xffff, ($a >> 16) & 0xffff, ($a >> 32) & 0xffff, ($a >> 48) & 0xffff];
    $y = [$b & 0xffff, ($b >> 16) & 0xffff, ($b >> 32) & 0xffff, ($b >> 48) & 0xffff];
    $col = [0, 0, 0, 0, 0, 0, 0, 0];
    for ($i = 0; $i < 4; $i++) for ($j = 0; $j < 4; $j++) $col[$i + $j] += $x[$i] * $y[$j];
    $hi = $lo = $carry = 0;
    for ($k = 0; $k < 8; $k++) {
      $t = $col[$k] + $carry; $carry = $t >> 16;
      if ($k < 4) $lo |= ($t & 0xffff) << (16 * $k); else $hi |= ($t & 0xffff) << (16 * ($k - 4));
    }
    return [$hi, $lo];
  }
  /** The signed 128-bit product, as [hi, lo]: the unsigned one, less b × 2^64 when a is negative and less
   *  a × 2^64 when b is. */
  private static function smul(int $a, int $b): array {
    [$hi, $lo] = self::umul($a, $b);
    if ($a < 0) $hi = self::sub($hi, $b);
    if ($b < 0) $hi = self::sub($hi, $a);
    return [$hi, $lo];
  }
  /**
   * hi:lo ÷ d, all unsigned and d not zero, as [quotient hi, quotient lo, remainder]. The quotient is 128 bits
   * wide; a caller keeps its low 64, as a cell keeps them. One bit at a time, from the top: when the partial
   * remainder has its top bit set, doubling it passes 2^64, which is more than d, so d is taken away.
   */
  private static function udiv128(int $hi, int $lo, int $d): array {
    if ($hi === 0 && $lo >= 0 && $d > 0) return [0, intdiv($lo, $d), $lo % $d];
    $qhi = $qlo = $r = 0;
    for ($k = $hi === 0 ? 63 : 127; $k >= 0; $k--) {
      $top = $r < 0;
      $r = ($r << 1) | ($k >= 64 ? ($hi >> ($k - 64)) & 1 : ($lo >> $k) & 1);
      if ($top || !self::ult($r, $d)) {
        $r = self::sub($r, $d);
        if ($k >= 64) $qhi |= 1 << ($k - 64); else $qlo |= 1 << $k;
      }
    }
    return [$qhi, $qlo, $r];
  }

  // ── stacks ─────────────────────────────────────────────────────────────────────────────────────────
  /** need($n + 1) for an index that may be PHP_INT_MAX, which `+ 1` would turn into a float. */
  private function needMore(int $n): void {
    if ($n >= count($this->ds))
      throw new JfScriptError('stack underflow: need ' . self::udec(self::add($n, 1)) . ', have ' . count($this->ds));
  }
  private function need(int $n): void {
    if (count($this->ds) < $n) throw new JfScriptError("stack underflow: need $n, have " . count($this->ds));
  }
  private function pop(): int {
    if (!$this->ds) throw new JfScriptError('stack underflow');
    return array_pop($this->ds);
  }
  private function push(int $v): void { $this->ds[] = $v; }
  private function flag(bool $b): void { $this->ds[] = $b ? -1 : 0; }   // Forth TRUE is all bits set

  // ── memory ─────────────────────────────────────────────────────────────────────────────────────────
  /** The offset of $addr in program memory, which lies at mbase. */
  private function bounds(int $addr, int $len): int {
    if ($addr < $this->mbase || $len < 0 || $addr - $this->mbase > $this->memSize - $len)
      throw new JfScriptError("memory out of range: addr=$addr len=$len size=" . $this->memSize);
    // made, zeroed, when first touched: a function that never touches memory costs nothing for it
    if ($this->mem === '') $this->mem = str_repeat("\x00", $this->memSize);
    return $addr - $this->mbase;
  }
  /** $a + $off as an address. Past PHP_INT_MAX it is out of range, said as the JavaScript port says it. */
  private function at(int $a, int $off): int {
    if ($a > PHP_INT_MAX - $off)
      throw new JfScriptError('memory out of range: addr=' . self::udec(self::add($a, $off)) . ' len=8 size=' . $this->memSize);
    return $a + $off;
  }
  /** A cell is 8 bytes in memory, little-endian two's complement: unpack('P') reads them as PHP's signed int. */
  private function fetch(int $addr): int {
    return unpack('P', $this->view($addr, 8))[1];
  }
  private function store(int $addr, int $v): void {
    $o = $this->bounds($addr, 8);
    $le = pack('P', $v);
    for ($k = 0; $k < 8; $k++) $this->mem[$o + $k] = $le[$k];
  }
  private function read(int $addr, int $len): string { return $this->view($addr, $len); }
  /** Bytes from program memory, or from wholly inside the push space. Writes never reach the push space. */
  private function view(int $addr, int $len): string {
    $p = strlen($this->pmem);
    if ($addr >= $this->pbase && $len >= 0 && $len <= $p && $addr - $this->pbase <= $p - $len) {
      $this->charge($len);
      return substr($this->pmem, $addr - $this->pbase, $len);
    }
    $o = $this->bounds($addr, $len);
    $this->charge($len);
    return substr($this->mem, $o, $len);
  }
  /** Each span read, written or pushed costs one more instruction for every whole 64 bytes in it (his call, 23 Oct).
   *  A function's channel bytes are charged when INVOKE reads its input span and when its output is pushed on return. */
  private function charge(int $n): void {
    $this->opCount += intdiv($n, 64);
    if ($this->opCount > $this->maxOps) throw new JfScriptError('op budget exhausted');
  }
  private function write(int $addr, string $b): void {
    $n = strlen($b);
    $o = $this->bounds($addr, $n);
    $this->charge($n);
    // byte by byte is faster up to about 128 bytes; above that substr_replace costs about 1 us at any length
    if ($n <= 128) { for ($k = 0; $k < $n; $k++) $this->mem[$o + $k] = $b[$k]; }
    else $this->mem = substr_replace($this->mem, $b, $o, $n);
  }
  /** `( c-addr u -- )` popped as a pair, u on top. */
  private function popSpan(): string { $u = $this->pop(); $a = $this->pop(); return $this->read($a, $u); }

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

  // ── the lock's declaration ─────────────────────────────────────────────────────────────────────────
  // `VER <version:4>`: the version the lock's code is written for, its four bytes as an entry's nVersion carries
  // them: D1 03 00 4A 46 for JF 3. Every lock starts with it, before its DEFS header, and a host reads it before
  // anything runs and runs the engine for the version it declares. ⇒ To the engine it is a statement, not a
  // question asked each tick: at the start of a lock it is stepped over, and so is a branch back to it. Anywhere else
  // it declares nothing, and is refused.
  private const VER_ELSEWHERE = 'VER declares the version a lock is written for, and is valid only as its first instruction';

  /** Where a script's code begins: past its declaration when it starts with one, then past its DEFS header. */
  private function codeStart(string $script): int
  {
    $i = 0;
    if ($script !== '' && ord($script[0]) === JF_WORD['VER']) $i = self::pastDeclaration($script, 1);
    $this->parseDefs($script, $i);
    return $i;
  }
  /** Past VER's four version bytes, $i being just after VER. */
  private static function pastDeclaration(string $code, int $i): int
  {
    if ($i + 4 > strlen($code)) throw new JfScriptError('truncated operand');
    return $i + 4;
  }

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

  // ── judging a tick ─────────────────────────────────────────────────────────────────────────────────
  /**
   * JF revision 3's limits when a tick is judged. They are the version's, the same for every host: a limit
   * that differed between hosts would be a verdict that differed between them. Taken from a BSV node's
   * defaults: a script is at most 500,000 bytes (500 KB, BSV's KB being 1,000), and a tick runs at most the same
   * number of instructions, each span read, written or pushed costing one more for every whole 64 bytes. At
   * most 1,000 items are held at once, as BSV's MAX_STACK_ELEMENTS (stack and altstack), counting here the data and
   * return stacks, the locals frames and what an INVOKE has set aside. Pushed bytes have their own 65,536 bytes,
   * read-only. At most 100 signature checks a tick, weighted as BSV weights them (CHECKSIG and ED25519-CHECKSIG 1,
   * CHECKMULTISIG its number of keys) and counted as each runs, before the check is made.
   */
  public const TICK_MAX_SCRIPT = 500000, TICK_MAX_OPS = 500000, TICK_MEM = 65536, TICK_MAX_DEPTH = 64, TICK_MAX_ITEMS = 1000,
               TICK_PUSH_MEM = 65536, TICK_MAX_SIGOPS = 100;

  /**
   * Judge a tick as a BSV node judges a spend (bitcoin-sv src/script/interpreter.cpp, VerifyScript):
   *   1  the unlocking script is byte pushes only: direct pushes and STR8 / STR16 / STR32, each whole;
   *   2  it runs, then the lock runs as a SECOND, separate run on the data stack and pushed bytes it left, so
   *      nothing in the first can jump into the second or end it;
   *   3  the tick is accepted when the lock leaves exactly one item and it is non-zero. Any error refuses it.
   * @return array{accepted: bool, stack?: int[], error?: string}
   */
  public static function verifyTick(string $unlocking, string $lock, ?string $preimage): array
  {
    if (strlen($unlocking) > self::TICK_MAX_SCRIPT || strlen($lock) > self::TICK_MAX_SCRIPT)
      return ['accepted' => false, 'error' => 'a script is longer than 500000 bytes'];
    if (!self::bytePushesOnly($unlocking)) return ['accepted' => false, 'error' => 'the unlocking script is not byte pushes only'];
    $vm = new self(self::TICK_MAX_OPS, self::TICK_MEM, self::TICK_MAX_DEPTH, self::TICK_MAX_ITEMS,
                   self::TICK_PUSH_MEM, self::TICK_MAX_SIGOPS);
    $vm->setPreimage($preimage);
    try {
      $vm->ds = $vm->rs = $vm->frames = $vm->chan = [];
      $vm->opCount = 0; $vm->depth = 0; $vm->frameCells = 0; $vm->held = 0; $vm->sigOps = 0;
      $vm->mem = '';
      $vm->pmem = ''; $vm->pbase = self::PUSH_BASE; $vm->mbase = 0;
      $vm->exec($unlocking, 0, true);
      // the second run: the data stack and the pushed bytes carry over, and the op and signature counts run on
      $vm->rs = $vm->frames = []; $vm->depth = 0; $vm->frameCells = 0;
      $vm->exec($lock, $vm->codeStart($lock), true);
      if ($vm->frames) throw new JfScriptError('unbalanced locals frame');
    } catch (JfHostError $e) {
      throw $e;                                     // this host cannot judge: never a refusal
    } catch (JfScriptError $e) {
      return ['accepted' => false, 'error' => $e->getMessage()];
    } catch (Throwable $e) {
      return ['accepted' => false, 'error' => 'the interpreter faulted: ' . get_class($e)];   // no host paths
    }
    return ['accepted' => count($vm->ds) === 1 && $vm->ds[0] !== 0, 'stack' => $vm->ds];
  }

  /** Byte pushes only: direct pushes (0 to 72 bytes) and STR8 / STR16 / STR32, each whole. */
  public static function bytePushesOnly(string $s): bool
  {
    $n = strlen($s);
    for ($p = 0; $p < $n;) {
      $op = ord($s[$p++]);
      if ($op <= JF_PUSH_MAX) $len = $op;
      elseif ($op === JF_LIT['STR8'])  { if ($p + 1 > $n) return false; $len = ord($s[$p]); $p += 1; }
      elseif ($op === JF_LIT['STR16']) { if ($p + 2 > $n) return false; $len = unpack('v', substr($s, $p, 2))[1]; $p += 2; }
      elseif ($op === JF_LIT['STR32']) { if ($p + 4 > $n) return false; $len = unpack('V', substr($s, $p, 4))[1]; $p += 4; }
      else return false;
      if ($p + $len > $n) return false;
      $p += $len;
    }
    return true;
  }

  // ── run ────────────────────────────────────────────────────────────────────────────────────────────
  /** @return int[] the final data stack, bottom first. @throws JfScriptError */
  public function run(string $script): array
  {
    $this->ds = $this->rs = $this->frames = $this->chan = [];
    $this->opCount = 0; $this->depth = 0; $this->frameCells = 0; $this->held = 0; $this->sigOps = 0;
    $this->mem = '';
    $this->pmem = ''; $this->pbase = self::PUSH_BASE; $this->mbase = 0;
    $this->exec($script, $this->codeStart($script), /* covenant tier */ true);
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
      // checked after every instruction, as BSV checks stack + altstack after every opcode
      if (count($this->ds) + count($this->rs) + $this->frameCells + $this->held > $this->maxItems) $this->tooMany();
      if (++$this->opCount > $this->maxOps) throw new JfScriptError('op budget exhausted');
      $op = ord($code[$i]); $i++;

      // ── direct push: the opcode IS the length ───────────────────────────────────────────────────
      // ⚠ A push puts (c-addr u) on the stack — the bytes are copied into the push space, because a
      //   cell cannot hold 32 bytes and Forth strings are addr+len.
      if ($op <= JF_PUSH_MAX) {
        if ($i + $op > $len) throw new JfScriptError('push past end of script');
        $this->pushSpan(substr($code, $i, $op));
        $i += $op;
        continue;
      }
      // ── small integers ──────────────────────────────────────────────────────────────────────────
      if ($op >= JF_SMALL0 && $op <= JF_SMALL_NEG1) {
        $this->push($op === JF_SMALL_NEG1 ? -1 : $op - JF_SMALL0);
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
        // ★ HERE ( -- addr ): where a function's program memory starts (CORE 6.1.1650, with no ALLOT)
        if ($word === 'HERE' && $this->chan) { $this->push($this->mbase); continue; }
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
    if (count($this->ds) + count($this->rs) + $this->frameCells + $this->held > $this->maxItems) $this->tooMany();
  }
  private function tooMany(): never {
    throw new JfScriptError(sprintf('stack size exceeded: %d items held, at most %d',
      count($this->ds) + count($this->rs) + $this->frameCells + $this->held, $this->maxItems));
  }

  /** Append bytes to the push space and leave `( c-addr u )`. ⚠ Deterministic: an address depends only on the lengths pushed before. */
  private function pushSpan(string $b): void {
    $n = strlen($b);
    if (strlen($this->pmem) + $n > $this->pushSize) throw new JfScriptError('push space exhausted');
    $this->charge($n);
    $at = $this->pbase + strlen($this->pmem);
    $this->pmem .= $b;
    $this->push($at); $this->push($n);
  }
  private function sigOp(int $n): void {
    $this->sigOps += $n;
    if ($this->sigOps > $this->maxSigOps)
      throw new JfScriptError(sprintf('signature check limit exceeded: at most %d a tick', $this->maxSigOps));
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
        $this->push(unpack('P', str_pad($le, 8, ord($le[$w - 1]) & 0x80 ? "\xff" : "\x00"))[1]);   // sign-extend
        return $i + $w;
      }
      case $L['LITBIG']: {
        $n = $this->varint($code, $i);
        if ($i + $n > strlen($code)) throw new JfScriptError('truncated LITBIG');
        // ⚠ A bignum does not fit a cell. It goes to the push space and arrives as (c-addr u), like any string.
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
      case $W['ROT']:   $this->need(3); $n = count($this->ds); $x = $this->ds[$n-3];
                        $this->ds[$n-3] = $this->ds[$n-2]; $this->ds[$n-2] = $this->ds[$n-1]; $this->ds[$n-1] = $x; return $i;
      case $W['?DUP']:  $this->need(1); $t = $this->ds[count($this->ds) - 1];
                        if ($t !== 0) $this->ds[] = $t; return $i;
      case $W['NIP']:   $this->need(2); $n = count($this->ds); $this->ds[$n-2] = $this->ds[$n-1]; array_pop($this->ds); return $i;
      case $W['TUCK']:  $this->need(2); $n = count($this->ds); $b = $this->ds[$n-1];
                        $this->ds[$n-1] = $this->ds[$n-2]; $this->ds[$n-2] = $b; $this->ds[] = $b; return $i;
      case $W['DEPTH']: $this->push(count($this->ds)); return $i;
      case $W['PICK']:  $n = $this->pop(); if ($n < 0) throw new JfScriptError('PICK: negative index'); $this->needMore($n);
                        $this->ds[] = $this->ds[count($this->ds) - 1 - $n]; return $i;
      case $W['ROLL']:  $n = $this->pop(); if ($n < 0) throw new JfScriptError('ROLL: negative index'); $this->needMore($n);
                        $x = array_splice($this->ds, count($this->ds) - 1 - $n, 1); $this->ds[] = $x[0]; return $i;
      case $W['2DUP']:  $this->need(2); $n = count($this->ds);
                        $this->ds[] = $this->ds[$n-2]; $this->ds[] = $this->ds[$n-1]; return $i;
      case $W['2DROP']: $this->need(2); $this->pop(); $this->pop(); return $i;
      case $W['2SWAP']: $this->need(4); $n = count($this->ds);
                        [$this->ds[$n-4], $this->ds[$n-3], $this->ds[$n-2], $this->ds[$n-1]]
                          = [$this->ds[$n-2], $this->ds[$n-1], $this->ds[$n-4], $this->ds[$n-3]]; return $i;
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
      case $W['+']:  $b = $this->pop(); $this->push(self::add($this->pop(), $b)); return $i;
      case $W['-']:  $b = $this->pop(); $this->push(self::sub($this->pop(), $b)); return $i;
      case $W['*']:  $b = $this->pop(); $this->push(self::mul($this->pop(), $b)); return $i;
      case $W['/']:  $b = $this->pop(); $a = $this->pop(); $this->push(self::divT($a, $b)); return $i;
      case $W['MOD']: $b = $this->pop(); $a = $this->pop(); $this->push(self::modT($a, $b)); return $i;
      case $W['/MOD']: $b = $this->pop(); $a = $this->pop();
                       $this->push(self::modT($a, $b)); $this->push(self::divT($a, $b)); return $i;
      // ★ */ and */MOD keep the intermediate at DOUBLE width: that is the whole point of them.
      //   Rounding down to a cell first would be a different word.
      case $W['*/']:  $c = $this->pop(); $b = $this->pop(); $a = $this->pop();
                      $this->push(self::mulDivT($a, $b, $c)[1]); return $i;
      case $W['*/MOD']: $c = $this->pop(); $b = $this->pop(); $a = $this->pop();
                      [$r, $q] = self::mulDivT($a, $b, $c);
                      $this->push($r); $this->push($q); return $i;
      case $W['1+']: $this->push(self::add($this->pop(), 1)); return $i;
      case $W['1-']: $this->push(self::sub($this->pop(), 1)); return $i;
      case $W['2*']: $this->push($this->pop() << 1); return $i;      // PHP's << keeps the low 64 bits
      case $W['2/']: $this->push($this->pop() >> 1); return $i;      // arithmetic shift: floor(a / 2)
      case $W['ABS']: $a = $this->pop(); $this->push($a < 0 ? self::neg($a) : $a); return $i;
      case $W['NEGATE']: $this->push(self::neg($this->pop())); return $i;
      case $W['MIN']: $b = $this->pop(); $a = $this->pop(); $this->push($a <= $b ? $a : $b); return $i;
      case $W['MAX']: $b = $this->pop(); $a = $this->pop(); $this->push($a >= $b ? $a : $b); return $i;
      // ⚠ FM/MOD is FLOORED, SM/REM is SYMMETRIC. They are two words BECAUSE they differ; collapsing
      //   them onto one division is the classic Forth implementation bug.
      case $W['FM/MOD']: $b = $this->pop(); $a = $this->pop();
                         if ($b === 0) throw new JfScriptError('FM/MOD by zero');
                         $q = self::divT($a, $b); $r = self::modT($a, $b);
                         // floored from truncated: when the remainder's sign differs from the divisor's, the
                         // quotient is one less and the remainder one divisor more
                         if ($r !== 0 && ($r < 0) !== ($b < 0)) { $q--; $r += $b; }
                         $this->push($r); $this->push($q); return $i;
      case $W['SM/REM']: $b = $this->pop(); $a = $this->pop();
                         $this->push(self::modT($a, $b)); $this->push(self::divT($a, $b)); return $i;
      case $W['UM*']:  $b = $this->pop(); $a = $this->pop();
                       [$hi, $lo] = self::umul($a, $b);
                       $this->push($lo); $this->push($hi); return $i;
      case $W['UM/MOD']: $b = $this->pop(); $hi = $this->pop(); $lo = $this->pop();
                       if ($b === 0) throw new JfScriptError('UM/MOD by zero');
                       [, $q, $r] = self::udiv128($hi, $lo, $b);
                       $this->push($r); $this->push($q); return $i;
      case $W['M*']:   $b = $this->pop(); $a = $this->pop();
                       [$hi, $lo] = self::smul($a, $b);
                       $this->push($lo); $this->push($hi); return $i;
      case $W['S>D']:  $this->need(1); $a = $this->ds[count($this->ds) - 1];
                       $this->push($a < 0 ? -1 : 0); return $i;

      // ── logic ─────────────────────────────────────────────────────────────────────────────────────
      case $W['AND']:    $b = $this->pop(); $this->push($this->pop() & $b); return $i;
      case $W['OR']:     $b = $this->pop(); $this->push($this->pop() | $b); return $i;
      case $W['XOR']:    $b = $this->pop(); $this->push($this->pop() ^ $b); return $i;
      case $W['INVERT']: $this->push(~$this->pop()); return $i;
      case $W['LSHIFT']: $n = $this->pop(); $a = $this->pop();
                         if ($n < 0) throw new JfScriptError('LSHIFT: negative count');
                         $this->push($n >= 64 ? 0 : $a << $n); return $i;
      case $W['RSHIFT']: $n = $this->pop(); $a = $this->pop();   // ⚠ LOGICAL, not arithmetic
                         if ($n < 0) throw new JfScriptError('RSHIFT: negative count');
                         $this->push(self::lshr($a, $n)); return $i;

      // ── comparison ────────────────────────────────────────────────────────────────────────────────
      case $W['=']:   $b = $this->pop(); $this->flag($this->pop() === $b); return $i;
      case $W['<>']:  $b = $this->pop(); $this->flag($this->pop() !== $b); return $i;
      case $W['<']:   $b = $this->pop(); $this->flag($this->pop() <  $b); return $i;
      case $W['>']:   $b = $this->pop(); $this->flag($this->pop() >  $b); return $i;
      case $W['U<']:  $b = $this->pop(); $this->flag(self::ult($this->pop(), $b)); return $i;
      case $W['U>']:  $b = $this->pop(); $this->flag(self::ult($b, $this->pop())); return $i;
      case $W['0=']:  $this->flag($this->pop() === 0); return $i;
      case $W['0<>']: $this->flag($this->pop() !== 0); return $i;
      case $W['0<']:  $this->flag($this->pop() <  0); return $i;
      case $W['0>']:  $this->flag($this->pop() >  0); return $i;
      case $W['WITHIN']: $hi = $this->pop(); $lo = $this->pop(); $t = $this->pop();
                         // Forth's WITHIN is circular: ( test lo hi -- flag ), lo inclusive, hi exclusive
                         $this->flag(self::ult(self::sub($t, $lo), self::sub($hi, $lo))); return $i;

      // ── constants ─────────────────────────────────────────────────────────────────────────────────
      case $W['TRUE']:  $this->push(-1); return $i;
      case $W['FALSE']: $this->push(0);  return $i;
      case $W['BL']:    $this->push(32); return $i;

      // ── memory ────────────────────────────────────────────────────────────────────────────────────
      case $W['@']:  $this->push($this->fetch($this->pop())); return $i;
      case $W['!']:  $a = $this->pop(); $this->store($a, $this->pop()); return $i;
      case $W['C@']: $this->push(ord($this->read($this->pop(), 1))); return $i;
      case $W['C!']: $a = $this->pop(); $v = $this->pop();
                     $this->write($a, chr($v & 0xff)); return $i;
      case $W['+!']: $a = $this->pop(); $this->store($a, self::add($this->fetch($a), $this->pop())); return $i;
      case $W['2@']: $a = $this->pop();
                     $this->push($this->fetch($this->at($a, 8))); $this->push($this->fetch($a)); return $i;
      case $W['2!']: $a = $this->pop(); $lo = $this->pop(); $hi = $this->pop();
                     $this->store($a, $lo); $this->store($this->at($a, 8), $hi); return $i;
      case $W['MOVE']: $u = $this->pop(); $to = $this->pop(); $from = $this->pop();
                       $this->write($to, $this->read($from, $u)); return $i;
      // ⚠ The range is checked BEFORE the bytes are built: built first, a script asking for gigabytes ended the process.
      case $W['FILL']: $ch = $this->pop(); $u = $this->pop(); $a = $this->pop();
                       if ($u > 0) { $this->bounds($a, $u); $this->write($a, str_repeat(chr($ch & 0xff), $u)); } return $i;
      case $W['ERASE']: $u = $this->pop(); $a = $this->pop();
                        if ($u > 0) { $this->bounds($a, $u); $this->write($a, str_repeat("\x00", $u)); } return $i;
      case $W['CELLS']: $this->push($this->pop() << 3); return $i;   // × 8, keeping the low 64 bits
      case $W['CELL+']: $this->push(self::add($this->pop(), 8)); return $i;
      case $W['CHARS']: return $i;                                  // a char is one address unit
      case $W['CHAR+']: $this->push(self::add($this->pop(), 1)); return $i;
      // (a + 7) truncated to a multiple of 8, so a negative a rounds toward zero. Past PHP_INT_MAX - 7 the sum is
      // 2^63 to 2^63 + 6, whose multiple of 8 is 2^63, which wraps to the most negative cell.
      case $W['ALIGNED']: $a = $this->pop();
                          $this->push($a > PHP_INT_MAX - 7 ? PHP_INT_MIN : intdiv($a + 7, 8) * 8); return $i;

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
      case $W['EXECUTE']: { $xt = $this->pop();
                    $this->call($code, $xt, $covenant); return $i; }

      // ── branch primitives (jetmora) ───────────────────────────────────────────────────────────────
      case $W['BRANCH']:  { $off = self::i16($code, $i); return $this->jump($code, $i + 2, $off); }
      case $W['0BRANCH']: { $off = self::i16($code, $i); $i += 2;
                    return $this->pop() === 0 ? $this->jump($code, $i, $off) : $i; }
      case $W['(DO)']:  { $ix = $this->pop(); $lim = $this->pop();
                    $this->rs[] = $lim; $this->rs[] = $ix; return $i; }
      case $W['(?DO)']: { $off = self::i16($code, $i); $i += 2;
                    $ix = $this->pop(); $lim = $this->pop();
                    if ($ix === $lim) return $this->jump($code, $i, $off);
                    $this->rs[] = $lim; $this->rs[] = $ix; return $i; }
      case $W['(LOOP)']: case $W['(+LOOP)']: {
                    $off = self::i16($code, $i); $i += 2;
                    if (count($this->rs) < 2) throw new JfScriptError('LOOP outside a loop');
                    $step = $op === $W['(+LOOP)'] ? $this->pop() : 1;
                    $ix   = array_pop($this->rs); $lim = $this->rs[count($this->rs) - 1];
                    $nx   = self::add($ix, $step);
                    // ★ Forth's rule: terminate when the index CROSSES the limit, which is a different
                    //   test from equality and is why a +LOOP with a negative step terminates at all.
                    $done = $step >= 0
                          ? ($ix < $lim && $nx >= $lim) || $ix >= $lim
                          : ($ix > $lim && $nx <= $lim) || $ix <= $lim;
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
                    $this->frameCells += $n;
                    return $i; }
      case $W['(LOCAL@)']: { $k = self::u8($code, $i); $i++;
                    $f = $this->frame(); if (!array_key_exists($k, $f)) throw new JfScriptError("local $k unset");
                    $this->ds[] = $f[$k]; return $i; }
      case $W['(LOCAL!)']: { $k = self::u8($code, $i); $i++;
                    $v = $this->pop(); $f = $this->frame();    // ⚠ refused with no frame, as (LOCAL@) is
                    if (!array_key_exists($k, $f)) $this->frameCells++;
                    $this->frames[count($this->frames) - 1][$k] = $v; return $i; }
      case $W['(UNFRAME)']: if (!$this->frames) throw new JfScriptError('(UNFRAME) with no frame');
                    $this->frameCells -= count(array_pop($this->frames)); return $i;

      // ── byte strings ──────────────────────────────────────────────────────────────────────────────
      case $W['SIZE']:  $this->need(2); $this->ds[] = $this->ds[count($this->ds) - 1]; return $i;
      case $W['SPLIT']: { $n = $this->pop(); $u = $this->pop(); $a = $this->pop();
                    if ($n < 0 || $n > $u) throw new JfScriptError('SPLIT out of range');
                    // ★ No copy: a split of (addr,len) is two spans of the SAME bytes.
                    $this->push($a); $this->push($n); $this->push(self::add($a, $n)); $this->push($u - $n); return $i; }
      case $W['CAT']:   { $d = $this->pop(); $s2 = $this->popSpan(); $s1 = $this->popSpan();
                    $this->write($d, $s1 . $s2);
                    $this->push($d); $this->push(strlen($s1) + strlen($s2)); return $i; }
      case $W['SUBSTR']:{ $d = $this->pop(); $cnt = $this->pop(); $beg = $this->pop();
                    $s = $this->popSpan();
                    if ($beg < 0 || $cnt < 0 || $beg + $cnt > strlen($s))
                      throw new JfScriptError('SUBSTR out of range');
                    $this->write($d, substr($s, $beg, $cnt));
                    $this->push($d); $this->push($cnt); return $i; }
      case $W['LEFT']:  { $d = $this->pop(); $n = $this->pop(); $s = $this->popSpan();
                    if ($n < 0 || $n > strlen($s)) throw new JfScriptError('LEFT out of range');
                    $this->write($d, substr($s, 0, $n)); $this->push($d); $this->push($n); return $i; }
      case $W['RIGHT']: { $d = $this->pop(); $n = $this->pop(); $s = $this->popSpan();
                    if ($n < 0 || $n > strlen($s)) throw new JfScriptError('RIGHT out of range');
                    $this->write($d, substr($s, strlen($s) - $n)); $this->push($d); $this->push($n); return $i; }
      case $W['NUM2BIN']: { $d = $this->pop(); $sz = $this->pop(); $v = $this->pop();
                    if ($sz < 0 || $sz > 0x10000) throw new JfScriptError('NUM2BIN size out of range');
                    // the cell, unsigned, little-endian, in as few bytes as it needs: none for 0
                    $le = rtrim(pack('P', $v), "\x00");
                    if (strlen($le) > $sz) throw new JfScriptError('NUM2BIN does not fit');
                    $this->write($d, $le . str_repeat("\x00", $sz - strlen($le)));
                    $this->push($d); $this->push($sz); return $i; }
      // ★★★ ( a1 u1 a2 u2 -- flag ) — THE COVENANT'S CENTRAL OPERATION.
      //   Comparing a computed hash against one from the preimage is what every covenant does, and
      //   nothing else could do it: `=` compares cells, and BIN2NUM on 32 bytes truncates to 64 bits.
      // ⚠ CONSTANT TIME over the compared bytes: hash_equals, never `===`. A byte-at-a-time compare
      //   leaks WHERE two hashes first differ, which is enough to forge one a byte at a time.
      case $W['BYTES=']: { $b = $this->popSpan(); $a = $this->popSpan();
                    $this->flag(strlen($a) === strlen($b) && hash_equals($a, $b)); return $i; }

      // a cell keeps the low 64 bits, which are the first 8 bytes
      case $W['BIN2NUM']: { $s = $this->popSpan();
                    $this->push(unpack('P', str_pad(substr($s, 0, 8), 8, "\x00"))[1]); return $i; }

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
        $this->sigOp(1);
        $msg = $this->popSpan(); $pub = $this->popSpan(); $sig = $this->popSpan();
        $ok  = self::ecdsaVerify($sig, $pub, $msg);
        if ($op === $W['CHECKSIGVERIFY']) {
          if (!$ok) throw new JfScriptError('CHECKSIGVERIFY failed');
        } else $this->flag($ok);
        return $i; }

      // `( a-sig u-sig a-pub u-pub a-msg u-msg -- flag )` — Ed25519 over the message as given; the
      // scheme hashes internally, so no digest word precedes it. A wrong key or signature length is a
      // failed check, never an error. Appended 15 Sept at 0xDD/0xDE; CHECKSIG above stays secp256k1.
      case $W['ED25519-CHECKSIG']: case $W['ED25519-CHECKSIGVERIFY']: {
        $this->sigOp(1);
        $msg = $this->popSpan(); $pub = $this->popSpan(); $sig = $this->popSpan();
        $ok  = self::ed25519Verify($sig, $pub, $msg);
        if ($op === $W['ED25519-CHECKSIGVERIFY']) {
          if (!$ok) throw new JfScriptError('ED25519-CHECKSIGVERIFY failed');
        } else $this->flag($ok);
        return $i; }

      // `( a-msg u-msg a-pub u-pub ... n a-sig u-sig ... m -- flag )` — m sigs, n keys, sigs in key order.
      // ⛔ NO dummy element. BTC's off-by-one is a bug `BT` carries for fidelity; `JF` is not trying to
      //    be Bitcoin, and reproducing a known bug in a new set would be an amputation in reverse.
      case $W['CHECKMULTISIG']: case $W['CHECKMULTISIGVERIFY']: {
        $m = $this->pop();
        if ($m < 0 || $m > 32) throw new JfScriptError('CHECKMULTISIG: bad signature count');
        $sigs = [];
        for ($k = 0; $k < $m; $k++) array_unshift($sigs, $this->popSpan());
        $n = $this->pop();
        if ($n < 0 || $n > 32 || $m > $n) throw new JfScriptError('CHECKMULTISIG: bad key count');
        $this->sigOp($n);
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
      case $W['PREIMAGE']: { $this->covenantOnly('PREIMAGE', $covenant); $d = $this->pop();
        if ($this->preimage === null) throw new JfScriptError('PREIMAGE: no transaction context');
        $this->write($d, $this->preimage);
        $this->push($d); $this->push(strlen($this->preimage)); return $i; }
      // The preimage's fields, each cut where FIELDS says, in PREIMAGE's order of checks: a number is pushed as a
      // number, and bytes are written to a destination the caller gives, as PREIMAGE writes the whole.
      //   PREVOUTS-HASH SEQUENCES-HASH OUTPOINT SCRIPTCODE OUTPUTS-HASH  ( dest -- dest u )
      case $W['PREVOUTS-HASH']: case $W['SEQUENCES-HASH']: case $W['OUTPOINT']:
      case $W['SCRIPTCODE']: case $W['OUTPUTS-HASH']: {
        $word = jf_op_name($op); $this->covenantOnly($word, $covenant); $d = $this->pop();
        if ($this->preimage === null) throw new JfScriptError("$word: no transaction context");
        $f = $this->field($word);
        $this->write($d, $f);
        $this->push($d); $this->push(strlen($f)); return $i; }
      //   TXVALUE             ( -- n )  8 bytes as a cell, converted as BIN2NUM converts them
      //   NSEQUENCE LOCKTIME  ( -- n )  4 bytes, unsigned
      case $W['TXVALUE']: case $W['NSEQUENCE']: case $W['LOCKTIME']: {
        $word = jf_op_name($op); $this->covenantOnly($word, $covenant);
        if ($this->preimage === null) throw new JfScriptError("$word: no transaction context");
        $f = $this->field($word);
        $this->push(strlen($f) === 8 ? unpack('P', $f)[1] : unpack('V', $f)[1]); return $i; }
      // the lock's declaration (codeStart): a lock's first instruction, reached here only by a branch back to it
      case $W['VER']:
        if (!$covenant || $i !== 1) throw new JfScriptError(self::VER_ELSEWHERE);
        return self::pastDeclaration($code, $i);

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
        if ($this->pop() !== 0) throw JfScriptError::aborted($msg);
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
        'EMIT'   => chr($this->pop() & 0xff),
        'CR'     => "\n",
        'SPACE'  => ' ',
        'SPACES' => $this->spaces($this->chan[$t]),
        'TYPE'   => $this->popSpan(),
        'EMIT?'  => '',
      };
      if ($word === 'EMIT?') {                       // ( -- flag ) is there room for one more?
        $this->flag(strlen($this->chan[$t]['out']) < min($this->chan[$t]['max'], $this->chan[$t]['room']));
        return;
      }
      if (strlen($this->chan[$t]['out']) + strlen($b) > $this->chan[$t]['max'])
        throw new JfScriptError(sprintf('output exceeds the declared out_max of %d',
                                        $this->chan[$t]['max']));
      if (strlen($this->chan[$t]['out']) + strlen($b) > $this->chan[$t]['room'])
        throw new JfScriptError('push space exhausted');
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
      $this->push(ord($in[$this->chan[$t]['pos']++]));
      return;
    }
    // ACCEPT ( c-addr +n1 -- +n2 ) — a LINE, as the standard says: up to n1 bytes, stopping at \n,
    // ⚠ and the newline is CONSUMED but NOT stored, which is the part that is easy to get wrong.
    $n1 = $this->pop(); $addr = $this->pop();
    if ($n1 < 0) throw new JfScriptError('ACCEPT: negative length');
    $pos = $this->chan[$t]['pos'];
    $take = min($n1, strlen($in) - $pos);
    $nl = $take > 0 ? strpos($in, "\n", $pos) : false;
    if ($nl !== false && $nl < $pos + $take) { $got = substr($in, $pos, $nl - $pos); $this->chan[$t]['pos'] = $nl + 1; }
    else { $got = (string)substr($in, $pos, $take); $this->chan[$t]['pos'] = $pos + $take; }
    if ($got !== '') $this->write($addr, $got);
    $this->push(strlen($got));
  }

  /** SPACES' bytes, refused BEFORE they are built when they would not fit the declared channel. */
  private function spaces(array $c): string
  {
    $n = max(0, $this->pop());
    if (strlen($c['out']) + $n > $c['max'])
      throw new JfScriptError(sprintf('output exceeds the declared out_max of %d', $c['max']));
    if (strlen($c['out']) + $n > $c['room']) throw new JfScriptError('push space exhausted');
    return str_repeat(' ', $n);
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

  /**
   * Where each field word cuts the preimage, [from, to), in BIP143's layout (preimage.php); a negative offset counts
   * from the end. Everything after the scriptCode field is 52 bytes, so the fields there are counted from the end,
   * whatever the script's length. SCRIPTCODE is that field as the preimage carries it, its length prefix first.
   */
  private const FIELDS = ['PREVOUTS-HASH' => [4, 36], 'SEQUENCES-HASH' => [36, 68], 'OUTPOINT' => [68, 104],
                          'SCRIPTCODE' => [104, -52], 'TXVALUE' => [-52, -44], 'NSEQUENCE' => [-44, -40],
                          'OUTPUTS-HASH' => [-40, -8], 'LOCKTIME' => [-8, -4]];

  /** A field's bytes, refused when the preimage is too short to hold them. */
  private function field(string $word): string
  {
    $n = strlen($this->preimage);
    [$from, $to] = self::FIELDS[$word];
    if ($from < 0) $from += $n;
    if ($to < 0) $to += $n;
    if ($from < 0 || $to > $n || $from > $to) throw new JfScriptError("$word: the preimage is too short");
    return substr($this->preimage, $from, $to - $from);
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
    $d = $this->pop(); $s = $this->popSpan();
    $this->write($d, $h($s));
    return $i;
  }

  /**
   * ⛔⛔ THE TIER BOUNDARY, AND IT IS ENFORCED RATHER THAN DECLARED. A declared arity is not a sandbox, so a
   * call gives the function only what it declares, and stdForth has no word that reaches back:
   *   stacks  a fresh data stack holding exactly its n_in cells, a fresh return stack, fresh locals. The n_out
   *           cells must be all it leaves; they are appended to the caller's stack.
   *   pushes  an empty push space of its own, from PUSH_BASE × (d + 1) at INVOKE depth d (the INVOKEs active: the
   *           lock is 0). No pushed key reaches it by address: a caller hands it bytes only through its input span.
   *   memory  fresh program memory, zeroed (made when first touched), at its push space + MEM_OFFSET; HERE gives
   *           its start. An address it returns, push or memory, is out of range in its caller.
   *   input   the declared input span (in_max), held in its channel for KEY and ACCEPT.
   *   output  the declared channel (out_max), checked as each byte is written against out_max and against the
   *           room left in the caller's push space, where it lands on return as ( c-addr u ).
   * The tick's counts run through the call: instructions (with the byte charge), the 100 signature checks, and
   * the 1,000 items, the caller's stacks and locals still counting while the function runs. A function takes
   * CELLS and its declared input channel, never addresses.
   */
  private function invoke(int $ix): void
  {
    if (!isset($this->defs[$ix])) throw new JfScriptError("INVOKE $ix: no such definition");
    $d = $this->defs[$ix];
    $inMax = $d['in_max'] ?? 0; $outMax = $d['out_max'] ?? 0;
    // ⚠ The input span sits ABOVE the cell arguments — pushed last, so popped first.
    $this->need($d['n_in'] + ($inMax > 0 ? 2 : 0));
    if (++$this->depth > $this->maxDepth) { $this->depth--; throw new JfScriptError('call depth exceeded'); }

    $savedRs = $this->rs; $savedFr = $this->frames;           // the function gets fresh ones: no copy needed
    $savedFc = $this->frameCells; $savedHeld = $this->held; $savedBase = $this->pbase; $savedMbase = $this->mbase;
    $chanDepth = count($this->chan);
    $taken = [];                                             // the caller's cells this call took, bottom first
    try {
      $inBytes = '';
      if ($inMax > 0) {
        $u = $this->pop(); $a = $this->pop(); $taken = [$a, $u];
        $inBytes = $this->read($a, $u);
        if (strlen($inBytes) > $inMax)
          throw new JfScriptError(sprintf('INVOKE %d: input is %d bytes, declared in_max %d',
                                          $ix, strlen($inBytes), $inMax));
      }
      $args = [];
      for ($k = 0; $k < $d['n_in']; $k++) $args[] = array_pop($this->ds);
      $args = array_reverse($args);
      $taken = array_merge($args, $taken);
      $callerDs = $this->ds;
      $this->held += count($callerDs) + count($savedRs) + $savedFc;   // still held while the function runs
      $this->ds = $args; $this->rs = []; $this->frames = []; $this->frameCells = 0;
      $savedMem = $this->mem; $savedP = $this->pmem;
      $this->mem = '';                                       // ⛔ fresh, zeroed when touched: no residue from the caller
      $this->pmem = '';                                      // ⛔ nor the caller's pushes: no key reaches a function
      // 'room': the caller's push space left, where the output is pushed on return
      $this->chan[] = ['in' => $inBytes, 'pos' => 0, 'inmax' => $inMax,
                       'out' => '', 'max' => $outMax, 'room' => $this->pushSize - strlen($savedP)];
      $this->pbase = self::PUSH_BASE * (count($this->chan) + 1);
      $this->mbase = $this->pbase + self::MEM_OFFSET;

      $this->exec($d['body'], 0, /* covenant */ false);
      if (count($this->ds) !== $d['n_out'])
        throw new JfScriptError(sprintf('INVOKE %d: declared %d out, produced %d',
                                        $ix, $d['n_out'], count($this->ds)));
      if ($this->frames) throw new JfScriptError("INVOKE $ix: unbalanced locals frame");
      $results = $this->ds;
      $emitted = array_pop($this->chan)['out'];
      $this->mem = $savedMem; $this->pmem = $savedP; $this->pbase = $savedBase; $this->mbase = $savedMbase;
      $this->frameCells = $savedFc; $this->held = $savedHeld;
    } catch (Throwable $e) {
      // ⚠ A failed call leaves NOTHING behind — not a partial stack, not a half-written channel,
      //   and not a scribbled-on arena.
      array_splice($this->chan, $chanDepth);
      if (isset($savedMem)) { $this->mem = $savedMem; $this->pmem = $savedP; }
      if (isset($callerDs)) $this->ds = $callerDs;
      foreach ($taken as $c) $this->ds[] = $c;
      $this->rs = $savedRs; $this->frames = $savedFr;
      $this->frameCells = $savedFc; $this->held = $savedHeld; $this->pbase = $savedBase; $this->mbase = $savedMbase;
      throw $e;
    } finally { $this->depth--; }

    $this->ds = $callerDs; unset($callerDs);                 // one reference, so the results append in place
    foreach ($results as $r) $this->ds[] = $r;
    $this->rs = $savedRs; $this->frames = $savedFr;
    // ⇒ THE CHANNEL COMES BACK AS ( c-addr u ), ABOVE the declared outputs. Declared, therefore
    //   counted — which is the whole reason it is allowed at all.
    if ($outMax > 0) $this->pushSpan($emitted);
  }

  // ── division ───────────────────────────────────────────────────────────────────────────────────────
  // ⚠⚠ SYMMETRIC (truncate toward zero): -7/2 = -3, and the remainder takes the sign of the DIVIDEND.
  // ★ Forth 2012 §3.2.2.1 PERMITS either floored or symmetric as a documented choice — this is not a
  //   deviation from the standard, it is one of the two answers the standard hands you.
  // PHP's intdiv and % both truncate, which is this rule. ⚠ intdiv refuses PHP_INT_MIN ÷ -1, whose answer,
  // 2^63, wraps to PHP_INT_MIN; % gives 0 for it, which is right.
  private static function divT(int $a, int $b): int {
    if ($b === 0) throw new JfScriptError('division by zero');
    return $b === -1 ? self::neg($a) : intdiv($a, $b);
  }
  private static function modT(int $a, int $b): int {
    if ($b === 0) throw new JfScriptError('division by zero');
    return $a % $b;
  }
  /**
   * a × b ÷ c with the product kept at double width, the same rule, as [remainder, quotient]: the remainder
   * takes the product's sign, and the quotient keeps its low 64 bits, as a cell does. A product that fits a
   * cell divides natively; a wider one divides as magnitudes, with the signs put back after.
   */
  private static function mulDivT(int $a, int $b, int $c): array {
    if ($c === 0) throw new JfScriptError('division by zero');
    $p = $a * $b;
    if (is_int($p)) return [self::modT($p, $c), self::divT($p, $c)];
    [$hi, $lo] = self::smul($a, $b);
    $neg = $hi < 0;
    if ($neg) { $hi = $lo === 0 ? self::neg($hi) : ~$hi; $lo = self::neg($lo); }   // |p|, as 128 bits
    [, $q, $r] = self::udiv128($hi, $lo, $c < 0 ? self::neg($c) : $c);           // |c|: 2^63 when c is PHP_INT_MIN
    return [$neg ? -$r : $r, $neg !== ($c < 0) ? self::neg($q) : $q];
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
    if (strlen($digest32) !== 32 || !self::isStrictDer($sig)) return false;
    return Secp256k1::verifyDigest($sig, $pub, $digest32);
  }

  /**
   * BIP66's strict DER, without a sighash byte (JF signs an explicit digest): one encoding per signature,
   * so a holder cannot re-encode one into another that also verifies.
   *   30 L 02 lenR R 02 lenS S   with L = total − 2, no negative and no padded integer
   */
  public static function isStrictDer(string $s): bool
  {
    $n = strlen($s);
    if ($n < 8 || $n > 72) return false;
    $b = array_values(unpack('C*', $s));
    if ($b[0] !== 0x30 || $b[1] !== $n - 2 || $b[2] !== 0x02) return false;
    $lr = $b[3];
    if ($lr === 0 || 5 + $lr >= $n || $b[4 + $lr] !== 0x02) return false;
    $ls = $b[5 + $lr];
    if ($ls === 0 || $lr + $ls + 6 !== $n) return false;
    if (($b[4] & 0x80) || ($lr > 1 && $b[4] === 0 && !($b[5] & 0x80))) return false;
    if (($b[6 + $lr] & 0x80) || ($ls > 1 && $b[6 + $lr] === 0 && !($b[7 + $lr] & 0x80))) return false;
    return true;
  }

  /** Ed25519 (RFC 8032) by ed25519.php, with libsodium 1.0.22's rules, and never by ext/sodium where it is loaded:
   *  libsodium's rules differ between versions, and a verdict must not depend on the version a host has. */
  public static function ed25519Verify(string $sig, string $pub, string $msg): bool
  {
    return Ed25519::verify($sig, $msg, $pub);
  }
}

/**
 * H(result) = sha256( for each cell: 8 bytes little-endian ) — the §2b comparison hash for `JF`.
 * ⚠ Canonical by construction: cells are fixed width, so there is no length prefix to disagree about.
 */
function jf_stack_hash(array $cells): string
{
  $b = '';
  foreach ($cells as $c) $b .= pack('P', $c);
  return hash('sha256', $b);
}
