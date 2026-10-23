// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE `JF` SET: the interpreter, in JavaScript ─────────────────────────────────────────────────────
// A PORT of server/interpreter-jf.php, line for line: the same structure, the same order of pops, the same
// error messages. It exists so a reader in a page EXECUTES a covenant's lock rather than re-deriving what
// the lock says by hand (his call, 3 Oct). verify-jf.mjs grades it with the PHP interpreter's own cases,
// and runs the two side by side on generated programs; a difference is a bug in one of them.
//
// jetmora Forth. TWO TIERS, and the tier boundary is a PRIVILEGE boundary (design notes §10.5e–§10.5j):
//   jetForth   one byte   — CONTROLS the covenant. Owns carried state. Decides valid / invalid.
//   stdForth   two bytes  — standard Forth, unmodified. A PURE FUNCTION: values in, values out.
//
// ⚠⚠⚠ CELLS ARE BigInt, never Number: a Number above 2^53 silently loses precision. A cell WRAPS at 64 bits.
// ⚠ CRYPTO IS SUPPLIED, not built in, so one interpreter serves a page (WebCrypto) and a test (Node):
//   { sha256, sha1, ripemd160 }  (bytes) -> bytes, synchronous
//   ed25519Verify(sig, pub, msg) -> boolean or a Promise of one
//   ecdsaVerify(sig, pub, digest32) -> boolean or a Promise of one
//   A word whose crypto was not supplied throws JfHostError: the host cannot answer, which is not a refusal.
// Bytes are Uint8Array throughout.

import { JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_WORD, JF_ESC0, JF_PLANE, JF_RESERVED0,
         JF_BANK_WORD, JF_CORE_KIND, JF_PROMOTED, jf_op_name, jf_bank_name } from './ops-jf.mjs'

export class JfScriptError extends Error {
  /** The diagnostic a refusal carries out (bytes the script chose), or null for a machine fault. */
  diagnostic = null
  static aborted(msg) {
    const e = new JfScriptError(msg.length === 0 ? 'ABORT' : `ABORT: ${new TextDecoder().decode(msg)}`)
    e.diagnostic = msg
    return e
  }
}
/**
 * THE HOST CANNOT JUDGE: a capability it was not given (a hash, secp256k1, Ed25519). It is not a refusal,
 * and verifyTick passes it on rather than turn it into one: a tick is never refused here and accepted there
 * because one host is missing a library.
 */
export class JfHostError extends Error {}
/** ⚠ Distinct on purpose: an unimplemented wordset is refused BY NAME. */
export class JfBankUnsupported extends JfScriptError {
  constructor(wordset, word = null) {
    super(word === null ? `stdForth wordset not implemented: ${wordset}`
                        : `stdForth wordset not implemented: ${wordset} (word ${word})`)
    this.wordset = wordset; this.word = word
  }
}

const M64 = 1n << 64n, H64 = 1n << 63n
const INT_MAX = H64 - 1n, INT_MIN = -H64                     // PHP_INT_MAX / PHP_INT_MIN on a 64-bit host
const hex2 = n => n.toString(16).padStart(2, '0')
const UTF8 = new TextEncoder()
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o }
const bytesOf = s => Uint8Array.from(s, c => c.charCodeAt(0))
/** Wrap into a signed 64-bit cell. ⚠ Two's complement WRAPPING, which is what a fixed cell means. */
const cell = v => { const u = ((v % M64) + M64) % M64; return u >= H64 ? u - M64 : u }
/** Unsigned view of a cell, for U< U> and shifts. */
const uns = v => v < 0n ? v + M64 : v
/** floor division, as gmp_div_q(..., GMP_ROUND_MINUSINF) */
const floorDiv = (a, b) => { const q = a / b; return (a % b !== 0n && ((a < 0n) !== (b < 0n))) ? q - 1n : q }
const leToBig = b => { let v = 0n; for (let k = b.length - 1; k >= 0; k--) v = (v << 8n) | BigInt(b[k]); return v }
/** big-endian magnitude bytes, empty for zero (gmp_export of 0 is '') */
const beBytes = v => { const o = []; while (v > 0n) { o.unshift(Number(v & 0xffn)); v >>= 8n } return Uint8Array.from(o) }
/** two's-complement view of a possibly-negative double-width product */
const u2 = p => p < 0n ? p + (1n << 128n) : p

// ★ `TYPE` `CR` `SPACE` `SPACES` are EMIT loops in every Forth, and `KEY` is what `ACCEPT` reads with.
const CHANNEL_WORDS = { EMIT: 'o', CR: 'o', SPACE: 'o', SPACES: 'o', TYPE: 'o', KEY: 'i', ACCEPT: 'i', 'EMIT?': 'o' }
const OP = new Map()
for (const [k, v] of Object.entries(JF_WORD)) OP.set(v, k)
for (const [k, v] of Object.entries(JF_LIT)) OP.set(v, k)
const DEFS_MARK = JF_RESERVED0                               // the reserved slot the compiler emits for the header
const BANK_SEL = new Map(Object.entries(JF_BANK_WORD).map(([set, words]) => {
  const m = new Map(); for (const [w, v] of Object.entries(words)) if (!m.has(v)) m.set(v, w)
  return [set, m]
}))
/** Where the push space starts. Program memory is below it, so the two can never overlap. A function at INVOKE
 *  depth d (the INVOKEs active: the lock is 0) has its own from PUSH_BASE × (d + 1), so a push address it returns
 *  is out of range in its caller. */
export const PUSH_BASE = 16777216
/** The lock's program memory is at 0. A function's is at its push space + MEM_OFFSET, so a memory address it
 *  returns is out of range in its caller too (his call, 23 Oct). A function finds its memory with HERE. */
export const MEM_OFFSET = 8388608

export class InterpreterJF {
  /** These limits are for run(), the interpreter as a tool. A tick is judged by verifyTick(), with TICK_LIMITS. */
  constructor({ maxOps = 200000, memSize = 65536, maxDepth = 64, maxItems = 1000, pushSize = 65536, maxSigOps = 100, crypto = {} } = {}) {
    Object.assign(this, { maxOps, memSize, maxDepth, maxItems, pushSize, maxSigOps, crypto })
    this.preimage = null
    this.ds = []; this.rs = []; this.defs = []; this.frames = []; this.chan = []
    this.mem = null; this.opCount = 0; this.depth = 0; this.sigOps = 0
    // every pushed byte, in order: read-only, and never at a program-memory address. Grown as needed.
    this.pmem = new Uint8Array(0); this.plen = 0; this.pbase = PUSH_BASE; this.mbase = 0
    // cells in the locals frames, and cells an active INVOKE has set aside: both count as items held
    this.frameCells = 0; this.held = 0
  }
  setPreimage(p) { this.preimage = p }

  // ── stacks ─────────────────────────────────────────────────────────────────────────────────────────
  need(n) { if (BigInt(this.ds.length) < BigInt(n)) throw new JfScriptError(`stack underflow: need ${n}, have ${this.ds.length}`) }
  pop() { if (!this.ds.length) throw new JfScriptError('stack underflow'); return this.ds.pop() }
  push(v) { this.ds.push(cell(v)) }
  pushI(v) { this.ds.push(cell(BigInt(v))) }
  /** ⚠ A BigInt in the host int range, as PHP's popInt (a cell always is). Converted to Number only where used as one. */
  popInt() { const v = this.pop(); if (v > INT_MAX || v < INT_MIN) throw new JfScriptError('cell out of host int range'); return v }
  flag(b) { this.pushI(b ? -1 : 0) }                         // Forth TRUE is all bits set

  // ── memory ─────────────────────────────────────────────────────────────────────────────────────────
  /** The offset of addr in program memory, which lies at mbase. */
  bounds(addr, len) {
    const mb = BigInt(this.mbase)
    if (addr < mb || len < 0n || addr - mb > BigInt(this.memSize) - len)
      throw new JfScriptError(`memory out of range: addr=${addr} len=${len} size=${this.memSize}`)
    // made, zeroed, when first touched: a function that never touches memory costs nothing for it
    if (this.mem === null) this.mem = new Uint8Array(this.memSize)
    return Number(addr - mb)
  }
  fetch(addr) { return cell(leToBig(this.view(addr, 8n))) }
  store(addr, v) {
    const a = this.bounds(addr, 8n)
    let u = uns(cell(v))
    for (let k = 0; k < 8; k++) { this.mem[a + k] = Number(u & 0xffn); u >>= 8n }
  }
  read(addr, len) { return this.view(addr, len) }
  /** Bytes from program memory, or from wholly inside the push space. Writes never reach the push space.
   *  `copy` false gives a view into that memory, for a caller that reads it before the memory can change. */
  view(addr, len, copy = true) {
    const p = BigInt(this.plen), pb = BigInt(this.pbase)
    const [m, a] = addr >= pb && len >= 0n && len <= p && addr - pb <= p - len ? [this.pmem, Number(addr - pb)]
                 : [null, this.bounds(addr, len)]
    const mem = m ?? this.mem
    this.charge(Number(len))
    return copy ? mem.slice(a, a + Number(len)) : mem.subarray(a, a + Number(len))
  }
  /** Each span read, written or pushed costs one more instruction for every whole 64 bytes in it (his call, 23 Oct).
   *  A function's channel bytes are charged when INVOKE reads its input span and when its output is pushed on return. */
  charge(n) {
    this.opCount += Math.floor(n / 64)
    if (this.opCount > this.maxOps) throw new JfScriptError('op budget exhausted')
  }
  write(addr, b) { const o = this.bounds(addr, BigInt(b.length)); this.charge(b.length); this.mem.set(b, o) }
  /** `( c-addr u -- )` popped as a pair, u on top. */
  popSpan() { const u = this.popInt(); const a = this.popInt(); return this.read(a, u) }

  // ── operands ───────────────────────────────────────────────────────────────────────────────────────
  static i16(s, i) { if (i + 2 > s.length) throw new JfScriptError('truncated operand'); const v = s[i] | (s[i + 1] << 8); return v >= 0x8000 ? v - 0x10000 : v }
  static u16(s, i) { if (i + 2 > s.length) throw new JfScriptError('truncated operand'); return s[i] | (s[i + 1] << 8) }
  static u8(s, i) { if (i + 1 > s.length) throw new JfScriptError('truncated operand'); return s[i] }

  // ── the DEFS header ────────────────────────────────────────────────────────────────────────────────
  /** `[ DEFS <count:u8> { <n_in:u8> <n_out:u8> <in_max:varint> <out_max:varint> <len:varint> <body> } x count ]? <covenant code>`. Returns the new position. */
  parseDefs(script, i) {
    this.defs = []
    if (i >= script.length || script[i] !== DEFS_MARK) return i
    i++
    const count = InterpreterJF.u8(script, i); i++
    for (let k = 0; k < count; k++) {
      const nin = InterpreterJF.u8(script, i); i++
      const nout = InterpreterJF.u8(script, i); i++
      let r = this.varint(script, i); const inm = r[0]; i = r[1]
      r = this.varint(script, i); const outm = r[0]; i = r[1]
      r = this.varint(script, i); const len = r[0]; i = r[1]
      if (i + len > script.length) throw new JfScriptError(`DEFS ${k} body past end of script`)
      this.defs.push({ n_in: nin, n_out: nout, in_max: inm, out_max: outm, body: script.slice(i, i + len) })
      i += len
    }
    return i
  }
  /** [value, new position] */
  varint(s, i) {
    const b = InterpreterJF.u8(s, i); i++
    if (b < 0xfd) return [b, i]
    if (b === 0xfd) return [InterpreterJF.u16(s, i), i + 2]
    if (b === 0xfe) {
      if (i + 4 > s.length) throw new JfScriptError('truncated varint')
      return [(s[i] | (s[i + 1] << 8) | (s[i + 2] << 16) | (s[i + 3] << 24)) >>> 0, i + 4]
    }
    throw new JfScriptError('8-byte varint is not a script length')
  }

  // ── run ────────────────────────────────────────────────────────────────────────────────────────────
  /** @returns {Promise<bigint[]>} the final data stack, bottom first. Throws JfScriptError. */
  async run(script) {
    this.ds = []; this.rs = []; this.frames = []; this.chan = []
    this.opCount = 0; this.depth = 0; this.frameCells = 0; this.held = 0; this.sigOps = 0
    this.mem = null
    this.pmem = new Uint8Array(0); this.plen = 0; this.pbase = PUSH_BASE; this.mbase = 0
    const i = this.parseDefs(script, 0)
    await this.exec(script, i, /* covenant tier */ true)
    if (this.frames.length) throw new JfScriptError('unbalanced locals frame')
    return this.ds
  }

  /** Execute from i to the end of code. `covenant` is true in the jetForth tier, where a bank escape is ILLEGAL. */
  async exec(code, i, covenant) {
    const len = code.length
    while (i < len) {
      // checked after every instruction, as BSV checks stack + altstack after every opcode
      if (this.ds.length + this.rs.length + this.frameCells + this.held > this.maxItems) this.tooMany()
      if (++this.opCount > this.maxOps) throw new JfScriptError('op budget exhausted')
      const op = code[i]; i++
      // ── direct push: the opcode IS the length ──
      if (op <= JF_PUSH_MAX) {
        if (i + op > len) throw new JfScriptError('push past end of script')
        this.pushSpan(code.slice(i, i + op))
        i += op
        continue
      }
      // ── small integers ──
      if (op >= JF_SMALL0 && op <= JF_SMALL_NEG1) { this.pushI(op === JF_SMALL_NEG1 ? -1 : op - JF_SMALL0); continue }
      // ── bank escape ──
      if (op >= JF_ESC0) {
        if (covenant)
          throw new JfScriptError(`bank escape 0x${hex2(op)} is illegal in jetForth — stdForth is entered only through INVOKE`)
        if (op === JF_PLANE) throw new JfScriptError('plane escape 0xff is unassigned')
        const set = jf_bank_name(op) ?? `unassigned bank 0x${hex2(op)}`
        const sel = InterpreterJF.u8(code, i); i++
        const word = BANK_SEL.get(set)?.get(sel) ?? false
        // ⚠ ONE WORD, ONE ENCODING: a promoted word's two-byte form is reserved-illegal.
        if (word !== false && JF_PROMOTED[word] !== undefined)
          throw new JfScriptError(`${word} is jetForth-only: its two-byte form is reserved-illegal`)
        // ★ HERE ( -- addr ): where a function's program memory starts (CORE 6.1.1650, with no ALLOT)
        if (word === 'HERE' && this.chan.length) { this.pushI(this.mbase); continue }
        if (word !== false && CHANNEL_WORDS[word] !== undefined && this.chan.length) { this.channel(word); continue }
        if (word !== false && JF_CORE_KIND[word] !== undefined) {
          const why = {
            'compile-time': 'the compiler executes it, bytecode never contains it',
            'text interpretation': 'it parses source text, which the compiler has already done',
            'output channel': 'it writes to a declared output channel, which exists only inside '
                            + 'a stdForth function whose DEFS entry sets out_max',
            'input channel': 'it reads a declared input channel, which exists only inside '
                           + 'a stdForth function whose DEFS entry sets in_max',
            'number formatting': 'NOT BUILT — it needs BASE as live state and pictured numeric '
                               + 'output (<# # #S #>)',
            'system': 'it abandons or restarts the interpreter, which a declared '
                    + 'arity cannot describe',
          }[JF_CORE_KIND[word]] ?? null
          throw new JfScriptError(why === null ? `${word} — refused: ${JF_CORE_KIND[word]}`
                                               : `${word} — ${JF_CORE_KIND[word]} word: ${why}`)
        }
        throw new JfBankUnsupported(set, word === false ? null : word)
      }
      i = await this.step(op, code, i, covenant)
    }
    if (this.ds.length + this.rs.length + this.frameCells + this.held > this.maxItems) this.tooMany()
  }
  tooMany() {
    throw new JfScriptError(`stack size exceeded: ${this.ds.length + this.rs.length + this.frameCells + this.held} items held, at most ${this.maxItems}`)
  }

  /** Append bytes to the push space and leave `( c-addr u )`. ⚠ Deterministic: an address depends only on the lengths pushed before. */
  pushSpan(b) {
    const n = b.length
    if (this.plen + n > this.pushSize) throw new JfScriptError('push space exhausted')
    this.charge(n)
    if (this.plen + n > this.pmem.length) {
      const grown = new Uint8Array(Math.min(this.pushSize, Math.max(this.plen + n, this.pmem.length * 2, 256)))
      grown.set(this.pmem.subarray(0, this.plen)); this.pmem = grown
    }
    this.pmem.set(b, this.plen)
    this.pushI(this.pbase + this.plen); this.pushI(n)
    this.plen += n
  }
  sigOp(n) {
    this.sigOps += Number(n)
    if (this.sigOps > this.maxSigOps) throw new JfScriptError(`signature check limit exceeded: at most ${this.maxSigOps} a tick`)
  }

  /** One opcode. Returns the new instruction pointer. */
  async step(op, code, i, covenant) {
    const name = OP.get(op)
    const ds = this.ds
    switch (name) {
      // ── literal forms ──
      case 'LIT8': case 'LIT16': case 'LIT32': case 'LIT64': {
        const w = { LIT8: 1, LIT16: 2, LIT32: 4, LIT64: 8 }[name]
        if (i + w > code.length) throw new JfScriptError('truncated literal')
        const le = code.subarray(i, i + w)
        let v = leToBig(le)
        if (le[w - 1] & 0x80) v -= 1n << BigInt(8 * w)          // sign-extend
        this.push(v)
        return i + w
      }
      case 'LITBIG': {
        const [n, j] = this.varint(code, i); i = j
        if (i + n > code.length) throw new JfScriptError('truncated LITBIG')
        this.pushSpan(code.slice(i, i + n))
        return i + n
      }
      case 'STR8': case 'STR16': case 'STR32': {
        const w = { STR8: 1, STR16: 2, STR32: 4 }[name]
        if (i + w > code.length) throw new JfScriptError('truncated string length')
        let n = 0; for (let k = 0; k < w; k++) n += code[i + k] * 2 ** (8 * k)
        i += w
        if (i + n > code.length) throw new JfScriptError('string past end of script')
        this.pushSpan(code.slice(i, i + n))
        return i + n
      }

      // ── stack ──
      case 'DUP': this.need(1); ds.push(ds[ds.length - 1]); return i
      case 'DROP': this.pop(); return i
      case 'SWAP': { this.need(2); const n = ds.length; [ds[n - 2], ds[n - 1]] = [ds[n - 1], ds[n - 2]]; return i }
      case 'OVER': this.need(2); ds.push(ds[ds.length - 2]); return i
      case 'ROT': { this.need(3); const n = ds.length; const x = ds[n - 3]; ds[n - 3] = ds[n - 2]; ds[n - 2] = ds[n - 1]; ds[n - 1] = x; return i }
      case '?DUP': { this.need(1); const t = ds[ds.length - 1]; if (t !== 0n) ds.push(t); return i }
      case 'NIP': { this.need(2); const n = ds.length; ds[n - 2] = ds[n - 1]; ds.pop(); return i }
      case 'TUCK': { this.need(2); const n = ds.length; const b = ds[n - 1]; ds[n - 1] = ds[n - 2]; ds[n - 2] = b; ds.push(b); return i }
      case 'DEPTH': this.pushI(ds.length); return i
      case 'PICK': { const n = this.popInt(); if (n < 0n) throw new JfScriptError('PICK: negative index'); this.need(n + 1n); ds.push(ds[ds.length - 1 - Number(n)]); return i }
      case 'ROLL': { const n = this.popInt(); if (n < 0n) throw new JfScriptError('ROLL: negative index'); this.need(n + 1n)
        // the cost is the depth rolled, not the depth of the stack
        const t = ds.length - 1, k0 = t - Number(n), x = ds[k0]
        for (let k = k0; k < t; k++) ds[k] = ds[k + 1]
        ds[t] = x; return i }
      case '2DUP': { this.need(2); const n = ds.length; ds.push(ds[n - 2]); ds.push(ds[n - 1]); return i }
      case '2DROP': this.need(2); this.pop(); this.pop(); return i
      case '2SWAP': { this.need(4); const n = ds.length; [ds[n - 4], ds[n - 3], ds[n - 2], ds[n - 1]] = [ds[n - 2], ds[n - 1], ds[n - 4], ds[n - 3]]; return i }
      case '2OVER': { this.need(4); const n = ds.length; ds.push(ds[n - 4]); ds.push(ds[n - 3]); return i }
      case '>R': this.rs.push(this.pop()); return i
      case 'R>': if (!this.rs.length) throw new JfScriptError('return stack underflow'); ds.push(this.rs.pop()); return i
      case 'R@': if (!this.rs.length) throw new JfScriptError('return stack underflow'); ds.push(this.rs[this.rs.length - 1]); return i
      case '2>R': { this.need(2); const b = this.pop(); const a = this.pop(); this.rs.push(a); this.rs.push(b); return i }
      case '2R>': { if (this.rs.length < 2) throw new JfScriptError('return stack underflow'); const b = this.rs.pop(); const a = this.rs.pop(); ds.push(a); ds.push(b); return i }
      case '2R@': { if (this.rs.length < 2) throw new JfScriptError('return stack underflow'); const n = this.rs.length; ds.push(this.rs[n - 2]); ds.push(this.rs[n - 1]); return i }

      // ── arithmetic ──
      case '+': { const b = this.pop(); this.push(this.pop() + b); return i }
      case '-': { const b = this.pop(); this.push(this.pop() - b); return i }
      case '*': { const b = this.pop(); this.push(this.pop() * b); return i }
      case '/': { const b = this.pop(); const a = this.pop(); this.push(divT(a, b)); return i }
      case 'MOD': { const b = this.pop(); const a = this.pop(); this.push(modT(a, b)); return i }
      case '/MOD': { const b = this.pop(); const a = this.pop(); this.push(modT(a, b)); this.push(divT(a, b)); return i }
      // ★ */ and */MOD keep the intermediate at DOUBLE width — that is the whole point of them.
      case '*/': { const c = this.pop(); const b = this.pop(); const a = this.pop(); this.push(divT(a * b, c)); return i }
      case '*/MOD': { const c = this.pop(); const b = this.pop(); const a = this.pop(); const p = a * b; this.push(modT(p, c)); this.push(divT(p, c)); return i }
      case '1+': this.push(this.pop() + 1n); return i
      case '1-': this.push(this.pop() - 1n); return i
      case '2*': this.push(this.pop() * 2n); return i
      case '2/': this.push(floorDiv(this.pop(), 2n)); return i            // arithmetic shift
      case 'ABS': { const v = this.pop(); this.push(v < 0n ? -v : v); return i }
      case 'NEGATE': this.push(-this.pop()); return i
      case 'MIN': { const b = this.pop(); const a = this.pop(); this.push(a <= b ? a : b); return i }
      case 'MAX': { const b = this.pop(); const a = this.pop(); this.push(a >= b ? a : b); return i }
      // ⚠ FM/MOD is FLOORED, SM/REM is SYMMETRIC. Collapsing them is the classic Forth bug.
      case 'FM/MOD': { const b = this.pop(); const a = this.pop()
        if (b === 0n) throw new JfScriptError('FM/MOD by zero')
        const q = floorDiv(a, b); this.push(a - q * b); this.push(q); return i }
      case 'SM/REM': { const b = this.pop(); const a = this.pop(); this.push(modT(a, b)); this.push(divT(a, b)); return i }
      case 'UM*': { const b = uns(this.pop()); const a = uns(this.pop()); const p = a * b; this.push(p % M64); this.push(p / M64); return i }
      case 'UM/MOD': { const b = uns(this.pop()); const hi = uns(this.pop()); const lo = uns(this.pop())
        if (b === 0n) throw new JfScriptError('UM/MOD by zero')
        const d = hi * M64 + lo; this.push(d % b); this.push(d / b); return i }
      case 'M*': { const b = this.pop(); const a = this.pop(); const p = a * b
        this.push(u2(p) % M64); this.push(floorDiv(p, M64)); return i }
      case 'S>D': { this.need(1); const a = ds[ds.length - 1]; this.pushI(a < 0n ? -1 : 0); return i }

      // ── logic ──
      case 'AND': { const b = this.pop(); this.push(uns(this.pop()) & uns(b)); return i }
      case 'OR': { const b = this.pop(); this.push(uns(this.pop()) | uns(b)); return i }
      case 'XOR': { const b = this.pop(); this.push(uns(this.pop()) ^ uns(b)); return i }
      case 'INVERT': this.push(-this.pop() - 1n); return i                // ~x == -x-1
      case 'LSHIFT': { const n = this.popInt(); const a = uns(this.pop())
        if (n < 0n) throw new JfScriptError('LSHIFT: negative count')
        this.push(n >= 64n ? 0n : a * (2n ** n)); return i }
      case 'RSHIFT': { const n = this.popInt(); const a = uns(this.pop())   // ⚠ LOGICAL, not arithmetic
        if (n < 0n) throw new JfScriptError('RSHIFT: negative count')
        this.push(n >= 64n ? 0n : a / (2n ** n)); return i }

      // ── comparison ──
      case '=': { const b = this.pop(); this.flag(this.pop() === b); return i }
      case '<>': { const b = this.pop(); this.flag(this.pop() !== b); return i }
      case '<': { const b = this.pop(); this.flag(this.pop() < b); return i }
      case '>': { const b = this.pop(); this.flag(this.pop() > b); return i }
      case 'U<': { const b = uns(this.pop()); this.flag(uns(this.pop()) < b); return i }
      case 'U>': { const b = uns(this.pop()); this.flag(uns(this.pop()) > b); return i }
      case '0=': this.flag(this.pop() === 0n); return i
      case '0<>': this.flag(this.pop() !== 0n); return i
      case '0<': this.flag(this.pop() < 0n); return i
      case '0>': this.flag(this.pop() > 0n); return i
      case 'WITHIN': { const hi = uns(this.pop()); const lo = uns(this.pop()); const t = uns(this.pop())
        // Forth's WITHIN is circular: ( test lo hi -- flag ), lo inclusive, hi exclusive
        this.flag(((t - lo) % M64 + M64) % M64 < ((hi - lo) % M64 + M64) % M64); return i }

      // ── constants ──
      case 'TRUE': this.pushI(-1); return i
      case 'FALSE': this.pushI(0); return i
      case 'BL': this.pushI(32); return i

      // ── memory ──
      case '@': this.push(this.fetch(this.popInt())); return i
      case '!': { const a = this.popInt(); this.store(a, this.pop()); return i }
      case 'C@': this.pushI(this.read(this.popInt(), 1n)[0]); return i
      case 'C!': { const a = this.popInt(); const v = this.popInt(); this.write(a, Uint8Array.of(Number(v & 0xffn))); return i }
      case '+!': { const a = this.popInt(); this.store(a, this.fetch(a) + this.pop()); return i }
      case '2@': { const a = this.popInt(); this.push(this.fetch(a + 8n)); this.push(this.fetch(a)); return i }
      case '2!': { const a = this.popInt(); const lo = this.pop(); const hi = this.pop(); this.store(a, lo); this.store(a + 8n, hi); return i }
      case 'MOVE': { const u = this.popInt(); const to = this.popInt(); const from = this.popInt(); this.write(to, this.read(from, u)); return i }
      // ⚠ the range is checked BEFORE anything is allocated: built first, a script asking for gigabytes ends the process
      case 'FILL': { const ch = this.popInt(); const u = this.popInt(); const a = this.popInt()
        if (u > 0n) { const o = this.bounds(a, u); this.charge(Number(u)); this.mem.fill(Number(ch & 0xffn), o, o + Number(u)) } return i }
      case 'ERASE': { const u = this.popInt(); const a = this.popInt(); if (u > 0n) { const o = this.bounds(a, u); this.charge(Number(u)); this.mem.fill(0, o, o + Number(u)) } return i }
      case 'CELLS': this.push(this.pop() * 8n); return i
      case 'CELL+': this.push(this.pop() + 8n); return i
      case 'CHARS': return i                                                // a char is one address unit
      case 'CHAR+': this.push(this.pop() + 1n); return i
      case 'ALIGNED': { const a = this.popInt(); this.push(((a + 7n) / 8n) * 8n); return i }

      // ── loop runtime ── DO pushes (limit, index) on the RETURN stack, as standard Forth does
      case 'I': if (this.rs.length < 2) throw new JfScriptError('I outside a loop'); ds.push(this.rs[this.rs.length - 1]); return i
      case 'J': if (this.rs.length < 4) throw new JfScriptError('J outside two loops'); ds.push(this.rs[this.rs.length - 3]); return i
      case 'UNLOOP': if (this.rs.length < 2) throw new JfScriptError('UNLOOP outside a loop'); this.rs.pop(); this.rs.pop(); return i
      case 'LEAVE': { const off = InterpreterJF.i16(code, i)
        if (this.rs.length < 2) throw new JfScriptError('LEAVE outside a loop')
        this.rs.pop(); this.rs.pop()
        return this.jump(code, i + 2, off) }
      case 'EXIT': return code.length
      case 'EXECUTE': { const xt = this.popInt(); await this.call(code, xt, covenant); return i }

      // ── branch primitives ──
      case 'BRANCH': { const off = InterpreterJF.i16(code, i); return this.jump(code, i + 2, off) }
      case '0BRANCH': { const off = InterpreterJF.i16(code, i); i += 2; return this.pop() === 0n ? this.jump(code, i, off) : i }
      case '(DO)': { const ix = this.pop(); const lim = this.pop(); this.rs.push(lim); this.rs.push(ix); return i }
      case '(?DO)': { const off = InterpreterJF.i16(code, i); i += 2
        const ix = this.pop(); const lim = this.pop()
        if (ix === lim) return this.jump(code, i, off)
        this.rs.push(lim); this.rs.push(ix); return i }
      case '(LOOP)': case '(+LOOP)': {
        const off = InterpreterJF.i16(code, i); i += 2
        if (this.rs.length < 2) throw new JfScriptError('LOOP outside a loop')
        const step = name === '(+LOOP)' ? this.pop() : 1n
        const ix = this.rs.pop(); const lim = this.rs[this.rs.length - 1]
        const nx = cell(ix + step)
        // ★ Forth's rule: terminate when the index CROSSES the limit
        const done = step >= 0n ? (ix < lim && nx >= lim) || ix >= lim
                                : (ix > lim && nx <= lim) || ix <= lim
        if (done) { this.rs.pop(); return i }
        this.rs.push(nx)
        return this.jump(code, i, off) }
      case 'CALL': { const to = InterpreterJF.u16(code, i); i += 2; await this.call(code, BigInt(to), covenant); return i }
      case 'RET': return code.length

      // ── locals ──
      case '(FRAME)': { const n = InterpreterJF.u8(code, i); i++
        this.need(n)
        this.frames.push(new Map((n === 0 ? [] : ds.splice(ds.length - n)).map((v, k) => [k, v])))
        this.frameCells += n
        return i }
      case '(LOCAL@)': { const k = InterpreterJF.u8(code, i); i++
        const f = this.frame(); if (!f.has(k)) throw new JfScriptError(`local ${k} unset`)
        ds.push(f.get(k)); return i }
      case '(LOCAL!)': { const k = InterpreterJF.u8(code, i); i++
        // ⚠ refused with no frame, as (LOCAL@) is
        const v = this.pop(); const f = this.frame(); if (!f.has(k)) this.frameCells++; f.set(k, v); return i }
      case '(UNFRAME)': if (!this.frames.length) throw new JfScriptError('(UNFRAME) with no frame'); this.frameCells -= this.frames.pop().size; return i

      // ── byte strings ──
      case 'SIZE': this.need(2); ds.push(ds[ds.length - 1]); return i
      case 'SPLIT': { const n = this.popInt(); const u = this.popInt(); const a = this.popInt()
        if (n < 0n || n > u) throw new JfScriptError('SPLIT out of range')
        this.push(a); this.push(n); this.push(a + n); this.push(u - n); return i }
      case 'CAT': { const d = this.popInt(); const s2 = this.popSpan(); const s1 = this.popSpan()
        this.write(d, cat(s1, s2)); this.push(d); this.pushI(s1.length + s2.length); return i }
      case 'SUBSTR': { const d = this.popInt(); const cnt = this.popInt(); const beg = this.popInt(); const s = this.popSpan()
        if (beg < 0n || cnt < 0n || beg + cnt > BigInt(s.length)) throw new JfScriptError('SUBSTR out of range')
        this.write(d, s.slice(Number(beg), Number(beg + cnt))); this.push(d); this.push(cnt); return i }
      case 'LEFT': { const d = this.popInt(); const n = this.popInt(); const s = this.popSpan()
        if (n < 0n || n > BigInt(s.length)) throw new JfScriptError('LEFT out of range')
        this.write(d, s.slice(0, Number(n))); this.push(d); this.push(n); return i }
      case 'RIGHT': { const d = this.popInt(); const n = this.popInt(); const s = this.popSpan()
        if (n < 0n || n > BigInt(s.length)) throw new JfScriptError('RIGHT out of range')
        this.write(d, s.slice(s.length - Number(n))); this.push(d); this.push(n); return i }
      case 'NUM2BIN': { const d = this.popInt(); const sz = this.popInt(); const v = this.pop()
        if (sz < 0n || sz > 0x10000n) throw new JfScriptError('NUM2BIN size out of range')
        const be = beBytes(uns(v))
        if (BigInt(be.length) > sz) throw new JfScriptError('NUM2BIN does not fit')
        const le = new Uint8Array(Number(sz)); for (let k = 0; k < be.length; k++) le[k] = be[be.length - 1 - k]
        this.write(d, le); this.push(d); this.push(sz); return i }
      // ★★★ ( a1 u1 a2 u2 -- flag ) — THE COVENANT'S CENTRAL OPERATION. ⚠ CONSTANT TIME over the bytes.
      case 'BYTES=': { const b = this.popSpan(); const a = this.popSpan()
        let eq = a.length === b.length
        if (eq) {
          let x = 0, k = 0
          if (a.byteOffset % 4 === 0 && b.byteOffset % 4 === 0) {
            const w = a.length >>> 2, A = new Uint32Array(a.buffer, a.byteOffset, w), B = new Uint32Array(b.buffer, b.byteOffset, w)
            for (let j = 0; j < w; j++) x |= A[j] ^ B[j]
            k = w << 2
          }
          for (; k < a.length; k++) x |= a[k] ^ b[k]
          eq = x === 0
        }
        this.flag(eq); return i }
      // a cell keeps the low 64 bits, which are the first 8 bytes
      case 'BIN2NUM': { const s = this.popSpan(); this.push(s.length === 0 ? 0n : leToBig(s.subarray(0, 8))); return i }

      // ── crypto ── `( c-addr u dest -- )`: the CALLER supplies the destination
      case 'SHA256': return this.hashTo(i, b => this.hash('sha256', b))
      case 'SHA1': return this.hashTo(i, b => this.hash('sha1', b))
      case 'RIPEMD160': return this.hashTo(i, b => this.hash('ripemd160', b))
      case 'HASH160': return this.hashTo(i, b => this.hash('ripemd160', this.hash('sha256', b)))
      case 'HASH256': return this.hashTo(i, b => this.hash('sha256', this.hash('sha256', b)))

      // `( a-sig u-sig a-pub u-pub a-digest 32 -- flag )` secp256k1 over an EXPLICIT digest
      case 'CHECKSIG': case 'CHECKSIGVERIFY': {
        this.sigOp(1)
        const msg = this.popSpan(); const pub = this.popSpan(); const sig = this.popSpan()
        const ok = await this.ecdsaVerify(sig, pub, msg)
        if (name === 'CHECKSIGVERIFY') { if (!ok) throw new JfScriptError('CHECKSIGVERIFY failed') } else this.flag(ok)
        return i }
      // `( a-sig u-sig a-pub u-pub a-msg u-msg -- flag )` Ed25519 over the message as given
      case 'ED25519-CHECKSIG': case 'ED25519-CHECKSIGVERIFY': {
        this.sigOp(1)
        const msg = this.popSpan(); const pub = this.popSpan(); const sig = this.popSpan()
        const ok = await this.ed25519Verify(sig, pub, msg)
        if (name === 'ED25519-CHECKSIGVERIFY') { if (!ok) throw new JfScriptError('ED25519-CHECKSIGVERIFY failed') } else this.flag(ok)
        return i }
      // `( a-msg u-msg a-pub u-pub ... n a-sig u-sig ... m -- flag )` ⛔ NO dummy element
      case 'CHECKMULTISIG': case 'CHECKMULTISIGVERIFY': {
        const m = this.popInt()
        if (m < 0n || m > 32n) throw new JfScriptError('CHECKMULTISIG: bad signature count')
        const sigs = []
        for (let k = 0n; k < m; k++) sigs.unshift(this.popSpan())
        const n = this.popInt()
        if (n < 0n || n > 32n || m > n) throw new JfScriptError('CHECKMULTISIG: bad key count')
        this.sigOp(n)
        const keys = []
        for (let k = 0n; k < n; k++) keys.unshift(this.popSpan())
        const msg = this.popSpan()
        let ki = 0, matched = 0
        for (const s of sigs) {
          while (ki < keys.length && !(await this.ecdsaVerify(s, keys[ki], msg))) ki++
          if (ki >= keys.length) break
          matched++; ki++
        }
        const ok = matched === Number(m)
        if (name === 'CHECKMULTISIGVERIFY') { if (!ok) throw new JfScriptError('CHECKMULTISIGVERIFY failed') } else this.flag(ok)
        return i }

      // ── transaction ──
      case 'PREIMAGE': { this.covenantOnly('PREIMAGE', covenant); const d = this.popInt()
        if (this.preimage === null) throw new JfScriptError('PREIMAGE: no transaction context')
        this.write(d, this.preimage); this.push(d); this.pushI(this.preimage.length); return i }
      case 'TXVERSION': case 'PREVOUTS-HASH': case 'SEQUENCES-HASH': case 'OUTPOINT':
      case 'SCRIPTCODE': case 'TXVALUE': case 'NSEQUENCE': case 'OUTPUTS-HASH': case 'LOCKTIME':
        this.covenantOnly(jf_op_name(op), covenant)
        throw new JfScriptError(`${jf_op_name(op)}: not built yet — derive it from PREIMAGE with SUBSTR`)
      case 'VER': case 'VERIF': case 'VERNOTIF':
        throw new JfScriptError(`${jf_op_name(op)}: version words are §6b and not built yet`)

      // ── INVOKE: the tier boundary ──
      case 'INVOKE': { const ix = InterpreterJF.u8(code, i); i++; await this.invoke(ix); return i }

      // ── abort ── ⛔ the message is a COMPILE-TIME LITERAL, never a stack span: it can carry nothing derived
      case 'ABORT': throw JfScriptError.aborted(new Uint8Array(0))
      case '(ABORT")': {
        const n = InterpreterJF.u8(code, i); i++
        if (i + n > code.length) throw new JfScriptError('truncated ABORT" message')
        const msg = code.slice(i, i + n); i += n
        if (this.pop() !== 0n) throw JfScriptError.aborted(msg)
        return i }
    }
    if (op >= JF_RESERVED0 && op < JF_ESC0) throw new JfScriptError(`0x${hex2(op)} is reserved and must not appear`)
    throw new JfScriptError(`unknown opcode 0x${hex2(op)}`)
  }

  channel(word) {
    const t = this.chan.length - 1, c = this.chan[t]
    if (CHANNEL_WORDS[word] === 'o') {
      if (c.max === 0) throw new JfScriptError(`${word}: this function declared no output channel (out_max is 0)`)
      if (word === 'EMIT?') { this.flag(c.olen < Math.min(c.max, c.room)); return }   // ( -- flag ) is there room for one more?
      const b = word === 'EMIT' ? Uint8Array.of(Number(this.popInt() & 0xffn))
              : word === 'CR' ? bytesOf('\n')
              : word === 'SPACE' ? bytesOf(' ')
              : word === 'SPACES' ? this.spaces(c)
              : this.popSpan()                                              // TYPE
      if (c.olen + b.length > c.max) throw new JfScriptError(`output exceeds the declared out_max of ${c.max}`)
      if (c.olen + b.length > c.room) throw new JfScriptError('push space exhausted')
      if (c.olen + b.length > c.out.length) {
        const grown = new Uint8Array(Math.max(c.olen + b.length, c.out.length * 2, 256)); grown.set(c.out.subarray(0, c.olen)); c.out = grown
      }
      c.out.set(b, c.olen); c.olen += b.length
      return
    }
    // ⚠ Check the DECLARED size, not whether bytes happen to be present
    if (c.inmax === 0) throw new JfScriptError(`${word}: this function declared no input channel (in_max is 0)`)
    if (word === 'KEY') {
      if (c.pos >= c.in.length) throw new JfScriptError('KEY: input exhausted')
      this.pushI(c.in[c.pos++]); return
    }
    // ACCEPT ( c-addr +n1 -- +n2 ) — a LINE: up to n1 bytes, stopping at \n, which is CONSUMED but NOT stored
    const n1 = this.popInt(); const addr = this.popInt()
    if (n1 < 0n) throw new JfScriptError('ACCEPT: negative length')
    const take = Number(n1 < BigInt(c.in.length - c.pos) ? n1 : BigInt(c.in.length - c.pos))
    const nl = newlineIn(c.in, c.pos, c.pos + take)
    let got
    if (nl !== -1 && nl < c.pos + take) { got = c.in.subarray(c.pos, nl); c.pos = nl + 1 }
    else { got = c.in.subarray(c.pos, c.pos + take); c.pos += take }
    if (got.length) this.write(addr, got)
    this.pushI(got.length)
  }

  /** SPACES' bytes, refused BEFORE they are allocated when they would not fit. */
  spaces(c) {
    const n = this.popInt(), k = n > 0n ? n : 0n
    if (BigInt(c.olen) + k > BigInt(c.max)) throw new JfScriptError(`output exceeds the declared out_max of ${c.max}`)
    if (BigInt(c.olen) + k > BigInt(c.room)) throw new JfScriptError('push space exhausted')
    return new Uint8Array(Number(k)).fill(32)
  }
  /** ⛔⛔ THE COVENANT'S OWN WORDS ARE NOT THE FUNCTION'S. */
  covenantOnly(word, covenant) {
    if (!covenant) throw new JfScriptError(`${word} is covenant-tier only: a stdForth function computes from what it `
                                          + 'was given, and reaches for nothing else')
  }
  frame() { if (!this.frames.length) throw new JfScriptError('local access with no frame'); return this.frames[this.frames.length - 1] }
  jump(code, from, off) { const to = from + off; if (to < 0 || to > code.length) throw new JfScriptError('branch out of range'); return to }
  async call(code, to, covenant) {
    if (++this.depth > this.maxDepth) { this.depth--; throw new JfScriptError('call depth exceeded') }
    try {
      if (to < 0n || to > BigInt(code.length)) throw new JfScriptError('call out of range')
      await this.exec(code, Number(to), covenant)
    } finally { this.depth-- }
  }
  hashTo(i, h) { const d = this.popInt(); const s = this.popSpan(); this.write(d, h(s)); return i }
  hash(kind, b) {
    const f = this.crypto[kind]
    if (!f) throw new JfHostError(`${kind.toUpperCase()} is not available on this host`)
    return f(b)
  }
  async ecdsaVerify(sig, pub, digest32) {
    if (digest32.length !== 32 || !isStrictDer(sig)) return false
    if (!this.crypto.ecdsaVerify) throw new JfHostError('CHECKSIG needs secp256k1 on this host')
    try { return !!(await this.crypto.ecdsaVerify(sig, pub, digest32)) } catch { return false }
  }
  /** Ed25519 (RFC 8032). A wrong key or signature length is a failed check, never an error. */
  async ed25519Verify(sig, pub, msg) {
    if (pub.length !== 32 || sig.length !== 64) return false
    if (!this.crypto.ed25519Verify) throw new JfHostError('ED25519-CHECKSIG needs Ed25519 on this host')
    try { return !!(await this.crypto.ed25519Verify(sig, pub, msg)) } catch { return false }
  }

  /** ⛔⛔ THE TIER BOUNDARY, ENFORCED: fresh stacks holding exactly n_in cells, fresh memory (made when touched), an empty
   *  push space at PUSH_BASE × (INVOKE depth + 1), the declared channels; the tick's counts run through. See InterpreterJF::invoke. */
  async invoke(ix) {
    if (this.defs[ix] === undefined) throw new JfScriptError(`INVOKE ${ix}: no such definition`)
    const d = this.defs[ix]
    const inMax = d.in_max ?? 0, outMax = d.out_max ?? 0
    this.need(d.n_in + (inMax > 0 ? 2 : 0))                  // the input span sits ABOVE the cell arguments
    if (++this.depth > this.maxDepth) { this.depth--; throw new JfScriptError('call depth exceeded') }
    const savedRs = this.rs, savedFr = this.frames           // the function gets fresh ones: no copy needed
    const savedFc = this.frameCells, savedHeld = this.held, savedBase = this.pbase, savedMbase = this.mbase
    const chanDepth = this.chan.length
    let savedMem, savedP, savedPl, callerDs, results, emitted
    let taken = []                                             // the caller's cells this call took, bottom first
    try {
      let inBytes = new Uint8Array(0)
      if (inMax > 0) {
        const u = this.popInt(); const a = this.popInt(); taken = [a, u]
        inBytes = this.view(a, u, false)                       // the caller's memory is not touched while the function runs
        if (inBytes.length > inMax)
          throw new JfScriptError(`INVOKE ${ix}: input is ${inBytes.length} bytes, declared in_max ${inMax}`)
      }
      const args = d.n_in === 0 ? [] : this.ds.splice(this.ds.length - d.n_in)
      taken = [...args, ...taken]
      callerDs = this.ds
      this.held += callerDs.length + savedRs.length + savedFc   // still held while the function runs
      this.ds = args; this.rs = []; this.frames = []; this.frameCells = 0
      savedMem = this.mem; savedP = this.pmem; savedPl = this.plen
      this.mem = null                                          // ⛔ fresh, zeroed when touched: no residue from the caller
      this.pmem = new Uint8Array(0); this.plen = 0              // ⛔ nor the caller's pushes: no key reaches a function
      // room: the caller's push space left, where the output is pushed on return
      this.chan.push({ in: inBytes, pos: 0, inmax: inMax, out: new Uint8Array(0), olen: 0, max: outMax, room: this.pushSize - savedPl })
      this.pbase = PUSH_BASE * (this.chan.length + 1)
      this.mbase = this.pbase + MEM_OFFSET

      await this.exec(d.body, 0, /* covenant */ false)
      if (this.ds.length !== d.n_out)
        throw new JfScriptError(`INVOKE ${ix}: declared ${d.n_out} out, produced ${this.ds.length}`)
      if (this.frames.length) throw new JfScriptError(`INVOKE ${ix}: unbalanced locals frame`)
      results = this.ds
      const done = this.chan.pop(); emitted = done.out.subarray(0, done.olen)
      this.mem = savedMem; this.pmem = savedP; this.plen = savedPl; this.pbase = savedBase; this.mbase = savedMbase
      this.frameCells = savedFc; this.held = savedHeld
    } catch (e) {
      // ⚠ A failed call leaves NOTHING behind
      this.chan.splice(chanDepth)
      if (savedMem !== undefined) { this.mem = savedMem; this.pmem = savedP; this.plen = savedPl }
      if (callerDs !== undefined) this.ds = callerDs
      for (const c of taken) this.ds.push(c)
      this.rs = savedRs; this.frames = savedFr
      this.frameCells = savedFc; this.held = savedHeld; this.pbase = savedBase; this.mbase = savedMbase
      throw e
    } finally { this.depth-- }
    this.ds = callerDs
    for (const r of results) this.ds.push(r)
    this.rs = savedRs; this.frames = savedFr
    if (outMax > 0) this.pushSpan(emitted)                     // the channel comes back as ( c-addr u ), above the outputs
  }
}

// ── judging a tick ─────────────────────────────────────────────────────────────────────────────────────
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
export const TICK_MAX_SCRIPT = 500000
export const TICK_LIMITS = Object.freeze({ maxOps: 500000, memSize: 65536, maxDepth: 64, maxItems: 1000, pushSize: 65536, maxSigOps: 100 })

/** Byte pushes only: direct pushes (0 to 72 bytes) and STR8 / STR16 / STR32, each whole. */
export function bytePushesOnly(s) {
  const n = s.length
  for (let p = 0; p < n;) {
    const op = s[p++]
    let len
    if (op <= JF_PUSH_MAX) len = op
    else if (op === JF_LIT.STR8) { if (p + 1 > n) return false; len = s[p]; p += 1 }
    else if (op === JF_LIT.STR16) { if (p + 2 > n) return false; len = s[p] | (s[p + 1] << 8); p += 2 }
    else if (op === JF_LIT.STR32) { if (p + 4 > n) return false; len = (s[p] | (s[p + 1] << 8) | (s[p + 2] << 16) | (s[p + 3] << 24)) >>> 0; p += 4 }
    else return false
    if (p + len > n) return false
    p += len
  }
  return true
}

/**
 * Judge a tick as a BSV node judges a spend (bitcoin-sv src/script/interpreter.cpp, VerifyScript):
 *   1  the unlocking script is byte pushes only: direct pushes and STR8 / STR16 / STR32, each whole;
 *   2  it runs, then the lock runs as a SECOND, separate run on the data stack and pushed bytes it left, so
 *      nothing in the first can jump into the second or end it;
 *   3  the tick is accepted when the lock leaves exactly one item and it is non-zero. Any error refuses it.
 * A port of InterpreterJF::verifyTick in server/interpreter-jf.php. A refusal's errorBytes are PHP's message bytes:
 * its text in UTF-8, and an abort's diagnostic appended as it was, which no JS string can always hold.
 * @returns {Promise<{accepted: boolean, stack?: bigint[], error?: string, errorBytes?: Uint8Array}>}
 */
export async function verifyTick({ unlocking, lock, preimage, crypto = {} }) {
  const refuse = (error, bytes = UTF8.encode(error)) => ({ accepted: false, error, errorBytes: bytes })
  if (unlocking.length > TICK_MAX_SCRIPT || lock.length > TICK_MAX_SCRIPT) return refuse('a script is longer than 500000 bytes')
  if (!bytePushesOnly(unlocking)) return refuse('the unlocking script is not byte pushes only')
  const vm = new InterpreterJF({ ...TICK_LIMITS, crypto })
  vm.setPreimage(preimage)
  try {
    vm.ds = []; vm.rs = []; vm.frames = []; vm.chan = []
    vm.opCount = 0; vm.depth = 0; vm.frameCells = 0; vm.held = 0; vm.sigOps = 0
    vm.mem = null
    vm.pmem = new Uint8Array(0); vm.plen = 0; vm.pbase = PUSH_BASE; vm.mbase = 0
    await vm.exec(unlocking, 0, true)
    // the second run: the data stack and the pushed bytes carry over, and the op and signature counts run on
    vm.rs = []; vm.frames = []; vm.depth = 0; vm.frameCells = 0
    const i = vm.parseDefs(lock, 0)
    await vm.exec(lock, i, true)
    if (vm.frames.length) throw new JfScriptError('unbalanced locals frame')
  } catch (e) {
    if (e instanceof JfHostError) throw e                     // this host cannot judge: never a refusal
    if (e instanceof JfScriptError)
      return refuse(e.message, e.diagnostic === null ? UTF8.encode(e.message) : cat(UTF8.encode(e.diagnostic.length ? 'ABORT: ' : 'ABORT'), e.diagnostic))
    return refuse(`the interpreter faulted: ${e.constructor?.name ?? 'Error'}`)
  }
  return { accepted: vm.ds.length === 1 && vm.ds[0] !== 0n, stack: vm.ds }
}

/**
 * BIP66's strict DER, without a sighash byte (JF signs an explicit digest): one encoding per signature,
 * so a holder cannot re-encode one into another that also verifies.
 *   30 L 02 lenR R 02 lenS S   with L = total − 2, no negative and no padded integer
 */
export function isStrictDer(b) {
  const n = b.length
  if (n < 8 || n > 72) return false
  if (b[0] !== 0x30 || b[1] !== n - 2 || b[2] !== 0x02) return false
  const lr = b[3]
  if (lr === 0 || 5 + lr >= n || b[4 + lr] !== 0x02) return false
  const ls = b[5 + lr]
  if (ls === 0 || lr + ls + 6 !== n) return false
  if ((b[4] & 0x80) || (lr > 1 && b[4] === 0 && !(b[5] & 0x80))) return false
  if ((b[6 + lr] & 0x80) || (ls > 1 && b[6 + lr] === 0 && !(b[7 + lr] & 0x80))) return false
  return true
}

// ⚠⚠ SYMMETRIC division (truncate toward zero): BigInt's own, and the remainder takes the sign of the DIVIDEND.
function divT(a, b) { if (b === 0n) throw new JfScriptError('division by zero'); return a / b }
function modT(a, b) { if (b === 0n) throw new JfScriptError('division by zero'); return a % b }

/** The first newline in b[from, to), or -1: four bytes at a time where aligned (3 times indexOf's speed). */
export function newlineIn(b, from, to) {
  let k = from
  while (k < to && (b.byteOffset + k) % 4 !== 0) { if (b[k] === 10) return k; k++ }
  const words = (to - k) >>> 2
  if (words > 0) {
    const w = new Uint32Array(b.buffer, b.byteOffset + k, words)
    for (let j = 0; j < words; j++) {
      const v = w[j] ^ 0x0a0a0a0a
      if (((v - 0x01010101) & ~v & 0x80808080) !== 0) { k += j << 2; for (const e = k + 4; k < e; k++) if (b[k] === 10) return k }
    }
    k += words << 2
  }
  for (; k < to; k++) if (b[k] === 10) return k
  return -1
}

/** H(result) = sha256( for each cell: 8 bytes little-endian ) — the §2b comparison hash for `JF`. */
export function jf_stack_hash(cells, sha256) {
  const b = new Uint8Array(cells.length * 8)
  cells.forEach((c, k) => { let u = uns(c); for (let j = 0; j < 8; j++) { b[k * 8 + j] = Number(u & 0xffn); u >>= 8n } })
  return sha256(b)
}
