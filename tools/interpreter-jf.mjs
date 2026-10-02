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
//   ecdsaVerify(sig, pub, digest32) -> boolean or a Promise of one; absent, CHECKSIG refuses to answer
// Bytes are Uint8Array throughout.

import { JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_WORD, JF_ESC0, JF_PLANE, JF_RESERVED0,
         JF_BANK_WORD, JF_CORE_KIND, JF_PROMOTED, jf_op_name, jf_bank_name } from './ops-jf.mjs'

export class JfScriptError extends Error {
  /** The diagnostic a refusal carries out (bytes the script chose), or null for a machine fault. */
  diagnostic = null
  static aborted(msg) {
    const e = new JfScriptError(msg.length === 0 ? 'ABORT' : `ABORT: ${latin1(msg)}`)
    e.diagnostic = msg
    return e
  }
}
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
const latin1 = b => { let s = ''; for (const x of b) s += String.fromCharCode(x); return s }
const hex2 = n => n.toString(16).padStart(2, '0')
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

export class InterpreterJF {
  /** Every limit is OPERATOR POLICY (§4.5), never a protocol constant. */
  constructor({ maxOps = 200000, memSize = 65536, maxDepth = 64, crypto = {} } = {}) {
    Object.assign(this, { maxOps, memSize, maxDepth, crypto })
    this.preimage = null
    this.ds = []; this.rs = []; this.defs = []; this.frames = []; this.chan = []
    this.mem = new Uint8Array(0); this.opCount = 0; this.depth = 0; this.scratchTop = 0
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
  bounds(addr, len) {
    if (addr < 0n || len < 0n || addr + len > BigInt(this.mem.length))
      throw new JfScriptError(`memory out of range: addr=${addr} len=${len} size=${this.mem.length}`)
  }
  fetch(addr) { this.bounds(addr, 8n); const a = Number(addr); return cell(leToBig(this.mem.subarray(a, a + 8))) }
  store(addr, v) {
    this.bounds(addr, 8n)
    let u = uns(cell(v)); const a = Number(addr)
    for (let k = 0; k < 8; k++) { this.mem[a + k] = Number(u & 0xffn); u >>= 8n }
  }
  read(addr, len) { this.bounds(addr, len); const a = Number(addr); return this.mem.slice(a, a + Number(len)) }
  write(addr, b) { this.bounds(addr, BigInt(b.length)); this.mem.set(b, Number(addr)) }
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
    this.opCount = 0; this.depth = 0
    this.mem = new Uint8Array(this.memSize)
    const i = this.parseDefs(script, 0)
    await this.exec(script, i, /* covenant tier */ true)
    if (this.frames.length) throw new JfScriptError('unbalanced locals frame')
    return this.ds
  }

  /** Execute from i to the end of code. `covenant` is true in the jetForth tier, where a bank escape is ILLEGAL. */
  async exec(code, i, covenant) {
    const len = code.length
    while (i < len) {
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
        const names = JF_BANK_WORD[set] ?? {}
        const found = Object.entries(names).find(([, v]) => v === sel)
        const word = found ? found[0] : false
        // ⚠ ONE WORD, ONE ENCODING: a promoted word's two-byte form is reserved-illegal.
        if (word !== false && JF_PROMOTED[word] !== undefined)
          throw new JfScriptError(`${word} is jetForth-only: its two-byte form is reserved-illegal`)
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
  }

  /** Copy bytes into scratch memory and leave `( c-addr u )`. */
  pushSpan(b) { const at = this.scratch(b.length); this.write(BigInt(at), b); this.pushI(at); this.pushI(b.length) }
  /** Scratch for literals only, growing DOWN from the top of memory. ⚠ Deterministic by construction. */
  scratch(n) {
    if (this.scratchTop === 0) this.scratchTop = this.mem.length
    this.scratchTop -= n
    if (this.scratchTop < 0) throw new JfScriptError('literal scratch exhausted')
    return this.scratchTop
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
      case 'ROT': { this.need(3); const x = ds.splice(ds.length - 3, 1)[0]; ds.push(x); return i }
      case '?DUP': { this.need(1); const t = ds[ds.length - 1]; if (t !== 0n) ds.push(t); return i }
      case 'NIP': this.need(2); ds.splice(ds.length - 2, 1); return i
      case 'TUCK': { this.need(2); const n = ds.length; ds.splice(n - 2, 0, ds[n - 1]); return i }
      case 'DEPTH': this.pushI(ds.length); return i
      // ⚠ a negative index is refused here; PHP's own reaches past the stack (reported 3 Oct, not yet decided)
      case 'PICK': { const n = this.popInt(); if (n < 0n) throw new JfScriptError('PICK: negative index'); this.need(n + 1n); ds.push(ds[ds.length - 1 - Number(n)]); return i }
      case 'ROLL': { const n = this.popInt(); if (n < 0n) throw new JfScriptError('ROLL: negative index'); this.need(n + 1n); const x = ds.splice(ds.length - 1 - Number(n), 1); ds.push(x[0]); return i }
      case '2DUP': { this.need(2); const n = ds.length; ds.push(ds[n - 2]); ds.push(ds[n - 1]); return i }
      case '2DROP': this.need(2); this.pop(); this.pop(); return i
      case '2SWAP': { this.need(4); const x = ds.splice(ds.length - 4, 2); ds.push(...x); return i }
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
      // ⚠ the range is checked BEFORE anything is allocated: PHP's own builds the bytes first, and a script asking
      //   for gigabytes ends the process (found 3 Oct, reported)
      case 'FILL': { const ch = this.popInt(); const u = this.popInt(); const a = this.popInt()
        if (u > 0n) { this.bounds(a, u); this.mem.fill(Number(ch & 0xffn), Number(a), Number(a + u)) } return i }
      case 'ERASE': { const u = this.popInt(); const a = this.popInt(); if (u > 0n) { this.bounds(a, u); this.mem.fill(0, Number(a), Number(a + u)) } return i }
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
        return i }
      case '(LOCAL@)': { const k = InterpreterJF.u8(code, i); i++
        const f = this.frame(); if (!f.has(k)) throw new JfScriptError(`local ${k} unset`)
        ds.push(f.get(k)); return i }
      case '(LOCAL!)': { const k = InterpreterJF.u8(code, i); i++
        // ⚠ refused with no frame, as (LOCAL@) is; PHP's own creates a frame instead (found 3 Oct, reported)
        const v = this.pop(); this.frame().set(k, v); return i }
      case '(UNFRAME)': if (!this.frames.length) throw new JfScriptError('(UNFRAME) with no frame'); this.frames.pop(); return i

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
        if (eq) { let x = 0; for (let k = 0; k < a.length; k++) x |= a[k] ^ b[k]; eq = x === 0 }
        this.flag(eq); return i }
      case 'BIN2NUM': { const s = this.popSpan(); this.push(s.length === 0 ? 0n : leToBig(s)); return i }

      // ── crypto ── `( c-addr u dest -- )`: the CALLER supplies the destination
      case 'SHA256': return this.hashTo(i, b => this.hash('sha256', b))
      case 'SHA1': return this.hashTo(i, b => this.hash('sha1', b))
      case 'RIPEMD160': return this.hashTo(i, b => this.hash('ripemd160', b))
      case 'HASH160': return this.hashTo(i, b => this.hash('ripemd160', this.hash('sha256', b)))
      case 'HASH256': return this.hashTo(i, b => this.hash('sha256', this.hash('sha256', b)))

      // `( a-sig u-sig a-pub u-pub a-digest 32 -- flag )` secp256k1 over an EXPLICIT digest
      case 'CHECKSIG': case 'CHECKSIGVERIFY': {
        const msg = this.popSpan(); const pub = this.popSpan(); const sig = this.popSpan()
        const ok = await this.ecdsaVerify(sig, pub, msg)
        if (name === 'CHECKSIGVERIFY') { if (!ok) throw new JfScriptError('CHECKSIGVERIFY failed') } else this.flag(ok)
        return i }
      // `( a-sig u-sig a-pub u-pub a-msg u-msg -- flag )` Ed25519 over the message as given
      case 'ED25519-CHECKSIG': case 'ED25519-CHECKSIGVERIFY': {
        const msg = this.popSpan(); const pub = this.popSpan(); const sig = this.popSpan()
        const ok = await this.ed25519Verify(sig, pub, msg)
        if (name === 'ED25519-CHECKSIGVERIFY') { if (!ok) throw new JfScriptError('ED25519-CHECKSIGVERIFY failed') } else this.flag(ok)
        return i }
      // `( a-msg u-msg n a-pub u-pub ... m a-sig u-sig ... -- flag )` ⛔ NO dummy element
      case 'CHECKMULTISIG': case 'CHECKMULTISIGVERIFY': {
        const m = this.popInt()
        if (m < 0n || m > 32n) throw new JfScriptError('CHECKMULTISIG: bad signature count')
        const sigs = []
        for (let k = 0n; k < m; k++) sigs.unshift(this.popSpan())
        const n = this.popInt()
        if (n < 0n || n > 32n || m > n) throw new JfScriptError('CHECKMULTISIG: bad key count')
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
      if (word === 'EMIT?') { this.flag(c.out.length < c.max); return }   // ( -- flag ) is there room for one more?
      const b = word === 'EMIT' ? Uint8Array.of(Number(this.popInt() & 0xffn))
              : word === 'CR' ? bytesOf('\n')
              : word === 'SPACE' ? bytesOf(' ')
              : word === 'SPACES' ? this.spaces(c)
              : this.popSpan()                                              // TYPE
      if (c.out.length + b.length > c.max) throw new JfScriptError(`output exceeds the declared out_max of ${c.max}`)
      c.out = cat(c.out, b)
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
    const got = []
    while (BigInt(got.length) < n1 && c.pos < c.in.length) {
      const ch = c.in[c.pos++]
      if (ch === 10) break
      got.push(ch)
    }
    if (got.length) this.write(addr, Uint8Array.from(got))
    this.pushI(got.length)
  }

  /** SPACES' bytes, refused BEFORE they are allocated when they would not fit (PHP's own allocates first). */
  spaces(c) {
    const n = this.popInt(), k = n > 0n ? n : 0n
    if (BigInt(c.out.length) + k > BigInt(c.max)) throw new JfScriptError(`output exceeds the declared out_max of ${c.max}`)
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
    if (!f) throw new JfScriptError(`${kind.toUpperCase()} is not available on this host`)
    return f(b)
  }
  async ecdsaVerify(sig, pub, digest32) {
    if (!this.crypto.ecdsaVerify) throw new JfScriptError('CHECKSIG needs secp256k1 on this host')
    try { return !!(await this.crypto.ecdsaVerify(sig, pub, digest32)) } catch { return false }
  }
  /** Ed25519 (RFC 8032). A wrong key or signature length is a failed check, never an error. */
  async ed25519Verify(sig, pub, msg) {
    if (pub.length !== 32 || sig.length !== 64) return false
    if (!this.crypto.ed25519Verify) throw new JfScriptError('ED25519-CHECKSIG needs Ed25519 on this host')
    try { return !!(await this.crypto.ed25519Verify(sig, pub, msg)) } catch { return false }
  }

  /** ⛔⛔ THE TIER BOUNDARY, ENFORCED: a function gets a FRESH stack holding exactly n_in items, fresh memory, fresh locals. */
  async invoke(ix) {
    if (this.defs[ix] === undefined) throw new JfScriptError(`INVOKE ${ix}: no such definition`)
    const d = this.defs[ix]
    const inMax = d.in_max ?? 0, outMax = d.out_max ?? 0
    this.need(d.n_in + (inMax > 0 ? 2 : 0))                  // the input span sits ABOVE the cell arguments
    if (++this.depth > this.maxDepth) { this.depth--; throw new JfScriptError('call depth exceeded') }
    const savedDs = this.ds.slice(), savedRs = this.rs.slice(), savedFr = this.frames.slice()
    const chanDepth = this.chan.length
    let savedMem, savedTop, callerDs, results, emitted
    try {
      let inBytes = new Uint8Array(0)
      if (inMax > 0) {
        inBytes = this.popSpan()
        if (inBytes.length > inMax)
          throw new JfScriptError(`INVOKE ${ix}: input is ${inBytes.length} bytes, declared in_max ${inMax}`)
      }
      const args = d.n_in === 0 ? [] : this.ds.splice(this.ds.length - d.n_in)
      callerDs = this.ds
      this.ds = args; this.rs = []; this.frames = []
      savedMem = this.mem; savedTop = this.scratchTop
      this.mem = new Uint8Array(savedMem.length)               // ⛔ zeroed: no residue from the caller
      this.scratchTop = 0
      this.chan.push({ in: inBytes, pos: 0, inmax: inMax, out: new Uint8Array(0), max: outMax })

      await this.exec(d.body, 0, /* covenant */ false)
      if (this.ds.length !== d.n_out)
        throw new JfScriptError(`INVOKE ${ix}: declared ${d.n_out} out, produced ${this.ds.length}`)
      if (this.frames.length) throw new JfScriptError(`INVOKE ${ix}: unbalanced locals frame`)
      results = this.ds
      emitted = this.chan.pop().out
      this.mem = savedMem; this.scratchTop = savedTop
    } catch (e) {
      // ⚠ A failed call leaves NOTHING behind
      this.chan.splice(chanDepth)
      if (savedMem !== undefined) { this.mem = savedMem; this.scratchTop = savedTop }
      this.ds = savedDs; this.rs = savedRs; this.frames = savedFr
      throw e
    } finally { this.depth-- }
    this.ds = [...callerDs, ...results]
    this.rs = savedRs; this.frames = savedFr
    if (outMax > 0) this.pushSpan(emitted)                     // the channel comes back as ( c-addr u ), above the outputs
  }
}

// ⚠⚠ SYMMETRIC division (truncate toward zero): BigInt's own, and the remainder takes the sign of the DIVIDEND.
function divT(a, b) { if (b === 0n) throw new JfScriptError('division by zero'); return a / b }
function modT(a, b) { if (b === 0n) throw new JfScriptError('division by zero'); return a % b }

/** H(result) = sha256( for each cell: 8 bytes little-endian ) — the §2b comparison hash for `JF`. */
export function jf_stack_hash(cells, sha256) {
  const b = new Uint8Array(cells.length * 8)
  cells.forEach((c, k) => { let u = uns(c); for (let j = 0; j < 8; j++) { b[k * 8 + j] = Number(u & 0xffn); u >>= 8n } })
  return sha256(b)
}
