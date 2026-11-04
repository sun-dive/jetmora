// © 2026 sun-dive — Apache License 2.0.
/**
 * BASIC → jetForth: the compiler for jetmora's covenants.
 *
 * jetmora BASIC is an easy way to write jetForth, as Bitcoin BASIC is an easy way to write Bitcoin
 * Script: the methods of writing a covenant by hand, behind a BASIC front end. The language is BRC-173,
 * the one the Bitcoin compiler takes. Its lexer and parser are copied from grafverse/mint/src/basic.ts
 * (BASIC_VERSION 1.0), which is never edited from here. The emitter writes what the hand-written jetForth
 * covenants do (server/verify-wired.php):
 *
 *   values      a number is one 64-bit cell; bytes are two cells, ( c-addr u ), the bytes in memory
 *   variables   cells at fixed addresses, chosen when compiling: `addr @`, `addr !`; bytes `addr 2@`, `addr 2!`
 *   bytes made  CAT, NUM2BIN, the hashes, PREIMAGE and the preimage's byte fields each write to their own fixed place
 *   loops       FOR … NEXT is a loop that branches back to its test. It is never unrolled
 *   truth       a comparison gives -1 or 0: jetForth's TRUE, every bit set
 *
 * THE HARD RULE carries over from basic.ts as it stands:
 *   1. the compiled script says what the program says: `x = 2 * 3 + 4` emits a multiply and an add;
 *   2. fold only what jetForth cannot express — today nothing: `^` is a multiply loop;
 *   3. never improve a released version in place: a new version, proved against the old one.
 *
 * A program names its version as its first statement, `VERSION JF 3`, and the compiler refuses one it
 * does not emit. The line compiles to the lock's declaration, VER and the version's four bytes, D1 03 00 4A 46:
 * the script's first five bytes, a covenant's and a program's alike. A host reads it before it runs anything
 * and runs the engine it names, and a tick must name that same version. Every result carries it as `nVersion`.
 *
 * ── A COVENANT ─────────────────────────────────────────────────────────────────────────────────────
 * The compiler writes the script once. Every rule a tick must meet is in it, and each tick the script
 * rebuilds itself into the new tip, as a Bitcoin covenant rebuilds itself into its next output:
 *
 *   VER JF 3        the declaration, carried into every successor unchanged
 *   <f0> … <fn>     the DIM fields: the thread's state, as pushes at the head of the script
 *   the frame       bind the fields and the inputs, check each input's size; then rules 1 and 2: signed by
 *                   the owner over HASH256(PREIMAGE); value + 1, and nSequence equal to it; then the next
 *                   output, made in one place: value + 1, then this script copied once
 *   the program     the covenant's own rules; it may assign the fields. A $ field it assigns once, with
 *                   bytes of the field's width, it writes in its place in the next output
 *   the rebuild     rules 3 and 4: each other field the program writes, written over its place; and
 *                   HASH256 of the next output is the tick's hashOutputs
 *
 * The signature, the key, value + 1 and the next output are kept on the stack, never in memory: the frame reads
 * each from where it lies, and the program's statements leave the stack as they find it.
 *
 * A tick is run as its unlocking script (byte pushes only) followed by this one, and is accepted when
 * it leaves exactly one non-zero cell: the rebuild's last check, the next output's hash against hashOutputs.
 * Every other check is one comparison and one abort (Emitter.verify).
 *
 * INPUT names what a tick carries: the pushes its unlocking script makes after the signature and the key,
 * in the order INPUT names them, bound to variables before the program runs. `code$` is bytes of any
 * length, `code$32` exactly 32 bytes; `r%2` is a number, a push of at most 2 bytes read as BIN2NUM reads
 * it, unsigned; `r%` is at most 8, a cell. The owner signs the preimage, which holds the successor
 * (hashOutputs) and not the unlocking script: an input is signed through what the program makes of it in
 * the successor's state, and only so.
 *
 * A program may check a signature, as the frame checks the owner's: `ED25519SIG(sig, pub, msg)` is Ed25519 over
 * the message as given, -1 or 0. A tick makes at most 100 signature checks, the frame's among them: JF revision 3's
 * limit, counted by the interpreter as each runs.
 */
import { JF_PUSH_MAX, JF_SMALL0, JF_LIT, JF_WORD } from '../tools/ops-jf.mjs'

/** The version of this compiler. A script's bytes are a function of it. */
export const BASIC_JF_VERSION = '0.8'

/** The JF revision the bytes are numbered in: tools/ops-jf.mjs, revision 3. */
export const JF_REVISION = 3
/**
 * The version the script declares, and an entry spending it names, so the JF revision 3 interpreter runs it
 * (spec §6b, server/dispatch.php): family `JF`, revision 3, on the wire `03 00 4A 46`.
 */
export const JF_NVERSION = ((0x46 << 24) | (0x4a << 16) | JF_REVISION) >>> 0
/** The lock's declaration, `VER JF 3`: VER and the four bytes of JF_NVERSION as the wire carries them. The script's first five bytes. */
export const DECLARATION = Object.freeze([JF_WORD.VER, JF_NVERSION & 0xff, (JF_NVERSION >>> 8) & 0xff,
                                          (JF_NVERSION >>> 16) & 0xff, JF_NVERSION >>> 24])

/** 1.0 in the project's fixed point — 2^32, as in basic.ts. */
export const BASIC_S = 2n ** 32n
/** A number as written, exactly: a cell holds whole numbers, so a fraction is refused rather than rounded. */
const exact = raw => {
  if (!/^\d+$/.test(raw)) throw new Error(`BASIC: ${raw} is not a whole number, and a jetForth cell holds whole numbers`)
  return BigInt(raw)
}
/** A constant the caller supplies, exactly as for a written number. */
const exactConst = (name, v) => {
  if (typeof v === 'bigint') return v
  if (Number.isSafeInteger(v)) return BigInt(v)
  throw new Error(`BASIC: the constant ${name} is ${v}, and a jetForth cell holds whole numbers (give a large one as a BigInt)`)
}

const I64_MAX = (1n << 63n) - 1n

// ── tokens ───────────────────────────────────────────────────────────────────────────────────────────
// ⇩ from basic.ts, unchanged in behaviour.

const KEYWORDS = new Set([
  'LET', 'IF', 'THEN', 'ELSE', 'REM', 'AND', 'OR', 'NOT',
  'FOR', 'TO', 'STEP', 'NEXT', 'DIM', 'VERIFY', 'END', 'ENDIF',
  'VERSION',
])

/**
 * Case-insensitive keywords, case-sensitive names. `IF`/`if` are the same word; `v` and `V` are not the
 * same variable.
 * @returns {{k: string, v: string, n?: number, d?: number[]}[]}
 */
function lex(src, internal = false) {
  const out = []
  let i = 0
  while (i < src.length) {
    const c = src[i]
    /* The newline is a token: an `IF … THEN … ELSE …` is line-scoped, its arms end where the line does. */
    if (c === '\n') {
      if (out.length && out[out.length - 1].k !== 'eol') out.push({ k: 'eol', v: '\n' })
      i++; continue
    }
    if (c === ' ' || c === '\t' || c === '\r') { i++; continue }
    if (c === "'") { while (i < src.length && src[i] !== '\n') i++; continue }        // ' comment
    /* `&H` is BASIC's own hex, and it means BYTES: a covenant's literals are hashes and keys. `$` is
       already the DIM sigil, so it cannot be the hex prefix too. */
    if ((c === '&') && /[Hh]/.test(src[i + 1] ?? '')) {
      let j = i + 2
      while (j < src.length && /[0-9a-fA-F]/.test(src[j])) j++
      const h = src.slice(i + 2, j)
      if (!h.length || h.length % 2) {
        throw new Error(`BASIC: &H${h}: a hex literal is whole BYTES, so it needs an even number of digits`)
      }
      const d = []
      for (let k = 0; k < h.length; k += 2) d.push(parseInt(h.slice(k, k + 2), 16))
      out.push({ k: 'hex', v: h, d }); i = j; continue
    }
    if (/[0-9]/.test(c)) {
      let j = i; while (j < src.length && /[0-9._]/.test(src[j])) j++
      const raw = src.slice(i, j).replace(/_/g, '')
      out.push({ k: 'num', v: raw, n: Number(raw) }); i = j; continue
    }
    if (/[A-Za-z]/.test(c) || (internal && c === '#')) {
      let j = i + 1; while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++
      const w = src.slice(i, j)
      const up = w.toUpperCase()
      if (up === 'REM') { while (i < src.length && src[i] !== '\n') i++; continue }
      out.push(KEYWORDS.has(up) ? { k: 'kw', v: up } : { k: 'name', v: w })
      i = j; continue
    }
    const two = src.slice(i, i + 2)
    if (two === '<=' || two === '>=' || two === '<>') { out.push({ k: 'op', v: two }); i += 2; continue }
    /* `%` and `$` are BASIC's own sigils and they are not operators here. */
    if ('+-*/()<>=,:%$^'.includes(c)) { out.push({ k: 'op', v: c }); i++; continue }
    throw new Error(`BASIC: what is ${JSON.stringify(c)}? (at ${i})`)
  }
  return out
}

// ── the parser: precedence climbing ─────────────────────────────────────────────────────────────────
/**
 * @typedef {{t:'num', v:number} | {t:'bytes', d:number[]} | {t:'var', v:string}
 *   | {t:'bin', op:string, l:Expr, r:Expr} | {t:'call', f:string, a:Expr[]} | {t:'neg', e:Expr}} Expr
 */

/** Binding power. Comparisons bind loosest, then + −, then * /, then `^`. */
const BP = {
  'OR': 1, 'AND': 2,
  '=': 3, '<>': 3, '<': 3, '>': 3, '<=': 3, '>=': 3,
  '+': 4, '-': 4,
  '*': 5, '/': 5,
  '^': 6,
}
/** Right-associative: 2^3^2 is 2^9. */
const RIGHT = new Set(['^'])

class Parser {
  constructor(t) { this.t = t; this.p = 0 }
  peek() { return this.t[this.p] }
  /** One token further on — needed only to tell `NEXT i` from `NEXT` followed by `i = …`. */
  peekAt(k) { return this.t[this.p + k] }
  next() { return this.t[this.p++] }
  eat(v) {
    const t = this.peek()
    if (t && (t.v === v)) { this.p++; return true }
    return false
  }
  expect(v) {
    if (this.eat(v)) return
    const t = this.peek()?.v
    throw new Error(`BASIC: expected ${v}, found ${t === undefined ? 'the end' : t === '\n' ? 'the end of the line' : t}`)
  }
  atEnd() { return this.p >= this.t.length }

  expr(min = 0) {
    let left = this.atom()
    for (;;) {
      const t = this.peek()
      if (!t || (t.k !== 'op' && t.k !== 'kw')) break
      const bp = BP[t.v]
      if (bp === undefined || bp < min) break
      this.next()
      const right = this.expr(RIGHT.has(t.v) ? bp : bp + 1)
      left = { t: 'bin', op: t.v, l: left, r: right }
    }
    return left
  }

  atom() {
    const t = this.next()
    if (!t) throw new Error('BASIC: expression ended early')
    if (t.k === 'num') return { t: 'num', v: exact(t.v) }
    if (t.k === 'hex') return { t: 'bytes', d: t.d }
    /* NOT is a keyword, so it is a prefix word here rather than an entry in the function table. */
    if (t.k === 'kw' && t.v === 'NOT') return { t: 'call', f: 'NOT', a: [this.atom()] }
    if (t.v === '-') return { t: 'neg', e: this.atom() }
    if (t.v === '(') { const e = this.expr(); this.expect(')'); return e }
    if (t.k === 'name') {
      if (this.eat('(')) {
        const args = []
        if (!this.eat(')')) {
          do { args.push(this.expr()) } while (this.eat(','))
          this.expect(')')
        }
        return { t: 'call', f: t.v.toUpperCase(), a: args }
      }
      return { t: 'var', v: t.v }
    }
    throw new Error(`BASIC: ${t.v} cannot start an expression`)
  }
}

// ── statements ───────────────────────────────────────────────────────────────────────────────────────
/**
 * @typedef {{t:'let', name:string, e:Expr} | {t:'if', cond:Expr, then:Stmt[], else:Stmt[]}
 *   | {t:'for', name:string, from:Expr, to:Expr, step:Expr|null, body:Stmt[]} | {t:'dim', fields:object[]}
 *   | {t:'verify', e:Expr} | {t:'split', left:string, right:string, of:Expr, at:Expr}} Stmt
 */

/** `lineScoped` makes an IF behave like BASIC's: its arms end at the end of the line. */
function parseStmts(p, stopAt, lineScoped = false) {
  const out = []
  for (;;) {
    p.eat(':')
    let t = p.peek()
    if (t && t.k === 'eol') {
      if (lineScoped) break                              // ← the IF's arm ends here
      while (p.peek()?.k === 'eol') p.next()
      t = p.peek()
    }
    if (!t) break
    if (t.k === 'kw' && stopAt.includes(t.v)) break
    /* A leading number is a line number and labels nothing. Not inside an IF arm: `IF x THEN 100` means
       GOTO 100, which this compiler cannot do, so there it stays an error. */
    if (!lineScoped && t.k === 'num') { p.next(); continue }
    if (t.k === 'kw' && t.v === 'LET') { p.next(); out.push(letStmt(p)); continue }
    if (t.k === 'kw' && t.v === 'IF') { p.next(); out.push(ifStmt(p)); continue }
    if (t.k === 'kw' && t.v === 'FOR') {
      /* A FOR spans lines and a line-scoped IF arm does not. */
      if (lineScoped) {
        throw new Error('BASIC: a FOR cannot open inside an IF arm: an IF is line-scoped, so its arms ' +
          'end where the line does, and a FOR does not. Put the FOR on its own line.')
      }
      p.next(); out.push(forStmt(p)); continue
    }
    if (t.k === 'kw' && t.v === 'NEXT') throw new Error('BASIC: a NEXT with no FOR to close')
    if (t.k === 'kw' && t.v === 'VERIFY') { p.next(); out.push({ t: 'verify', e: p.expr() }); continue }
    if (t.k === 'kw' && (t.v === 'END' || t.v === 'ENDIF')) {
      throw new Error(`BASIC: ${t.v === 'END' ? 'END IF' : 'ENDIF'} with no open IF block to close`)
    }
    if (t.k === 'kw' && t.v === 'DIM') {
      if (lineScoped) throw new Error('BASIC: DIM declares the script\'s layout: it cannot sit inside an IF')
      p.next(); out.push(dimStmt(p)); continue
    }
    if (t.k === 'kw' && t.v === 'VERSION') { p.next(); out.push(versionStmt(p)); continue }
    /* INPUT is a statement only where a name follows it, so a variable named `input` means what it did. */
    if (t.k === 'name' && t.v.toUpperCase() === 'INPUT' && p.peekAt(1)?.k === 'name') {
      if (lineScoped) throw new Error('BASIC: INPUT names what a tick carries: it cannot sit inside an IF')
      p.next(); out.push(inputStmt(p)); continue
    }
    if (t.k === 'name') { out.push(letStmt(p)); continue }       // LET is optional
    throw new Error(`BASIC: ${t.v} cannot start a statement`)
  }
  return out
}

function letStmt(p) {
  const n = p.next()
  if (!n || n.k !== 'name') throw new Error('BASIC: LET wants a variable name')
  /* Two names on the left, because SPLIT produces two values and no expression can stand for both. */
  if (p.eat(',')) {
    const n2 = p.next()
    if (!n2 || n2.k !== 'name') throw new Error('BASIC: two names on the left, and the second is missing')
    if (n2.v === n.v) throw new Error(`BASIC: ${n.v}, ${n.v} = SPLIT(…): the halves need different names`)
    p.expect('=')
    const e = p.expr()
    if (e.t !== 'call' || e.f !== 'SPLIT' || e.a.length !== 2) {
      throw new Error(`BASIC: ${n.v}, ${n2.v} = … needs SPLIT(bytes, at) on the right: it is the only ` +
        'word that produces two values, a left half and a right half')
    }
    return { t: 'split', left: n.v, right: n2.v, of: e.a[0], at: e.a[1] }
  }
  p.expect('=')
  return { t: 'let', name: n.v, e: p.expr() }
}

/**
 * `IF … THEN` in both of BASIC's shapes: one line, whose arms end with the line, or a block closed by
 * END IF. Which one turns on whether anything follows THEN on that line.
 */
function ifStmt(p) {
  const cond = p.expr()
  p.expect('THEN')
  if (p.peek()?.k === 'eol' || !p.peek()) {
    const thn = parseStmts(p, ['ELSE', 'END', 'ENDIF'])
    const els = p.eat('ELSE') ? parseStmts(p, ['END', 'ENDIF']) : []
    if (!p.eat('ENDIF')) {
      if (!p.eat('END')) throw new Error('BASIC: an IF written as a block has to be closed by END IF')
      if (!p.eat('IF')) throw new Error('BASIC: END on its own: did you mean END IF?')
    }
    return { t: 'if', cond, then: thn, else: els }
  }
  const thn = parseStmts(p, ['ELSE'], true)
  const els = p.eat('ELSE') ? parseStmts(p, [], true) : []
  return { t: 'if', cond, then: thn, else: els }
}

/** `DIM v%5, tag$20` — the state layout, widths in bytes. Parsed here; see compileBasic for its status. */
function dimStmt(p) {
  const fields = []
  do {
    const n = p.next()
    if (!n || n.k !== 'name') throw new Error('BASIC: DIM wants a name: DIM v%5')
    const sig = p.next()
    if (!sig || (sig.v !== '%' && sig.v !== '$')) {
      throw new Error(`BASIC: DIM ${n.v} needs a WIDTH: ${n.v}%5 for a five-byte number, ${n.v}$20 for ` +
        'twenty raw bytes. A field is a layout, and a layout has a size.')
    }
    const w = p.next()
    if (!w || w.k !== 'num' || !Number.isInteger(w.n) || w.n < 1 || w.n > 0xffff) {
      throw new Error(`BASIC: DIM ${n.v}: the width must be a whole number of bytes from 1 to 65535, the most one push holds`)
    }
    fields.push({ name: n.v, width: w.n, bytes: sig.v === '$' })
  } while (p.eat(','))
  return { t: 'dim', fields }
}

/**
 * `INPUT code$, h$32, r%2`: what a covenant's tick carries after the signature and the key, in this order,
 * widths in bytes. A `$` input is bytes, that many or any number; a `%` input is a number, a push of at most
 * that many bytes, 8 when no width is given.
 */
function inputStmt(p) {
  const inputs = []
  do {
    const n = p.next()
    if (!n || n.k !== 'name') throw new Error('BASIC: INPUT wants a name: INPUT code$, r%2')
    const sig = p.next()
    if (!sig || (sig.v !== '%' && sig.v !== '$')) {
      throw new Error(`BASIC: INPUT ${n.v} needs a sigil: ${n.v}$ for bytes, ${n.v}%2 for a number of at most two bytes`)
    }
    let width = null
    if (p.peek()?.k === 'num') {
      const w = p.next(), most = sig.v === '%' ? INPUT_WIDEST.number : INPUT_WIDEST.bytes
      if (!Number.isInteger(w.n) || w.n < 1 || w.n > most) {
        throw new Error(`BASIC: INPUT ${n.v}${sig.v}: the width must be a whole number of bytes from 1 to ${most}, ` +
          (sig.v === '%' ? 'as a number is a 64-bit cell' : 'what the push space holds'))
      }
      width = w.n
    }
    inputs.push({ name: n.v, width: sig.v === '%' ? width ?? 8 : width, bytes: sig.v === '$' })
  } while (p.eat(','))
  return { t: 'input', inputs }
}

/** `FOR i = <from> TO <to> [STEP <s>] … NEXT [i]` — the body runs to NEXT, however many lines. */
function forStmt(p) {
  const n = p.next()
  if (!n || n.k !== 'name') throw new Error('BASIC: FOR wants a counter name: FOR i = 0 TO 9')
  p.expect('=')
  const from = p.expr()
  p.expect('TO')
  const to = p.expr()
  const step = p.eat('STEP') ? p.expr() : null
  const body = parseStmts(p, ['NEXT'])
  if (!p.eat('NEXT')) throw new Error(`BASIC: FOR ${n.v} is never closed by a NEXT`)
  /* `NEXT i` names the loop it closes; a bare `NEXT` is allowed too. Only swallow the name when it cannot
     be the start of the next statement — `NEXT` then `i = 1` on one line is legal. */
  const after = p.peek()
  if (after && after.k === 'name' && p.peekAt(1)?.v !== '=') {
    p.next()
    if (after.v !== n.v) throw new Error(`BASIC: NEXT ${after.v} closes a FOR ${after.v}, but the open loop is ${n.v}`)
  }
  return { t: 'for', name: n.v, from, to, step, body }
}

/** `VERSION JF 3` — the instruction set and revision the program is written for: the nVersion its entries name. */
function versionStmt(p) {
  const f = p.next(), r = p.next()
  if (!f || f.k !== 'name' || !/^[A-Z0-9]{2}$/.test(f.v) || !r || r.k !== 'num' || !Number.isInteger(r.n)) {
    throw new Error('BASIC: VERSION names an instruction set and its revision: VERSION JF 3')
  }
  return { t: 'version', family: f.v, revision: r.n }
}

function parseProgram(src, internal = false) {
  const p = new Parser(lex(src, internal))
  const prog = parseStmts(p, [])
  if (!p.atEnd()) throw new Error(`BASIC: stopped making sense at ${p.peek()?.v}`)
  return prog
}
// ⇧ from basic.ts.

// ── the bytecode, assembled ─────────────────────────────────────────────────────────────────────────
const W = name => {
  const b = JF_WORD[name]
  if (b === undefined) throw new Error(`no jetForth word ${name}`)
  return b
}
const le = (v, n) => { const o = []; let u = v < 0n ? v + (1n << BigInt(8 * n)) : v
  for (let k = 0; k < n; k++) { o.push(Number(u & 0xffn)); u >>= 8n } return o }

/** Instructions and labels. Every instruction's size is known when it is laid down, so one pass places the labels. */
class Code {
  constructor() { this.parts = []; this.nlab = 0 }
  bytes(...b) { this.parts.push(b) }
  /** A word. SWAP SWAP and 2SWAP 2SWAP undo each other, as when values are taken from the stack in the order they lie:
   *  the second takes the first back. A label between them would be a place a branch lands, and keeps both. */
  word(name) {
    const last = this.parts.at(-1)
    if ((name === 'SWAP' || name === '2SWAP') && Array.isArray(last) && last.length === 1 && last[0] === W(name)) { this.parts.pop(); return }
    this.bytes(W(name))
  }
  /** The smallest form that holds v. A negative constant is its magnitude and NEGATE, as `-5` is written. */
  num(v) {
    v = BigInt(v)
    if (v < 0n) { this.num(-v); this.word('NEGATE'); return }
    if (v > I64_MAX) throw new Error(`BASIC: ${v} is past what a 64-bit cell holds`)
    if (v <= 8n) this.bytes(JF_SMALL0 + Number(v))
    else if (v <= 0x7fn) this.bytes(JF_LIT.LIT8, ...le(v, 1))
    else if (v <= 0x7fffn) this.bytes(JF_LIT.LIT16, ...le(v, 2))
    else if (v <= 0x7fffffffn) this.bytes(JF_LIT.LIT32, ...le(v, 4))
    else this.bytes(JF_LIT.LIT64, ...le(v, 8))
  }
  /** A byte literal: a direct push to 72 bytes, then STR8 and STR16. Leaves ( c-addr u ). */
  push(d) {
    this.pushed = (this.pushed ?? 0) + d.length
    if (d.length <= JF_PUSH_MAX) this.bytes(d.length, ...d)
    else if (d.length <= 0xff) this.bytes(JF_LIT.STR8, d.length, ...d)
    else if (d.length <= 0xffff) this.bytes(JF_LIT.STR16, ...le(BigInt(d.length), 2), ...d)
    else throw new Error('BASIC: a byte literal over 65535 bytes')
  }
  /** `(ABORT")` with an empty message: refuse when the flag on top is non-zero. */
  abortIf() { this.bytes(W('(ABORT")'), 0) }
  label() { return this.nlab++ }
  place(l) { this.parts.push({ place: l }) }
  branch(name, l) { this.parts.push({ branch: W(name), to: l }) }

  assemble() {
    const at = new Map(); let pos = 0
    for (const p of this.parts) {
      if (p.place !== undefined) at.set(p.place, pos)
      else pos += p.branch !== undefined ? 3 : p.length
    }
    const out = []
    for (const p of this.parts) {
      if (p.place !== undefined) continue
      if (p.branch === undefined) { out.push(...p); continue }
      const off = at.get(p.to) - (out.length + 3)
      if (off < -0x8000 || off > 0x7fff) throw new Error('BASIC: a branch longer than 32 KB')
      out.push(p.branch, ...le(BigInt(off), 2))
    }
    return out
  }
}

// ── emission ─────────────────────────────────────────────────────────────────────────────────────────
/** Words on numbers: name → [jetForth word, arity, result]. A flag is a number that is -1 or 0. */
const NUMWORD = {
  ABS: ['ABS', 1, 'num'], NEGATE: ['NEGATE', 1, 'num'], INVERT: ['INVERT', 1, 'num'],
  NOT: ['0=', 1, 'flag'], ISTRUE: ['0<>', 1, 'flag'],
  MIN: ['MIN', 2, 'num'], MAX: ['MAX', 2, 'num'], MOD: ['MOD', 2, 'num'],
  BITAND: ['AND', 2, 'num'], BITOR: ['OR', 2, 'num'], BITXOR: ['XOR', 2, 'num'],
  LSHIFT: ['LSHIFT', 2, 'num'], RSHIFT: ['RSHIFT', 2, 'num'],
  WITHIN: ['WITHIN', 3, 'flag'],
}
/** The hashes, and the size of what each writes. */
const HASHES = { SHA256: 32, HASH256: 32, HASH160: 20, RIPEMD160: 20, SHA1: 20 }
const ARITH = { '+': '+', '-': '-', '*': '*', '/': '/' }
const CMP = { '=': '=', '<>': '<>', '<': '<', '>': '>' }
/** The word that is true when a comparison is false, where jetForth has one */
const OPPOSITE = { '=': '<>', '<>': '=', '<=': '>', '>=': '<' }

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
/** The larger of two lengths; unknown if either is. */
const join = (a, b) => (a === null || b === null ? null : Math.max(a, b))
const isNum = t => t === 'num' || t === 'flag'
const findVersion = ss => ss.some(s => s.t === 'version'
  || (s.t === 'if' && (findVersion(s.then) || findVersion(s.else))) || (s.t === 'for' && findVersion(s.body)))

/** Which variables a block assigns. A FOR counter is left out: the IF rule below is about the program's values. */
function assignedBy(ss, into) {
  for (const s of ss) {
    if (s.t === 'let') into.add(s.name)
    else if (s.t === 'split') { into.add(s.left); into.add(s.right) }
    else if (s.t === 'for') assignedBy(s.body, into)
    else if (s.t === 'verify' || s.t === 'dim' || s.t === 'version' || s.t === 'input') continue
    else { assignedBy(s.then, into); assignedBy(s.else, into) }
  }
}
/** Every name a block writes, FOR counters too. */
function writes(ss, into) {
  for (const s of ss) {
    if (s.t === 'for') { into.add(s.name); writes(s.body, into) }
    else if (s.t === 'if') { writes(s.then, into); writes(s.else, into) }
    else if (s.t === 'let' || s.t === 'split') assignedBy([s], into)
  }
}
/** INPUT is a declaration, as DIM is: the program's variables it names are bound before the program runs. */
const INPUT_FIRST = 'BASIC: every INPUT comes before the first statement that runs: what the tick carries is bound ' +
  'before anything reads it'

/**
 * Memory, laid out when compiling, from 0 up, so most addresses are one-byte literals (LIT8 is signed: below 128):
 *   the variables named before the program runs   a covenant's fields, its inputs and the frame's own; what a program
 *                                                 finds on the stack
 *   a covenant's next output                      made by the frame, written in by the program and the rebuild; until
 *                                                 it is made, the frame's checks use it as scratch
 *   the scratch                                   bytes a word makes for the statement it is in: each statement uses it
 *                                                 from its start again. A hash reads all it hashes before it writes, so
 *                                                 it writes over its input when that was made in the scratch
 *   the program's variables, and the bytes kept   bytes a statement assigns or SPLITs stay where they were made
 * The scratch's size is the most any statement uses, measured by compiling, so a script is compiled until it holds.
 * The frame and the rebuild use only the first three: their bytes are the same whatever the program is. Pushed bytes
 * are not in this memory: the interpreter keeps them in a push space of their own, read-only.
 */
/** JF revision 3's program memory and push space, and the signature and key a covenant's tick pushes. */
const MEMORY = 65536, PUSH_MEM = 65536, TICK_PUSHES = 64 + 32
/** The widths INPUT gives, in bytes, from 1: a % input at most a cell, a $ input at most what the push space holds */
export const INPUT_WIDEST = Object.freeze({ number: 8, bytes: PUSH_MEM })

/**
 * Emits statements into `code`, allocating every variable and every made byte string a fixed address.
 * @typedef {{ name: string, addr: number, type: 'num'|'bytes', max: number|null }} Var
 */
class Emitter {
  /** `scratch` is the scratch's size, as the last compile of this script measured it. */
  constructor(consts = {}, scratch = 0) {
    this.consts = consts
    /** @type {Map<string, Var>} */
    this.vars = new Map()
    this.next = 0                // the next free address for a variable, or for bytes kept
    this.scratch = scratch
    this.scratchAt = null        // where the scratch starts, once the variables before the program are laid out
    this.top = null              // the next free scratch address in this statement
    this.used = 0                // the most scratch a statement has used in this compile
    this.code = new Code()
    this.loops = 0               // how many FOR bodies deep
    this.open = new Set()        // FOR counters whose loops are open
    this.hidden = 0
    this.internal = false        // emitting the frame: its own words and names are allowed
    this.preMax = 0
    this.assigned = []
    this.loopMax = []            // per open FOR: the longest a byte string can be inside it
    this.held = []               // the frame's values kept on the stack, the bottom first
    this.above = 0               // how many cells the statement being emitted has above them
    this.places = new Map()      // a $ field the program writes in its place in the next output → { at, width, bare }
  }
  declare(name, type, max = null) {
    const addr = this.next
    this.next += type === 'bytes' ? 16 : 8
    const v = { name, addr, type: type === 'bytes' ? 'bytes' : 'num', max }
    this.vars.set(name, v)
    return v
  }
  /** One of the frame's values that is kept on the stack and never in memory: `reads` counts down to its last read. */
  holdVar(name, type, max = null) {
    const v = { name, held: true, type: type === 'bytes' ? 'bytes' : 'num', max, reads: 0 }
    this.vars.set(name, v)
    return v
  }
  /** A held value is on top of the stack, read `reads` times from here. */
  hold(v, r, reads) {
    if (!(reads > 0)) throw new Error(`BASIC: the frame keeps ${v.name} on the stack and never reads it`)
    v.reads = reads; v.max = r.max; this.held.push(v)
  }
  /**
   * A held value, read: copied when it is read again later (DUP, OVER or PICK; 2DUP, 2OVER or two PICKs for bytes),
   * taken when this is its last read (nothing when it is on top; SWAP, ROT or ROLL; 2SWAP or two ROLLs for bytes).
   * Its depth is the held values above it and the cells this statement has pushed.
   */
  takeHeld(v) {
    const c = this.code, i = this.held.indexOf(v)
    if (i < 0) throw new Error(`BASIC: the frame reads ${v.name} past its last read`)
    const cells = x => (x.type === 'bytes' ? 2 : 1)
    let d = this.above
    for (let j = i + 1; j < this.held.length; j++) d += cells(this.held[j])
    const last = --v.reads === 0
    const pick = (word, k) => { c.num(k); c.word(word) }
    if (v.type === 'num') {
      if (last) { if (d === 1) c.word('SWAP'); else if (d === 2) c.word('ROT'); else if (d > 2) pick('ROLL', d) }
      else if (d === 0) c.word('DUP'); else if (d === 1) c.word('OVER'); else pick('PICK', d)
    } else if (last) { if (d === 2) c.word('2SWAP'); else if (d > 0) { pick('ROLL', d + 1); pick('ROLL', d + 1) } }
    else if (d === 0) c.word('2DUP'); else if (d === 2) c.word('2OVER'); else { pick('PICK', d + 1); pick('PICK', d + 1) }
    if (last) this.held.splice(i, 1)
    return { t: v.type, max: v.max }
  }
  /** The variables before the program are laid out: the scratch starts here, and what comes later goes past it. */
  layScratch() { this.scratchAt = this.top = this.next; this.next += this.scratch }
  /** A statement starts: the scratch is free again, from `early` while that is set. */
  freeScratch() { if (this.scratchAt !== null) this.top = this.early ?? this.scratchAt }
  /** How much memory the script uses: up to the last thing laid out, or the scratch's end if that is further. */
  memory() { return Math.max(this.next, (this.scratchAt ?? 0) + this.used) }
  /**
   * A fixed place for a byte string a word makes: in the scratch, or past it when `kept`, for bytes a statement
   * assigns. Inside a loop the place would be rewritten every trip.
   */
  site(n, what, kept = false) {
    if (this.loops) {
      throw new Error(`BASIC: ${what} writes its bytes to a place fixed when the program is compiled, and inside a ` +
        'FOR loop it would write that place again on every trip: work it out before the loop')
    }
    if (n === null) throw new Error(`BASIC: ${what}: the length of what it is given is not known when compiling`)
    if (kept || this.scratchAt === null) { const a = this.next; this.next += n; return a }
    const a = this.top
    this.top += n; this.used = Math.max(this.used, this.top - this.scratchAt)
    return a
  }
  fetch(v) { this.code.num(v.addr); this.code.word(v.type === 'bytes' ? '2@' : '@') }
  store(v) { this.code.num(v.addr); this.code.word(v.type === 'bytes' ? '2!' : '!') }

  want(r, what, f) {
    if (what === 'num' && !isNum(r.t)) throw new Error(`BASIC: ${f} works on numbers, and this is bytes: BIN2NUM turns bytes into a number`)
    if (what === 'bytes' && r.t !== 'bytes') throw new Error(`BASIC: ${f} works on bytes, and this is a number: NUM2BIN turns a number into bytes`)
    return r
  }

  /** The value of an expression if it is knowable now — for the direction of a STEP and the width of NUM2BIN. */
  constEval(e) {
    const cell = v => {
      if (v > I64_MAX || v < -I64_MAX) throw new Error(`BASIC: ${v} is past what a 64-bit cell holds`)
      return v
    }
    switch (e.t) {
      case 'num': return cell(e.v)
      case 'var': return has(this.consts, e.v) ? cell(exactConst(e.v, this.consts[e.v])) : undefined
      case 'neg': { const x = this.constEval(e.e); return x === undefined ? undefined : -x }
      case 'bin': {
        if (!['+', '-', '*', '/', '^'].includes(e.op)) return undefined
        const l = this.constEval(e.l), r = this.constEval(e.r)
        if (l === undefined || r === undefined) return undefined
        switch (e.op) {
          case '+': return cell(l + r)
          case '-': return cell(l - r)
          case '*': return cell(l * r)
          case '/':
            if (r === 0n) throw new Error('BASIC: a division by zero the compiler can already see: the tick would fail')
            return l / r
          case '^':
            if (r < 0n) throw new Error(`BASIC: ${l} ^ ${r}: a negative power is not a whole number`)
            if (r > 64n && (l > 1n || l < -1n)) throw new Error(`BASIC: ${l} ^ ${r} is past what a 64-bit cell holds`)
            return cell(l ** r)
        }
      }
    }
    return undefined
  }

  /**
   * Emit an expression. `kept`: bytes it makes are kept past the scratch. `into`: { at, bare }, the place the statement
   * gives the bytes the expression's word makes, and with `bare` they are not left on the stack.
   * @returns {{ t: 'num'|'flag'|'bytes', max?: number|null }}
   */
  emit(e, kept = false, into = null) {
    const above = this.above
    try { return this.emitAt(e, kept, into) } finally { this.above = above }
  }
  /** An argument of a word: what it leaves stays on the stack, under what is emitted next. */
  arg(x, what, f) {
    const r = this.want(this.emit(x), what, f)
    this.above += r.t === 'bytes' ? 2 : 1
    return r
  }
  /** Where a word writes the bytes it makes: the statement's place, or a site. */
  dest(n, what, kept, into) { return into ? into.at : this.site(n, what, kept) }
  /** What a word that makes bytes leaves, ( d u ) on the stack: dropped when the statement says. */
  made(into) { if (into?.bare) this.code.word('2DROP') }

  emitAt(e, kept, into) {
    const c = this.code
    switch (e.t) {
      case 'num': if (e.v > I64_MAX) throw new Error(`BASIC: ${e.v} is past what a 64-bit cell holds`)
        c.num(e.v); return { t: 'num' }
      case 'bytes':
        if (this.loops) {
          throw new Error('BASIC: a byte literal is copied into the push space each time it runs, and inside a FOR loop ' +
            'that is every trip: give it a name before the loop')
        }
        c.push(e.d); return { t: 'bytes', max: e.d.length }
      case 'var': {
        if (has(this.consts, e.v)) { c.num(exactConst(e.v, this.consts[e.v])); return { t: 'num' } }
        const v = this.vars.get(e.v)
        if (!v || (e.v.startsWith('#') && !this.internal)) throw new Error(`BASIC: ${e.v} has no value here: assign it first`)
        if (v.held) return this.takeHeld(v)
        this.fetch(v)
        return { t: v.type, max: v.max }
      }
      case 'neg': this.arg(e.e, 'num', '-'); c.word('NEGATE'); return { t: 'num' }
      case 'bin': {
        /* `^` is a multiply loop, because JF revision 3 has no power word. jetForth can express a power,
           so nothing is folded: `2 ^ 8` is this loop too. A negative exponent is refused when it runs.
             ( b e )  DUP 0< (ABORT")  1 SWAP  0 (?DO) OVER * (LOOP)  NIP  ( b^e )                      */
        if (e.op === '^') {
          this.arg(e.l, 'num', '^'); this.arg(e.r, 'num', '^')
          c.word('DUP'); c.word('0<'); c.abortIf()
          c.num(1n); c.word('SWAP'); c.num(0n)
          const top = c.label(), end = c.label()
          c.branch('(?DO)', end)
          c.place(top); c.word('OVER'); c.word('*'); c.branch('(LOOP)', top)
          c.place(end); c.word('NIP')
          return { t: 'num' }
        }
        /* AND and OR are BASIC's: true when both (either) are non-zero. A value that is not already a
           flag is made one with 0<> first, so the bitwise word gives the logical answer. */
        if (e.op === 'AND' || e.op === 'OR') {
          for (const side of [e.l, e.r]) {
            const r = this.arg(side, 'num', e.op)
            if (r.t !== 'flag') c.word('0<>')
          }
          c.word(e.op); return { t: 'flag' }
        }
        this.arg(e.l, 'num', e.op)
        /* x + 1 and x - 1 are jetForth's 1+ and 1-: the same add, in one word */
        if ((e.op === '+' || e.op === '-') && e.r.t === 'num' && e.r.v === 1n) { c.word(e.op === '+' ? '1+' : '1-'); return { t: 'num' } }
        this.arg(e.r, 'num', e.op)
        if (ARITH[e.op]) { c.word(ARITH[e.op]); return { t: 'num' } }
        if (CMP[e.op]) { c.word(CMP[e.op]); return { t: 'flag' } }
        if (e.op === '<=') { c.word('>'); c.word('0='); return { t: 'flag' } }
        if (e.op === '>=') { c.word('<'); c.word('0='); return { t: 'flag' } }
        throw new Error(`BASIC: no jetForth word for ${e.op}`)
      }
      case 'call': {
        const f = e.f
        const need = n => { if (e.a.length !== n) throw new Error(`BASIC: ${f} takes ${n} argument(s), got ${e.a.length}`) }
        if (NUMWORD[f]) {
          const [w, n, t] = NUMWORD[f]
          need(n)
          for (const x of e.a) this.arg(x, 'num', f)
          c.word(w); return { t }
        }
        // trunc(x·y / 2^32) and trunc(x·2^32 / y). The word */ keeps the product at double width, which a
        // 64-bit cell needs: 1.0 × 1.0 is already 2^64.
        if (f === 'FMUL' || f === 'FDIV') {
          need(2)
          this.arg(e.a[0], 'num', f)
          if (f === 'FMUL') { this.arg(e.a[1], 'num', f); c.num(BASIC_S) }
          else { c.num(BASIC_S); this.above++; this.arg(e.a[1], 'num', f) }
          c.word('*/'); return { t: 'num' }
        }
        if (f === 'SIZE') { need(1); this.arg(e.a[0], 'bytes', f); c.word('NIP'); return { t: 'num' } }
        if (f === 'BIN2NUM') { need(1); this.arg(e.a[0], 'bytes', f); c.word('BIN2NUM'); return { t: 'num' } }
        if (f === 'SAMEBYTES') {
          need(2); this.arg(e.a[0], 'bytes', f); this.arg(e.a[1], 'bytes', f)
          c.word('BYTES='); return { t: 'flag' }
        }
        // the frame's next output, made in one place: see place()
        if (this.internal && (f === 'CAT' || f === 'REPLACE')) {
          need(f === 'CAT' ? 2 : 3)
          const r = this.place(e, this.dest(this.spanOf(e).max, f, kept, into), !into?.bare)
          return { t: 'bytes', max: r.max }
        }
        if (f === 'CAT') {
          need(2)
          const a = this.arg(e.a[0], 'bytes', f), b = this.arg(e.a[1], 'bytes', f)
          const max = a.max === null || b.max === null ? null : a.max + b.max
          c.num(this.dest(max, 'CAT', kept, into)); c.word('CAT'); this.made(into); return { t: 'bytes', max }
        }
        if (f === 'NUM2BIN') {
          need(2)
          const w = this.constEval(e.a[1])
          if (w === undefined) throw new Error('BASIC: NUM2BIN: the width has to be a number known when compiling, so its bytes have a place')
          if (w < 0n || w > 65536n) throw new Error(`BASIC: NUM2BIN: a width of ${w} bytes; it is 0 to 65536`)
          this.arg(e.a[0], 'num', f); this.arg(e.a[1], 'num', f)
          c.num(this.dest(Number(w), 'NUM2BIN', kept, into)); c.word('NUM2BIN'); this.made(into); return { t: 'bytes', max: Number(w) }
        }
        if (HASHES[f]) {
          need(1)
          /* A hash reads all it hashes before it writes. What its input made in the scratch is used up once it is hashed,
             and so is a held value read for the last time: the hash is written from where that began. */
          const x = e.a[0], hv = x.t === 'var' ? this.vars.get(x.v) : null
          const over = hv?.held && hv.at !== undefined && hv.reads === 1 ? hv.at : null
          const from = this.top
          this.arg(x, 'bytes', f)
          if (!kept && from !== null) this.top = from
          const d = into ? into.at : !kept && over !== null ? over : this.site(HASHES[f], f, kept)
          c.num(d); c.word(f)
          if (!into?.bare) { c.num(d); c.num(BigInt(HASHES[f])) }
          return { t: 'bytes', max: HASHES[f] }
        }
        /* Ed25519 over the message as given, the frame's check and a program's alike. A key that is not 32 bytes, or a
           signature that is not 64, is a failed check, never an error. */
        if (f === 'ED25519SIG') {
          need(3)
          for (const x of e.a) this.arg(x, 'bytes', f)
          c.word('ED25519-CHECKSIG'); return { t: 'flag' }
        }
        // the frame's own words
        if (this.internal && f === 'PREIMAGE') {
          need(0); c.num(this.site(this.preMax, 'PREIMAGE', kept)); c.word('PREIMAGE'); return { t: 'bytes', max: this.preMax }
        }
        if (this.internal && f === 'DEPTH') { need(0); c.word('DEPTH'); return { t: 'num' } }
        // the preimage's fields, each its own word: the value and nSequence as numbers; the scriptCode field (the
        // script, its length in front) and hashOutputs as bytes, each written to its own place
        if (this.internal && (f === 'TXVALUE' || f === 'NSEQUENCE')) { need(0); c.word(f); return { t: 'num' } }
        if (this.internal && (f === 'SCRIPTCODE' || f === 'OUTPUTS_HASH')) {
          const n = f === 'SCRIPTCODE' ? this.preMax - PREIMAGE_AROUND : 32
          need(0); c.num(this.site(n, f, kept)); c.word(f === 'SCRIPTCODE' ? 'SCRIPTCODE' : 'OUTPUTS-HASH'); return { t: 'bytes', max: n }
        }
        if (f === 'SPLIT') {
          throw new Error('BASIC: SPLIT gives back TWO values, a left half and a right half, so it ' +
            'needs two names: left, right = SPLIT(bytes, at)')
        }
        if (f === 'CHECKSIG') {
          throw new Error('BASIC: CHECKSIG: jetForth\'s takes the digest it checks as well as the signature ' +
            'and the key, so its BASIC form is still to be decided')
        }
        throw new Error(`BASIC: no such word: ${f}`)
      }
    }
  }

  /**
   * VERIFY: one comparison and one abort, `(ABORT")` refusing when the flag on top is non-zero. A comparison aborts on
   * its opposite where jetForth has one word for it: = on <>, <> on =, <= on >, >= on <. NOT(x) aborts on x itself.
   * Anything else, < and > among them, aborts when it is 0.
   */
  verify(e) {
    const c = this.code
    if (e.t === 'bin' && OPPOSITE[e.op]) {
      this.arg(e.l, 'num', e.op); this.arg(e.r, 'num', e.op); this.above -= 2
      c.word(OPPOSITE[e.op]); c.abortIf(); return
    }
    if (e.t === 'call' && e.f === 'NOT' && e.a.length === 1) { this.want(this.emit(e.a[0]), 'num', 'NOT'); c.abortIf(); return }
    this.want(this.emit(e), 'num', 'VERIFY'); c.word('0='); c.abortIf()
  }

  /** How long the frame's next output can be (`max`), and how long it is when that is known when compiling (`exact`). */
  spanOf(e) {
    if (e.t === 'call' && e.f === 'CAT') {
      const a = this.spanOf(e.a[0]), b = this.spanOf(e.a[1])
      return { max: a.max + b.max, exact: a.exact === undefined || b.exact === undefined ? undefined : a.exact + b.exact }
    }
    if (e.t === 'call' && e.f === 'REPLACE') return this.spanOf(e.a[0])
    if (e.t === 'call' && e.f === 'NUM2BIN') { const w = Number(this.constEval(e.a[1])); return { max: w, exact: w } }
    if (e.t === 'call' && e.f === 'SCRIPTCODE') return { max: this.preMax - PREIMAGE_AROUND }
    if (e.t === 'var' && this.vars.has(e.v)) return { max: this.vars.get(e.v).max }
    throw new Error('BASIC: the frame\'s next output is made of CAT, REPLACE, NUM2BIN, SCRIPTCODE and variables')
  }
  /**
   * The frame's next output, made where it belongs: `e`'s bytes are written from the address `d`, and ( d u ) left
   * when `keep`. CAT lays its halves end to end, the first of a length known when compiling. REPLACE(x, at, y) writes
   * y over x from `at`, in place: the frame checks y's size first. NUM2BIN and SCRIPTCODE write there themselves;
   * a held value already there is taken from the stack; any other variable's bytes are copied there with MOVE.
   */
  place(e, d, keep = true) {
    const c = this.code, s = this.spanOf(e), held = e.t === 'var' && this.vars.get(e.v)?.held && this.vars.get(e.v).at === d
    const under = n => { if (keep) this.above += n }               // ( d u ) kept stays under what is placed next
    if (e.f === 'CAT') {
      const a = this.spanOf(e.a[0])
      if (a.exact === undefined) throw new Error('BASIC: the frame\'s CAT: the first half\'s length is not known when compiling')
      this.place(e.a[0], d, keep); under(2); this.place(e.a[1], d + a.exact, keep); under(-2)
      if (keep) { c.word('ROT'); c.word('+'); c.word('NIP') }     // ( d ua d+ua ub ) → ( d ua+ub )
    } else if (e.f === 'REPLACE') {
      const at = this.constEval(e.a[1])
      if (at === undefined) throw new Error('BASIC: the frame\'s REPLACE: where it writes is known when compiling')
      this.place(e.a[0], d, keep); under(2); this.place(e.a[2], d + Number(at), false); under(-2)
    } else if (held) {
      this.emit(e)
      if (!keep) c.word('2DROP')
    } else if (e.f === 'NUM2BIN') {
      this.want(this.emit(e.a[0]), 'num', 'NUM2BIN'); c.num(s.exact); c.num(d); c.word('NUM2BIN')
      if (!keep) c.word('2DROP')
    } else if (e.f === 'SCRIPTCODE') {
      c.num(d); c.word('SCRIPTCODE')
      if (!keep) c.word('2DROP')
    } else {
      this.want(this.emit(e), 'bytes', 'the frame')
      if (keep) { c.word('TUCK'); c.num(d); c.word('SWAP'); c.word('MOVE'); c.num(d); c.word('SWAP') }   // ( a u ) → ( d u )
      else { c.num(d); c.word('SWAP'); c.word('MOVE') }
    }
    return s
  }

  /** Assign what `r` describes, on top of the stack, to `name`, creating it on first assignment. */
  assign(name, r) {
    if (has(this.consts, name)) throw new Error(`BASIC: ${name} is a compile-time constant and cannot be assigned`)
    let v = this.vars.get(name)
    /* Inside a loop a byte string can only be one that existed when the loop began, or part of one, so the
       longest of those bounds it — whatever trip this is. */
    const max = r.t === 'bytes' && this.loopMax.length ? join(r.max, this.loopMax[this.loopMax.length - 1]) : r.max
    if (!v) v = this.declare(name, r.t, r.t === 'bytes' ? max : null)
    else if ((v.type === 'bytes') !== (r.t === 'bytes')) {
      throw new Error(`BASIC: ${name} holds ${v.type === 'bytes' ? 'bytes' : 'a number'}, and this gives it ` +
        `${r.t === 'bytes' ? 'bytes' : 'a number'}: a variable keeps one kind`)
    } else if (v.type === 'bytes') v.max = join(v.max, max)
    this.store(v)
    if (!this.assigned.includes(name)) this.assigned.push(name)
  }

  run(ss) {
    const c = this.code
    for (const s of ss) {
      this.freeScratch()
      this.above = 0
      if (s.t === 'let') {
        const v = this.vars.get(s.name), place = this.places.get(s.name)
        /* one of the frame's values kept on the stack, made where it belongs */
        if (v?.held) { this.hold(v, this.emit(s.e, false, v.at === undefined ? null : { at: v.at }), s.held?.n); continue }
        /* a $ field written in its place in the next output; the variable is given the place only if anything reads it */
        if (place && !this.internal) {
          this.emit(s.e, false, place)
          if (!place.bare) this.assign(s.name, { t: 'bytes', max: place.width })
          else if (!this.assigned.includes(s.name)) this.assigned.push(s.name)
          continue
        }
        this.assign(s.name, this.emit(s.e, true)); continue
      }
      if (s.t === 'verify') { this.verify(s.e); continue }
      if (s.t === 'split') {
        const of = this.want(this.emit(s.of, true), 'bytes', 'SPLIT'); this.want(this.emit(s.at), 'num', 'SPLIT')
        c.word('SPLIT')
        /* Both names are created left first, as written; the right half is on top, so it is stored first. */
        for (const n of [s.left, s.right]) if (!this.vars.has(n) && !has(this.consts, n)) this.declare(n, 'bytes', of.max)
        this.assign(s.right, { t: 'bytes', max: of.max }); this.assign(s.left, { t: 'bytes', max: of.max })
        continue
      }
      if (s.t === 'for') { this.loop(s); continue }
      if (s.t === 'dim') {
        throw new Error('BASIC: every DIM comes before the first statement that runs: the state is laid out at ' +
          'the head of the script, before anything reads it')
      }
      if (s.t === 'version') throw new Error('BASIC: VERSION is said once, as the first statement')
      if (s.t === 'input') throw new Error(INPUT_FIRST)
      // IF
      /* A variable assigned inside an IF must exist before it, or there is a path on which it was never
         given a value. */
      const names = new Set()
      assignedBy(s.then, names); assignedBy(s.else, names)
      for (const n of names) {
        if (!this.vars.has(n)) {
          throw new Error(`BASIC: ${n} is assigned inside an IF but does not exist before it: ` +
            'give it a value first, or one path leaves it with none')
        }
      }
      this.want(this.emit(s.cond), 'num', 'IF')
      const lElse = c.label()
      c.branch('0BRANCH', lElse)
      this.run(s.then)
      if (s.else.length) {
        const lEnd = c.label()
        c.branch('BRANCH', lEnd)
        c.place(lElse)
        this.run(s.else)
        c.place(lEnd)
      } else c.place(lElse)
    }
  }

  /**
   * FOR … NEXT, as a loop. From, TO and STEP are worked out once, before the counter is set — BASIC's
   * order — and the test sits at the top, so `FOR i = 1 TO 0` runs the body no times.
   *
   *   <from> <to> [<step>]  [st !] lim ! i !
   *   top:  i @ lim @ > 0=  (i @ lim @ < 0= when STEP is negative)      0BRANCH end
   *         body
   *         i @ 1+ i !   or   i @ st @ + i !                              BRANCH top
   *   end:
   *
   * A STEP whose sign is known only when the script runs tests that sign on every trip. A loop that does
   * not end is stopped by the interpreter's instruction budget (JF revision 3's, InterpreterJF::TICK_MAX_OPS).
   */
  loop(s) {
    const c = this.code
    if (this.open.has(s.name)) throw new Error(`BASIC: FOR ${s.name} is already open: a nested loop needs its own counter`)
    if (has(this.consts, s.name)) throw new Error(`BASIC: ${s.name} is a compile-time constant and cannot count a loop`)
    const old = this.vars.get(s.name)
    if (old && old.type === 'bytes') throw new Error(`BASIC: ${s.name} holds bytes, and a FOR counter is a number`)
    this.want(this.emit(s.from), 'num', 'FOR'); this.want(this.emit(s.to), 'num', 'TO')
    let dir = 1
    if (s.step) {
      this.want(this.emit(s.step), 'num', 'STEP')
      const k = this.constEval(s.step)
      dir = k === undefined ? 0 : k < 0n ? -1 : 1
    }
    const i = old ?? this.declare(s.name, 'num')
    this.hidden++
    const lim = this.declare(`#lim${this.hidden}`, 'num')
    const st = s.step ? this.declare(`#st${this.hidden}`, 'num') : null
    if (st) this.store(st)
    this.store(lim)
    this.store(i)
    if (!this.assigned.includes(s.name)) this.assigned.push(s.name)

    const top = c.label(), end = c.label()
    const test = cmp => { this.fetch(i); this.fetch(lim); c.word(cmp); c.word('0=') }
    c.place(top)
    if (dir === 0) {
      const up = c.label(), go = c.label()
      this.fetch(st); c.word('0<'); c.branch('0BRANCH', up)
      test('<'); c.branch('BRANCH', go)
      c.place(up); test('>')
      c.place(go)
    } else test(dir > 0 ? '>' : '<')
    c.branch('0BRANCH', end)

    const bytesVars = [...this.vars.values()].filter(v => v.type === 'bytes')
    const M = bytesVars.reduce((m, v) => join(m, v.max), 0)
    for (const n of (() => { const w = new Set(); writes(s.body, w); return w })()) {
      const v = this.vars.get(n)
      if (v && v.type === 'bytes') v.max = join(v.max, M)
    }
    this.open.add(s.name); this.loops++; this.loopMax.push(M)
    this.run(s.body)
    this.open.delete(s.name); this.loops--; this.loopMax.pop()

    this.fetch(i)
    if (st) { this.fetch(st); c.word('+') } else c.word('1+')
    this.store(i)
    c.branch('BRANCH', top)
    c.place(end)
  }

  /** Bind what is on the stack, bottom first, to variables: a number takes one cell, bytes two. */
  bind(vars, num2bin = new Set(), unbound = new Set()) {
    for (const v of [...vars].reverse()) {
      if (unbound.has(v.name)) { this.code.word('2DROP'); continue }   // pushed bytes nothing reads
      if (num2bin.has(v.name)) this.code.word('BIN2NUM')      // a % field: its pushed bytes, read as a number
      this.store(v)
    }
  }
}

/** variable address → name, for the reader: every variable but the compiler's own. */
const namesOf = em => Object.fromEntries([...em.vars.values()].filter(v => !v.name.startsWith('#')).map(v => [v.addr, v.name]))

/**
 * Compile a program. What it leaves on the stack is what `env.leave` names.
 * @param {string} src
 * @param {{ stack?: string[], consts?: Record<string, number>, leave?: string[] }} [env]
 *   stack  what is on the stack when it starts, bottom first: `n` a number, `b$` bytes
 *   leave  variables whose values the program leaves on the stack, in order
 */
export function compileBasic(src, env = {}) {
  const prog = parseProgram(src)
  const v = prog.shift()
  if (!v || v.t !== 'version') throw new Error(`BASIC: a jetForth program names its version first: VERSION JF ${JF_REVISION}`)
  if (v.family !== 'JF' || v.revision !== JF_REVISION) throw new Error(`BASIC: VERSION ${v.family} ${v.revision}: this compiler emits JF revision ${JF_REVISION}`)
  if (findVersion(prog)) throw new Error('BASIC: VERSION is said once, as the first statement')
  if (prog.some(s => s.t === 'dim')) {
    throw new Error('BASIC: DIM lays out a covenant\'s state at the head of its script: compile it with compileCovenant')
  }
  if (prog.some(s => s.t === 'input')) {
    throw new Error('BASIC: INPUT names what a covenant\'s tick carries, and a covenant has DIM owner$20: compile it ' +
      'with compileCovenant. What a program finds on the stack is named by env.stack')
  }
  const leave = env.leave ?? []
  const build = scratch => {
    const em = new Emitter(env.consts ?? {}, scratch)
    const inputs = (env.stack ?? []).map(raw => {
      const m = /^([A-Za-z][A-Za-z0-9_]*)(\$)?$/.exec(raw)
      if (!m) throw new Error(`BASIC: ${raw} is not a name for what is on the stack`)
      if (em.vars.has(m[1])) throw new Error(`BASIC: ${m[1]} is named twice on the stack`)
      return em.declare(m[1], m[2] ? 'bytes' : 'num', null)
    })
    em.layScratch()
    em.bind(inputs)
    em.run(prog)
    for (const n of leave) {
      const l = em.vars.get(n)
      if (!l || n.startsWith('#')) throw new Error(`BASIC: ${n} is left on the stack but never given a value`)
      em.fetch(l)
    }
    return em
  }
  /* The scratch's size is what the program's statements use, which no address changes: a second compile holds it. */
  let em = build(0)
  if (em.used > 0) em = build(em.used)
  /* What it pushes goes to the push space as it runs; nothing it pushes is in a loop. Bytes on the stack
     when it starts are not counted: their length is the caller's. */
  const memory = em.memory(), pushed = em.code.pushed ?? 0
  if (memory > MEMORY) throw new Error(`BASIC: the program needs ${memory} bytes of memory, and the interpreter has ${MEMORY}`)
  if (pushed > PUSH_MEM) throw new Error(`BASIC: the program pushes ${pushed} bytes, and the push space has ${PUSH_MEM}`)
  /* The VERSION line is the declaration, ahead of the code: every branch is relative, so nothing in the code moves. */
  return { bytes: Uint8Array.from([...DECLARATION, ...em.code.assemble()]), nVersion: JF_NVERSION, revision: JF_REVISION,
           compiler: BASIC_JF_VERSION, assigned: em.assigned, names: namesOf(em), inputs: env.stack ?? [], leave, memory, pushed }
}

// ── the covenant ─────────────────────────────────────────────────────────────────────────────────────
/** BIP143's varint in front of a scriptCode of this length. */
export const varintSize = n => (n < 253 ? 1 : n < 0x10000 ? 3 : 5)
/** A preimage is 156 bytes around its scriptCode field (varint ‖ script): 104 before, 52 after. */
const PREIMAGE_AROUND = 156

/**
 * The frame, as BASIC: rules 1 and 2 and the next output before the program, the rest of the rebuild (rules 3 and 4)
 * after it. It is compiled by the same emitter as the program, with the frame's own words, PREIMAGE and DEPTH, and
 * names that start with `#`, which a program cannot write.
 *   #sig #pub        the unlocking script's first two pushes: the owner's 64-byte signature and 32-byte key.
 *                    ED25519-CHECKSIG is false for any other sizes
 *   the inputs       the pushes after them, one for each name INPUT gives. A push left over is still on the
 *                    stack at the end, where a tick must leave exactly one item; a push missing leaves the
 *                    binding short of what it stores
 *   the preimage     read with its own words: TXVALUE and NSEQUENCE, numbers; SCRIPTCODE, the script with its length
 *                    in front, as an output carries it; OUTPUTS_HASH, hashOutputs. PREIMAGE, all of it, only for the
 *                    owner's signature, which is over HASH256 of it
 *   #next #out       value + 1, and the next output: value + 1, then this script, its length in front
 * #sig, #pub, #next and #out are kept on the stack, never in memory: the program's statements leave the stack as they
 * find it, so #out waits under them for the rebuild. `rebuilt` is the fields the rebuild writes into #out: those the
 * program assigns and does not write in their places itself. A `$` one is checked for its width first: a push of
 * another length would leave bytes in the successor that run as code.
 */
/** What comes before a field's bytes in the head: its push, as Code.push lays it down. A direct push to 72 bytes, then
 *  STR8 to 255, then STR16, its length in two bytes, least significant first. */
const pushHead = n => n <= JF_PUSH_MAX ? [n] : n <= 0xff ? [JF_LIT.STR8, n] : [JF_LIT.STR16, n & 0xff, n >> 8]
/** Where each field's bytes are in the next output: past the value, the script's length and the declaration, and
 *  past each field before it and its own push's head. */
function fieldOffsets(layout, vl) {
  const out = new Map()
  let at = 8 + vl + DECLARATION.length
  for (const f of layout) { at += pushHead(f.width).length; out.set(f.name, at); at += f.width }
  return out
}

function frameText(layout, vl, rebuilt, inputs) {
  /* Each input is checked before anything reads it. A % input is bound as the bytes pushed, to #in_ followed by
     its name; BIN2NUM reads only the first 8 of them, so their size is checked first. Below 8 bytes the number
     is never negative; at 8 a negative cell fits, so it is checked, as a field's is. */
  const given = inputs.length ? ['REM  what the tick carries after the key: each the size INPUT says'] : []
  for (const x of inputs) {
    if (x.bytes) { if (x.width !== null) given.push(`VERIFY SIZE(${x.name}) = ${x.width}`); continue }
    given.push(`VERIFY SIZE(#in_${x.name}) <= ${x.width}`, `${x.name} = BIN2NUM(#in_${x.name})`)
    if (x.width === 8) given.push(`VERIFY ${x.name} >= 0`)
  }
  /* The checks read the key and the signature in the order they lie on the stack, the key copied for the first. */
  const before = [
    ...given,
    "REM  rule 1: signed by the thread's owner",
    'VERIFY SAMEBYTES(HASH160(#pub), owner)',
    'VERIFY ED25519SIG(#sig, #pub, HASH256(PREIMAGE()))',
    "REM  rule 2: the next tick, never another — the value plus one, and nSequence that same number",
    '#next = TXVALUE() + 1',
    'VERIFY #next = NSEQUENCE()',
    "REM  nSequence counts from 1: a value of all ones reads as -1 and would come round to 0",
    'VERIFY #next >= 1',
    /* Rules 3 and 4: the successor is this script, its state rebuilt. The scriptCode field is already the successor's
       script with its length in front, as an output carries it, every field's value as it was: it is copied once,
       behind the value, before the program, which may write a field there itself. */
    "REM  the next output: value + 1, then this script",
    '#out = CAT(NUM2BIN(#next, 8), SCRIPTCODE())',
  ]
  /* Each field the rebuild writes is written over its place, its push's head left as it is. */
  const after = []
  for (const f of layout) if (f.bytes && rebuilt.has(f.name)) after.push(`VERIFY SIZE(${f.name}) = ${f.width}`)
  /* A % field is unsigned. Below 8 bytes NUM2BIN refuses a negative; at 8 a negative cell fits, so it is checked. */
  for (const f of layout) if (!f.bytes && f.width === 8 && rebuilt.has(f.name)) after.push(`VERIFY ${f.name} >= 0`)
  let out = '#out'
  for (const [name, at] of fieldOffsets(layout, vl)) {
    const f = layout.find(g => g.name === name)
    if (rebuilt.has(name)) out = `REPLACE(${out}, ${at}, ${f.bytes ? name : `NUM2BIN(${name}, ${f.width})`})`
  }
  if (out !== '#out') after.push(`#out = ${out}`)
  after.push('VERIFY SAMEBYTES(HASH256(#out), OUTPUTS_HASH())')
  return { before, after }
}

/** The DIM fields, checked against what a jetForth push and cell can carry, and the INPUT line's names. */
function covenantLayout(prog, consts = {}) {
  const layout = [], inputs = []
  let running = false
  const body = []
  const both = name => `BASIC: ${name} is a DIM field and an INPUT: give the input its own name, and assign the field from it`
  for (const s of prog) {
    if (s.t !== 'dim' && s.t !== 'input') { running = true; body.push(s); continue }
    if (running && s.t === 'input') throw new Error(INPUT_FIRST)
    if (running) {
      throw new Error('BASIC: every DIM comes before the first statement that runs: the state is laid out at ' +
        'the head of the script, before anything reads it')
    }
    if (s.t === 'input') {
      for (const x of s.inputs) {
        if (layout.some(f => f.name === x.name)) throw new Error(both(x.name))
        if (inputs.some(y => y.name === x.name)) throw new Error(`BASIC: ${x.name} is named twice by INPUT`)
        if (has(consts, x.name)) throw new Error(`BASIC: ${x.name} is a compile-time constant, so a tick cannot carry it`)
        inputs.push(x)
      }
      continue
    }
    for (const f of s.fields) {
      if (layout.some(g => g.name === f.name)) throw new Error(`BASIC: ${f.name} is DIMmed twice`)
      if (inputs.some(x => x.name === f.name)) throw new Error(both(f.name))
      if (!f.bytes && f.width > 8) throw new Error(`BASIC: DIM ${f.name}%${f.width}: a number is a 64-bit cell, so at most 8 bytes`)
      layout.push(f)
    }
  }
  const owner = layout.find(f => f.name === 'owner')
  if (!owner || !owner.bytes || owner.width !== 20) {
    throw new Error("BASIC: a thread is owned — DIM owner$20, the HASH160 of the owner's key (rule 1)")
  }
  return { layout, inputs, body }
}

/** One field's bytes, as the head of the script pushes them. */
function fieldBytes(f, v) {
  if (v === undefined) throw new Error(`BASIC: no value for the field ${f.name}`)
  if (f.bytes) {
    const d = [...v]
    if (d.length !== f.width) throw new Error(`BASIC: ${f.name} is ${d.length} bytes, but DIM says ${f.width}`)
    return d
  }
  const n = BigInt(v)
  if (n < 0n || n >= 1n << BigInt(8 * f.width) || n > I64_MAX) {
    throw new Error(`BASIC: ${f.name} = ${v} does not fit ${f.width} bytes: widen the DIM`)
  }
  return le(n, f.width)
}

/** Every name a block's expressions read, and how many times: `into` is a Map. */
function reads(ss, into) {
  const of = e => {
    if (!e) return
    if (e.t === 'var') into.set(e.v, (into.get(e.v) ?? 0) + 1)
    else if (e.t === 'neg') of(e.e)
    else if (e.t === 'bin') { of(e.l); of(e.r) }
    else if (e.t === 'call') e.a.forEach(of)
  }
  for (const s of ss) {
    if (s.t === 'let' || s.t === 'verify') of(s.e)
    else if (s.t === 'split') { of(s.of); of(s.at) }
    else if (s.t === 'for') { of(s.from); of(s.to); of(s.step); reads(s.body, into) }
    else if (s.t === 'if') { of(s.cond); reads(s.then, into); reads(s.else, into) }
  }
}
/** A byte string's length when it is known when compiling: a literal's, a hash's, NUM2BIN's width, a CAT of two. */
function exactLength(e, constEval) {
  if (e.t === 'bytes') return e.d.length
  if (e.t !== 'call') return undefined
  if (HASHES[e.f] && e.a.length === 1) return HASHES[e.f]
  if (e.f === 'NUM2BIN' && e.a.length === 2) { const w = constEval(e.a[1]); return w === undefined ? undefined : Number(w) }
  if (e.f === 'CAT' && e.a.length === 2) {
    const a = exactLength(e.a[0], constEval), b = exactLength(e.a[1], constEval)
    return a === undefined || b === undefined ? undefined : a + b
  }
  return undefined
}
/**
 * The $ fields the program writes in their places in the next output: those it assigns once, in a statement not
 * inside a FOR, with a word that makes bytes of exactly the field's width. Bytes a variable is given from that place
 * no later write changes, and they need no check of their width: they have it.
 */
function inPlaceFields(layout, body, constEval) {
  const lets = new Map(), other = new Set()
  const walk = (ss, inFor) => {
    for (const s of ss) {
      if (s.t === 'let') lets.set(s.name, [...(lets.get(s.name) ?? []), { e: s.e, inFor }])
      else if (s.t === 'split') { other.add(s.left); other.add(s.right) }
      else if (s.t === 'for') { other.add(s.name); walk(s.body, true) }
      else if (s.t === 'if') { walk(s.then, inFor); walk(s.else, inFor) }
    }
  }
  walk(body, false)
  return new Set(layout.filter(f => {
    const l = lets.get(f.name)
    if (!f.bytes || other.has(f.name) || l?.length !== 1 || l[0].inFor) return false
    const e = l[0].e
    return e.t === 'call' && (HASHES[e.f] || e.f === 'NUM2BIN' || e.f === 'CAT') && exactLength(e, constEval) === f.width
  }).map(f => f.name))
}
/**
 * The fields whose value in the head nothing reads, so the frame drops it rather than store it: the frame does not
 * read it, nor the program, nor the rebuild, because the program never writes the field, writes it in its place, or
 * writes it in a statement every tick runs, one not inside an IF or a FOR, and the rebuild reads what the program wrote.
 */
function unboundFields(layout, inputs, body, written, inPlace) {
  const read = new Map(), top = new Set()
  reads(parseProgram(frameText(layout, 1, new Set(), inputs).before.join('\n'), true), read)
  reads(body, read)
  for (const s of body) {
    if (s.t === 'let' || s.t === 'for') top.add(s.name)
    else if (s.t === 'split') { top.add(s.left); top.add(s.right) }
  }
  return new Set(layout.filter(f => !read.has(f.name) && (!written.has(f.name) || inPlace.has(f.name) || top.has(f.name)))
    .map(f => f.name))
}
/**
 * How many times the frame reads each value it keeps on the stack, from one assignment to the next: put on each
 * assignment as `held.n`. For the values on the stack when the frame starts, from the start: the Map returned.
 */
function heldReads(ss, names) {
  const cur = new Map(names.map(n => [n, { n: 0 }])), start = new Map(cur)
  for (const s of ss) {
    const r = new Map(); reads([s], r)
    for (const [name, k] of r) if (cur.has(name)) cur.get(name).n += k
    if (s.t === 'let' && cur.has(s.name)) { s.held = { n: 0 }; cur.set(s.name, s.held) }
  }
  return start
}

/**
 * Lay the script down for a guess at its own length and its scratch's size; `compileCovenant` repeats until both
 * hold. `unbound` is the fields the frame drops, `inPlace` those the program writes in their places.
 */
function buildCovenant(layout, inputs, body, state, L, written, consts, scratch, unbound, inPlace) {
  const em = new Emitter(consts, scratch)
  const fields = layout.map(f => em.declare(f.name, f.bytes ? 'bytes' : 'num', f.bytes ? f.width : null))
  const given = inputs.map(x => em.declare(x.name, x.bytes ? 'bytes' : 'num', x.bytes ? x.width : null))
  em.internal = true
  const carried = inputs.map((x, i) => x.bytes ? given[i] : em.declare(`#in_${x.name}`, 'bytes', x.width))
  const vl = varintSize(L), outLength = 8 + vl + L
  em.preMax = PREIMAGE_AROUND + vl + L
  /* The next output has a place of its own, before the scratch: the program runs while it is there. */
  const outAt = em.next
  em.next += outLength
  em.layScratch()
  const HELD = ['#sig', '#pub', '#next', '#out']
  const sig = em.holdVar('#sig', 'bytes', 64), pub = em.holdVar('#pub', 'bytes', 32)
  em.holdVar('#next', 'num'); em.holdVar('#out', 'bytes', outLength).at = outAt
  const read = new Map(), offsets = fieldOffsets(layout, vl)
  reads(body, read)
  for (const name of inPlace) {
    em.places.set(name, { at: outAt + offsets.get(name), width: layout.find(f => f.name === name).width, bare: !read.has(name) })
  }
  const { before, after } = frameText(layout, vl, new Set([...written].filter(n => !inPlace.has(n))), inputs)
  const frameSs = parseProgram(before.join('\n'), true), rebuild = parseProgram(after.join('\n'), true)
  const start = heldReads([...frameSs, ...rebuild], HELD)

  const head = new Code()
  head.bytes(...DECLARATION)
  for (const f of layout) head.push(fieldBytes(f, state[f.name]))
  /* The frame is laid out before the program, so its addresses are the same whatever the program is.
     Emission order is head, frame, program, rebuild; allocation order is frame, rebuild, program. The program leaves
     the stack as it finds it, so the rebuild finds the frame's values there as the frame left them. */
  const frame = em.code
  em.bind([...carried, ...fields], new Set(layout.filter(f => !f.bytes).map(f => f.name)), unbound)
  sig.reads = start.get('#sig').n; pub.reads = start.get('#pub').n
  em.held = [sig, pub]
  /* Until the next output is made, its place is free: the checks before it use the scratch from there, the preimage
     among them, so the two are never in memory at once. */
  const made = frameSs.findIndex(s => s.t === 'let' && s.name === '#out')
  em.early = outAt
  em.run(frameSs.slice(0, made))
  em.early = null
  em.run(frameSs.slice(made))
  const rebuildCode = em.code = new Code()
  /* The rebuild's last check is the tick's result: its flag is left as the one cell, in place of an abort and TRUE. */
  const last = rebuild.pop()
  em.run(rebuild)
  em.freeScratch(); em.above = 0
  em.want(em.emit(last.e), 'num', 'the rebuild')
  if (em.held.length) throw new Error(`BASIC: the frame leaves ${em.held.map(v => v.name).join(', ')} on the stack`)
  em.internal = false
  const prog = em.code = new Code()
  em.run(body)
  const parts = { head: head.assemble(), frame: frame.assemble(), prog: prog.assemble(), rebuild: rebuildCode.assemble() }
  /* Literals go to the push space as they run, after the tick's own pushes; nothing a covenant pushes is in
     a loop, so their total is known now. An input counts at its width; one of any length is not counted, its
     length being the tick's. */
  const memory = em.memory(), pushed = TICK_PUSHES + inputs.reduce((n, x) => n + (x.width ?? 0), 0)
    + [head, frame, prog, rebuildCode].reduce((n, c) => n + (c.pushed ?? 0), 0)
  return { parts, bytes: Uint8Array.from([...parts.head, ...parts.frame, ...parts.prog, ...parts.rebuild]), em, memory, pushed }
}

/**
 * Compile a covenant. `env.state` gives each DIM field its value in this thread: a number for `%`, an
 * array of bytes for `$`. The fields are the head of the script, so two threads of one program differ
 * only there, and every tick rebuilds them. The result's `inputs` is what INPUT names, in its order:
 * { name, width, bytes }, width null for bytes of any length.
 * @param {string} src
 * @param {{ state?: Record<string, number|bigint|number[]|Uint8Array>, consts?: Record<string, number> }} [env]
 */
export function compileCovenant(src, env = {}) {
  const prog = parseProgram(src)
  const v = prog.shift()
  if (!v || v.t !== 'version') throw new Error(`BASIC: a jetForth program names its version first: VERSION JF ${JF_REVISION}`)
  if (v.family !== 'JF' || v.revision !== JF_REVISION) throw new Error(`BASIC: VERSION ${v.family} ${v.revision}: this compiler emits JF revision ${JF_REVISION}`)
  if (findVersion(prog)) throw new Error('BASIC: VERSION is said once, as the first statement')
  const { layout, inputs, body } = covenantLayout(prog, env.consts ?? {})
  const all = new Set(); writes(body, all)
  const written = new Set(layout.filter(f => all.has(f.name)).map(f => f.name))
  const inPlace = inPlaceFields(layout, body, e => new Emitter(env.consts ?? {}).constEval(e))
  const unbound = unboundFields(layout, inputs, body, written, inPlace)
  /* The script's own length is inside it, twice over: in the preimage's size and in the varint the
     rebuild steps past. Build, measure, build again until the length holds, as a covenant is built by hand.
     The scratch's size follows the length, and the program's addresses follow the scratch: it is grown, never
     shrunk, until both hold. */
  let L = 0, S = 0
  for (let k = 0; k < 16; k++) {
    const r = buildCovenant(layout, inputs, body, env.state ?? {}, L, written, env.consts ?? {}, S, unbound, inPlace)
    if (r.bytes.length === L && r.em.used <= S) {
      if (r.memory > MEMORY) {
        throw new Error(`BASIC: the covenant needs ${r.memory} bytes of memory, and the interpreter has ${MEMORY}`)
      }
      if (r.pushed > PUSH_MEM) throw new Error(`BASIC: the covenant pushes ${r.pushed} bytes, and the push space has ${PUSH_MEM}`)
      return { bytes: r.bytes, nVersion: JF_NVERSION, revision: JF_REVISION, compiler: BASIC_JF_VERSION,
               layout, inputs, written: [...written], unbound: [...unbound], inPlace: [...inPlace], assigned: r.em.assigned, names: namesOf(r.em),
               memory: r.memory, pushed: r.pushed }
    }
    L = r.bytes.length; S = Math.max(S, r.em.used)
  }
  throw new Error('BASIC: the script\'s length did not settle: it sits where a varint changes size')
}

/**
 * The frame and the rebuild of a covenant with this layout and length, as bytes: for the reader, which
 * finds them in a script by laying them down again. `written` is the fields the program assigns, `inputs`
 * what INPUT names, `unbound` the fields the frame drops, `inPlace` those the program writes in their places. H is where
 * the frame starts: past the declaration and the fields.
 */
export function covenantFrame(layout, L, written, inputs = [], unbound = [], inPlace = []) {
  const state = Object.fromEntries(layout.map(f => [f.name, f.bytes ? new Array(f.width).fill(0) : 0]))
  const { parts, em } = buildCovenant(layout, inputs, [], state, L, new Set(written), {}, 0, new Set(unbound), new Set(inPlace))
  /* where each $ field's bytes are in the next output, for a program that writes one there */
  const places = new Map(layout.filter(f => f.bytes).map(f => [em.vars.get('#out').at + fieldOffsets(layout, varintSize(L)).get(f.name), f]))
  return { H: parts.head.length, frame: parts.frame, rebuild: parts.rebuild, places }
}
