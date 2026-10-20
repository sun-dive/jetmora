// © 2026 sun-dive — Apache License 2.0.
/**
 * BASIC → jetForth: the compiler for jetmora's covenants.
 *
 * jetmora BASIC is an easy way to write jetForth, as Bitcoin BASIC is an easy way to write Bitcoin
 * Script. The language is BRC-173, the one the Bitcoin compiler takes. Its lexer and parser are copied from
 * grafverse/mint/src/basic.ts (BASIC_VERSION 1.0), which is never edited from here. The emitter is new,
 * because jetForth is a Forth and not Script:
 *
 *   values      a number is one 64-bit cell; bytes are two cells, ( c-addr u ), the bytes in memory
 *   variables   locals — (LOCAL@) and (LOCAL!) — so the two arms of an IF never have to balance a stack
 *   loops       FOR … NEXT is a loop that branches back to its test. It is never unrolled
 *   truth       a comparison gives -1 or 0: jetForth's TRUE, every bit set
 *   bytes made  CAT, NUM2BIN, the hashes and PREIMAGE write at the heap pointer, which only grows
 *
 * THE HARD RULE carries over from basic.ts as it stands:
 *   1. the compiled script says what the program says: `x = 2 * 3 + 4` emits a multiply and an add;
 *   2. fold only what jetForth cannot express — today nothing: `^` is a multiply loop;
 *   3. never improve a released version in place: a new version, proved against the old one.
 *
 * A program names its version as its first statement, `VERSION JF 3`, and the compiler refuses one it
 * does not emit. The bytes are numbered in that revision, and every result carries `nVersion`: the
 * version an entry carrying the script must name, so the interpreter for that revision runs it.
 *
 * ── THE LAYOUT OF A COMPILED PROGRAM ───────────────────────────────────────────────────────────────
 *   (FRAME) n                     the unlocking script's values become locals 0 … n-1
 *   <literal> (LOCAL!) (LOCAL!)   every byte literal, pushed once, here
 *   PUSH0 DROP (LOCAL!) fl        the floor: the lowest address the literals reached
 *   0 (LOCAL!) hp                 the heap starts at address 0 and grows up to the floor
 *   [PREIMAGE, for a covenant]    → the variable `preimage`
 *   the program
 *   (UNFRAME) [TRUE, for a covenant]
 *
 * Literals are pushed in the prologue because the interpreter keeps each literal pushed at run time in
 * memory, growing down from the top. Pushed once, before anything else, they sit above a floor that never
 * moves, and every block the heap hands out is checked against it: a program that would reach a literal
 * is refused rather than overwrite it.
 */
import { JF_PUSH_MAX, JF_SMALL0, JF_LIT, JF_WORD } from '../tools/ops-jf.mjs'

/** The version of this compiler. A script's bytes are a function of it. */
export const BASIC_JF_VERSION = '0.1'

/** The JF revision the bytes are numbered in: tools/ops-jf.mjs, revision 3. */
export const JF_REVISION = 3
/**
 * The nVersion an entry carrying this script names, so the JF revision 3 interpreter runs it (spec §6b,
 * server/dispatch.php): family `JF`, revision 3 — on the wire `03 00 4A 46`.
 */
export const JF_NVERSION = ((0x46 << 24) | (0x4a << 16) | JF_REVISION) >>> 0

/** 1.0 in the project's fixed point — 2^32, as in basic.ts. */
export const BASIC_S = 2n ** 32n

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
function lex(src) {
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
        throw new Error(`BASIC: &H${h} — a hex literal is whole BYTES, so it needs an even number of digits`)
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
    if (/[A-Za-z]/.test(c)) {
      let j = i; while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++
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
  expect(v) { if (!this.eat(v)) throw new Error(`BASIC: expected ${v}, found ${this.peek()?.v ?? 'end'}`) }
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
    if (t.k === 'num') return { t: 'num', v: t.n }
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
        throw new Error('BASIC: a FOR cannot open inside an IF arm — an IF is line-scoped, so its arms ' +
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
      if (lineScoped) throw new Error('BASIC: DIM declares the script\'s layout — it cannot sit inside an IF')
      p.next(); out.push(dimStmt(p)); continue
    }
    if (t.k === 'kw' && t.v === 'VERSION') { p.next(); out.push(versionStmt(p)); continue }
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
    if (n2.v === n.v) throw new Error(`BASIC: ${n.v}, ${n.v} = SPLIT(…) — the halves need different names`)
    p.expect('=')
    const e = p.expr()
    if (e.t !== 'call' || e.f !== 'SPLIT' || e.a.length !== 2) {
      throw new Error(`BASIC: ${n.v}, ${n2.v} = … needs SPLIT(bytes, at) on the right — it is the only ` +
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
      if (!p.eat('IF')) throw new Error('BASIC: END on its own — did you mean END IF?')
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
    if (!n || n.k !== 'name') throw new Error('BASIC: DIM wants a name — DIM v%5')
    const sig = p.next()
    if (!sig || (sig.v !== '%' && sig.v !== '$')) {
      throw new Error(`BASIC: DIM ${n.v} needs a WIDTH — ${n.v}%5 for a five-byte number, ${n.v}$20 for ` +
        'twenty raw bytes. A field is a layout, and a layout has a size.')
    }
    const w = p.next()
    if (!w || w.k !== 'num' || !Number.isInteger(w.n) || w.n < 1 || w.n > 75) {
      throw new Error(`BASIC: DIM ${n.v} — the width must be a whole number of bytes from 1 to 75`)
    }
    fields.push({ name: n.v, width: w.n, bytes: sig.v === '$' })
  } while (p.eat(','))
  return { t: 'dim', fields }
}

/** `FOR i = <from> TO <to> [STEP <s>] … NEXT [i]` — the body runs to NEXT, however many lines. */
function forStmt(p) {
  const n = p.next()
  if (!n || n.k !== 'name') throw new Error('BASIC: FOR wants a counter name — FOR i = 0 TO 9')
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
    throw new Error('BASIC: VERSION names an instruction set and its revision — VERSION JF 3')
  }
  return { t: 'version', family: f.v, revision: r.n }
}

function parseProgram(src) {
  const p = new Parser(lex(src))
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
  word(name) { this.bytes(W(name)) }
  /** `(LOCAL@) k` or `(LOCAL!) k`. */
  local(name, k) {
    if (k > 255) throw new Error('BASIC: more than 256 locals — the program has too many variables')
    this.bytes(W(name), k)
  }
  /** The smallest form that holds v. A negative constant is its magnitude and NEGATE, as `-5` is written. */
  num(v) {
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
    return Uint8Array.from(out)
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

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k)
const findVersion = ss => ss.some(s => s.t === 'version'
  || (s.t === 'if' && (findVersion(s.then) || findVersion(s.else))) || (s.t === 'for' && findVersion(s.body)))
const isNum = t => t === 'num' || t === 'flag'

/**
 * @typedef {{ name: string, k: number, type: 'num'|'bytes' }} Local
 * @typedef {{ stack?: string[], consts?: Record<string, number>, leave?: string[] }} BasicEnv
 *   stack   what the unlocking script leaves, bottom first; a name ending in `$` is bytes
 *   consts  named constants, substituted where they are read
 *   leave   variables whose values the program leaves on the stack, in order
 */

function compile(src, env, covenant) {
  const prog = parseProgram(src)
  /* The version is part of the source, so the source hash a genesis commits to fixes it too. */
  const v = prog.shift()
  if (!v || v.t !== 'version') {
    throw new Error(`BASIC: a jetForth program names its version first — VERSION JF ${JF_REVISION}`)
  }
  if (v.family !== 'JF' || v.revision !== JF_REVISION) {
    throw new Error(`BASIC: VERSION ${v.family} ${v.revision} — this compiler emits JF revision ${JF_REVISION}`)
  }
  if (findVersion(prog)) throw new Error('BASIC: VERSION is said once, as the first statement')
  if (prog.some(s => s.t === 'dim')) {
    throw new Error('BASIC: DIM is the state layout, and how a jetmora covenant carries its state is still ' +
      'to be decided — this version compiles programs without it')
  }
  const consts = env.consts ?? {}
  const body = new Code()
  /** @type {Map<string, Local>} */
  const locals = new Map()
  let nextLocal = 0
  const alloc = (name, type) => {
    const l = { name, k: nextLocal, type: type === 'bytes' ? 'bytes' : 'num' }
    nextLocal += l.type === 'bytes' ? 2 : 1
    locals.set(name, l)
    return l
  }

  // The unlocking script's values, bottom first — they become locals 0 … n-1, in that order.
  for (const raw of env.stack ?? []) {
    const bytes = raw.endsWith('$'), name = bytes ? raw.slice(0, -1) : raw
    if (locals.has(name)) throw new Error(`BASIC: ${name} is named twice on the stack`)
    alloc(name, bytes ? 'bytes' : 'num')
  }
  const nIn = nextLocal
  const hp = alloc('#hp', 'num').k, fl = alloc('#fl', 'num').k
  if (covenant) {
    if (locals.has('preimage')) throw new Error('BASIC: preimage is supplied by the covenant frame')
    alloc('preimage', 'bytes')
  }
  /** hex → the local holding that literal's ( c-addr u ). */
  const literals = new Map()
  const assigned = []
  /** FOR counters whose loops are open. */
  const open = new Set()
  let hidden = 0

  const fetch = l => { body.local('(LOCAL@)', l.k); if (l.type === 'bytes') body.local('(LOCAL@)', l.k + 1) }
  const store = l => { if (l.type === 'bytes') body.local('(LOCAL!)', l.k + 1); body.local('(LOCAL!)', l.k) }
  /** After a word that wrote ( d u ) at the heap pointer: move the pointer past it, refusing to reach the floor. */
  const commit = () => {
    body.word('2DUP'); body.word('+'); body.word('DUP'); body.local('(LOCAL@)', fl); body.word('>')
    body.abortIf(); body.local('(LOCAL!)', hp)
  }

  const want = (t, what, f) => {
    if (what === 'num' && !isNum(t)) throw new Error(`BASIC: ${f} works on numbers, and this is bytes — BIN2NUM turns bytes into a number`)
    if (what === 'bytes' && t !== 'bytes') throw new Error(`BASIC: ${f} works on bytes, and this is a number — NUM2BIN turns a number into bytes`)
  }

  /** The value of an expression if it is knowable now — only for the direction of a STEP. */
  function constEval(e) {
    const cell = v => {
      if (v > I64_MAX || v < -I64_MAX) throw new Error(`BASIC: ${v} is past what a 64-bit cell holds`)
      return v
    }
    switch (e.t) {
      case 'num': return BigInt(Math.round(e.v))
      case 'var': return has(consts, e.v) ? BigInt(Math.round(consts[e.v])) : undefined
      case 'neg': { const x = constEval(e.e); return x === undefined ? undefined : -x }
      case 'bin': {
        if (!['+', '-', '*', '/', '^'].includes(e.op)) return undefined
        const l = constEval(e.l), r = constEval(e.r)
        if (l === undefined || r === undefined) return undefined
        switch (e.op) {
          case '+': return cell(l + r)
          case '-': return cell(l - r)
          case '*': return cell(l * r)
          /* BigInt division truncates toward zero, as jetForth's `/` does. */
          case '/':
            if (r === 0n) throw new Error('BASIC: a division by zero the compiler can already see — the tick would fail')
            return l / r
          case '^':
            if (r < 0n) throw new Error(`BASIC: ${l} ^ ${r} — a negative power is not a whole number`)
            if (r > 64n && (l > 1n || l < -1n)) throw new Error(`BASIC: ${l} ^ ${r} is past what a 64-bit cell holds`)
            return cell(l ** r)
        }
      }
    }
    return undefined
  }

  /** Emit an expression. @returns {'num'|'flag'|'bytes'} */
  function emit(e) {
    switch (e.t) {
      case 'num': body.num(BigInt(Math.round(e.v))); return 'num'
      case 'bytes': {
        const h = e.d.map(b => b.toString(16).padStart(2, '0')).join('')
        let k = literals.get(h)
        if (k === undefined) { k = alloc(`#lit${literals.size}`, 'bytes').k; literals.set(h, k) }
        body.local('(LOCAL@)', k); body.local('(LOCAL@)', k + 1)
        return 'bytes'
      }
      case 'var': {
        if (has(consts, e.v)) { body.num(BigInt(Math.round(consts[e.v]))); return 'num' }
        const l = locals.get(e.v)
        if (!l || e.v.startsWith('#')) throw new Error(`BASIC: ${e.v} has no value here — assign it first`)
        fetch(l)
        return l.type
      }
      case 'neg': want(emit(e.e), 'num', '-'); body.word('NEGATE'); return 'num'
      case 'bin': {
        /* `^` is a multiply loop, because JF revision 3 has no power word. jetForth can express a power,
           so nothing is folded: `2 ^ 8` is this loop too. A negative exponent is refused when it runs.
             ( b e )  DUP 0< (ABORT")  1 SWAP  0 (?DO) OVER * (LOOP)  NIP  ( b^e )                      */
        if (e.op === '^') {
          want(emit(e.l), 'num', '^'); want(emit(e.r), 'num', '^')
          body.word('DUP'); body.word('0<'); body.abortIf()
          body.num(1n); body.word('SWAP'); body.num(0n)
          const top = body.label(), end = body.label()
          body.branch('(?DO)', end)
          body.place(top); body.word('OVER'); body.word('*'); body.branch('(LOOP)', top)
          body.place(end); body.word('NIP')
          return 'num'
        }
        /* AND and OR are BASIC's: true when both (either) are non-zero. A value that is not already a
           flag is made one with 0<> first, so the bitwise word gives the logical answer. */
        if (e.op === 'AND' || e.op === 'OR') {
          for (const side of [e.l, e.r]) {
            const t = emit(side)
            want(t, 'num', e.op)
            if (t !== 'flag') body.word('0<>')
          }
          body.word(e.op); return 'flag'
        }
        const tl = emit(e.l), tr = emit(e.r)
        want(tl, 'num', e.op); want(tr, 'num', e.op)
        if (ARITH[e.op]) { body.word(ARITH[e.op]); return 'num' }
        if (CMP[e.op]) { body.word(CMP[e.op]); return 'flag' }
        if (e.op === '<=') { body.word('>'); body.word('0='); return 'flag' }
        if (e.op === '>=') { body.word('<'); body.word('0='); return 'flag' }
        throw new Error(`BASIC: no jetForth word for ${e.op}`)
      }
      case 'call': {
        const f = e.f
        const need = n => { if (e.a.length !== n) throw new Error(`BASIC: ${f} takes ${n} argument(s), got ${e.a.length}`) }
        if (NUMWORD[f]) {
          const [w, n, r] = NUMWORD[f]
          need(n)
          for (const x of e.a) want(emit(x), 'num', f)
          body.word(w); return r
        }
        // trunc(x·y / 2^32) and trunc(x·2^32 / y). The word */ keeps the product at double width, which a
        // 64-bit cell needs: 1.0 × 1.0 is already 2^64.
        if (f === 'FMUL' || f === 'FDIV') {
          need(2)
          want(emit(e.a[0]), 'num', f)
          if (f === 'FMUL') { want(emit(e.a[1]), 'num', f); body.num(BASIC_S) }
          else { body.num(BASIC_S); want(emit(e.a[1]), 'num', f) }
          body.word('*/'); return 'num'
        }
        if (f === 'SIZE') { need(1); want(emit(e.a[0]), 'bytes', f); body.word('NIP'); return 'num' }
        if (f === 'BIN2NUM') { need(1); want(emit(e.a[0]), 'bytes', f); body.word('BIN2NUM'); return 'num' }
        if (f === 'SAMEBYTES') {
          need(2); want(emit(e.a[0]), 'bytes', f); want(emit(e.a[1]), 'bytes', f)
          body.word('BYTES='); return 'flag'
        }
        if (f === 'CAT') {
          need(2); want(emit(e.a[0]), 'bytes', f); want(emit(e.a[1]), 'bytes', f)
          body.local('(LOCAL@)', hp); body.word('CAT'); commit(); return 'bytes'
        }
        if (f === 'NUM2BIN') {
          need(2); want(emit(e.a[0]), 'num', f); want(emit(e.a[1]), 'num', f)
          body.local('(LOCAL@)', hp); body.word('NUM2BIN'); commit(); return 'bytes'
        }
        if (HASHES[f]) {
          need(1); want(emit(e.a[0]), 'bytes', f)
          body.local('(LOCAL@)', hp); body.word('DUP'); body.word('>R'); body.word(f); body.word('R>')
          body.num(BigInt(HASHES[f])); commit(); return 'bytes'
        }
        if (f === 'SPLIT') {
          throw new Error('BASIC: SPLIT gives back TWO values — a left half and a right half — so it ' +
            'needs two names: left, right = SPLIT(bytes, at)')
        }
        if (f === 'CHECKSIG') {
          throw new Error('BASIC: CHECKSIG — jetForth\'s takes the digest it checks as well as the signature ' +
            'and the key, so its BASIC form is still to be decided')
        }
        throw new Error(`BASIC: no such word — ${f}`)
      }
    }
  }

  /** Assign the value on top to `name`, creating it on first assignment. */
  function assign(name, t) {
    if (has(consts, name)) throw new Error(`BASIC: ${name} is a compile-time constant and cannot be assigned`)
    let l = locals.get(name)
    if (!l) l = alloc(name, t)
    else if ((l.type === 'bytes') !== (t === 'bytes')) {
      throw new Error(`BASIC: ${name} holds ${l.type === 'bytes' ? 'bytes' : 'a number'}, and this gives it ` +
        `${t === 'bytes' ? 'bytes' : 'a number'} — a variable keeps one kind`)
    }
    store(l)
    if (!assigned.includes(name)) assigned.push(name)
  }

  /** Which variables a block assigns. */
  function assignedBy(ss, into) {
    for (const s of ss) {
      if (s.t === 'let') into.add(s.name)
      else if (s.t === 'split') { into.add(s.left); into.add(s.right) }
      else if (s.t === 'for') assignedBy(s.body, into)
      else if (s.t === 'verify') continue
      else { assignedBy(s.then, into); assignedBy(s.else, into) }
    }
  }

  function run(ss) {
    for (const s of ss) {
      if (s.t === 'let') { assign(s.name, emit(s.e)); continue }
      if (s.t === 'verify') {
        want(emit(s.e), 'num', 'VERIFY')
        body.word('0='); body.abortIf(); continue
      }
      if (s.t === 'split') {
        want(emit(s.of), 'bytes', 'SPLIT'); want(emit(s.at), 'num', 'SPLIT')
        body.word('SPLIT')
        /* Both names are created left first, as written; the right half is on top, so it is stored first. */
        for (const n of [s.left, s.right]) if (!locals.has(n) && !has(consts, n)) alloc(n, 'bytes')
        assign(s.right, 'bytes'); assign(s.left, 'bytes')
        continue
      }
      if (s.t === 'for') { loop(s); continue }
      // IF
      /* A variable assigned inside an IF must exist before it, or there is a path on which it was never
         given a value. */
      const names = new Set()
      assignedBy(s.then, names); assignedBy(s.else, names)
      for (const n of names) {
        if (!locals.has(n)) {
          throw new Error(`BASIC: ${n} is assigned inside an IF but does not exist before it — ` +
            'give it a value first, or one path leaves it with none')
        }
      }
      want(emit(s.cond), 'num', 'IF')
      const lElse = body.label()
      body.branch('0BRANCH', lElse)
      run(s.then)
      if (s.else.length) {
        const lEnd = body.label()
        body.branch('BRANCH', lEnd)
        body.place(lElse)
        run(s.else)
        body.place(lEnd)
      } else body.place(lElse)
    }
  }

  /**
   * FOR … NEXT, as a loop. From, TO and STEP are worked out once, before the counter is set — BASIC's
   * order — and the test sits at the top, so `FOR i = 1 TO 0` runs the body no times.
   *
   *   <from> <to> [<step>]  [(LOCAL!) st] (LOCAL!) lim (LOCAL!) i
   *   top:  i lim > 0=  (i lim < 0= when STEP is negative)      0BRANCH end
   *         body
   *         i 1+ (LOCAL!) i   or   i st + (LOCAL!) i              BRANCH top
   *   end:
   *
   * A STEP whose sign is known only when the script runs tests that sign on every trip. Whether a loop
   * ends is not the compiler's question: jetmora checks a loop before it runs it.
   */
  function loop(s) {
    if (open.has(s.name)) throw new Error(`BASIC: FOR ${s.name} is already open — a nested loop needs its own counter`)
    if (has(consts, s.name)) throw new Error(`BASIC: ${s.name} is a compile-time constant and cannot count a loop`)
    const old = locals.get(s.name)
    if (old && old.type === 'bytes') throw new Error(`BASIC: ${s.name} holds bytes, and a FOR counter is a number`)
    want(emit(s.from), 'num', 'FOR'); want(emit(s.to), 'num', 'TO')
    let dir = 1
    if (s.step) {
      want(emit(s.step), 'num', 'STEP')
      const k = constEval(s.step)
      dir = k === undefined ? 0 : k < 0n ? -1 : 1
    }
    const i = old ?? alloc(s.name, 'num')
    hidden++
    const lim = alloc(`#lim${hidden}`, 'num')
    const st = s.step ? alloc(`#st${hidden}`, 'num') : null
    if (st) body.local('(LOCAL!)', st.k)
    body.local('(LOCAL!)', lim.k)
    body.local('(LOCAL!)', i.k)
    if (!assigned.includes(s.name)) assigned.push(s.name)

    const top = body.label(), end = body.label()
    const test = cmp => { body.local('(LOCAL@)', i.k); body.local('(LOCAL@)', lim.k); body.word(cmp); body.word('0=') }
    body.place(top)
    if (dir === 0) {
      const up = body.label(), go = body.label()
      body.local('(LOCAL@)', st.k); body.word('0<'); body.branch('0BRANCH', up)
      test('<'); body.branch('BRANCH', go)
      body.place(up); test('>')
      body.place(go)
    } else test(dir > 0 ? '>' : '<')
    body.branch('0BRANCH', end)

    open.add(s.name)
    run(s.body)
    open.delete(s.name)

    body.local('(LOCAL@)', i.k)
    if (st) { body.local('(LOCAL@)', st.k); body.word('+') } else body.word('1+')
    body.local('(LOCAL!)', i.k)
    body.branch('BRANCH', top)
    body.place(end)
  }

  run(prog)

  const leave = env.leave ?? []
  for (const n of leave) {
    const l = locals.get(n)
    if (!l || n.startsWith('#')) throw new Error(`BASIC: ${n} is left on the stack but never given a value`)
    fetch(l)
  }
  body.word('(UNFRAME)')
  if (covenant) body.word('TRUE')

  // ── the prologue, now that every literal is known ──
  const pro = new Code()
  pro.bytes(W('(FRAME)'), nIn)
  for (const [h, k] of literals) {
    pro.push(h.match(/../g).map(x => parseInt(x, 16)))
    pro.local('(LOCAL!)', k + 1); pro.local('(LOCAL!)', k)
  }
  pro.bytes(0); pro.word('DROP'); pro.local('(LOCAL!)', fl)          // PUSH0 leaves ( floor 0 )
  pro.num(0n); pro.local('(LOCAL!)', hp)
  if (covenant) {
    const p = locals.get('preimage')
    pro.local('(LOCAL@)', hp); pro.word('PREIMAGE')
    pro.word('2DUP'); pro.word('+'); pro.word('DUP'); pro.local('(LOCAL@)', fl); pro.word('>')
    pro.abortIf(); pro.local('(LOCAL!)', hp)
    pro.local('(LOCAL!)', p.k + 1); pro.local('(LOCAL!)', p.k)
  }
  const a = pro.assemble(), b = body.assemble()
  const bytes = new Uint8Array(a.length + b.length)
  bytes.set(a, 0); bytes.set(b, a.length)

  /** local index → name, for the reader. Inputs, variables and counters; not the compiler's own. */
  const names = {}
  for (const l of locals.values()) if (!l.name.startsWith('#')) names[l.k] = l.name
  return { bytes, nVersion: JF_NVERSION, revision: JF_REVISION, compiler: BASIC_JF_VERSION,
           assigned, names, inputs: env.stack ?? [], leave }
}

/**
 * Compile a program. What it leaves on the stack is what `env.leave` names.
 * @param {string} src
 * @param {BasicEnv} [env]
 */
export function compileBasic(src, env = {}) { return compile(src, env, false) }

/**
 * Compile a covenant: the program runs with `preimage` bound to the tick's own preimage, through the
 * PREIMAGE word, and accepts the tick by running to the end — it leaves exactly TRUE. A VERIFY that fails
 * refuses it.
 * @param {string} src
 * @param {{ stack?: string[], consts?: Record<string, number> }} [env]
 */
export function compileCovenant(src, env = {}) {
  if (env.leave?.length) throw new Error('BASIC: a covenant leaves its verdict and nothing else')
  return compile(src, env, true)
}
