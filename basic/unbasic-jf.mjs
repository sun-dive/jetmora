// © 2026 sun-dive — Apache License 2.0.
/**
 * jetForth → BASIC: the decompiler, a view over any jetForth. It reads bytecode and renders what it computes, so a
 * script can be checked by reading it, whoever wrote it: this compiler, an earlier version of it, or a person.
 *
 * The method is grafverse/mint/src/unbasic.ts's: symbolic execution, on a stack of expressions instead of values.
 * A number is one cell, a byte string two, its address and its length, and lengths and addresses are followed as
 * sums of constants and lengths. Variables are cells at addresses known when the script is read: `addr @` reads one
 * and `addr !` assigns it. What a word writes to memory (a hash, CAT, NUM2BIN, the preimage's fields, MOVE…) is kept
 * by its place, so a span read back from memory is the expression written there, CAT of writes side by side, or
 * REPLACE(x, at, y) where a later write lies inside an earlier one. A value used twice is computed once: it gets a
 * name and a line of its own. Under everything the lock pushes are the tick's own pushes, in0, in1, … the first
 * pushed first. Anything the decompiler does not model stops the reading, by name, at the instruction. It never guesses:
 * a listing that quietly skipped an instruction would be believed.
 *
 * A script's first instruction is the lock's declaration, `VER JF 3`, and it is read back as the VERSION line. A
 * script that declares no version, or another one, is not read: this decompiler reads JF revision 3.
 *
 * Three readings, the first that holds:
 *   a covenant as this compiler writes one: its head pushes are its DIM fields, the stores that bind the tick's pushes
 *     after the key and the checks after them its INPUT line, its frame and rebuild laid down again for that layout
 *     and matched byte for byte; what lies between is the program. The reading compiles back to the same bytes
 *   a program as this compiler writes one: what is on the stack bound to variables first, then the program, then
 *     what it leaves. The reading compiles back to the same bytes
 *   any script: read as what it computes. A script that uses a word only a covenant's lock runs (the preimage's words)
 *     is a covenant: its leading pushes are its state, as DIM fields. This reading is a READING, not a source: it
 *     names what BASIC has no word for (REPLACE, SUBSTR, MEMORY, BYTE) and need not compile back
 * Variables come back named by their address (`v24`) unless the names are supplied; the compiler returns them as
 * `names`, and a covenant's fields take the names of the variables they are bound to.
 */
import { JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_WORD, JF_ESC0, JF_RESERVED0, jf_op_name } from '../tools/ops-jf.mjs'
import { JF_NVERSION, JF_REVISION, INPUT_WIDEST, covenantFrame } from './basic-jf.mjs'

const NAME = new Map(Object.entries(JF_WORD).map(([k, v]) => [v, k]))
const LIT = new Map(Object.entries(JF_LIT).map(([k, v]) => [v, k]))
const REL16 = new Set(['0BRANCH', 'BRANCH', 'LEAVE', '(?DO)', '(LOOP)', '(+LOOP)'])
const U8 = new Set(['INVOKE', '(FRAME)', '(LOCAL!)', '(LOCAL@)'])
const HEX = d => Array.from(d, b => b.toString(16).padStart(2, '0')).join('')
const S32 = 4294967296n

/**
 * Bytecode → instructions.
 * @returns {{at:number, size:number, name:string, arg?:number, value?:bigint, data?:Uint8Array}[]}
 */
export function disassemble(b) {
  const out = []
  const u = (i, n) => { if (i + n > b.length) throw new Error(`truncated at ${i}`); let v = 0n
    for (let k = n - 1; k >= 0; k--) v = (v << 8n) | BigInt(b[i + k]); return v }
  let i = 0
  while (i < b.length) {
    const at = i, op = b[i++]
    // a DEFS header opens the script, or follows the lock's declaration
    if (op === JF_RESERVED0 && (at === 0 || (at === 5 && out[0]?.name === 'VER')))
      throw new Error('a DEFS header: stdForth functions, which this decompiler does not read')
    if (op <= JF_PUSH_MAX) {
      if (i + op > b.length) throw new Error(`a push past the end, at ${at}`)
      out.push({ at, size: 1 + op, name: 'PUSH', data: b.slice(i, i + op) }); i += op; continue
    }
    if (op >= JF_SMALL0 && op <= JF_SMALL_NEG1) {
      out.push({ at, size: 1, name: 'NUM', value: op === JF_SMALL_NEG1 ? -1n : BigInt(op - JF_SMALL0) }); continue
    }
    const lit = LIT.get(op)
    if (lit) {
      if (lit.startsWith('LIT') && lit !== 'LITBIG') {
        const w = { LIT8: 1, LIT16: 2, LIT32: 4, LIT64: 8 }[lit]
        let v = u(i, w); if (v >> BigInt(8 * w - 1)) v -= 1n << BigInt(8 * w)
        out.push({ at, size: 1 + w, name: 'NUM', value: v }); i += w; continue
      }
      if (lit === 'LITBIG') throw new Error(`LITBIG at ${at}: a number wider than a cell, which this decompiler does not read`)
      const w = { STR8: 1, STR16: 2, STR32: 4 }[lit]
      const n = Number(u(i, w)); i += w
      if (i + n > b.length) throw new Error(`a string past the end, at ${at}`)
      out.push({ at, size: 1 + w + n, name: 'PUSH', data: b.slice(i, i + n) }); i += n; continue
    }
    if (op >= JF_ESC0) {
      out.push({ at, size: 2, name: `${jf_op_name(op)}:${b[i] ?? '?'}` }); i++; continue
    }
    const name = NAME.get(op) ?? jf_op_name(op)
    if (REL16.has(name)) {
      let off = Number(u(i, 2)); if (off >= 0x8000) off -= 0x10000
      out.push({ at, size: 3, name, arg: at + 3 + off }); i += 2; continue
    }
    if (name === 'CALL') { out.push({ at, size: 3, name, arg: Number(u(i, 2)) }); i += 2; continue }
    // the lock's declaration: arg is the version it declares, an nVersion
    if (name === 'VER') { out.push({ at, size: 5, name, arg: Number(u(i, 4)) }); i += 4; continue }
    if (U8.has(name)) { out.push({ at, size: 2, name, arg: Number(u(i, 1)) }); i++; continue }
    if (name === '(ABORT")') {
      const n = Number(u(i, 1)); i++
      out.push({ at, size: 2 + n, name, data: b.slice(i, i + n) }); i += n; continue
    }
    out.push({ at, size: 1, name })
  }
  return out
}

/** A declared version as the assembler writes it, `JF 3`; one whose family is not two of A to Z and 0 to 9, as its four bytes. */
const versionText = v => {
  const c0 = (v >>> 16) & 0xff, c1 = v >>> 24, legal = c => (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39)
  return legal(c0) && legal(c1) ? `${String.fromCharCode(c0, c1)} ${v & 0xffff}` : `&H${HEX([v & 0xff, (v >>> 8) & 0xff, c0, c1])}`
}

/** The instructions as text, one per line, with their offsets — the layer beneath the BASIC. */
export function jfListing(b) {
  return disassemble(b).map(x => {
    const arg = x.data ? (x.name === '(ABORT")' ? JSON.stringify(new TextDecoder().decode(x.data)) : `&H${HEX(x.data)}`)
      : x.value !== undefined ? String(x.value) : x.name === 'VER' ? versionText(x.arg)
      : x.arg !== undefined ? (REL16.has(x.name) ? `→ ${x.arg}` : String(x.arg)) : ''
    return `${String(x.at).padStart(5)}  ${x.name === 'NUM' ? '' : x.name}${x.name === 'NUM' || !arg ? arg : ' ' + arg}`
  }).join('\n')
}

// ── expressions ─────────────────────────────────────────────────────────────────────────────────────
/** An expression's text, the binding power of its outermost operator, and whether it is a name or a literal. */
const atom = txt => ({ txt, bp: 99, simple: true })
const wrap = (v, need) => (v.bp < need ? `(${v.txt})` : v.txt)
/** The binding powers the compiler parses with, so a reading parses back as it reads. */
const BPOF = { 'OR': 1, 'AND': 2, '=': 3, '<>': 3, '<': 3, '>': 3, '<=': 3, '>=': 3, '+': 4, '-': 4, '*': 5, '/': 5 }
const bin = (l, o, r) => { const bp = BPOF[o]; return { txt: `${wrap(l, bp)} ${o} ${wrap(r, bp + 1)}`, bp, simple: false } }
const call = (f, ...a) => ({ txt: `${f}(${a.map(v => v.txt).join(', ')})`, bp: 99, simple: false })
/** `^` binds tightest and is right-associative: 2 ^ 3 ^ 2 is 2 ^ 9. */
const pow = (l, r) => ({ txt: `${wrap(l, 7)} ^ ${wrap(r, 6)}`, bp: 6, simple: false })

/* A cell on the symbolic stack:
     { k: 'n', v, flag, cmp?, l?, r?, istrue?, not?, lin? }   a number; `flag` when it is -1 or 0; `not`, what a 0= was
                                                             made from; `lin` when it is a constant, a byte string's
                                                             length, or a sum of those: what an address or a length is
     { k: 'a', b, at? } { k: 'u', b }                        the two cells of a byte string b, its address then its length;
                                                             `at`, the address, when a word wrote b to memory there
   A byte string is { e, len }: its expression, and its length as a linear form. */
const N = (v, flag = false, more = {}) => ({ k: 'n', v, flag, ...more })
const HASH = { SHA256: 32n, HASH256: 32n, HASH160: 20n, RIPEMD160: 20n, SHA1: 20n }
/** The preimage's byte fields, ( dest -- dest u ): their BASIC names, and their lengths when fixed */
const FIELD = { 'PREIMAGE': ['PREIMAGE', null], 'SCRIPTCODE': ['SCRIPTCODE', null], 'OUTPUTS-HASH': ['OUTPUTS_HASH', 32n],
                'PREVOUTS-HASH': ['PREVOUTS_HASH', 32n], 'SEQUENCES-HASH': ['SEQUENCES_HASH', 32n], 'OUTPOINT': ['OUTPOINT', 36n] }
/** Words only a covenant's lock may run: a script that uses one reads its leading pushes as its state */
export const COVENANT_WORDS = new Set([...Object.keys(FIELD), 'TXVALUE', 'NSEQUENCE', 'LOCKTIME'])
/** A check that aborts when its flag is set holds when the opposite comparison does */
const OPPOSITE = { '=': '<>', '<>': '=', '<': '>=', '>': '<=', '<=': '>', '>=': '<' }

// ── linear forms: { c, t }, a constant and a sum of named lengths, so an address or a length can be followed ──
const lin = (c = 0n, t = new Map()) => ({ c: BigInt(c), t })
const linOf = txt => lin(0n, new Map([[txt, 1n]]))
const linAdd = (a, b, s = 1n) => {
  const t = new Map(a.t)
  for (const [key, v] of b.t) { const x = (t.get(key) ?? 0n) + s * v; if (x) t.set(key, x); else t.delete(key) }
  return { c: a.c + s * b.c, t }
}
const linEq = (a, b) => a.c === b.c && a.t.size === b.t.size && [...a.t].every(([key, v]) => b.t.get(key) === v)
const linConst = a => a.t.size === 0 ? a.c : null
/** -1, 0 or 1 when the sign of a − b is known: a constant, or lengths (never negative) all added, or all taken
 *  away, with a constant of the same sign; null otherwise */
const linCmp = (a, b) => {
  const d = linAdd(a, b, -1n)
  if (!d.t.size) return d.c < 0n ? -1 : d.c > 0n ? 1 : 0
  const ts = [...d.t.values()]
  if (ts.every(v => v > 0n) && d.c >= 0n) return 1
  if (ts.every(v => v < 0n) && d.c <= 0n) return -1
  return null
}
const linText = a => {
  const parts = [...a.t].map(([key, v]) => v === 1n ? key : `${v} * ${key}`)
  if (a.c || !parts.length) parts.push(String(a.c))
  return parts.join(' + ').replace(/\+ -/g, '- ')
}
const B = (e, len) => ({ e, len })

class Stop extends Error {}

/**
 * The reading machine over a run of instructions. `vars` is what the decompiler knows of memory as variables:
 * address → { name, type: 'n' | 'b' | 'hidden' }; a store to an address it does not know declares it. With
 * `opts.inputs`, reading below the bottom of the stack reaches the tick's own pushes, each a byte string, and names
 * them; without it, that stops the reading. `opts.names` names the variables a head field is bound to.
 */
function machine(ins, vars, nameOf, opts = {}) {
  const lines = []
  let cur = 0                        // the depth being written at
  const say = (depth, s) => lines.push('  '.repeat(depth) + s)
  const st = [], rs = []
  const written = new Set()          // the names this reading assigns
  const inputs = []                  // the tick's pushes reached, the last pushed first
  const writes = []                  // byte strings words wrote to memory: { at, b, seq }
  let seq = 0, temps = 0
  const idxAt = new Map(ins.map((x, k) => [x.at, k]))
  /* a branch to just past the last instruction read lands at the end of the run */
  if (ins.length) idxAt.set(ins[ins.length - 1].at + ins[ins.length - 1].size, ins.length)
  const is = (k, name, arg) => ins[k] !== undefined && ins[k].name === name && (arg === undefined || ins[k].arg === arg)
  const isNum = (k, v) => ins[k] !== undefined && ins[k].name === 'NUM' && (v === undefined || ins[k].value === BigInt(v))
  const addrAt = k => Number(ins[k].value)
  const temp = () => `t${++temps}`
  let loopDepth = 0                  // inside a FOR, a variable's value is not one form

  /** Loops: a BRANCH back to an earlier instruction. top index → { back: index of that BRANCH }. */
  const loops = new Map()
  ins.forEach((x, k) => { if (x.name === 'BRANCH' && x.arg <= x.at) loops.set(idxAt.get(x.arg), { back: k }) })

  const pushBytes = (b, at) => { st.push(at === undefined ? { k: 'a', b } : { k: 'a', b, at }, { k: 'u', b }) }
  /* the tick's pushes are under everything the lock pushes; each is a byte string, the unlocking script being byte
     pushes only. Named for now by how deep they are; in0 is the first pushed once the reading knows how many */
  const more = () => {
    if (!opts.inputs) throw new Stop('the script reads below the bottom of the stack')
    const b = B(atom(`in·${inputs.length}`), null)
    b.len = linOf(`SIZE(${b.e.txt})`)
    inputs.push(b); st.unshift({ k: 'a', b }, { k: 'u', b })
  }
  const ensure = n => { while (st.length < n) more() }
  const pop = () => { if (!st.length) more(); return st.pop() }
  const numOf = c => {
    if (c.k === 'n') return c
    if (c.k === 'u') return N(c.b.n ?? call('SIZE', c.b.e), false, { lin: c.b.len })
    if (c.at !== undefined) return N(atom(String(c.at)), false, { lin: lin(c.at) })
    throw new Stop('a byte string\'s address used as a number')
  }
  const popNum = () => numOf(pop())
  /** A place in memory: a number known when the script is read */
  const popAddr = () => {
    const v = popNum(), a = v.lin ? linConst(v.lin) : null
    if (a === null) throw new Stop('an address that is worked out as the script runs, which this decompiler does not follow')
    return a
  }
  const write = (at, b) => { writes.push({ at, b, seq: ++seq }) }
  /* A word that writes a $ field's bytes in their place in the next output (`opts.places`) is the program assigning
     the field; when what it wrote is then stored in a variable, the store says so instead. `n` is where that store's
     2! is: past the address CAT and NUM2BIN leave, or past the ( d u ) a hash's is given. */
  const placed = (k, d, b, n) => {
    const f = opts.places?.get(Number(d))
    if (!f || !b.len || linConst(b.len) !== BigInt(f.width)) return
    let stored = is(k + n, '2!')
    for (let j = 1; j < n; j++) stored &&= isNum(k + j)
    if (stored) return
    say(cur, `${f.name} = ${b.e.txt}`); written.add(f.name)
  }
  /** The byte string a ( c-addr u ) pair stands for: a string on the stack, or what was written to memory there */
  const spanOf = (a, u) => {
    if (a.k === 'a' && u.k === 'u' && a.b === u.b) return a.b
    if (a.k === 'a' && a.at !== undefined) a = numOf(a)
    const n = numOf(u)
    if (a.k === 'n' && a.lin && linConst(a.lin) !== null && n.lin) return memRead(linConst(a.lin), n.lin) ?? B(call('MEMORY', a.v, n.v), n.lin)
    throw new Stop('a byte string ( c-addr u ) was expected here')
  }
  const popBytes = () => { const u = pop(), a = pop(); return spanOf(a, u) }

  /**
   * The bytes in memory from `at`, `len` long, rebuilt from what was written there. First as whole writes laid end to
   * end, each the newest at its place, landing exactly on the end of the read; else piece by piece, a write that starts
   * here or covers here taken from where this place falls in it. In both, one written later inside a piece is laid
   * over it as REPLACE (the later bytes over the earlier, as long as the earlier is), and pieces side by side are
   * joined with CAT. null when the writes do not account for every byte.
   */
  function memRead(at, len) {
    const end = linAdd(lin(at), len)
    const parts = whole(at, end) ?? pieces(at, end)
    return parts && B(parts.reduce((l, r) => call('CAT', l, r)), len)
  }
  /** The newest write that starts at this place, or covers it */
  const newestAt = pc => {
    let w = null
    for (const x of writes) {
      const n = linConst(x.b.len)
      if ((x.at === pc || (x.at < pc && n !== null && x.at + n > pc)) && (!w || x.seq > w.seq)) w = x
    }
    return w
  }
  /** A write's bytes from `pc`, with the writes made later inside it laid over them */
  const overlaid = (e, w, pc, pieceEnd) => {
    for (const o of writes) {
      if (o.seq <= w.seq || o.at <= pc) continue
      const inside = linCmp(lin(o.at), pieceEnd)
      if (inside === null || inside < 0) e = call('REPLACE', e, atom(String(o.at - pc)), o.b.e)
    }
    return e
  }
  function whole(at, end) {
    const parts = []
    let p = lin(at)
    for (let guard = 0; !linEq(p, end); guard++) {
      const pc = linConst(p)
      if (pc === null || guard > 64) return null
      const w = newestAt(pc)
      if (!w || w.at !== pc) return null
      const next = linAdd(p, w.b.len)
      if (linCmp(next, end) === 1) return null
      parts.push(overlaid(w.b.e, w, pc, next))
      p = next
    }
    return parts
  }
  function pieces(at, end) {
    const parts = []
    let p = lin(at)
    for (let guard = 0; !linEq(p, end); guard++) {
      const pc = linConst(p)
      if (pc === null || guard > 64) return null
      const w = newestAt(pc)
      if (!w) return null
      const off = pc - w.at, wEnd = linAdd(lin(w.at), w.b.len), toEnd = linCmp(end, wEnd)
      let pieceLen
      if (off === 0n && (toEnd === 0 || linEq(end, wEnd))) pieceLen = w.b.len
      else if (toEnd !== null && toEnd <= 0) pieceLen = linAdd(end, p, -1n)
      else if (toEnd !== null) pieceLen = linAdd(wEnd, p, -1n)
      else return null
      const e = off === 0n && linEq(pieceLen, w.b.len) ? w.b.e
        : call('SUBSTR', w.b.e, atom(String(off)), atom(linText(pieceLen)))
      const pieceEnd = linAdd(p, pieceLen)
      parts.push(overlaid(e, w, pc, pieceEnd))
      p = pieceEnd
    }
    return parts
  }

  /** A value about to be used twice is computed once: it gets a name and a line of its own */
  const mat = c => {
    if (c.k === 'n') { if (!c.v.simple) { const t = temp(); say(cur, `${t} = ${c.v.txt}`); c.v = atom(t) } return c }
    if (!c.b.e.simple) { const t = temp(); say(cur, `${t} = ${c.b.e.txt}`); c.b.e = atom(t) }
    return c
  }
  /** A flag made with 0<> renders as the value it was made from, inside AND and OR. */
  const plain = c => c.istrue ?? c.v
  /** What a check that aborts on this flag requires: the flag's opposite */
  const holds = f => f.not ?? (f.cmp ? bin(f.l, OPPOSITE[f.cmp], f.r) : call('NOT', f.v))

  /** The variable at an address, declared by its first store. */
  const varFor = (addr, type) => {
    let v = vars.get(addr)
    if (!v) { v = { name: nameOf(addr), type }; vars.set(addr, v) }
    if (v.type !== type) throw new Stop(`address ${addr} holds ${v.type === 'b' ? 'bytes' : 'a number'} and is given ${type === 'b' ? 'bytes' : 'a number'}`)
    return v
  }
  const read = (addr, type) => {
    const v = vars.get(addr)
    if (!v || v.type === 'hidden') throw new Stop(`address ${addr} is read before anything is stored there`)
    if (v.type !== type) throw new Stop(`address ${addr} holds ${v.type === 'b' ? 'bytes' : 'a number'}`)
    return v
  }
  /** A constant the instruction before pushed: the depth PICK reaches */
  const depthOf = c => { const d = c.lin ? linConst(c.lin) : null; if (d === null || d < 0n) throw new Stop('PICK at a depth worked out as the script runs'); return Number(d) }

  /** Straight-line code from k, statement by statement, to `end` (an instruction index). */
  function block(k, end, depth) {
    while (k < end) {
      cur = depth
      const x = ins[k]
      const where = `${x.name === 'NUM' ? String(x.value) : x.name} at ${x.at}`
      try {
        // a FOR: its counter, limit and step are stored straight before the top of the loop
        if (x.name === 'NUM' && is(k + 1, '!')) {
          let t = k, pairs = 0
          while (t < end && isNum(t) && is(t + 1, '!')) { t += 2; pairs++ }
          if (loops.has(t) && (pairs === 2 || pairs === 3)) { k = forLoop(k, t, pairs, depth); continue }
        }
        switch (x.name) {
          case 'NUM': st.push(N(atom(String(x.value)), false, { lin: lin(x.value) })); k++; continue
          case 'PUSH': pushBytes(B(atom(`&H${HEX(x.data)}`), lin(x.data.length))); k++; continue
          case 'TRUE': st.push(N(atom('-1'), true, { lin: lin(-1n) })); k++; continue
          case 'FALSE': st.push(N(atom('0'), true, { lin: lin(0n) })); k++; continue

          // ── variables, at addresses known when the script is read ──
          case '@': { const a = popAddr(), v = read(Number(a), 'n'); st.push(N(atom(v.name), false, v.once && v.lin ? { lin: v.lin } : {})); k++; continue }
          case 'C@': { const a = popAddr(); st.push(N(call('BIN2NUM', (memRead(a, lin(1n)) ?? B(call('MEMORY', atom(String(a)), atom('1')), lin(1n))).e))); k++; continue }
          case 'C!': { const a = popAddr(), v = popNum(); write(a, B(call('BYTE', v.v), lin(1n))); k++; continue }
          case '2@': { const a = popAddr(); pushBytes(B(atom(read(Number(a), 'b').name), null)); st.at(-1).b.len = linOf(`SIZE(${st.at(-1).b.e.txt})`); k++; continue }
          case '!': {
            const a = Number(popAddr()), val = popNum(), v = varFor(a, 'n')
            v.once = !written.has(v.name) && !loopDepth; v.lin = val.lin
            written.add(v.name); say(depth, `${v.name} = ${val.v.txt}`); k++; continue
          }
          case '2!': {
            const a = Number(popAddr()), b = popBytes()
            /* a head field bound to a variable the compiler named takes that name: the binding is the frame's, not a line */
            if (b.field !== undefined && opts.names?.[a] && !vars.has(a)) {
              b.e = atom(opts.names[a]); b.len = b.len ?? lin(0); vars.set(a, { name: opts.names[a], type: 'b' }); opts.onField?.(b.field, opts.names[a]); k++; continue
            }
            const v = varFor(a, 'b')
            written.add(v.name); say(depth, `${v.name} = ${b.e.txt}`); k++; continue
          }

          // ── the stack ──
          case 'DUP': {
            // `DUP 0< (ABORT") 1 SWAP 0 (?DO) OVER * (LOOP) NIP` — the compiler's `^`
            if (is(k + 1, '0<') && is(k + 2, '(ABORT")') && ins[k + 2].data.length === 0
              && isNum(k + 3, 1) && is(k + 4, 'SWAP') && isNum(k + 5, 0)
              && is(k + 6, '(?DO)', ins[k + 10]?.at) && is(k + 7, 'OVER') && is(k + 8, '*') && is(k + 9, '(LOOP)', ins[k + 7].at)
              && is(k + 10, 'NIP')) {
              const r = popNum(), l = popNum(); st.push(N(pow(l.v, r.v))); k += 11; continue
            }
            const c = mat(pop()); st.push(c, c); k++; continue
          }
          case 'DROP': pop(); k++; continue
          case '2DROP': pop(); pop(); k++; continue
          case 'NIP': {
            const t = pop(), s = pop()
            if (t.k === 'u' && s.k === 'a' && t.b === s.b) { st.push(N(call('SIZE', t.b.e), false, { lin: t.b.len })); k++; continue }
            st.push(t); k++; continue
          }
          case 'SWAP': { const b2 = pop(), a2 = pop(); st.push(b2, a2); k++; continue }
          case 'OVER': { const b2 = pop(), a2 = mat(pop()); st.push(a2, b2, a2); k++; continue }
          case 'TUCK': { const b2 = mat(pop()), a2 = pop(); st.push(b2, a2, b2); k++; continue }
          case 'ROT': { const c3 = pop(), b3 = pop(), a3 = pop(); st.push(b3, c3, a3); k++; continue }
          case '2DUP': { const b2 = mat(pop()), a2 = mat(pop()); st.push(a2, b2, a2, b2); k++; continue }
          case '2SWAP': { const d4 = pop(), c4 = pop(), b4 = pop(), a4 = pop(); st.push(c4, d4, a4, b4); k++; continue }
          case '2OVER': { const d4 = pop(), c4 = pop(), b4 = mat(pop()), a4 = mat(pop()); st.push(a4, b4, c4, d4, a4, b4); k++; continue }
          case 'PICK': { const d = depthOf(popNum()); ensure(d + 1); const c = mat(st[st.length - 1 - d]); st.push(c); k++; continue }
          case '>R': rs.push(pop()); k++; continue
          case 'R>': { if (!rs.length) throw new Stop('R> with nothing set aside'); st.push(rs.pop()); k++; continue }
          case 'R@': { if (!rs.length) throw new Stop('R@ with nothing set aside'); st.push(mat(rs.at(-1))); k++; continue }
          case '2>R': { const b2 = pop(), a2 = pop(); rs.push(a2, b2); k++; continue }
          case '2R>': { if (rs.length < 2) throw new Stop('2R> with nothing set aside'); const b2 = rs.pop(), a2 = rs.pop(); st.push(a2, b2); k++; continue }
          case '2R@': { if (rs.length < 2) throw new Stop('2R@ with nothing set aside'); const b2 = mat(rs.at(-1)), a2 = mat(rs.at(-2)); st.push(a2, b2); k++; continue }

          // ── byte strings ──
          case 'SIZE': { const t = pop(); st.push(t, t.k === 'u' ? N(call('SIZE', t.b.e), false, { lin: t.b.len }) : mat(numOf(t))); k++; continue }
          case 'BIN2NUM': st.push(N(call('BIN2NUM', popBytes().e))); k++; continue
          case 'BYTES=': { const b2 = popBytes(), b1 = popBytes(); st.push(N(call('SAMEBYTES', b1.e, b2.e), true)); k++; continue }
          case 'CAT': {
            const d = popAddr(), b2 = popBytes(), b1 = popBytes(), b = B(call('CAT', b1.e, b2.e), linAdd(b1.len, b2.len))
            write(d, b); placed(k, d, b, 2); pushBytes(b, d); k++; continue
          }
          case 'NUM2BIN': {
            const d = popAddr(), w = popNum(), v = popNum(), b = B(call('NUM2BIN', v.v, w.v), w.lin ?? null); b.n = w.v
            if (!b.len) b.len = linOf(`SIZE(${b.e.txt})`)
            write(d, b); placed(k, d, b, 2); pushBytes(b, d); k++; continue
          }
          case 'SUBSTR': case 'LEFT': case 'RIGHT': {
            const d = popAddr(), n = popNum(), beg = x.name === 'SUBSTR' ? popNum() : null, s = popBytes()
            const b = B(x.name === 'SUBSTR' ? call('SUBSTR', s.e, beg.v, n.v) : call(x.name, s.e, n.v), n.lin ?? null); b.n = n.v
            if (!b.len) b.len = linOf(`SIZE(${b.e.txt})`)
            write(d, b); pushBytes(b, d); k++; continue
          }
          case 'MOVE': {
            const n = pop(), d = popAddr(), a = pop()
            write(d, spanOf(a, n)); k++; continue
          }
          case 'SPLIT': {
            const n = popNum(), b = popBytes()
            if (isNum(k + 1) && is(k + 2, '2!') && isNum(k + 3) && is(k + 4, '2!')) {
              const r = varFor(addrAt(k + 1), 'b'), l = varFor(addrAt(k + 3), 'b')
              written.add(l.name); written.add(r.name)
              say(depth, `${l.name}, ${r.name} = SPLIT(${b.e.txt}, ${n.v.txt})`)
              k += 5; continue
            }
            /* SPLIT gives two values: both get names, one expression cannot stand for two results */
            const tl = temp(), tr = temp()
            say(depth, `${tl}, ${tr} = SPLIT(${b.e.txt}, ${n.v.txt})`)
            const lb = B(atom(tl), n.lin ?? linOf(`SIZE(${tl})`)), rb = B(atom(tr), n.lin ? linAdd(b.len, n.lin, -1n) : linOf(`SIZE(${tr})`))
            pushBytes(lb); pushBytes(rb); k++; continue
          }
          case 'PREIMAGE': case 'SCRIPTCODE': case 'OUTPUTS-HASH': case 'PREVOUTS-HASH': case 'SEQUENCES-HASH': case 'OUTPOINT': {
            const d = popAddr(), [name, n] = FIELD[x.name], b = B(call(name), n === null ? null : lin(n))
            if (!b.len) b.len = linOf(`SIZE(${b.e.txt})`)
            write(d, b); pushBytes(b, d); k++; continue
          }
          case 'TXVALUE': case 'NSEQUENCE': case 'LOCKTIME': st.push(N(call(x.name))); k++; continue
          case 'SHA256': case 'HASH256': case 'HASH160': case 'RIPEMD160': case 'SHA1': {
            const d = popAddr(), b = popBytes(), h = B(call(x.name, b.e), lin(HASH[x.name])); write(d, h); placed(k, d, h, 4); k++; continue
          }
          case 'ED25519-CHECKSIG': {
            const m = popBytes(), p = popBytes(), s = popBytes(); st.push(N(call('ED25519SIG', s.e, p.e, m.e), true)); k++; continue
          }
          case 'CHECKSIG': {
            const m = popBytes(), p = popBytes(), s = popBytes(); st.push(N(call('CHECKSIG', s.e, p.e, m.e), true)); k++; continue
          }

          // ── numbers ──
          case '+': case '-': {
            const r = popNum(), l = popNum()
            st.push(N(bin(l.v, x.name, r.v), false, l.lin && r.lin ? { lin: linAdd(l.lin, r.lin, x.name === '+' ? 1n : -1n) } : {})); k++; continue
          }
          case '1+': case '1-': {
            const v = popNum(), one = lin(1n)
            st.push(N(bin(v.v, x.name === '1+' ? '+' : '-', atom('1')), false, v.lin ? { lin: linAdd(v.lin, one, x.name === '1+' ? 1n : -1n) } : {})); k++; continue
          }
          case '*': case '/': { const r = popNum(), l = popNum(); st.push(N(bin(l.v, x.name, r.v))); k++; continue }
          case '=': case '<>': case '<': case '>': {
            const r = popNum(), l = popNum(); st.push(N(bin(l.v, x.name, r.v), true, { cmp: x.name, l: l.v, r: r.v })); k++; continue
          }
          case 'AND': case 'OR': {
            const r = popNum(), l = popNum()
            st.push(l.flag && r.flag ? N(bin(plain(l), x.name, plain(r)), true) : N(call(x.name === 'AND' ? 'BITAND' : 'BITOR', l.v, r.v)))
            k++; continue
          }
          case 'XOR': { const r = popNum(), l = popNum(); st.push(N(call('BITXOR', l.v, r.v))); k++; continue }
          case 'MIN': case 'MAX': case 'MOD': case 'LSHIFT': case 'RSHIFT': {
            const r = popNum(), l = popNum(); st.push(N(call(x.name, l.v, r.v))); k++; continue
          }
          case 'ABS': case 'INVERT': st.push(N(call(x.name, popNum().v))); k++; continue
          case 'NEGATE': { const v = popNum().v; st.push(N({ txt: `-${wrap(v, 99)}`, bp: 99, simple: false })); k++; continue }
          case 'WITHIN': { const hi = popNum(), lo = popNum(), t = popNum(); st.push(N(call('WITHIN', t.v, lo.v, hi.v), true)); k++; continue }
          case '*/': {
            const c = popNum(), b2 = popNum(), a2 = popNum()
            if (c.v.txt === String(S32)) st.push(N(call('FMUL', a2.v, b2.v)))
            else if (b2.v.txt === String(S32)) st.push(N(call('FDIV', a2.v, c.v)))
            else st.push(N(call('MULDIV', a2.v, b2.v, c.v)))
            k++; continue
          }
          case '0<>': { const v = popNum(); st.push(N(call('ISTRUE', v.v), true, { istrue: v.v })); k++; continue }
          case '0<': { const v = popNum(); st.push(N(bin(v.v, '<', atom('0')), true, { cmp: '<', l: v.v, r: atom('0') })); k++; continue }
          case '0>': { const v = popNum(); st.push(N(bin(v.v, '>', atom('0')), true, { cmp: '>', l: v.v, r: atom('0') })); k++; continue }
          case '0=': {
            const v = popNum()
            if (v.cmp === '>') st.push(N(bin(v.l, '<=', v.r), true, { not: v.v, cmp: '<=', l: v.l, r: v.r }))
            else if (v.cmp === '<') st.push(N(bin(v.l, '>=', v.r), true, { not: v.v, cmp: '>=', l: v.l, r: v.r }))
            else st.push(N(call('NOT', v.v), true, { not: v.v }))
            k++; continue
          }

          // ── checks and branches ──
          case '(ABORT")': {
            const f = popNum(), h = holds(f)
            say(depth, `VERIFY ${h.txt}` + (x.data.length ? `   REM  else it aborts with "${new TextDecoder().decode(x.data)}"` : ''))
            k++; continue
          }
          case 'ABORT': say(depth, 'STOP'); k++; continue
          case '0BRANCH': { k = ifThen(k, depth); continue }
        }
        throw new Stop('this decompiler does not model it')
      } catch (e) {
        if (e instanceof Stop && !e.message.includes(' at ')) throw new Stop(`${where}: ${e.message}`)
        throw e
      }
    }
    return k
  }

  /** IF at the 0BRANCH k: the THEN arm runs to its target, and a BRANCH just before that target is the ELSE. Values
   *  held across it are named first, and both arms must leave the same values. */
  function ifThen(k, depth) {
    const cond = popNum()
    for (const c of st) mat(c)
    const before = st.slice()
    const lElse = idxAt.get(ins[k].arg)
    if (lElse === undefined || lElse <= k) throw new Stop('a 0BRANCH that is not forward to an instruction')
    say(depth, `IF ${cond.v.txt} THEN`)
    const j = lElse - 1
    const same = (a, b) => a.length === b.length && a.every((c, i) => c === b[i])
    if (is(j, 'BRANCH') && ins[j].arg > ins[j].at) {
      const lEnd = idxAt.get(ins[j].arg) ?? ins.length
      block(k + 1, j, depth + 1)
      const thenEnd = st.splice(0); st.push(...before)
      say(depth, 'ELSE')
      block(lElse, lEnd, depth + 1)
      if (!same(thenEnd, st)) throw new Stop('the two arms of an IF leave different values on the stack, which this decompiler does not follow')
      say(depth, 'END IF')
      return lEnd
    }
    block(k + 1, lElse, depth + 1)
    if (!same(before, st)) throw new Stop('an IF whose arm changes what is on the stack, which this decompiler does not follow')
    say(depth, 'END IF')
    return lElse
  }

  /**
   * FOR at the setup stores [k, top): ( from to [step] ) stored to [st] lim i, then the test, the body, and
   * `i @ 1+` or `i @ st @ +` stored back to i before the BRANCH to the top.
   */
  function forLoop(k, top, pairs, depth) {
    const iK = addrAt(top - 2), limK = addrAt(top - 4), stK = pairs === 3 ? addrAt(k) : -1
    const vals = []
    for (let t = 0; t < pairs; t++) vals.unshift(popNum())   // bottom first: from, to, [step]
    const [vFrom, vTo, vStep] = vals
    const t = top
    const test = (at, cmp) => isNum(at, iK) && is(at + 1, '@') && isNum(at + 2, limK) && is(at + 3, '@') && is(at + 4, cmp) && is(at + 5, '0=')
    let body
    if (test(t, '>') && is(t + 6, '0BRANCH')) body = t + 7
    else if (stK >= 0 && test(t, '<') && is(t + 6, '0BRANCH')) body = t + 7
    else if (stK >= 0 && isNum(t, stK) && is(t + 1, '@') && is(t + 2, '0<') && is(t + 3, '0BRANCH') && test(t + 4, '<')
      && is(t + 10, 'BRANCH') && test(t + 11, '>') && is(t + 17, '0BRANCH')
      && ins[t + 3].arg === ins[t + 11].at && ins[t + 10].arg === ins[t + 17].at) body = t + 18
    else throw new Stop('a loop whose test this decompiler does not recognise')
    const back = loops.get(top).back
    if (ins[body - 1].arg !== ins[back].at + 3) throw new Stop('a loop whose exit is not straight after its BRANCH back')
    const inc = stK < 0
      ? isNum(back - 5, iK) && is(back - 4, '@') && is(back - 3, '1+') && isNum(back - 2, iK) && is(back - 1, '!') ? back - 5 : -1
      : isNum(back - 7, iK) && is(back - 6, '@') && isNum(back - 5, stK) && is(back - 4, '@') && is(back - 3, '+')
        && isNum(back - 2, iK) && is(back - 1, '!') ? back - 7 : -1
    if (inc < 0) throw new Stop('a loop whose counter does not step')
    const i = varFor(iK, 'n')
    vars.set(limK, { name: '#lim', type: 'hidden' })
    if (stK >= 0) vars.set(stK, { name: '#st', type: 'hidden' })
    written.add(i.name)
    say(depth, `FOR ${i.name} = ${vFrom.v.txt} TO ${vTo.v.txt}${vStep ? ` STEP ${vStep.v.txt}` : ''}`)
    loopDepth++; block(body, inc, depth + 1); loopDepth--
    say(depth, `NEXT ${i.name}`)
    return back + 1
  }

  return { lines, st, written, block, is, isNum, inputs, pushBytes }
}

/** A field's value in the head of the script: a number for `%`, its bytes for `$`. */
const fieldValue = (f, data) => f.bytes ? [...data] : [...data].reverse().reduce((v, b) => (v << 8n) | BigInt(b), 0n)

/**
 * The covenant in a script, if there is one: its head pushes, the binding that follows them, and a frame
 * and rebuild that are byte for byte what the compiler lays down for that layout. `ins` is the instructions
 * after the declaration; `version` is the VERSION line read from it.
 */
function readCovenant(bytes, ins, opts, version) {
  let n = 0
  while (ins[n]?.name === 'PUSH' && ins[n].data.length >= 1) n++
  if (n === 0) return null
  /* the binding: the fields from the top down — a number through BIN2NUM, one nothing reads dropped — then the key and
     the signature */
  const bound = []
  let k = n
  for (let i = n - 1; i >= 0; i--) {
    if (ins[k]?.name === 'BIN2NUM' && ins[k + 1]?.name === 'NUM' && ins[k + 2]?.name === '!') { bound[i] = { bytes: false, addr: Number(ins[k + 1].value) }; k += 3 }
    else if (ins[k]?.name === 'NUM' && ins[k + 1]?.name === '2!') { bound[i] = { bytes: true, addr: Number(ins[k].value) }; k += 2 }
    else if (ins[k]?.name === '2DROP') { bound[i] = null; k += 1 }
    else return null
  }
  /* The fields' variables are laid out from 0 in their order, a $ field's 16 bytes, a % field's 8. A dropped field shows
     neither its kind nor its place: each kind is tried, the places it gives held to the stored fields', and the frame
     laid down for it must then match byte for byte */
  const unknown = bound.flatMap((b, i) => b ? [] : [i])
  const kindsTried = []
  for (let m = 0; m < 1 << unknown.length; m++) {
    let at = 0
    const kinds = bound.map((b, i) => {
      const bytes = b ? b.bytes : !(m >> unknown.indexOf(i) & 1), x = { bytes, addr: at, dropped: !b }
      at += bytes ? 16 : 8
      return x
    })
    if (kinds.every((x, i) => !bound[i] || bound[i].addr === x.addr)) kindsTried.push(kinds)
  }
  // then the inputs, the last first; the key and the signature stay on the stack
  const stores = []
  while (ins[k]?.name === 'NUM' && ins[k + 1]?.name === '2!') { stores.push(Number(ins[k].value)); k += 2 }
  /* Each input's checks follow, in the order INPUT names them: a $ input's size when it has a width; a % input's size,
     its bytes read as a number into the variable the program reads, and at 8 bytes that the number is not negative.
     What is read here is only a reading: the frame laid down for it must then match byte for byte. */
  const given = []
  for (const a of [...stores].reverse()) {
    const at = (j, name, v) => ins[k + j]?.name === name && (v === undefined || ins[k + j].value === BigInt(v))
    /* each check is one comparison, the opposite of what must hold, and an abort: SIZE <> w for SIZE = w, > for <= */
    const size = cmp => at(0, 'NUM', a) && at(1, '2@') && at(2, 'NIP') && at(3, 'NUM') && at(4, cmp)
      && at(5, '(ABORT")') && ins[k + 5].data.length === 0
    if (size('<>')) { given.push({ addr: a, width: Number(ins[k + 3].value), bytes: true }); k += 6 }
    else if (size('>') && at(6, 'NUM', a) && at(7, '2@') && at(8, 'BIN2NUM') && at(9, 'NUM') && at(10, '!')) {
      const width = Number(ins[k + 3].value)
      given.push({ addr: Number(ins[k + 9].value), width, bytes: false })
      k += width === 8 ? 11 + 5 : 11                    // at 8 bytes, the VERIFY that it is not negative: 5 more
    } else given.push({ addr: a, width: null, bytes: true })
  }
  const inputs = given.map((x, i) => ({ name: opts.names?.[x.addr] ?? `in${i}`, width: x.width, bytes: x.bytes }))
  // a width INPUT does not give is in no INPUT line: the reading stops there, and gives none that would not compile
  const odd = inputs.find(x => x.width !== null && (x.width < 1 || x.width > (x.bytes ? INPUT_WIDEST.bytes : INPUT_WIDEST.number)))
  const L = bytes.length
  const same = (at, part) => part.length <= L - at && part.every((b, j) => bytes[at + j] === b)
  for (const kinds of kindsTried) for (let o = 0; o < n; o++) {
    if (!kinds[o].bytes || ins[o].data.length !== 20) continue
    const layout = ins.slice(0, n).map((x, i) => ({
      name: i === o ? 'owner' : (opts.names?.[kinds[i].addr] ?? `f${i}`), width: x.data.length, bytes: kinds[i].bytes,
    }))
    const dollars = layout.filter(f => f.bytes).map(f => f.name)
    const numbers = layout.filter(f => !f.bytes).map(f => f.name)
    const dropped = layout.filter((_, i) => kinds[i].dropped).map(f => f.name)
    const { H, frame, places } = covenantFrame(layout, L, [], inputs, dropped)
    if (!same(H, frame)) continue
    /* which fields the program writes decides the rebuild, and of its $ fields, which it writes in their places in the
       next output, which the rebuild then leaves: try each, then hold the reading to it */
    const tries = [[]]
    for (let m = 0; m < 1 << dollars.length; m++) {
      const d = dollars.filter((_, j) => m >> j & 1)
      if (d.length) tries.push(d)
      if (numbers.length) tries.push([...d, numbers[0]])
    }
    const placings = written => {
      const d = written.filter(x => dollars.includes(x))
      return Array.from({ length: 1 << d.length }, (_, m) => d.filter((_, j) => m >> j & 1))
    }
    /* The rebuild with no field to write is the last check alone, the tail of every covenant: the longest rebuild that
       matches is tried first, or a shorter one would read the rest of it as the program */
    const matching = tries.flatMap(written => placings(written).map(inPlace =>
      ({ written, inPlace, rebuild: covenantFrame(layout, L, written, inputs, dropped, inPlace).rebuild })))
      .filter(x => same(L - x.rebuild.length, x.rebuild)).sort((a, b) => b.rebuild.length - a.rebuild.length)
    for (const { written, rebuild } of matching) {
      const state = Object.fromEntries(layout.map((f, i) => [f.name, fieldValue(f, ins[i].data)]))
      const dims = layout.map(f => `DIM ${f.name}${f.bytes ? '$' : '%'}${f.width}`)
      if (odd) {
        return { covenant: true, layout, inputs, state, lines: [version, ...dims],
                 stoppedAt: `${odd.name}${odd.bytes ? '$' : '%'}${odd.width}: no INPUT line has this width (a % input is 1 to ` +
                   `${INPUT_WIDEST.number} bytes, a $ input 1 to ${INPUT_WIDEST.bytes})` }
      }
      const start = H + frame.length, stop = L - rebuild.length
      const vars = new Map([...layout.map((f, i) => [kinds[i].addr, { name: f.name, type: f.bytes ? 'b' : 'n' }]),
                            ...inputs.map((x, i) => [given[i].addr, { name: x.name, type: x.bytes ? 'b' : 'n' }])])
      const body = disassemble(bytes.slice(start, stop))
      /* every $ field's place: a field written there is one the program writes, which the reading is then held to */
      const m = machine(body, vars, a => opts.names?.[a] ?? `v${a}`, { places })
      let stoppedAt
      try { m.block(0, body.length, 0); if (m.st.length) throw new Stop('values left on the stack at the end of the program') }
      catch (e) { if (!(e instanceof Stop)) throw e; stoppedAt = e.message }
      const wrote = layout.filter(f => m.written.has(f.name)).map(f => f.name)
      const holds = wrote.length === 0 ? written.length === 0
        : written.length > 0 && dollars.every(d => wrote.includes(d) === written.includes(d))
      if (!holds && !stoppedAt) continue
      return {
        covenant: true, layout, inputs, stoppedAt, state,
        lines: [version, ...dims,
          ...(inputs.length ? [`INPUT ${inputs.map(x => `${x.name}${x.bytes ? '$' : '%'}${x.width ?? ''}`).join(', ')}`] : []),
          "REM  rules 1 to 4 are the frame: the owner's signature, value + 1 and nSequence, the script rebuilt", ...m.lines],
      }
    }
  }
  return null
}

/**
 * Read bytecode as BASIC.
 * @param {Uint8Array} bytes
 * @param {{ names?: Record<number, string>, stack?: string[], nVersion?: number, general?: boolean }} [opts]
 *   names     address → variable name (the compiler returns this)
 *   stack     what is on the stack when a program starts, bottom first, as given to compileBasic
 *   nVersion  the version the entry names; bytes numbered in another revision are not read as this one
 *   general   read it as any script, as what it computes, even when it is laid out as this compiler writes one
 * @returns {{ lines: string[], covenant: boolean, leave: string[], stack: string[], state?: object, stoppedAt?: string }}
 */
export function unbasic(bytes, opts = {}) {
  if (opts.nVersion !== undefined && opts.nVersion >>> 0 !== JF_NVERSION) {
    return { lines: [], covenant: false, leave: [], stack: [],
      stoppedAt: `the entry names version 0x${(opts.nVersion >>> 0).toString(16)}, and this decompiler reads JF revision ${JF_REVISION} (0x${JF_NVERSION.toString(16)})` }
  }
  // the lock's declaration, VER and the four bytes of the version its code is written for, is the VERSION line
  const declared = bytes.length >= 5 && bytes[0] === JF_WORD.VER ? (bytes[1] | (bytes[2] << 8) | (bytes[3] << 16) | (bytes[4] << 24)) >>> 0 : null
  if (declared === null) {
    return { lines: [], covenant: false, leave: [], stack: [],
      stoppedAt: 'the script declares no version: a lock starts with VER and the version its code is written for' }
  }
  if (declared !== JF_NVERSION) {
    return { lines: [], covenant: false, leave: [], stack: [],
      stoppedAt: `the script declares ${versionText(declared)} (0x${declared.toString(16)}), and this decompiler reads JF revision ${JF_REVISION} (0x${JF_NVERSION.toString(16)})` }
  }
  const lines = [`VERSION ${versionText(declared)}`]
  let ins
  try { ins = disassemble(bytes).slice(1) } catch (e) { return { lines, covenant: false, leave: [], stack: [], stoppedAt: e.message } }
  if (opts.general) return readAny(ins, opts, lines)
  const cov = readCovenant(bytes, ins, opts, lines[0])
  if (cov) return { ...cov, leave: [], stack: [] }
  const own = readProgram(ins, opts, lines)
  return own.stoppedAt === undefined ? own : readAny(ins, opts, lines)
}

/**
 * A program as the compiler writes one: what is on the stack bound to variables first, then the program, then what it
 * leaves, so the reading compiles back to the same bytes. Stops where the script is not laid out so.
 */
function readProgram(ins, opts, lines) {
  const vars = new Map()
  const m = machine(ins, vars, a => opts.names?.[a] ?? `v${a}`)
  const inputs = opts.stack ?? []
  let addr = 0, k = 0
  try {
    const bound = inputs.map(raw => {
      const bytesIn = raw.endsWith('$'), name = raw.replace(/\$$/, '')
      const v = { name, type: bytesIn ? 'b' : 'n', addr }
      addr += bytesIn ? 16 : 8
      if (bytesIn) { const b = atom(name); m.st.push({ k: 'a', b }, { k: 'u', b }) } else m.st.push(N(atom(name)))
      return v
    })
    for (const v of [...bound].reverse()) {
      if (!(m.isNum(k, v.addr) && m.is(k + 1, v.type === 'b' ? '2!' : '!'))) throw new Stop(`the program does not begin by storing ${v.name}`)
      m.st.splice(m.st.length - (v.type === 'b' ? 2 : 1))
      vars.set(v.addr, { name: v.name, type: v.type })
      k += 2
    }
    // what it leaves is the run of fetches at its end: no statement ends with one
    let lv = ins.length
    while (lv - 2 >= k && m.isNum(lv - 2) && (m.is(lv - 1, '@') || m.is(lv - 1, '2@'))) lv -= 2
    m.block(k, lv, 0)
    /* what a program leaves is its variables, fetched at its end: anything else left is not laid out as this compiler
       writes a program, and the general reading says what it is */
    if (m.st.length) throw new Stop('values left on the stack that are not fetched variables')
    const leave = []
    for (let t = lv; t < ins.length; t += 2) {
      const v = vars.get(Number(ins[t].value))
      if (!v) throw new Stop(`address ${ins[t].value} is left on the stack without a value`)
      leave.push(v.name)
    }
    return { lines: [...lines, ...m.lines], covenant: false, leave, stack: inputs }
  } catch (e) {
    if (!(e instanceof Stop)) throw e
    return { lines: [...lines, ...m.lines], covenant: false, leave: [], stack: inputs, stoppedAt: e.message }
  }
}

/**
 * Any script, read as what it computes: the method of grafverse/mint/src/unbasic.ts. Under everything the lock pushes
 * are the tick's own pushes, named in0, in1, … the first pushed first, or as `opts.stack` names them. A script that
 * uses a word only a covenant's lock runs is a covenant: its leading pushes are its state, read back as DIM fields,
 * each named by the variable it is bound to when `opts.names` names it. What is left on the stack at the end is
 * what the script leaves, and a lock is accepted when that is exactly one non-zero cell.
 */
function readAny(ins, opts, lines) {
  const covenant = ins.some(x => COVENANT_WORDS.has(x.name))
  let n = 0
  if (covenant) while (ins[n]?.name === 'PUSH') n++
  const fields = ins.slice(0, n).map((x, i) => ({ name: `f${i}`, width: x.data.length, data: x.data }))
  const vars = new Map()
  const m = machine(ins, vars, a => opts.names?.[a] ?? `v${a}`,
    { inputs: true, names: opts.names, onField: (i, name) => { fields[i].name = name } })
  for (const raw of opts.stack ?? []) {
    const name = raw.replace(/\$$/, ''), b = B(atom(name), linOf(`SIZE(${name})`))
    if (raw.endsWith('$')) m.pushBytes(b); else m.st.push(N(atom(name)))
  }
  for (const [i, f] of fields.entries()) { const b = B(atom(f.name), lin(f.width)); b.field = i; m.pushBytes(b) }
  let stoppedAt
  try { m.block(n, ins.length, 0) }
  catch (e) { if (!(e instanceof Stop)) throw e; stoppedAt = e.message }
  /* the tick's pushes, named as the reading reached them, the last pushed first: in0 is the first pushed */
  const total = m.inputs.length
  const named = s => s.replace(/in·(\d+)/g, (_, d) => `in${total - 1 - Number(d)}`)
  const left = []
  for (let k = 0; k < m.st.length; k++) {
    const c = m.st[k]
    if (c.k === 'a' && m.st[k + 1]?.k === 'u' && m.st[k + 1].b === c.b) { left.push(named(c.b.e.txt)); k++ }
    else left.push(named(c.k === 'n' ? c.v.txt : c.k === 'u' ? `SIZE(${c.b.e.txt})` : `the address of ${c.b.e.txt}`))
  }
  const state = Object.fromEntries(fields.map(f => [f.name, [...f.data]]))
  return {
    covenant, general: true, layout: fields.map(f => ({ name: f.name, width: f.width, bytes: true })), state,
    lines: [...lines, ...fields.map(f => `DIM ${f.name}$${f.width}`),
            ...(total ? [`REM  ${Array.from({ length: total }, (_, i) => `in${i}`).join(', ')}: what the tick pushes, the first pushed first`] : []),
            ...m.lines.map(named)],
    leave: left, stack: opts.stack ?? [], inputs: total, stoppedAt: stoppedAt && named(stoppedAt),
  }
}

/** A full listing, numbered the way BASIC always was. */
export function unbasicListing(bytes, opts = {}) {
  const r = unbasic(bytes, opts)
  const out = r.lines.map((l, i) => `${String((i + 1) * 10).padStart(5)} ${l}`)
  if (r.general && r.leave.length) {
    out.push('', `REM  left on the stack${r.covenant ? ' (the tick is accepted when exactly one cell is left, and it is not zero)' : ''}:`)
    r.leave.forEach((s, i) => out.push(`REM    [${i}] ${s}`))
  } else if (r.leave.length) out.push('', `REM  left on the stack: ${r.leave.join(', ')}`)
  if (r.stoppedAt) out.push('', `REM  ⚠ STOPPED: ${r.stoppedAt}`)
  return out.join('\n')
}
