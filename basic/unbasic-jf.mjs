// © 2026 sun-dive — Apache License 2.0.
/**
 * jetForth → BASIC: the reader. It reads bytecode and renders what it computes, so a covenant can be
 * checked by reading it.
 *
 * The method is grafverse/mint/src/unbasic.ts's: symbolic execution, on a stack of expressions instead of
 * values. What it reads is what basic-jf.mjs emits — its prologue, its loops, its heap — and anything it
 * does not model stops the reading, by name, at the instruction. It never guesses: a listing that quietly
 * skipped an instruction would be believed.
 *
 * Variables come back named by their local slot (`v12`) unless the names are supplied; the compiler
 * returns them as `names`.
 */
import { JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_WORD, JF_ESC0, JF_RESERVED0, jf_op_name } from '../tools/ops-jf.mjs'
import { JF_NVERSION, JF_REVISION } from './basic-jf.mjs'

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
    if (at === 0 && op === JF_RESERVED0) throw new Error('a DEFS header — stdForth functions, which this reader does not read')
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
      if (lit === 'LITBIG') throw new Error(`LITBIG at ${at} — a number wider than a cell, which this reader does not read`)
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
    if (U8.has(name)) { out.push({ at, size: 2, name, arg: Number(u(i, 1)) }); i++; continue }
    if (name === '(ABORT")') {
      const n = Number(u(i, 1)); i++
      out.push({ at, size: 2 + n, name, data: b.slice(i, i + n) }); i += n; continue
    }
    out.push({ at, size: 1, name })
  }
  return out
}

/** The instructions as text, one per line, with their offsets — the layer beneath the BASIC. */
export function jfListing(b) {
  return disassemble(b).map(x => {
    const arg = x.data ? (x.name === '(ABORT")' ? JSON.stringify(new TextDecoder().decode(x.data)) : `&H${HEX(x.data)}`)
      : x.value !== undefined ? String(x.value) : x.arg !== undefined ? (REL16.has(x.name) ? `→ ${x.arg}` : String(x.arg)) : ''
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
     { k: 'n', v, flag, cmp?, l?, r?, istrue? }   a number; `flag` when it is -1 or 0
     { k: 'a', b } { k: 'u', b }                   the two cells of a byte string b, address then length
     { k: 'hp' }                                   the heap pointer, where the next bytes will be written */
const N = (v, flag = false, more = {}) => ({ k: 'n', v, flag, ...more })

class Stop extends Error {}

/**
 * Read bytecode as BASIC.
 * @param {Uint8Array} bytes
 * @param {{ names?: Record<number, string>, stack?: string[], nVersion?: number }} [opts]
 *   names     local slot → variable name (compileBasic returns this)
 *   stack     what the unlocking script leaves, bottom first, `$` for bytes — as given to the compiler
 *   nVersion  the version the entry names; bytes numbered in another revision are not read as this one
 * @returns {{ lines: string[], covenant: boolean, leave: string[], stack: string[], stoppedAt?: string }}
 */
export function unbasic(bytes, opts = {}) {
  const lines = []
  if (opts.nVersion !== undefined && opts.nVersion >>> 0 !== JF_NVERSION) {
    return { lines, covenant: false, leave: [], stack: [],
      stoppedAt: `the entry names version 0x${(opts.nVersion >>> 0).toString(16)}, and this reader reads JF revision ${JF_REVISION} (0x${JF_NVERSION.toString(16)})` }
  }
  const say = (depth, s) => lines.push('  '.repeat(depth) + s)
  let ins
  try { ins = disassemble(bytes) } catch (e) { return { lines, covenant: false, leave: [], stack: [], stoppedAt: e.message } }
  lines.push(`VERSION JF ${JF_REVISION}`)
  const idxAt = new Map(ins.map((x, k) => [x.at, k]))
  const is = (k, name, arg) => ins[k] && ins[k].name === name && (arg === undefined || ins[k].arg === arg)

  /** local slot → { name, type: 'n'|'b'|'lit'|'hp'|'fl', lit? } */
  const L = new Map()
  const nameOf = k => opts.names?.[k] ?? `v${k}`
  const st = []
  const rs = []
  let hp = -1, fl = -1, covenant = false
  const leave = [], inputs = []

  /** Loops: a BRANCH back to an earlier instruction. top index → { back: index of that BRANCH }. */
  const loops = new Map()
  ins.forEach((x, k) => { if (x.name === 'BRANCH' && x.arg <= x.at) loops.set(idxAt.get(x.arg), { back: k }) })

  const pop = () => { const v = st.pop(); if (!v) throw new Stop('the script reads below the bottom of the stack'); return v }
  const popNum = () => { const v = pop(); if (v.k !== 'n') throw new Stop('a number was expected here'); return v }
  const popBytes = () => {
    const u = pop(), a = pop()
    if (u.k !== 'u' || a.k !== 'a' || u.b !== a.b) throw new Stop('a byte string ( c-addr u ) was expected here')
    return u.b
  }
  const pushBytes = b => { st.push({ k: 'a', b }, { k: 'u', b }) }
  /** A flag made with 0<> renders as the value it was made from, inside AND and OR. */
  const plain = c => c.istrue ?? c.v

  // ── the compiler's idioms, matched instruction for instruction ──
  /** `2DUP + DUP (LOCAL@) fl > (ABORT") "" (LOCAL!) hp` — the heap pointer moved past what was written. */
  const commitAt = k => is(k, '2DUP') && is(k + 1, '+') && is(k + 2, 'DUP') && is(k + 3, '(LOCAL@)', fl)
    && is(k + 4, '>') && is(k + 5, '(ABORT")') && ins[k + 5].data.length === 0 && is(k + 6, '(LOCAL!)', hp)
  const HASH = { SHA256: 32n, HASH256: 32n, HASH160: 20n, RIPEMD160: 20n, SHA1: 20n }

  /**
   * Straight-line code from k, statement by statement, to `end` (an instruction index).
   * Structure — IF and FOR — is read where its branches say it is.
   */
  function block(k, end, depth) {
    while (k < end) {
      const x = ins[k]
      const where = `${x.name} at ${x.at}`
      try {
        // ── a FOR: its counter, limit and step are stored straight before the top of the loop ──
        if (x.name === '(LOCAL!)') {
          let t = k; while (t < end && ins[t].name === '(LOCAL!)') t++
          if (loops.has(t) && (t - k === 2 || t - k === 3)) { k = forLoop(k, t, depth); continue }
        }
        switch (x.name) {
          case 'NUM': st.push(N(atom(String(x.value)))); k++; continue
          case 'PUSH': pushBytes(atom(`&H${HEX(x.data)}`)); k++; continue
          case '(LOCAL@)': {
            const l = L.get(x.arg)
            if (!l) throw new Stop(`local ${x.arg} is read before anything is stored in it`)
            if (l.type === 'hp') {
              const h = Object.keys(HASH).find(f => is(k + 1, 'DUP') && is(k + 2, '>R') && is(k + 3, f) && is(k + 4, 'R>')
                && is(k + 5, 'NUM') && ins[k + 5].value === HASH[f] && commitAt(k + 6))
              if (h) { pushBytes(call(h, popBytes())); k += 13; continue }
              st.push({ k: 'hp' }); k++; continue
            }
            if (l.type === 'n') { st.push(N(atom(l.name))); k++; continue }
            if (!is(k + 1, '(LOCAL@)', x.arg + 1)) throw new Stop(`half of the byte string in local ${x.arg}`)
            pushBytes(l.type === 'lit' ? l.lit : atom(l.name)); k += 2; continue
          }
          case '(LOCAL!)': {
            const top = st[st.length - 1]
            if (!top) throw new Stop('a store with nothing to store')
            if (top.k === 'n') {
              const v = popNum()
              const l = L.get(x.arg) ?? { name: nameOf(x.arg), type: 'n' }
              if (l.type !== 'n') throw new Stop(`local ${x.arg} held bytes and is given a number`)
              L.set(x.arg, l); say(depth, `${l.name} = ${v.v.txt}`); k++; continue
            }
            if (!is(k + 1, '(LOCAL!)', x.arg - 1)) throw new Stop('half of a byte string stored')
            const b = popBytes()
            const l = L.get(x.arg - 1) ?? { name: nameOf(x.arg - 1), type: 'b' }
            if (l.type !== 'b') throw new Stop(`local ${x.arg - 1} is given bytes`)
            L.set(x.arg - 1, l); say(depth, `${l.name} = ${b.txt}`); k += 2; continue
          }
          case 'DUP': {
            // `DUP 0< (ABORT") 1 SWAP 0 (?DO) OVER * (LOOP) NIP` — the compiler's `^`
            if (is(k + 1, '0<') && is(k + 2, '(ABORT")') && ins[k + 2].data.length === 0
              && is(k + 3, 'NUM') && ins[k + 3].value === 1n && is(k + 4, 'SWAP') && is(k + 5, 'NUM') && ins[k + 5].value === 0n
              && is(k + 6, '(?DO)', ins[k + 10]?.at) && is(k + 7, 'OVER') && is(k + 8, '*') && is(k + 9, '(LOOP)', ins[k + 7].at)
              && is(k + 10, 'NIP')) {
              const r = popNum(), l = popNum(); st.push(N(pow(l.v, r.v))); k += 11; continue
            }
            throw new Stop('DUP outside a sequence the compiler emits')
          }
          case 'NIP': {
            const t = pop(), s = pop()
            if (t.k === 'u' && s.k === 'a' && t.b === s.b) { st.push(N(call('SIZE', t.b))); k++; continue }
            throw new Stop('NIP of something other than a byte string\'s address')
          }
          case 'BIN2NUM': st.push(N(call('BIN2NUM', popBytes()))); k++; continue
          case 'BYTES=': { const b2 = popBytes(), b1 = popBytes(); st.push(N(call('SAMEBYTES', b1, b2), true)); k++; continue }
          case 'CAT': case 'NUM2BIN': {
            if (pop().k !== 'hp') throw new Stop(`${x.name} writing somewhere other than the heap`)
            if (!commitAt(k + 1)) throw new Stop(`${x.name} whose result the heap pointer does not move past`)
            if (x.name === 'CAT') { const b2 = popBytes(), b1 = popBytes(); pushBytes(call('CAT', b1, b2)) }
            else { const w = popNum(), v = popNum(); pushBytes(call('NUM2BIN', v.v, w.v)) }
            k += 8; continue
          }
          case 'SPLIT': {
            const n = popNum(), b = popBytes()
            const r = ins[k + 1]?.arg, l = ins[k + 3]?.arg
            if (!(is(k + 1, '(LOCAL!)') && is(k + 2, '(LOCAL!)', r - 1) && is(k + 3, '(LOCAL!)') && is(k + 4, '(LOCAL!)', l - 1)))
              throw new Stop('SPLIT whose halves are not stored straight away')
            for (const s of [l - 1, r - 1]) {
              const v = L.get(s) ?? { name: nameOf(s), type: 'b' }
              if (v.type !== 'b') throw new Stop(`local ${s} is given bytes`)
              L.set(s, v)
            }
            say(depth, `${L.get(l - 1).name}, ${L.get(r - 1).name} = SPLIT(${b.txt}, ${n.v.txt})`)
            k += 5; continue
          }
          case '+': case '-': case '*': case '/': {
            const r = popNum(), l = popNum(); st.push(N(bin(l.v, x.name, r.v))); k++; continue
          }
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
            else throw new Stop('*/ that is neither FMUL nor FDIV')
            k++; continue
          }
          case '0<>': { const v = popNum(); st.push(N(call('ISTRUE', v.v), true, { istrue: v.v })); k++; continue }
          case '0=': {
            const v = popNum()
            if (is(k + 1, '(ABORT")') && ins[k + 1].data.length === 0) { say(depth, `VERIFY ${v.v.txt}`); k += 2; continue }
            if (v.cmp === '>') st.push(N(bin(v.l, '<=', v.r), true))
            else if (v.cmp === '<') st.push(N(bin(v.l, '>=', v.r), true))
            else st.push(N(call('NOT', v.v), true))
            k++; continue
          }
          case '0BRANCH': { k = ifThen(k, depth); continue }
        }
        throw new Stop('this reader does not model it')
      } catch (e) {
        if (e instanceof Stop) throw new Stop(`${where}: ${e.message}`)
        throw e
      }
    }
    return k
  }

  /** IF at the 0BRANCH k: the THEN arm runs to its target, and a BRANCH just before that target is the ELSE. */
  function ifThen(k, depth) {
    const cond = popNum()
    if (st.length) throw new Stop('values held on the stack across an IF, which this reader does not follow')
    const lElse = idxAt.get(ins[k].arg)
    if (lElse === undefined || lElse <= k) throw new Stop('a 0BRANCH that is not forward to an instruction')
    say(depth, `IF ${cond.v.txt} THEN`)
    const j = lElse - 1
    if (is(j, 'BRANCH') && ins[j].arg > ins[j].at) {
      const lEnd = idxAt.get(ins[j].arg) ?? ins.length
      block(k + 1, j, depth + 1)
      say(depth, 'ELSE')
      block(lElse, lEnd, depth + 1)
      say(depth, 'END IF')
      return lEnd
    }
    block(k + 1, lElse, depth + 1)
    say(depth, 'END IF')
    return lElse
  }

  /**
   * FOR at the setup stores [k, top): ( from to [step] ) stored to [st] lim i, then the test, the body, and
   * `i 1+` or `i st +` stored back to i before the BRANCH to the top.
   */
  function forLoop(k, top, depth) {
    const n = top - k
    const iK = ins[top - 1].arg, limK = ins[top - 2].arg, stK = n === 3 ? ins[k].arg : -1
    const vals = []
    for (let t = 0; t < n; t++) vals.unshift(popNum())  // bottom first: from, to, [step]
    const [vFrom, vTo, vStep] = vals
    const t = top
    const test = (at, cmp) => is(at, '(LOCAL@)', iK) && is(at + 1, '(LOCAL@)', limK) && is(at + 2, cmp) && is(at + 3, '0=')
    let body
    if (test(t, '>') && is(t + 4, '0BRANCH')) body = t + 5
    else if (test(t, '<') && is(t + 4, '0BRANCH')) {
      if (stK < 0) throw new Stop('a downward test with no STEP')
      body = t + 5
    } else if (stK >= 0 && is(t, '(LOCAL@)', stK) && is(t + 1, '0<') && is(t + 2, '0BRANCH') && test(t + 3, '<')
      && is(t + 7, 'BRANCH') && test(t + 8, '>') && is(t + 12, '0BRANCH')
      && ins[t + 2].arg === ins[t + 8].at && ins[t + 7].arg === ins[t + 12].at) body = t + 13
    else throw new Stop('a loop whose test this reader does not recognise')
    const back = loops.get(top).back
    const endAt = ins[body - 1].arg
    if (endAt !== ins[back].at + 3) throw new Stop('a loop whose exit is not straight after its BRANCH back')
    const inc = stK < 0
      ? is(back - 3, '(LOCAL@)', iK) && is(back - 2, '1+') && is(back - 1, '(LOCAL!)', iK) ? back - 3 : -1
      : is(back - 4, '(LOCAL@)', iK) && is(back - 3, '(LOCAL@)', stK) && is(back - 2, '+') && is(back - 1, '(LOCAL!)', iK) ? back - 4 : -1
    if (inc < 0) throw new Stop('a loop whose counter does not step')
    const i = L.get(iK) ?? { name: nameOf(iK), type: 'n' }
    L.set(iK, i)
    L.set(limK, { name: '#lim', type: 'hidden' })
    if (stK >= 0) L.set(stK, { name: '#st', type: 'hidden' })
    say(depth, `FOR ${i.name} = ${vFrom.v.txt} TO ${vTo.v.txt}${vStep ? ` STEP ${vStep.v.txt}` : ''}`)
    block(body, inc, depth + 1)
    say(depth, `NEXT ${i.name}`)
    return back + 1
  }

  try {
    let k = 0
    if (is(0, '(FRAME)')) {
      // ── the prologue ──
      let slot = 0
      for (const raw of opts.stack ?? []) {
        const b = raw.endsWith('$'), name = b ? raw.slice(0, -1) : raw
        L.set(slot, { name, type: b ? 'b' : 'n' }); inputs.push(raw); slot += b ? 2 : 1
      }
      if (slot !== ins[0].arg) {
        if ((opts.stack ?? []).length) throw new Stop(`(FRAME) ${ins[0].arg} takes ${ins[0].arg} cells from the unlocking script, and ${slot} are named`)
        for (let s = 0; s < ins[0].arg; s++) { L.set(s, { name: `in${s}`, type: 'n' }); inputs.push(`in${s}`) }
      }
      k = 1
      while (is(k, 'PUSH') && ins[k].data.length && is(k + 1, '(LOCAL!)') && is(k + 2, '(LOCAL!)', ins[k + 1].arg - 1)) {
        L.set(ins[k + 2].arg, { name: '#lit', type: 'lit', lit: atom(`&H${HEX(ins[k].data)}`) }); k += 3
      }
      if (!(is(k, 'PUSH') && ins[k].data.length === 0 && is(k + 1, 'DROP') && is(k + 2, '(LOCAL!)')
        && is(k + 3, 'NUM') && ins[k + 3].value === 0n && is(k + 4, '(LOCAL!)')))
        throw new Stop(`instruction ${k}: the heap is not set up where a compiled program sets it up`)
      fl = ins[k + 2].arg; hp = ins[k + 4].arg
      L.set(fl, { name: '#fl', type: 'fl' }); L.set(hp, { name: '#hp', type: 'hp' })
      k += 5
      if (is(k, '(LOCAL@)', hp) && is(k + 1, 'PREIMAGE') && commitAt(k + 2) && is(k + 9, '(LOCAL!)') && is(k + 10, '(LOCAL!)', ins[k + 9].arg - 1)) {
        covenant = true
        lines.push('REM  a covenant: preimage is the tick\'s own, and running to the end accepts it')
        L.set(ins[k + 10].arg, { name: 'preimage', type: 'b' })
        k += 11
      }
    }
    // ── the epilogue: (UNFRAME), TRUE for a covenant, and what the program leaves before it ──
    let end = ins.length
    if (covenant) {
      if (!(is(end - 1, 'TRUE') && is(end - 2, '(UNFRAME)'))) throw new Stop('a covenant that does not end with its verdict')
      end -= 2
    } else if (is(0, '(FRAME)')) {
      if (!is(end - 1, '(UNFRAME)')) throw new Stop('a program that does not close its frame')
      end -= 1
    }
    // what is left is the run of fetches straight before (UNFRAME): no statement ends with a fetch
    let lv = end
    while (lv > k && is(lv - 1, '(LOCAL@)')) lv--
    block(k, lv, 0)
    for (let t = lv; t < end; t++) {
      const l = L.get(ins[t].arg)
      if (!l) throw new Stop(`local ${ins[t].arg} is left on the stack without a value`)
      if (l.type === 'b') { if (!is(t + 1, '(LOCAL@)', ins[t].arg + 1)) throw new Stop('half a byte string left'); t++ }
      leave.push(l.name)
    }
    return { lines, covenant, leave, stack: inputs }
  } catch (e) {
    if (!(e instanceof Stop)) throw e
    return { lines, covenant, leave, stack: inputs, stoppedAt: e.message }
  }
}

/** A full listing, numbered the way BASIC always was. */
export function unbasicListing(bytes, opts = {}) {
  const r = unbasic(bytes, opts)
  const out = r.lines.map((l, i) => `${String((i + 1) * 10).padStart(5)} ${l}`)
  if (r.leave.length) out.push('', `REM  left on the stack: ${r.leave.join(', ')}`)
  if (r.stoppedAt) out.push('', `REM  ⚠ STOPPED: ${r.stoppedAt}`)
  return out.join('\n')
}
