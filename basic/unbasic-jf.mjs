// © 2026 sun-dive — Apache License 2.0.
/**
 * jetForth → BASIC: the reader. It reads bytecode and renders what it computes, so a covenant can be
 * checked by reading it.
 *
 * The method is grafverse/mint/src/unbasic.ts's: symbolic execution, on a stack of expressions instead of
 * values. Variables are cells at fixed addresses, so `addr @` reads one and `addr !` assigns it; anything
 * the reader does not model stops the reading, by name, at the instruction. It never guesses: a listing
 * that quietly skipped an instruction would be believed.
 *
 * A covenant is read by its parts: the pushes at its head are its DIM fields; its frame and rebuild are
 * found by laying them down again for that layout, and must match byte for byte; what lies between is
 * the program. Variables come back named by their address (`v24`) unless the names are supplied; the
 * compiler returns them as `names`.
 */
import { JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_WORD, JF_ESC0, JF_RESERVED0, jf_op_name } from '../tools/ops-jf.mjs'
import { JF_NVERSION, JF_REVISION, covenantFrame } from './basic-jf.mjs'

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
    if (at === 0 && op === JF_RESERVED0) throw new Error('a DEFS header: stdForth functions, which this reader does not read')
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
      if (lit === 'LITBIG') throw new Error(`LITBIG at ${at}: a number wider than a cell, which this reader does not read`)
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
     { k: 'a', b } { k: 'u', b }                   the two cells of a byte string b, address then length */
const N = (v, flag = false, more = {}) => ({ k: 'n', v, flag, ...more })
const HASH = { SHA256: 32n, HASH256: 32n, HASH160: 20n, RIPEMD160: 20n, SHA1: 20n }

class Stop extends Error {}

/**
 * The reading machine over a run of instructions. `vars` is what the reader knows of memory:
 * address → { name, type: 'n' | 'b' | 'hidden' }; a store to an address it does not know declares it.
 */
function machine(ins, vars, nameOf) {
  const lines = []
  const say = (depth, s) => lines.push('  '.repeat(depth) + s)
  const st = []
  const written = new Set()          // the names this reading assigns
  const idxAt = new Map(ins.map((x, k) => [x.at, k]))
  /* a branch to just past the last instruction read lands at the end of the run */
  if (ins.length) idxAt.set(ins[ins.length - 1].at + ins[ins.length - 1].size, ins.length)
  const is = (k, name, arg) => ins[k] !== undefined && ins[k].name === name && (arg === undefined || ins[k].arg === arg)
  const isNum = (k, v) => ins[k] !== undefined && ins[k].name === 'NUM' && (v === undefined || ins[k].value === BigInt(v))
  const addrAt = k => Number(ins[k].value)

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

  /** Straight-line code from k, statement by statement, to `end` (an instruction index). */
  function block(k, end, depth) {
    while (k < end) {
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
          case 'NUM': {
            const next = ins[k + 1]?.name, addr = Number(x.value)
            if (next === '@') { st.push(N(atom(read(addr, 'n').name))); k += 2; continue }
            if (next === '2@') { pushBytes(atom(read(addr, 'b').name)); k += 2; continue }
            if (next === '!') {
              const val = popNum(), v = varFor(addr, 'n')
              written.add(v.name); say(depth, `${v.name} = ${val.v.txt}`); k += 2; continue
            }
            if (next === '2!') {
              const b = popBytes(), v = varFor(addr, 'b')
              written.add(v.name); say(depth, `${v.name} = ${b.txt}`); k += 2; continue
            }
            if (next === 'CAT') { const b2 = popBytes(), b1 = popBytes(); pushBytes(call('CAT', b1, b2)); k += 2; continue }
            if (next === 'NUM2BIN') { const w = popNum(), v = popNum(); pushBytes(call('NUM2BIN', v.v, w.v)); k += 2; continue }
            if (next === 'PREIMAGE') { pushBytes(call('PREIMAGE')); k += 2; continue }
            if (HASH[next] !== undefined && isNum(k + 2, addr) && isNum(k + 3, HASH[next])) {
              pushBytes(call(next, popBytes())); k += 4; continue
            }
            st.push(N(atom(String(x.value)))); k++; continue
          }
          case 'PUSH': pushBytes(atom(`&H${HEX(x.data)}`)); k++; continue
          case 'NIP': {
            const t = pop(), s = pop()
            if (t.k === 'u' && s.k === 'a' && t.b === s.b) { st.push(N(call('SIZE', t.b))); k++; continue }
            throw new Stop('NIP of something other than a byte string\'s address')
          }
          case 'BIN2NUM': st.push(N(call('BIN2NUM', popBytes()))); k++; continue
          case 'BYTES=': { const b2 = popBytes(), b1 = popBytes(); st.push(N(call('SAMEBYTES', b1, b2), true)); k++; continue }
          case 'ED25519-CHECKSIG': {
            const m = popBytes(), p = popBytes(), s = popBytes(); st.push(N(call('ED25519SIG', s, p, m), true)); k++; continue
          }
          case 'SPLIT': {
            const n = popNum(), b = popBytes()
            if (!(isNum(k + 1) && is(k + 2, '2!') && isNum(k + 3) && is(k + 4, '2!'))) {
              throw new Stop('SPLIT whose halves are not stored straight away')
            }
            const r = varFor(addrAt(k + 1), 'b'), l = varFor(addrAt(k + 3), 'b')
            written.add(l.name); written.add(r.name)
            say(depth, `${l.name}, ${r.name} = SPLIT(${b.txt}, ${n.v.txt})`)
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
          case 'DUP': {
            // `DUP 0< (ABORT") 1 SWAP 0 (?DO) OVER * (LOOP) NIP` — the compiler's `^`
            if (is(k + 1, '0<') && is(k + 2, '(ABORT")') && ins[k + 2].data.length === 0
              && isNum(k + 3, 1) && is(k + 4, 'SWAP') && isNum(k + 5, 0)
              && is(k + 6, '(?DO)', ins[k + 10]?.at) && is(k + 7, 'OVER') && is(k + 8, '*') && is(k + 9, '(LOOP)', ins[k + 7].at)
              && is(k + 10, 'NIP')) {
              const r = popNum(), l = popNum(); st.push(N(pow(l.v, r.v))); k += 11; continue
            }
            throw new Stop('DUP outside a sequence the compiler emits')
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
        if (e instanceof Stop && !e.message.includes(' at ')) throw new Stop(`${where}: ${e.message}`)
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
    else throw new Stop('a loop whose test this reader does not recognise')
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
    block(body, inc, depth + 1)
    say(depth, `NEXT ${i.name}`)
    return back + 1
  }

  return { lines, st, written, block, is, isNum }
}

/** A field's value in the head of the script: a number for `%`, its bytes for `$`. */
const fieldValue = (f, data) => f.bytes ? [...data] : [...data].reverse().reduce((v, b) => (v << 8n) | BigInt(b), 0n)

/**
 * The covenant in a script, if there is one: its head pushes, the binding that follows them, and a frame
 * and rebuild that are byte for byte what the compiler lays down for that layout.
 */
function readCovenant(bytes, ins, opts) {
  let n = 0
  while (ins[n]?.name === 'PUSH' && ins[n].data.length >= 1 && ins[n].data.length <= JF_PUSH_MAX) n++
  if (n === 0) return null
  // the binding: the fields from the top down — a number through BIN2NUM — then the key and the signature
  const kinds = []
  let k = n
  for (let i = n - 1; i >= 0; i--) {
    if (ins[k]?.name === 'BIN2NUM' && ins[k + 1]?.name === 'NUM' && ins[k + 2]?.name === '!') { kinds[i] = { bytes: false, addr: Number(ins[k + 1].value) }; k += 3 }
    else if (ins[k]?.name === 'NUM' && ins[k + 1]?.name === '2!') { kinds[i] = { bytes: true, addr: Number(ins[k].value) }; k += 2 }
    else return null
  }
  const layoutOf = ownerIdx => ins.slice(0, n).map((x, i) => ({
    name: i === ownerIdx ? 'owner' : (opts.names?.[kinds[i].addr] ?? `f${i}`), width: x.data.length, bytes: kinds[i].bytes,
  }))
  const L = bytes.length
  const same = (at, part) => part.length <= L - at && part.every((b, j) => bytes[at + j] === b)
  for (let o = 0; o < n; o++) {
    if (!kinds[o].bytes || ins[o].data.length !== 20) continue
    const layout = layoutOf(o)
    const dollars = layout.filter(f => f.bytes).map(f => f.name)
    const numbers = layout.filter(f => !f.bytes).map(f => f.name)
    const { H, frame } = covenantFrame(layout, L, [])
    if (!same(H, frame)) continue
    // which fields the program writes decides the rebuild: try each, then hold the reading to it
    const tries = [[]]
    for (let m = 0; m < 1 << dollars.length; m++) {
      const d = dollars.filter((_, j) => m >> j & 1)
      if (d.length) tries.push(d)
      if (numbers.length) tries.push([...d, numbers[0]])
    }
    for (const written of tries) {
      const { rebuild } = covenantFrame(layout, L, written)
      if (!same(L - rebuild.length, rebuild)) continue
      const start = H + frame.length, stop = L - rebuild.length
      const vars = new Map(layout.map((f, i) => [kinds[i].addr, { name: f.name, type: f.bytes ? 'b' : 'n' }]))
      const body = disassemble(bytes.slice(start, stop))
      const m = machine(body, vars, a => opts.names?.[a] ?? `v${a}`)
      let stoppedAt
      try { m.block(0, body.length, 0); if (m.st.length) throw new Stop('values left on the stack at the end of the program') }
      catch (e) { if (!(e instanceof Stop)) throw e; stoppedAt = e.message }
      const wrote = layout.filter(f => m.written.has(f.name)).map(f => f.name)
      const holds = wrote.length === 0 ? written.length === 0
        : written.length > 0 && dollars.every(d => wrote.includes(d) === written.includes(d))
      if (!holds && !stoppedAt) continue
      return {
        covenant: true, layout, stoppedAt,
        state: Object.fromEntries(layout.map((f, i) => [f.name, fieldValue(f, ins[i].data)])),
        lines: [`VERSION JF ${JF_REVISION}`, ...layout.map(f => `DIM ${f.name}${f.bytes ? '$' : '%'}${f.width}`),
          "REM  rules 1 to 4 are the frame: the owner's signature, value + 1 and nSequence, the script rebuilt", ...m.lines],
      }
    }
  }
  return null
}

/**
 * Read bytecode as BASIC.
 * @param {Uint8Array} bytes
 * @param {{ names?: Record<number, string>, stack?: string[], nVersion?: number }} [opts]
 *   names     address → variable name (the compiler returns this)
 *   stack     what is on the stack when a program starts, bottom first, as given to compileBasic
 *   nVersion  the version the entry names; bytes numbered in another revision are not read as this one
 * @returns {{ lines: string[], covenant: boolean, leave: string[], stack: string[], state?: object, stoppedAt?: string }}
 */
export function unbasic(bytes, opts = {}) {
  const lines = [`VERSION JF ${JF_REVISION}`]
  if (opts.nVersion !== undefined && opts.nVersion >>> 0 !== JF_NVERSION) {
    return { lines: [], covenant: false, leave: [], stack: [],
      stoppedAt: `the entry names version 0x${(opts.nVersion >>> 0).toString(16)}, and this reader reads JF revision ${JF_REVISION} (0x${JF_NVERSION.toString(16)})` }
  }
  let ins
  try { ins = disassemble(bytes) } catch (e) { return { lines, covenant: false, leave: [], stack: [], stoppedAt: e.message } }
  const cov = readCovenant(bytes, ins, opts)
  if (cov) return { ...cov, leave: [], stack: [] }

  // a program: what is on the stack is bound to variables first, then the program, then what it leaves
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

/** A full listing, numbered the way BASIC always was. */
export function unbasicListing(bytes, opts = {}) {
  const r = unbasic(bytes, opts)
  const out = r.lines.map((l, i) => `${String((i + 1) * 10).padStart(5)} ${l}`)
  if (r.leave.length) out.push('', `REM  left on the stack: ${r.leave.join(', ')}`)
  if (r.stoppedAt) out.push('', `REM  ⚠ STOPPED: ${r.stoppedAt}`)
  return out.join('\n')
}
