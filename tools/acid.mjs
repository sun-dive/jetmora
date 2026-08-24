// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE ACID TEST. A REAL covenant — the lane, 212 lines of BASIC, the physics of a slot car —
// compiled ONCE and executed on THREE independent implementations:
//
//   · an independent BSV Script interpreter, on BSV-numbered bytes
//   · ours, on the same program transcoded to jetmora numbering
//   · the JavaScript reference, which is not a Script interpreter at all
//
// Agreement across all three is evidence. Disagreement names which one is wrong.
// ⇒ doc §2b: H(source) · H(input) → H(output). Run anywhere, same answer.
import { evaluate } from './interpreter.mjs'
import { serialize } from './serialize.mjs'
import { push } from './ops.mjs'
import { bsvToJetmora, jetmoraOnly } from './transcode.mjs'
import { stackHash } from './hash.mjs'

const MINT = process.env.BASIC ?? '/home/sundive/Documents/GitHub/grafverse/mint'
const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const hex = b => Buffer.from(b).toString('hex')

let L, compileState, Spend, LockingScript, UnlockingScript
try {
  L = await import(`${MINT}/src/betaLane.ts`)
  ;({ compileState } = await import(`${MINT}/src/basic.ts`))
  ;({ Spend, LockingScript, UnlockingScript } = await import(SDK))
} catch (e) {
  console.log(`\nSKIPPED — needs the lane source and the BSV SDK.\n  ${String(e.message).split('\n')[0]}\n`); process.exit(0)
}

const toNum = n => {
  n = BigInt(n); if (n === 0n) return []
  const neg = n < 0n; let x = neg ? -n : n; const o = []
  while (x > 0n) { o.push(Number(x & 0xffn)); x >>= 8n }
  if (o[o.length-1] & 0x80) o.push(neg ? 0x80 : 0); else if (neg) o[o.length-1] |= 0x80
  return o
}
const fixed = (n, w) => {
  n = BigInt(n); const neg = n < 0n; let x = neg ? -n : n
  const o = new Array(w).fill(0)
  for (let i = 0; i < w && x > 0n; i++, x >>= 8n) o[i] = Number(x & 0xffn)
  if (neg) o[w - 1] |= 0x80
  return o
}

const inputs = L.laneInputNames()
const consts = L.laneConsts(L.BETA_LANE_REGS, L.AURORA_FIG8)
const HEADER = [0x01, 0x50]
const SUFFIX = [0x51, 0x52, 0x93]
const fieldOffset = HEADER.length + 1

// ⚠ 'scriptCode' is NOT declared. `compileState` accounts for it itself; naming it makes the compiler
//   believe the stack is one deeper than it is and every OP_PICK index comes out wrong.
//   ★ Both interpreters refused IDENTICALLY when it was — agreement on a failure is still agreement,
//   and that is how the harness bug was found rather than mistaken for a divergence.
const st = compileState(L.LANE_SRC, { fieldOffset, consts, stack: [...inputs, 'spenderOutputs', 'newValue'] })
const bsvOps = st.ops, jetOps = bsvToJetmora(bsvOps)
const bsvBytes = serialize(bsvOps), jetBytes = serialize(jetOps)
const renumbered = bsvOps.filter((c, i) => c.op !== jetOps[i].op).length

console.log('\nACID TEST — the lane covenant, three implementations\n')
console.log(`  source      ${L.LANE_SRC.split('\n').length} lines of BASIC, ${Object.keys(consts).length} constants`)
console.log(`  compiled    ${bsvBytes.length} B · ${bsvOps.length} opcodes · ${st.layout.length} state fields`)
console.log(`  transcoded  ${renumbered} opcodes renumbered · jetmora-only: ${[...new Set(jetmoraOnly(jetOps))].join(',')}`)
console.log(`  same length ${bsvBytes.length === jetBytes.length ? 'yes' : 'NO'}\n`)

// ⚠ v and t are FIXED POINT at S = 2^32. A raw integer here is not a small number, it is an absurdly
//   small SPEED, and the physics overflows its field trying to integrate it. Use L.f().
const STATES = [
  ['crawl',        { v: L.f(0.2), section: 0, fuel: 40000, t: 0 }],
  ['cruising',     { v: L.f(0.9), section: 0, fuel: 40000, t: 3000 }],
  ['into a bend',  { v: L.f(0.6), section: 1, fuel: 30000, t: 9000 }],
  ['fast at bend', { v: L.f(1.5), section: 1, fuel: 30000, t: 9000 }],
  ['late race',    { v: L.f(0.8), section: 3, fuel: 500,   t: 60000, lap: 2 }],
]
const TRIGGERS = [['full throttle', 16], ['half throttle', 8], ['lifted', 0]]

const scriptCodeFor = v => {
  const out = [...HEADER]
  for (const f of st.layout) out.push(f.width, ...(f.bytes ? v[f.name] : fixed(v[f.name] ?? 0, f.width)))
  return [...out, ...SUFFIX]
}
/** Read a named field back out of a rebuilt scriptCode, using the compiler's own layout. */
function readField(sc, name) {
  let off = fieldOffset
  for (const f of st.layout) {
    if (f.name === name) {
      const b = sc.slice(off, off + f.width)
      let v = 0n
      for (let i = f.width - 1; i >= 0; i--) v = (v << 8n) | BigInt(i === f.width - 1 ? (b[i] & 0x7f) : b[i])
      return (b[f.width - 1] & 0x80) ? -v : v
    }
    off += 1 + f.width
  }
  throw new Error(`no field ${name}`)
}
const runBsv = (bytes, initial) => {
  // ⚠ the real push encoder: the scriptCode is ~92 bytes and [len, ...data] is only valid below 76
  const unlock = initial.flatMap(d => d.length ? push(d) : [0x00])
  const sp = new Spend({
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    lockingScript: LockingScript.fromHex(hex(bytes)), transactionVersion: 2,
    otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(hex(unlock)), inputSequence: 0xffffffff, lockTime: 0,
  })
  let g = 0
  while (sp.step() && ++g < 2_000_000) {}
  return sp.stack.map(hex)
}

let pass = 0, fail = 0, refAgree = 0, refDiff = 0
for (const [sname, partial] of STATES) {
  for (const [tname, th] of TRIGGERS) {
    const state = { phase: 1, eng: 14, tyr: 10, dia: 10, lap: 0, ...partial,
                    raceId: new Array(32).fill(9), driver: new Array(24).fill(3) }
    const initial = [...inputs.map(n => toNum(/^th/.test(n) ? th : 0)), toNum(0), toNum(1), scriptCodeFor(state)]

    let mine = null, theirs = null, bsvErr = null
    try { mine = evaluate(jetBytes, { stack: initial }) } catch (e) { mine = { ok: false, error: 'threw: ' + e.message } }
    try { theirs = runBsv(bsvBytes, initial) } catch (e) { bsvErr = String(e.message).replace(/^Script evaluation error: /, '').split('\n')[0] }

    const mh = mine?.ok ? stackHash(mine.stack.map(hex)) : null
    const th2 = theirs ? stackHash(theirs) : null
    const bothRefused = !mine?.ok && !theirs
    const ok = (mh && th2 && mh === th2) || bothRefused

    let note = ''
    if (ok && bothRefused) note = 'both refused — agreement'
    else if (ok) {
      note = mh.slice(0, 16) + '…'
      try {
        const ref = L.laneSection(state, th, th)
        const rebuilt = mine.stack[mine.stack.length - 1]
        const gv = readField(rebuilt, 'v'), gs = readField(rebuilt, 'section')
        if (gv === BigInt(ref.v) && gs === BigInt(ref.section)) { refAgree++; note += '  ref ✓' }
        else { refDiff++; note += `  ⚠ ref: v ${gv} vs ${ref.v}, sec ${gs} vs ${ref.section}` }
      } catch (e) { refDiff++; note += `  ⚠ ref threw: ${String(e.message).split('\n')[0]}` }
    }
    console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${sname.padEnd(13)} ${tname.padEnd(14)} ${note}`)
    if (!ok) {
      console.log(`        jet  ${mine?.ok ? `ok(${mine.stack.length} items, ${mine.ops} ops)` : 'refused: ' + mine?.error}`)
      console.log(`        bsv  ${theirs ? `ok(${theirs.length} items)` : 'refused: ' + bsvErr}`)
    }
    ok ? pass++ : fail++
  }
}
console.log(`\n  ${pass} pass, ${fail} fail   ·   JS reference: ${refAgree} agree, ${refDiff} differ\n`)
if (fail || refDiff) process.exitCode = 1
