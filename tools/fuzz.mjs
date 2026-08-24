// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// DIFFERENTIAL FUZZING against an independent BSV interpreter.
// ⚠ The conformance vectors were hand-written and the interpreter was written to satisfy them. That is
// circular on its own. This is not: it generates scripts nobody curated and compares two implementations.
//
// ⚠⚠ ONLY opcodes where Bitcoin 0.1.3 and BSV genuinely AGREE are generated. Excluded, with cause:
//   LSHIFT/RSHIFT  — numeric in 0.1.3, bytewise in BSV
//   SUBSTR/LEFT/RIGHT — 0.1.3 only; BSV has SPLIT/NUM2BIN/BIN2NUM at those numbers
//   VER/VERIF/VERNOTIF — 0.1.3 only, and entry-bound here
//   AND/OR/XOR      — 0.1.3 zero-pads to the longer (MakeSameSize); BSV refuses unequal sizes
//   IF/NOTIF/ELSE/ENDIF — 0.1.3 does not require balance at end of script; BSV does
//   CHECKSIG family — needs a spend context
// ⚠ LICENCE: @bsv/sdk is used to establish BSV compatibility, i.e. use on BSV. See NOTICE.
import { evaluate } from './interpreter.mjs'
import { OP } from './ops.mjs'
import { toNum } from './scriptnum.mjs'

const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { Spend, LockingScript, UnlockingScript } = await import(SDK)
const hex = b => Buffer.from(b).toString('hex')

const SHARED = [
  'OP_0','OP_1','OP_2','OP_3','OP_4','OP_5','OP_6','OP_7','OP_8','OP_9','OP_10','OP_11','OP_12',
  'OP_13','OP_14','OP_15','OP_16','OP_1NEGATE',
  'OP_ADD','OP_SUB','OP_MUL','OP_DIV','OP_MOD','OP_1ADD','OP_1SUB','OP_2MUL','OP_2DIV',
  'OP_NEGATE','OP_ABS','OP_NOT','OP_0NOTEQUAL','OP_MIN','OP_MAX','OP_WITHIN',
  'OP_BOOLAND','OP_BOOLOR','OP_NUMEQUAL','OP_NUMNOTEQUAL','OP_LESSTHAN','OP_GREATERTHAN',
  'OP_LESSTHANOREQUAL','OP_GREATERTHANOREQUAL',
  'OP_DUP','OP_DROP','OP_SWAP','OP_ROT','OP_OVER','OP_NIP','OP_TUCK','OP_DEPTH','OP_IFDUP',
  '2DROP:OP_2DROP','OP_2DUP','OP_3DUP','OP_2OVER','OP_2ROT','OP_2SWAP',
  'OP_TOALTSTACK','OP_FROMALTSTACK','OP_PICK','OP_ROLL',
  'OP_CAT','OP_SIZE','OP_EQUAL','OP_INVERT',
  'OP_RIPEMD160','OP_SHA1','OP_SHA256','OP_HASH160','OP_HASH256',
  'OP_VERIFY','OP_RETURN','OP_NOP',
].map(s => OP[s.includes(':') ? s.split(':')[1] : s]).filter(v => v !== undefined)

// seeded PRNG so any failure is reproducible from its seed
let seed = Number(process.env.SEED ?? 20260824)
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
const pick = a => a[Math.floor(rnd() * a.length)]

function genScript(len) {
  const s = []
  for (let i = 0; i < len; i++) {
    const r = rnd()
    if (r < 0.35) {                                   // a number, sometimes large
      const mag = rnd() < 0.15 ? 2n ** BigInt(Math.floor(rnd() * 90)) : BigInt(Math.floor(rnd() * 1000))
      const n = rnd() < 0.5 ? -mag : mag
      const d = toNum(n); s.push(d.length, ...d)
    } else if (r < 0.45) {                            // raw bytes
      const n = 1 + Math.floor(rnd() * 6), d = []
      for (let k = 0; k < n; k++) d.push(Math.floor(rnd() * 256))
      s.push(d.length, ...d)
    } else s.push(pick(SHARED))
  }
  return s
}

function runBsv(script) {
  try {
    const sp = new Spend({
      sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
      lockingScript: LockingScript.fromHex(hex(script)), transactionVersion: 2,
      otherInputs: [], outputs: [], inputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(''), inputSequence: 0xffffffff, lockTime: 0,
    })
    let g = 0
    while (sp.step() && ++g < 200000) {}
    return { ok: true, stack: sp.stack.map(hex) }
  } catch (e) { return { ok: false, why: String(e.message ?? e).split('\n')[0] } }
}

const N = Number(process.env.N ?? 4000)
let same = 0, bothFail = 0, diff = 0
const cases = []
for (let i = 0; i < N; i++) {
  const script = genScript(2 + Math.floor(rnd() * 10))
  const mine = evaluate(script)
  const theirs = runBsv(script)
  if (!mine.ok && !theirs.ok) { bothFail++; continue }
  if (mine.ok !== theirs.ok) {
    diff++
    if (cases.length < 8) cases.push([hex(script),
      mine.ok ? `we ok [${mine.stack.map(hex)}]` : `we fail: ${mine.error}`,
      theirs.ok ? `bsv ok [${theirs.stack}]` : `bsv fail: ${theirs.why}`])
    continue
  }
  if (JSON.stringify(mine.stack.map(hex)) === JSON.stringify(theirs.stack)) same++
  else {
    diff++
    if (cases.length < 8) cases.push([hex(script), `we [${mine.stack.map(hex)}]`, `bsv [${theirs.stack}]`])
  }
}
console.log(`\nDIFFERENTIAL FUZZ — ${N} generated scripts, seed ${process.env.SEED ?? 20260824}\n`)
console.log(`  agree (both ran, same stack)   ${same}`)
console.log(`  agree (both refused)           ${bothFail}`)
console.log(`  DIVERGENT                      ${diff}\n`)
for (const [s, a, b] of cases) console.log(`  ${s}\n    ${a}\n    ${b}\n`)
if (diff) process.exitCode = 1
