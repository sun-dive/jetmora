// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE PHASE-1 TEST: one program, two rails, one answer.
//
// Compiles BASIC with the existing BSV-targeted compiler, then runs the result BOTH ways —
// as BSV bytes through an independent BSV interpreter, and transcoded to jetmora numbering
// through ours — and requires the resulting stacks to be identical.
//
// ⚠ This does NOT modify the compiler. It imports it read-only. The compiler is live and is never
//   edited (see the project's standing rule); jetmora supplies only a table, a serializer and a map.
//
//   BASIC=/path/to/grafverse/mint   BSV_SDK=/path/to/@bsv/sdk/dist/esm/mod.js   node tools/crosscompile.mjs
import { evaluate } from './interpreter.mjs'
import { serialize, disasm } from './serialize.mjs'
import { bsvToJetmora, jetmoraOnly } from './transcode.mjs'
import { stackHash } from './hash.mjs'

const MINT = process.env.BASIC ?? '/home/sundive/Documents/GitHub/grafverse/mint'
const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const hex = b => Buffer.from(b).toString('hex')

let compileBasic, compileState, Spend, LockingScript, UnlockingScript
try {
  ;({ compileBasic, compileState } = await import(`${MINT}/src/basic.ts`))
  ;({ Spend, LockingScript, UnlockingScript } = await import(SDK))
} catch (e) {
  console.log(`\nSKIPPED — needs the compiler and the BSV SDK.\n  ${String(e.message).split('\n')[0]}\n`)
  process.exit(0)
}

function runBsv(bytes) {
  const sp = new Spend({
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    lockingScript: LockingScript.fromHex(hex(bytes)), transactionVersion: 2,
    otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(''), inputSequence: 0xffffffff, lockTime: 0,
  })
  let g = 0
  while (sp.step() && ++g < 500000) {}
  return sp.stack.map(hex)
}

const PROGRAMS = [
  ['arithmetic',   ['v = v * 3 / 4 + 2', 'w = w * 7 + 9 - 3']],
  ['branching',    ['IF v > 12 THEN v = v - 5', 'IF w < 6 THEN w = w + 11']],
  ['fixed-point',  ['v = v * 256 / 100', 'w = w * 2', 'v = v / 2']],
  ['comparison',   ['IF v > w THEN v = w', 'w = w + 1']],
  ['chained',      ['v = v + 1', 'v = v * v', 'w = v - w', 'IF w > 100 THEN w = 100']],
]
const INPUTS = [[3n, 5n], [17n, 2n], [0n, 0n], [-4n, 9n], [1000n, 7n]]
const toNum = n => { // script-number encoding for the initial stack
  n = BigInt(n); if (n === 0n) return []
  const neg = n < 0n; let x = neg ? -n : n; const o = []
  while (x > 0n) { o.push(Number(x & 0xffn)); x >>= 8n }
  if (o[o.length-1] & 0x80) o.push(neg ? 0x80 : 0); else if (neg) o[o.length-1] |= 0x80
  return o
}

let pass = 0, fail = 0
console.log('\nCROSS-COMPILE — one program, two rails\n')

// ⚠⚠ A STATE PROGRAM FIRST, AND FOR A REASON. The five programs below compile to IDENTICAL bytes on
// both rails, because none of them uses SPLIT/NUM2BIN/BIN2NUM — so they never exercise the transcoder
// at all. A green result from them alone would be a test on a path the change cannot reach.
// `compileState` emits all three, so this is the case that actually proves the mapping.
{
  const st = compileState('DIM phase%1\n DIM v%5\n', { fieldOffset: 6, stack: ['scriptCode'] })
  const bsvBytes = serialize(st.ops)
  const jetChunks = bsvToJetmora(st.ops)
  const jetBytes = serialize(jetChunks)
  const only = jetmoraOnly(jetChunks)
  const changed = hex(bsvBytes) !== hex(jetBytes)
  console.log(`  ${changed ? 'PASS' : 'FAIL'}  ${'state-peel'.padEnd(12)} ${String(bsvBytes.length).padStart(4)} B  ` +
    `${changed ? 'RENUMBERED' : '⚠ identical — transcoder not exercised'}` +
    `${only.length ? '  jetmora-only: ' + [...new Set(only)].join(',') : ''}`)
  if (!changed) { fail++ } else {
    pass++
    const diffs = st.ops.filter((c, i) => c.op !== jetChunks[i].op).length
    console.log(`        ${diffs} opcode${diffs === 1 ? '' : 's'} renumbered; same length, so byte counts are unaffected`)
  }
}

// ★★★ AND NOW ACTUALLY RUN IT. The case above proves the MAPPING and nothing else — the transcoded
// program was never executed, which is the same trap as five "identical bytes" passes proving nothing.
// A state peel that cannot rebuild its own scriptCode byte-for-byte is broken, so that is the test.
{
  const HEADER = [0x01, 0x50, 0x01, 0x01]          // two small pushes, as a real lock begins
  const SUFFIX = [0x51, 0x52, 0x93]                // pretend code after the state
  const fieldOffset = HEADER.length + 1            // past field 0's own push opcode
  const st = compileState('DIM phase%1\n DIM v%5\n DIM pos%5\n',
    { fieldOffset, stack: ['scriptCode'] })
  const fixed = (n, w) => {                        // fixed-width, same convention the peel expects
    n = BigInt(n); const neg = n < 0n; let x = neg ? -n : n
    const o = new Array(w).fill(0)
    for (let i = 0; i < w && x > 0n; i++, x >>= 8n) o[i] = Number(x & 0xffn)
    if (neg) o[w - 1] |= 0x80
    return o
  }
  const values = { phase: 2, v: 1234567, pos: -98765 }
  const scriptCode = [...HEADER]
  for (const f of st.layout) scriptCode.push(f.width, ...fixed(values[f.name], f.width))
  scriptCode.push(...SUFFIX)

  const jetBytes = serialize(bsvToJetmora(st.ops))
  const r = evaluate(jetBytes, { stack: [scriptCode] })
  const rebuilt = r.ok && r.stack.length === 1 ? r.stack[0] : null
  const same = rebuilt && hex(rebuilt) === hex(scriptCode)
  console.log(`  ${same ? 'PASS' : 'FAIL'}  ${'state-run'.padEnd(12)} ${String(jetBytes.length).padStart(4)} B  ` +
    (same ? `peeled ${st.layout.length} fields and rebuilt the scriptCode byte-for-byte`
          : (r.ok ? `rebuilt ${rebuilt ? hex(rebuilt).slice(0,40) : '(stack depth ' + r.stack.length + ')'} ≠ ${hex(scriptCode).slice(0,40)}`
                  : `failed: ${r.error}`)))
  same ? pass++ : fail++
}
for (const [name, lines] of PROGRAMS) {
  const r = compileBasic(lines.join('\n'), { stack: ['v', 'w'] })
  const bsvBytes = serialize(r.ops)
  const jetBytes = serialize(bsvToJetmora(r.ops))
  const only = jetmoraOnly(bsvToJetmora(r.ops))
  const moved = bsvBytes.length === jetBytes.length &&
    hex(bsvBytes) !== hex(jetBytes) ? 'renumbered' : (hex(bsvBytes) === hex(jetBytes) ? 'identical bytes' : 'resized')

  let ok = true, note = ''
  for (const [a, b] of INPUTS) {
    const init = [toNum(a), toNum(b)]
    const mine = evaluate(jetBytes, { stack: init })
    let theirs
    try { theirs = runBsv([...init.flatMap(d => [d.length, ...d]), ...bsvBytes]) }
    catch (e) { theirs = null; note = String(e.message).split('\n')[0] }
    const mineHex = mine.ok ? mine.stack.map(hex) : null
    if (!mineHex || !theirs || stackHash(mineHex) !== stackHash(theirs)) {
      ok = false
      note = note || (mine.ok ? `v=${a} w=${b}: jet ${JSON.stringify(mineHex)} vs bsv ${JSON.stringify(theirs)}`
                              : `v=${a} w=${b}: jet failed — ${mine.error}`)
      break
    }
  }
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(12)} ${String(bsvBytes.length).padStart(4)} B  ${moved}${only.length ? '  jetmora-only: ' + only.join(',') : ''}`)
  if (!ok) console.log(`        ${note}`)
  ok ? pass++ : fail++
}
console.log(`\n  ${pass} pass, ${fail} fail\n`)
if (fail) process.exitCode = 1
