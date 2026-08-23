// © 2026 sun-dive. Apache License 2.0 — see LICENSE. DIFFERENTIAL CHECK against an independent BSV interpreter.
//
// ⚠⚠ LICENCE POSITION (doc §5.0): `@bsv/sdk` is Open BSV Licensed and may only be used ON BSV.
// This tool is used for exactly that: establishing which of our vectors describe behaviour BSV
// SHARES, i.e. BSV compatibility. It is NOT a jetmora interpreter and produces no jetmora code.
// Vectors marked oracle:'013' or 'jetmora' are SKIPPED — BSV is not an oracle for those.
import { VECTORS } from './vectors.mjs'
import { stackHash } from './hash.mjs'

// Resolve the SDK however the caller has it. Set BSV_SDK to an absolute path if it is not
// installed alongside this repo:  BSV_SDK=/path/to/@bsv/sdk/dist/esm/mod.js node tools/crosscheck.mjs
const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { Spend, LockingScript, UnlockingScript } = await import(SDK)

const hx = b => Buffer.from(b).toString('hex')

function run(scriptBytes) {
  const spend = new Spend({
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    lockingScript: LockingScript.fromHex(hx(scriptBytes)),
    transactionVersion: 2, otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(''), inputSequence: 0xffffffff, lockTime: 0,
  })
  let guard = 0
  while (spend.step() && ++guard < 100000) { /* run to completion */ }
  return spend.stack.map(hx)
}

let agree = 0, differ = 0, threw = 0, skipped = 0
const problems = []
for (const v of VECTORS) {
  if (v.oracle !== 'bsv') { skipped++; continue }
  let got, err = null
  try { got = run(v.script) } catch (e) { err = String(e.message ?? e).split('\n')[0] }

  if (v.error) {                                   // we expect a failure
    if (err) { agree++ } else { differ++; problems.push([v.id, `expected error, BSV gave [${got}]`]) }
    continue
  }
  if (err) { threw++; problems.push([v.id, `we expect ${JSON.stringify(v.stack)}, BSV threw: ${err}`]); continue }
  if (stackHash(got) === stackHash(v.stack)) agree++
  else { differ++; problems.push([v.id, `ours ${JSON.stringify(v.stack)}  bsv ${JSON.stringify(got)}`]) }
}
console.log(`\nCROSS-CHECK vs @bsv/sdk — oracle:'bsv' vectors only\n`)
console.log(`  agree   ${agree}`)
console.log(`  differ  ${differ}`)
console.log(`  threw   ${threw}`)
console.log(`  skipped ${skipped}   (oracle 013/jetmora — BSV is not an oracle)\n`)
if (problems.length) {
  console.log('DISAGREEMENTS — each is either our error, or a real BSV/0.1.3 divergence:\n')
  for (const [id, why] of problems) console.log(`  ${id.padEnd(20)} ${why}`)
}
