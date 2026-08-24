// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
// Run the conformance vectors against our own interpreter. This is the test that matters:
// an implementation is conformant if and only if it reproduces vectors/core.json.
import { readFileSync } from 'node:fs'
import { evaluate } from './interpreter.mjs'
import { stackHash } from './hash.mjs'

const unhex = h => Array.from(Buffer.from(h, 'hex'))
const hex = b => Buffer.from(b).toString('hex')
const V = JSON.parse(readFileSync(new URL('../vectors/core.json', import.meta.url), 'utf8'))

let pass = 0, failed = 0, skipped = 0
const bad = []
for (const v of V.vectors) {
  if (!v.stack && !v.error) { skipped++; continue }        // undecided / note-only
  const r = evaluate(unhex(v.script), { version: 103 })
  if (v.error) {
    if (!r.ok) pass++
    else { failed++; bad.push([v.id, v.oracle, `expected failure, got stack [${r.stack.map(hex)}]`]) }
    continue
  }
  if (!r.ok) { failed++; bad.push([v.id, v.oracle, `expected ${JSON.stringify(v.stack)}, failed: ${r.error}`]); continue }
  const got = r.stack.map(hex)
  if (stackHash(got) === v.result_hash) pass++
  else { failed++; bad.push([v.id, v.oracle, `want ${JSON.stringify(v.stack)}  got ${JSON.stringify(got)}`]) }
}
console.log(`\nCONFORMANCE — vectors/core.json v${V.version} against tools/interpreter.mjs\n`)
console.log(`  pass    ${pass}`)
console.log(`  fail    ${failed}`)
console.log(`  skipped ${skipped}  (note-only vectors with no asserted result)\n`)
if (bad.length) {
  for (const [id, oracle, why] of bad) console.log(`  ✗ ${id.padEnd(22)} [${oracle}] ${why}`)
  console.log('')
  process.exitCode = 1
} else console.log('  ✓ conformant\n')
