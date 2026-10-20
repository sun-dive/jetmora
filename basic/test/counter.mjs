// © 2026 sun-dive — Apache License 2.0.
//
// The 7 Sept counter, written in BASIC, must accept and refuse exactly the ticks the hand-written one does.
//   node basic/test/counter.mjs
// Each tick is built for each script by the same PHP code (counter-ticks.php), judged by the PHP
// interpreter, and the BASIC one's ticks are judged again by the JavaScript interpreter. The reader then
// reads the compiled counter, and what it reads compiles back to the same bytes.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileCovenant, JF_NVERSION } from '../basic-jf.mjs'
import { unbasic, unbasicListing } from '../unbasic-jf.mjs'
import { InterpreterJF } from '../../tools/interpreter-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const h = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const crypto = { sha256: h('sha256'), sha1: h('sha1'), ripemd160: h('ripemd160') }

const src = readFileSync(join(HERE, 'counter.bas'), 'utf8')
const c = compileCovenant(src)
console.log(`── the counter in BASIC: ${c.bytes.length} bytes of jetForth, nVersion 0x${c.nVersion.toString(16)} ──`)
ok(c.nVersion === JF_NVERSION, 'the result names JF revision 3')

const out = JSON.parse(execFileSync('php', [join(HERE, 'counter-ticks.php')],
  { input: JSON.stringify({ hand: null, basic: hex(c.bytes) }) }).toString())
const hand = out.hand.ticks, basic = out.basic.ticks
console.log(`   the hand-written one: ${out.hand.script.length / 2} bytes\n`)

console.log('── every tick, judged by both covenants ──')
console.log('   hand    BASIC   the tick')
let agree = 0
hand.forEach((t, k) => {
  const b = basic[k], same = t.accepted === b.accepted && t.case === b.case
  if (same) agree++
  console.log(`   ${t.accepted ? 'accept' : 'refuse'}  ${b.accepted ? 'accept' : 'refuse'}  ${same ? ' ' : '✗'} ${t.case}`)
})
ok(agree === hand.length, `★ the BASIC counter accepts and refuses exactly the ticks the hand-written one does (${agree}/${hand.length})`)
const verdict = what => hand.find(t => t.case.startsWith(what))?.accepted
ok(verdict('41 → 42') === true && hand.filter(t => t.case.startsWith('the thread')).every(t => t.accepted)
  && ['41 → 43', '41 → 41', '41 → 40', 'a successor with a different script', 'an extra output'].every(w => verdict(w) === false),
  '…and the hand-written one gives verify-wired\'s own answers: 41 → 42 and the thread accepted; the skip, the stall, going back, the escape and the extra output refused')

console.log('\n── and the comparison can fail: each sabotaged counter disagrees with the hand-written one ──')
const SABOTAGE = [
  ['plus two', src.replace('+ 1, 8', '+ 2, 8')],
  ['the value read one byte early', src.replace('n - 52', 'n - 53')],
  ['the script read without its length', src.replace('SPLIT(head, 104)', 'SPLIT(head, 105)')],
  ['compared with the wrong field', src.replace('), hashout)', '), tail)')],
  ['no VERIFY at all', src.replace(/^VERIFY .*$/m, 'x = 1')],
]
const sab = JSON.parse(execFileSync('php', [join(HERE, 'counter-ticks.php')],
  { input: JSON.stringify(Object.fromEntries(SABOTAGE.map(([n, s]) => [n, hex(compileCovenant(s).bytes)]))) }).toString())
for (const [n] of SABOTAGE) {
  const bad = sab[n].ticks.filter((t, k) => t.accepted !== hand[k].accepted).length
  ok(bad > 0, `${n}: disagrees on ${bad} of ${hand.length} ticks`)
}

console.log('\n── the BASIC counter\'s ticks, in the JavaScript interpreter too ──')
let same = 0
for (const t of basic) {
  const vm = new InterpreterJF({ crypto }); vm.setPreimage(unhex(t.preimage))
  let r
  try { r = { stack: (await vm.run(c.bytes)).map(String) } } catch (e) { r = { error: hex(Buffer.from(e.message)) } }
  if (JSON.stringify(r) === JSON.stringify(t.result)) same++
  else console.log(`   ✗ ${t.case}: PHP ${JSON.stringify(t.result)} · JS ${JSON.stringify(r)}`)
}
ok(same === basic.length, `both interpreters leave the same thing on every tick (${same}/${basic.length})`)

console.log('\n── read back ──')
const r = unbasic(c.bytes, { names: c.names, nVersion: c.nVersion })
console.log(unbasicListing(c.bytes, { names: c.names }).split('\n').map(l => '   ' + l).join('\n'))
ok(!r.stoppedAt && r.covenant, 'the reader reads it to the end, as a covenant')
const blind = unbasic(c.bytes)
ok(hex(compileCovenant(blind.lines.join('\n')).bytes) === hex(c.bytes),
  'what it reads, without the names, compiles back to the same bytes')
ok(unbasic(c.bytes, { nVersion: 0x56530001 }).stoppedAt?.includes('revision 3') === true,
  'and it will not read the bytes as JF revision 3 when the entry names another version')

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the 7 Sept counter, in BASIC]`)
process.exit(fail === 0 ? 0 : 1)
