// © 2026 sun-dive — Apache License 2.0.
//
// THE DECOMPILER IS A VIEW OVER ANY jetForth (basic/unbasic-jf.mjs): it reads a script whoever wrote it.
//   node basic/test/decompiler.mjs
//   by hand    the channel covenant written by hand (basic/test/channel-target.mjs), read to its end, line by line
//   counter    the 7 Sept counter (server/verify-wired.php), written by hand, read to its end
//   0.7        every covenant here as compiler 0.7 wrote it (read from git, 64eb708), read to its end as a covenant,
//              its state the head's values, its fields named by the variables they are bound to
//   general    every program and covenant here as this compiler writes it, read as any script: none stops
//   honest     a word it does not model stops the reading, by name; an IF whose arms leave different values stops
//              with that reason; one whose arms agree is read as IF … ELSE … END IF
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileBasic, compileCovenant, BASIC_JF_VERSION } from '../basic-jf.mjs'
import { unbasic } from '../unbasic-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..', '..')
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const assemble = src => unhex(execFileSync('php', ['-r', 'require $argv[1]; echo bin2hex(jf_asm(stream_get_contents(STDIN)));', '--',
  join(ROOT, 'server/jf-asm.php')], { input: src.replace(/\\[^\n]*/g, '') }).toString().trim())
const same = (got, want) => { const j = v => JSON.stringify(v, (_, x) => typeof x === 'bigint' ? String(x) : x); return j(got) === j(want) }
const show = r => `${r.lines.length} lines${r.stoppedAt ? `, stopped: ${r.stoppedAt}` : ''}`

// ── by hand ──
console.log('── the channel covenant, written by hand ──')
{
  const src = /const HAND = String\.raw`([^`]*)`/.exec(readFileSync(join(HERE, 'channel-target.mjs'), 'utf8'))[1]
  const r = unbasic(assemble(src))
  ok(r.covenant && r.stoppedAt === undefined, `read to its end, as a covenant: ${show(r)}`)
  ok(same(r.lines, [
    'VERSION JF 3', 'DIM f0$20', 'DIM f1$32', 'REM  in0, in1, in2: what the tick pushes, the first pushed first',
    'VERIFY SAMEBYTES(HASH160(in1), f0)', 'VERIFY ED25519SIG(in0, in1, HASH256(PREIMAGE()))',
    't1 = TXVALUE() + 1', 'VERIFY t1 = NSEQUENCE()', 'VERIFY t1 >= 1', 'VERIFY SIZE(in2) <= 1687']),
    'line by line: the owner, the signature, value + 1 and nSequence, the size of the packed details')
  ok(same(r.leave, ['SAMEBYTES(HASH256(CAT(NUM2BIN(t1, 8), REPLACE(SCRIPTCODE(), 28, SHA256(in2)))), OUTPUTS_HASH())']),
    `and what it leaves: the next output, this script with the new hash written over the old, is the tick's: ${r.leave[0]}`)
}

// ── the 7 Sept counter ──
console.log('\n── the 7 Sept counter, written by hand ──')
{
  const r = unbasic(unhex(execFileSync('php', [join(ROOT, 'tools/judge-run.php'), 'counter']).toString().trim()))
  ok(r.covenant && r.stoppedAt === undefined && r.leave.length === 1, `read to its end, as a covenant: ${show(r)}`)
  ok(same(r.lines.slice(2), ['t1 = PREIMAGE()', 'v8 = SIZE(t1)', 'v16 = BIN2NUM(SUBSTR(t1, v8 - 52, 8))', 'v24 = v8 - 157'])
     && /^SAMEBYTES\(HASH256\(CAT\(CAT\(NUM2BIN\(v16 \+ 1, 8\), BYTE\(v24\)\), .*SUBSTR\(t1, 105, v8 - 157\).*\)\), SUBSTR\(t1, v8 - 40, 32\)\)$/.test(r.leave[0]),
    `the value read from the preimage, its scriptCode cut out of it, and the next output hashed against hashOutputs: ${r.leave[0]}`)
}

// ── 0.7's covenants ──
/** basic-jf.mjs as it was at a revision, importing that revision's opcode table; null when git does not have it */
async function released(rev) {
  const show = path => { try { return execFileSync('git', ['-C', ROOT, 'show', `${rev}:${path}`], { stdio: ['ignore', 'pipe', 'ignore'] }).toString() } catch { return null } }
  const src = show('basic/basic-jf.mjs'), ops = show('tools/ops-jf.mjs')
  if (src === null || ops === null) return null
  const url = s => `data:text/javascript;base64,${Buffer.from(s).toString('base64')}`
  return import(url(src.replace("'../tools/ops-jf.mjs'", `'${url(ops)}'`)))
}
const OWN = new Array(20).fill(0xab), V = 'VERSION JF 3\n'
const CHANNEL = /const CHANNEL = `([^`]*)`/.exec(readFileSync(join(ROOT, 'site/basic.html'), 'utf8'))[1]
const COVENANTS = [
  ['DIM owner$20', { owner: OWN }],
  ['DIM owner$20\nDIM n%4\nn = n + 1', { owner: OWN, n: 7 }],
  [`DIM owner$20\nowner = &H${'cd'.repeat(20)}`, { owner: OWN }],
  ['DIM owner$20\nDIM n%4\nIF n > 3 THEN n = n + 1', { owner: OWN, n: 2 }],
  ['DIM owner$20\nDIM n%4\nDIM tag$3\nIF n > 3 THEN\n tag = &H010203\nELSE\n IF n = 0 THEN n = 9\nEND IF\nn = n + 2 ^ 3', { owner: OWN, n: 9, tag: [7, 8, 9] }],
  ['DIM owner$20\nDIM h$32\nh = HASH256(CAT(h, owner))', { owner: OWN, h: new Array(32).fill(1) }],
  ['DIM owner$20\nDIM n%2\nINPUT t$4, k%2, m%\nn = SIZE(t) + k + m', { owner: OWN, n: 0 }],
  ['DIM owner$20\nDIM tag$300\nINPUT t$300\ntag = t', { owner: OWN, tag: new Array(300).fill(7) }],
  [CHANNEL.replace(/^\s*VERSION JF 3\s*$/m, ''), { owner: OWN, details: new Array(32).fill(5) }],
  [readFileSync(join(ROOT, 'basic/code-thread.bas'), 'utf8').replace(/^\s*VERSION JF 3\s*$/m, ''), null],
]
console.log(`\n── every covenant here as 0.7 wrote it, read by this decompiler ──`)
const B7 = await released('64eb708')
if (B7 === null) console.log('  - no 0.7 to read: revision 64eb708 is not in this repository. Skipped, never counted as passed.')
else {
  let read = 0, named = 0
  for (const [text, given] of COVENANTS) {
    /* a covenant given no state here gets one from its DIM lines: each $ field 3s, each % field 1 */
    const src = V + text, state = given ?? Object.fromEntries([...text.matchAll(/^\s*DIM\s+([A-Za-z_]\w*)([$%])(\d+)/gim)]
      .map(m => [m[1], m[2] === '$' ? new Array(Number(m[3])).fill(3) : 1]))
    const c = B7.compileCovenant(src, { state })
    const r = unbasic(c.bytes, { names: c.names })
    const values = c.layout.every(f => same(r.state[f.name], f.bytes ? [...state[f.name]] : undefined) || !f.bytes)
    if (r.covenant && r.stoppedAt === undefined) read++
    else console.log(`  ✗ ${text.split('\n')[0]}…: ${show(r)}`)
    if (values && c.layout.every(f => r.lines.includes(`DIM ${f.name}$${f.width}`) || !f.bytes)) named++
    else console.log(`  ✗ ${text.split('\n')[0]}…: its fields ${JSON.stringify(c.layout.map(f => f.name))}, read ${JSON.stringify(Object.keys(r.state ?? {}))}`)
  }
  ok(read === COVENANTS.length, `every one of them, ${read}/${COVENANTS.length}, read to its end as a covenant`)
  ok(named === COVENANTS.length, `and each $ field named by the variable it is bound to, its value the head's (${named}/${COVENANTS.length})`)
}

// ── this compiler's, read as any script ──
console.log(`\n── every program and covenant here as ${BASIC_JF_VERSION} writes it, read as any script ──`)
{
  const PROGRAMS = [
    ['total = 0\nFOR i = 1 TO 10\n  total = total + i * i\nNEXT i', { leave: ['total'] }],
    ['y = b ^ e', { stack: ['b', 'e'], leave: ['y'] }],
    ['big = 0\nIF a > b THEN\n  big = a\nELSE\n  big = b\nEND IF', { stack: ['a', 'b'], leave: ['big'] }],
    ['VERIFY SAMEBYTES(SHA256(k), &H368a693d784c7d1957ec748148a5de1e1f2e97f1f6360c69b0cfcf6471bbbf07)\nok = 1', { stack: ['k$'], leave: ['ok'] }],
  ]
  let read = 0
  for (const [text, env] of PROGRAMS) {
    const c = compileBasic(V + text, env), r = unbasic(c.bytes, { stack: env.stack, general: true })
    if (r.stoppedAt === undefined) read++; else console.log(`  ✗ ${text.split('\n')[0]}…: ${show(r)}`)
  }
  for (const [text, given] of COVENANTS.filter(([, g]) => g)) {
    const c = compileCovenant(V + text, { state: given }), r = unbasic(c.bytes, { names: c.names, general: true })
    if (r.covenant && r.stoppedAt === undefined) read++; else console.log(`  ✗ ${text.split('\n')[0]}…: ${show(r)}`)
  }
  const total = PROGRAMS.length + COVENANTS.filter(([, g]) => g).length
  ok(read === total, `every one, ${read}/${total}, read to its end as what it computes, FOR, ^, IF and ELSE among them`)
}

// ── honest ──
console.log('\n── what it cannot follow, said ──')
{
  const r1 = unbasic(assemble('VER JF 3 $01 INVOKE#0'))
  ok(/INVOKE/.test(r1.stoppedAt ?? '') && /does not model it/.test(r1.stoppedAt), `a word it does not model stops the reading, by name: ${r1.stoppedAt}`)
  const r2 = unbasic(assemble('VER JF 3 $01 BIN2NUM 0BRANCH>no 1 BRANCH>end no: 1 2 end:'))
  ok(/different values/.test(r2.stoppedAt ?? ''), `an IF whose arms leave different values: ${r2.stoppedAt}`)
  const r3 = unbasic(assemble('VER JF 3 7 $01 BIN2NUM 0BRANCH>no FALSE (ABORT")$ BRANCH>end no: TRUE (ABORT")$ end:'))
  ok(r3.stoppedAt === undefined && r3.lines.includes('IF BIN2NUM(&H01) THEN') && r3.lines.includes('ELSE') && same(r3.leave, ['7']),
    `one whose arms agree is read as IF … ELSE … END IF, what is held across it kept: ${r3.lines.slice(1).join(' · ')}`)
}

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the decompiler, a view over any jetForth]`)
process.exit(fail ? 1 : 0)
