// © 2026 sun-dive — Apache License 2.0.
//
// A covenant thread written in BASIC, ticked forward: does its script accept exactly the ticks its rules allow?
//   node basic/test/thread.mjs
// The rules: 1 signed by the owner · 2 value + 1, and nSequence that same number ·
// 3 the successor is this script · 4 the state is inside it. Each tick is built and signed by PHP
// (thread-ticks.php), judged by the PHP interpreter, then judged again by the JavaScript one. Every check
// in the script is then disabled in turn, and some tick must change its verdict, or that check is untested.
// A covenant with INPUT is ticked too: each tick carries what its INPUT line names, pushed after the key.
// Last, every tick PHP judged here is judged again by tools/thread.mjs from its bytes alone (the entry, the tip's
// script, its value), with its own preimage and its own crypto, and must get CovenantThread::judge's verdict.
import { execFileSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileCovenant } from '../basic-jf.mjs'
import { disassemble, unbasic } from '../unbasic-jf.mjs'
import { verifyTick } from '../../tools/interpreter-jf.mjs'
import { JF_WORD, JF_SMALL0, JF_LIT } from '../../tools/ops-jf.mjs'
import { verify as ed25519 } from '../../tools/ed25519.mjs'     // libsodium 1.0.22's rules, as server/ed25519.php's
import { judge as judgeTick, VersionError, OTHER_VERSION } from '../../tools/thread.mjs'
import { parseEntry } from '../../tools/entry.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const H = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const hash160 = b => H('ripemd160')(H('sha256')(b))
const crypto = {
  sha256: H('sha256'), sha1: H('sha1'), ripemd160: H('ripemd160'),
  ed25519Verify: (s, p, m) => ed25519(s, m, p),
}
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }

// ── the keys: seeds both sides derive the same Ed25519 pair from ──
const seed = s => hex(H('sha256')(Buffer.from(s)))
const KEYS = { owner: seed('the owner'), other: seed('somebody else') }
const pubOf = name => createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(KEYS[name], 'hex')]), format: 'der', type: 'pkcs8' }))
  .export({ format: 'der', type: 'spki' }).subarray(12)
const OWNER = [...hash160(pubOf('owner'))], OTHER = [...hash160(pubOf('other'))]

// ── the threads ──
const MINIMAL = 'VERSION JF 3\nDIM owner$20'
const COUNTING = 'VERSION JF 3\nDIM owner$20\nDIM n%4\nn = n + 1'
/** The code thread's covenant: each release carries its code, and the successor holds its SHA-256 and its revision */
const RELEASE = 'VERSION JF 3\nDIM owner$20\nDIM rev%2\nDIM code$32\nINPUT bundle$, r%\ncode = SHA256(bundle)\nrev = r'
const P2PKH = '76a914' + '99'.repeat(20) + '88ac'
const out = (value, locking) => ({ value, locking: typeof locking === 'string' ? locking : hex(locking) })
const sign = (more = {}) => ({ kind: 'sign', key: 'owner', ...more })

/** The cases for one thread: [what, the tip, value, seq, outputs, unlock, should it be accepted]. */
function cases(S, next) {
  return [
    ['0 → 1, the first tick', S, 0, 1, [out(1, next)], sign(), true],
    ['41 → 42', S, 41, 42, [out(42, next)], sign(), true],
    ['2^32 − 2 → 2^32 − 1, the last nSequence there is', S, 2 ** 32 - 2, 2 ** 32 - 1, [out(2 ** 32 - 1, next)], sign(), true],
    ['rule 2: 41 → 43, a value skipped', S, 41, 43, [out(43, next)], sign(), false],
    ['rule 2: 41 → 41, no advance', S, 41, 41, [out(41, next)], sign(), false],
    ['rule 2: 41 → 40, backwards', S, 41, 40, [out(40, next)], sign(), false],
    ['rule 2: 41 → 42 but nSequence 41', S, 41, 41, [out(42, next)], sign(), false],
    ['rule 2: 41 → 42 but nSequence 43', S, 41, 43, [out(42, next)], sign(), false],
    ['rule 2: 41 → 42 but nSequence 1', S, 41, 1, [out(42, next)], sign(), false],
    ['rule 2: a value of all ones does not come round to 0', S, -1, 0, [out(0, next)], sign(), false],
    ['rule 1: signed by somebody else, with their own key', S, 41, 42, [out(42, next)], sign({ key: 'other' }), false],
    ['rule 1: the owner\'s signature with one bit changed', S, 41, 42, [out(42, next)], sign({ flip: true }), false],
    ['rule 1: the owner\'s signature over another message', S, 41, 42, [out(42, next)], sign({ msgFlip: true }), false],
    ['rule 1: a signature and no key', S, 41, 42, [out(42, next)], sign({ onlySig: true }), false],
    ['rule 1: an extra push beside the signature and key', S, 41, 42, [out(42, next)], sign({ extra: '01' }), false],
    ['rule 1: a 65-byte signature', S, 41, 42, [out(42, next)], sign({ longSig: true }), false],
    ['rule 1: key and signature the other way round', S, 41, 42, [out(42, next)], sign({ swap: true }), false],
    ['the run: a number pushed where the key belongs is not a direct push', S, 41, 42, [out(42, next)], sign({ lit: true }), false],
    ['rule 3: the successor is another script', S, 41, 42, [out(42, P2PKH)], sign(), false],
    ['rule 3: the successor one byte longer', S, 41, 42, [out(42, [...next, 0])], sign(), false],
    ['rule 3: the successor one byte shorter', S, 41, 42, [out(42, next.slice(0, -1))], sign(), false],
    ['outputs: an extra output after the successor', S, 41, 42, [out(42, next), out(1, '51')], sign(), false],
    ['outputs: an extra output before it', S, 41, 42, [out(1, '51'), out(42, next)], sign(), false],
    ['outputs: the successor twice', S, 41, 42, [out(42, next), out(42, next)], sign(), false],
  ]
}

const minimal = compileCovenant(MINIMAL, { state: { owner: OWNER } }).bytes
const counting = n => compileCovenant(COUNTING, { state: { owner: OWNER, n } }).bytes
/** A covenant whose every input check can be seen: each input reaches the successor's state */
const WIDTHS = 'VERSION JF 3\nDIM owner$20\nDIM n%2\nINPUT t$4, k%2, m%\nn = SIZE(t) + k + m'
const widths = n => compileCovenant(WIDTHS, { state: { owner: OWNER, n } }).bytes
/** t of 4 bytes, k 2, m 1: the successor's n is 7 */
const T4 = '74697073', CARRIED = [T4, '02', '01']
const carrying = inputs => ['', widths(0), 41, 42, [out(42, widths(4 + 2 + 1))], sign({ inputs })]
const ALL = [
  ...cases(minimal, minimal).map(c => ['minimal · ' + c[0], ...c.slice(1)]),
  ['minimal · rule 4: the successor gives the thread to another owner', minimal, 41, 42,
    [out(42, compileCovenant(MINIMAL, { state: { owner: OTHER } }).bytes)], sign(), false],
  ...cases(counting(7), counting(8)).map(c => ['counting · ' + c[0], ...c.slice(1)]),
  ['counting · rule 4: n left as it was', counting(7), 41, 42, [out(42, counting(7))], sign(), false],
  ['counting · rule 4: n + 2', counting(7), 41, 42, [out(42, counting(9))], sign(), false],
  ['counting · rule 4: n + 1 but another owner', counting(7), 41, 42,
    [out(42, compileCovenant(COUNTING, { state: { owner: OTHER, n: 8 } }).bytes)], sign(), false],
  ['counting · n at the top of its 4 bytes cannot advance', counting(2 ** 32 - 1), 41, 42, [out(42, counting(2 ** 32 - 1))], sign(), false],
  ...[1, 2, 3, 4, 5].map(k => [`counting · the thread, tick ${k}: n ${k - 1} → ${k}`, counting(k - 1), k - 1, k, [out(k, counting(k))], sign(), true]),
  ...cases(widths(0), widths(7)).map(c => ['widths · ' + c[0], ...c.slice(1, 5), { ...c[5], inputs: CARRIED }, c[6]]),
  ['widths · rule 4: n left as it was', widths(0), 41, 42, [out(42, widths(0))], sign({ inputs: CARRIED }), false],
  ['widths · INPUT: t in 3 bytes, where INPUT says 4', widths(0), 41, 42, [out(42, widths(3 + 2 + 1))], sign({ inputs: ['746970', '02', '01'] }), false],
  ['widths · INPUT: t in 5 bytes', widths(0), 41, 42, [out(42, widths(5 + 2 + 1))], sign({ inputs: [T4 + '73', '02', '01'] }), false],
  ['widths · INPUT: k in 3 bytes, where INPUT says at most 2', ...carrying([T4, '020000', '01']).slice(1), false],
  ['widths · INPUT: k in 2 bytes, 02 00: read as BIN2NUM reads it', ...carrying([T4, '0200', '01']).slice(1), true],
  ['widths · INPUT: k in no bytes at all, which BIN2NUM reads as 0', widths(0), 41, 42, [out(42, widths(4 + 0 + 1))], sign({ inputs: [T4, '', '01'] }), true],
  ['widths · INPUT: m in 8 bytes, the most a % input with no width may be', ...carrying([T4, '02', '0100000000000000']).slice(1), true],
  ['widths · INPUT: m in 9 bytes, past a cell, its first 8 a 1', ...carrying([T4, '02', '010000000000000000']).slice(1), false],
  ['widths · INPUT: m in 8 bytes, all ones: a negative number, with k 4', ...carrying([T4, '04', 'ff'.repeat(8)]).slice(1), false],
  ['widths · INPUT: m left out', ...carrying([T4, '02']).slice(1), false],
  ['widths · INPUT: nothing carried', ...carrying([]).slice(1), false],
  ['widths · INPUT: a push more than INPUT names', ...carrying([...CARRIED, '01']).slice(1), false],
  ['widths · INPUT: the inputs in another order', ...carrying(['02', T4, '01']).slice(1), false],
  ['widths · INPUT: the inputs before the signature and the key', widths(0), 41, 42, [out(42, widths(7))], sign({ inputs: CARRIED, inputsFirst: true }), false],
  ['widths · INPUT: one push below the signature, the rest as INPUT names: left on the stack, where a tick leaves one item',
    widths(0), 41, 42, [out(42, widths(7))], sign({ inputs: CARRIED, under: '01' }), false],
]

const verifies = script => disassemble(script).flatMap((x, k, all) =>
  x.name === '0=' && all[k + 1]?.name === '(ABORT")' && all[k + 1].data.length === 0 ? [x.at] : [])
/** `0= (ABORT") ""` → `DROP 1 DROP`: the same three bytes, and the check gone. */
const disable = (script, at) => { const b = Uint8Array.from(script); b[at] = JF_WORD.DROP; b[at + 1] = JF_SMALL0 + 1; b[at + 2] = JF_WORD.DROP; return b }
/** Every tick PHP judged here, for tools/thread.mjs to judge again at the end. */
const judgedByPhp = []
/** Judge ticks in PHP. */
function judge(list) {
  const res = JSON.parse(execFileSync('php', [join(HERE, 'thread-ticks.php')], {
    input: JSON.stringify({ keys: KEYS, cases: list.map(([, S, value, seq, outputs, unlock, , extra]) =>
      ({ script: typeof S === 'string' ? S : hex(S), value, seq, outputs, unlock, ...extra })) }),
    maxBuffer: 1 << 28,
  }).toString())
  judgedByPhp.push(...res)
  return res
}
/** The same tick, judged by the JavaScript interpreter's verifyTick. */
async function runJs(script, r) {
  const v = await verifyTick({ unlocking: unhex(r.unlocking), lock: script, preimage: unhex(r.preimage), crypto })
  return { accepted: v.accepted, result: v.stack ? { stack: v.stack.map(String) } : { error: hex(v.errorBytes) } }
}

console.log(`\n── the threads: minimal ${minimal.length} B · counting ${counting(0).length} B ──`)
const res = judge(ALL)
let right = 0, same = 0
for (const [k, c] of ALL.entries()) {
  const r = res[k], js = await runJs(c[1], r)
  const agree = JSON.stringify(js) === JSON.stringify({ accepted: r.accepted, result: r.result })
  if (agree) same++
  if (r.accepted === c[6]) right++
  console.log(`   ${r.accepted ? 'accept' : 'refuse'}  ${r.accepted === c[6] ? ' ' : '✗'}${agree ? ' ' : '≠'} ${c[0]}`)
}
ok(right === ALL.length, `★★ every tick is accepted or refused as its rules say (${right}/${ALL.length})`)
ok(same === ALL.length, `★ the JavaScript interpreter gives the same verdict and leaves the same thing on every tick (${same}/${ALL.length})`)

// ── rules 1 and 2: the lock's declaration names the interpreter, and the judge builds the preimage from the entry ──
console.log('\n── rules 1 and 2: the version, and the preimage built from the entry ──')
{
  const tick = extra => ['', counting(7), 41, 42, [out(42, counting(8))], sign(), null, extra]
  const version = (family, revision) => ((family.charCodeAt(1) << 24) | (family.charCodeAt(0) << 16) | revision) >>> 0
  const [named, tampered, jf2, sv, legacy] = judge([tick({ version: version('JF', 3) }), tick({ tamper: true }),
    tick({ version: version('JF', 2) }), tick({ version: version('SV', 1) }), tick({ version: 103 })])
  ok(named.accepted, 'an entry naming JF revision 3, the version its lock declares, is judged by it, and accepted')
  ok(!tampered.accepted && tampered.asSigned, '★ the successor\'s value changed after signing: refused, though the preimage that was signed passes')
  for (const [r, what] of [[jf2, 'JF revision 2'], [sv, 'SV revision 1'], [legacy, 'legacy version 103']])
    ok(r.accepted === false && r.result?.error === hex(new TextEncoder().encode(OTHER_VERSION)),
       `an entry naming ${what} on a lock that declares JF 3: refused, its script never run (${r.cannotJudge ?? (r.result?.error ? Buffer.from(r.result.error, 'hex').toString() : 'accepted')})`)
  const undeclared = counting(7).slice(5)
  const [none] = judge([['', undeclared, 41, 42, [out(42, undeclared)], sign(), null]])
  ok(none.cannotJudge !== undefined, `the counting covenant with its declaration taken off: this host cannot judge it, ${none.cannotJudge ?? 'a verdict'}`)
}

// ── an 8-byte % field is unsigned: it does not come round past 2^63 ──
console.log('\n── an 8-byte number field at its top ──')
{
  const WIDE = 'VERSION JF 3\nDIM owner$20\nDIM n%8\nn = n + 1'
  const top = 2n ** 63n - 1n
  const tip = compileCovenant(WIDE, { state: { owner: OWNER, n: top } }).bytes
  const wrapped = Uint8Array.from(tip); wrapped.set([0, 0, 0, 0, 0, 0, 0, 0x80], 27)   // n = 2^63, as a cell −2^63: past VER JF 3, owner's push and n's length
  const r = judge([['', compileCovenant(WIDE, { state: { owner: OWNER, n: top - 1n } }).bytes, 41, 42, [out(42, tip)], sign(), true],
                   ['', tip, 41, 42, [out(42, wrapped)], sign(), false]])
  ok(r[0].accepted, 'n 2^63 − 2 → 2^63 − 1 is accepted')
  ok(!r[1].accepted, '★ n 2^63 − 1 → 2^63 is refused: the field is unsigned, and that value is not one the compiler lays down')
}

// ── the reader: every covenant here reads back to its BASIC, and that compiles to the same bytes ──
console.log('\n── every covenant read back ──')
for (const [src, state] of [
  [MINIMAL, { owner: OWNER }], [COUNTING, { owner: OWNER, n: 7 }],
  [`VERSION JF 3\nDIM owner$20\nowner = &H${hex(OTHER)}`, { owner: OWNER }],
  ['VERSION JF 3\nDIM owner$20\nDIM n%4\nIF n > 3 THEN n = n + 1', { owner: OWNER, n: 2 }],
  ['VERSION JF 3\nDIM owner$20\nDIM n%4\nDIM tag$3\nIF n > 3 THEN\n tag = &H010203\nELSE\n IF n = 0 THEN n = 9\nEND IF\nn = n + 2 ^ 3', { owner: OWNER, n: 9, tag: [7, 8, 9] }],
  [WIDTHS, { owner: OWNER, n: 0 }], [RELEASE, { owner: OWNER, rev: 3, code: new Array(32).fill(0) }],
]) {
  const c = compileCovenant(src, { state })
  const r = unbasic(c.bytes)
  let again = ''
  try { again = hex(compileCovenant(r.lines.join('\n'), { state: r.state }).bytes) } catch (e) { again = e.message }
  ok(!r.stoppedAt && again === hex(c.bytes), `${src.split('\n').slice(1).join(' · ')} — ${r.stoppedAt ?? (again === hex(c.bytes) ? 'the same bytes' : 'DIFFERENT bytes')}`)
}

// ── a program that writes a $ field: the width check is what keeps a malformed push out of the successor ──
console.log('\n── a program that writes its $ field ──')
{
  const TRANSFER = `VERSION JF 3\nDIM owner$20\nowner = &H${hex(OTHER)}`
  const BADWIDTH = 'VERSION JF 3\nDIM owner$20\nowner = &H0102'
  const tipT = compileCovenant(TRANSFER, { state: { owner: OWNER } }).bytes
  const nextT = compileCovenant(TRANSFER, { state: { owner: OTHER } }).bytes
  const tipB = compileCovenant(BADWIDTH, { state: { owner: OWNER } }).bytes
  /* what BADWIDTH's rebuild would make: the declaration, then a push that says 20 bytes and carries 2, so 18 bytes
     of the code after it would be read as the field, and the rest would run */
  const malformed = Uint8Array.from([...tipB.slice(0, 5), 20, 1, 2, ...tipB.slice(26)])
  const list = [
    ['transfer: the thread passes to the new owner', tipT, 41, 42, [out(42, nextT)], sign(), true],
    ['transfer: and only to them', tipT, 41, 42, [out(42, tipT)], sign(), false],
    ['transfer: the new owner signs the next tick', nextT, 42, 43, [out(43, nextT)], sign({ key: 'other' }), true],
    ['transfer: the old owner no longer can', nextT, 42, 43, [out(43, nextT)], sign(), false],
    ['wrong width: the malformed successor is refused', tipB, 41, 42, [out(42, malformed)], sign(), false],
  ]
  const r = judge(list)
  list.forEach((c, k) => ok(r[k].accepted === c[6], `${c[0]} — ${r[k].accepted ? 'accepted' : 'refused'}`))
  /* With the width check taken out, a wrong-width successor is still refused here: its length no longer
     matches the length the rebuild carries over, so the output's bytes differ. A value LONGER than its
     field could pass only if the bytes it pushes past the script happened to read as one more output.
     Every length a push can be, measured: none does for this program. The check stays as rule 4 stated
     in the script — the state is fixed-width fields — rather than left to how its last bytes fall. */
  const at = verifies(tipB).at(-2)        // the width check: the last VERIFY before the binding
  const m = judge([['', disable(tipB, at), 41, 42, [out(42, disable(malformed, at))], sign(), false]])
  ok(!m[0].accepted, 'wrong width, the check taken out: still refused — by the output comparison, as measured')
}

// ── INPUT: a release that carries its code; the successor holds its SHA-256 and its revision ──
console.log('\n── INPUT: the code thread\'s covenant, a release carrying its code ──')
{
  const release = (rev, code) => compileCovenant(RELEASE, { state: { owner: OWNER, rev, code: [...code] } }).bytes
  const sha = H('sha256'), hash256 = b => sha(sha(b))
  /* a bundle of 33,600 bytes, so it is a STR16 push; and one a direct push holds */
  const BUNDLE = Buffer.concat(Array.from({ length: 1050 }, (_, k) => sha(Buffer.from(`the engine, part ${k}`))))
  const SMALL = Buffer.from('a release a direct push holds')
  const tip = release(3, sha(Buffer.from('revision 3'))), next = release(4, sha(BUNDLE))
  const carried = (inputs, more = {}) => sign({ inputs, ...more })
  const R4 = [hex(BUNDLE), '04']
  const list = [
    ['revision 4: the bundle carried, its SHA-256 the successor\'s code', tip, 41, 42, [out(42, next)], carried(R4), true],
    ['the release after it, revision 5, its bundle in a direct push', next, 42, 43, [out(43, release(5, sha(SMALL)))], carried([hex(SMALL), '05']), true],
    ['the revision in two bytes, 04 00', tip, 41, 42, [out(42, next)], carried([hex(BUNDLE), '0400']), true],
    ['the successor\'s code is not the SHA-256 of the bundle carried', tip, 41, 42, [out(42, release(4, sha(SMALL)))], carried(R4), false],
    ['the successor\'s code is the bundle\'s HASH256, not its SHA-256', tip, 41, 42, [out(42, release(4, hash256(BUNDLE)))], carried(R4), false],
    ['the successor says revision 5, and the tick carries 4', tip, 41, 42, [out(42, release(5, sha(BUNDLE)))], carried(R4), false],
    ['the successor keeps revision 3', tip, 41, 42, [out(42, release(3, sha(BUNDLE)))], carried(R4), false],
    ['the revision left out: a missing input', tip, 41, 42, [out(42, next)], carried([hex(BUNDLE)]), false],
    ['nothing carried', tip, 41, 42, [out(42, next)], sign(), false],
    ['a push more than INPUT names', tip, 41, 42, [out(42, next)], carried([...R4, '01']), false],
    ['the revision in 9 bytes, past a cell, its first 8 a 4', tip, 41, 42, [out(42, next)], carried([hex(BUNDLE), '04' + '00'.repeat(8)]), false],
    ['revision 65,536, which DIM rev%2 cannot hold: the rebuild refuses it', tip, 41, 42, [out(42, next)], carried([hex(BUNDLE), '000001']), false],
    ['the bundle and the revision the other way round', tip, 41, 42, [out(42, next)], carried(['04', hex(BUNDLE)]), false],
    ['signed by somebody else, with their own key', tip, 41, 42, [out(42, next)], carried(R4, { key: 'other' }), false],
  ]
  const r = judge(list)
  let agree = 0
  for (const [k, c] of list.entries()) {
    const js = await runJs(c[1], r[k])
    if (JSON.stringify(js) === JSON.stringify({ accepted: r[k].accepted, result: r[k].result })) agree++
    ok(r[k].accepted === c[6], `${c[0]}: ${r[k].accepted ? 'accepted' : 'refused'}`)
  }
  ok(agree === list.length, `★ the JavaScript interpreter gives the same verdict and leaves the same thing on every one (${agree}/${list.length})`)
  ok(unhex(r[0].unlocking)[2 + 64 + 32] === JF_LIT.STR16 && r[0].entry.length / 2 > BUNDLE.length && r[0].entry.length / 2 < 100000,
    `the release tick is ${r[0].entry.length / 2} bytes, its bundle one STR16 push after the key: under the service's 100,000`)
}

// ── against the hand-written 7 Sept counter, on the rules both have: value + 1, the same script, the outputs ──
console.log('\n── the same ticks, with the hand-written 7 Sept counter as the tip (server/verify-wired.php) ──')
{
  const plainSign = u => u.kind === 'sign' && u.key === 'owner' && Object.keys(u).length === 2
  const shared = ALL.map((c, k) => [c, res[k]]).filter(([c]) => c[0].startsWith('minimal') && plainSign(c[5])
    && c[4].every(o => o.locking === hex(minimal) || o.locking === P2PKH || o.locking === '51')
    && c[4].some(o => o.value === c[3]))
  const hand = judge(shared.map(([c]) => [c[0], 'hand', c[2], c[3],
    c[4].map(o => ({ ...o, locking: o.locking === hex(minimal) ? 'hand' : o.locking })), { kind: 'raw', hex: '0101' }]))
  /* The one tick they differ on, and why: the hand counter reads its value as a signed cell too, so a value
     of all ones comes round to 0 and it accepts. The BASIC thread refuses it (nSequence counts from 1). */
  const WRAP = 'minimal · rule 2: a value of all ones does not come round to 0'
  let agree = 0, wrap = null
  shared.forEach(([c, r], k) => {
    const same = hand[k].accepted === r.accepted
    if (c[0] === WRAP) wrap = { hand: hand[k].accepted, basic: r.accepted }
    else if (same) agree++
    console.log(`   hand ${hand[k].accepted ? 'accept' : 'refuse'} · BASIC ${r.accepted ? 'accept' : 'refuse'} ${same || c[0] === WRAP ? ' ' : '✗'} ${c[0].replace(/^minimal · /, '')}`)
  })
  ok(agree === shared.length - 1, `★ on every other one of those ${shared.length} ticks, the BASIC thread and the hand-written counter agree`)
  ok(wrap && wrap.hand && !wrap.basic, '★ …and the hand counter comes round from all ones to 0, where the BASIC thread refuses')
}

// ── every check matters: disable each VERIFY in turn ──
console.log('\n── every VERIFY in the script, disabled in turn: some tick must change its verdict ──')
for (const [name, base, list] of [
  ['minimal', minimal, ALL.filter(c => c[0].startsWith('minimal'))],
  ['counting', counting(7), ALL.filter(c => c[0].startsWith('counting'))],
  ['widths', widths(0), ALL.filter(c => c[0].startsWith('widths'))],
]) {
  const sites = verifies(base)
  const mutated = []
  for (const at of sites) {
    // the mutation is in the code, after the head, so it lands at the same place in every successor
    mutated.push(...list.map(c => [c[0], c[1].length === base.length ? disable(c[1], at) : c[1], c[2], c[3],
      c[4].map(o => ({ ...o, locking: o.locking.length === base.length * 2 ? hex(disable(unhex(o.locking), at)) : o.locking })), c[5], c[6], at]))
  }
  const r = judge(mutated)
  for (const at of sites) {
    const flipped = mutated.map((c, k) => [c, r[k]]).filter(([c, x]) => c[7] === at && x.accepted !== c[6])
    ok(flipped.length > 0, `${name}: the VERIFY at byte ${at} — ${flipped.length ? `${flipped.length} tick(s) change, e.g. "${flipped[0][0][0].replace(/^\w+ · /, '')}"` : 'NO tick changes'}`)
  }
}

// ── every tick above, judged again by the JavaScript judge, which is given only the tick's bytes ──
console.log('\n── every tick above, judged again by tools/thread.mjs from the entry, the tip\'s script and its value ──')
{
  const le64 = b => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n)
  let same = 0, accepted = 0, refused = 0, none = 0
  const diffs = []
  for (const r of judgedByPhp) {
    let js
    try {
      const v = await judgeTick(parseEntry(unhex(r.entry)), 0, unhex(r.lock), le64(unhex(r.value)))
      js = { accepted: v.accepted, result: v.stack ? { stack: v.stack.map(String) } : { error: hex(v.errorBytes) } }
    } catch (e) {
      js = e instanceof VersionError ? { accepted: false, cannotJudge: e.message } : { threw: `${e.constructor.name}: ${e.message}` }
    }
    const php = r.cannotJudge !== undefined ? { accepted: false, cannotJudge: r.cannotJudge } : { accepted: r.accepted, result: r.result }
    if (JSON.stringify(js) === JSON.stringify(php)) { same++; php.cannotJudge !== undefined ? none++ : php.accepted ? accepted++ : refused++ }
    else if (diffs.length < 5) diffs.push(`      php ${JSON.stringify(php)}\n      js  ${JSON.stringify(js)}`)
  }
  for (const d of diffs) console.log(`  ✗ differ\n${d}`)
  ok(same === judgedByPhp.length, `★ the JavaScript judge gives CovenantThread::judge's verdict on every tick PHP judged here (${same}/${judgedByPhp.length}: `
     + `${accepted} accepted, ${refused} refused with the same bytes, ${none} no verdict in the same words)`)
}

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [a covenant thread in BASIC]`)
process.exit(fail === 0 ? 0 : 1)
