// © 2026 sun-dive — Apache License 2.0.
//
// THE TARGET FOR THE CODE GENERATOR: a covenant compiled from BASIC, and the same covenant written by hand in jetForth.
//   node basic/test/channel-target.mjs
// The covenant is foenjam's channel details, the BASIC page's channel example (site/basic.html): one input, the
// details packed, at most 1,687 bytes, and their SHA-256 in the next tip's state. It is compiled by basic/basic-jf.mjs,
// and written by hand below, assembled by server/jf-asm.php: the same head (VER JF 3, the owner, the details' hash),
// then values kept on the stack, the preimage read with its own words, the next tip this script copied once with the
// new hash written over the old. Both scripts judge the same ticks, by CovenantThread::judge (tools/judge-run.php) and
// by judge() of tools/thread.mjs, and must give the same verdict on each; the bytes and instructions of both are shown.
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileCovenant, BASIC_JF_VERSION } from '../basic-jf.mjs'
import { tick, create, authorisedHashes, judge, VersionError, JfHostError } from '../../tools/thread.mjs'
import { ed25519Signer, basicUnlock } from '../../tools/thread-writer.mjs'
import { parseEntry } from '../../tools/entry.mjs'
import { sha256 } from '../../tools/sha256.mjs'
import { ripemd160 } from '../../tools/ripemd160.mjs'
import { InterpreterJF } from '../../tools/interpreter-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..', '..')
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const le64 = v => hex(Uint8Array.from({ length: 8 }, (_, k) => Number((BigInt(v) >> BigInt(8 * k)) & 0xffn)))
const utf8 = s => new TextEncoder().encode(s)

/* The covenant written by hand. Memory is used only where a word must write, from 0 and again and again: a hash reads
   what it hashes before it writes, so it may write over it. Every address stays below 128, where a literal is one
   byte (LIT8 is signed). The details' hash in the next output is at 8 (its value) + 1 (the script's length, for a
   script under 253 bytes) + 27 (its place in the head): 36. */
const HAND = String.raw`
  VER JF 3
  $0000000000000000000000000000000000000000                           \ owner: the HASH160 of the owner's key
  $0000000000000000000000000000000000000000000000000000000000000000   \ details: the SHA-256 of the packed details
                                    \ the stack: signature, key, packed details, owner, details (each address and length)
  2DROP                             \ the old details: not needed
  2>R 2>R                           \ owner and packed details aside
  2DUP 0 HASH160                    \ [0..20) = HASH160(key)
  0 20 2R> 2R> 2SWAP 2>R
  BYTES= 0= (ABORT")$               \ rule 1: the key is the owner's
  0 PREIMAGE 0 HASH256              \ [0..32) = HASH256(PREIMAGE)
  0 32 ED25519-CHECKSIG 0= (ABORT")$   \ rule 1: the owner signed this tick
  TXVALUE 1+                        \ next = the value + 1
  DUP NSEQUENCE <> (ABORT")$        \ rule 2: nSequence is that number
  DUP 1 < (ABORT")$                 \         and above 0
  8 0 NUM2BIN 2DROP                 \ the next output: [0..8) = next, 8 bytes
  8 SCRIPTCODE NIP                  \                  [8..) = this script, its length in front
  2R> SIZE 1687 > (ABORT")$         \ the packed details: 1,687 bytes at most
  36 SHA256                         \ rules 3 and 4: their SHA-256 written over the old details, in place
  0 SWAP 8 + 0 HASH256              \ [0..32) = HASH256(the next output)
  0 32 32 OUTPUTS-HASH BYTES=       \ the tick's one output is exactly that
`
const assemble = src => unhex(execFileSync('php', ['-r', 'require $argv[1]; echo bin2hex(jf_asm(stream_get_contents(STDIN)));', '--',
  join(ROOT, 'server/jf-asm.php')], { input: src.replace(/\\[^\n]*/g, '') }).toString().trim())
const FIELDS = [{ name: 'owner', at: 6, width: 20 }, { name: 'details', at: 27, width: 32 }]

/** The channel example's BASIC, read from the page */
const BAS = /const CHANNEL = `([^`]*)`/.exec(readFileSync(join(ROOT, 'site/basic.html'), 'utf8'))?.[1]

console.log(`── the channel covenant, compiled (${BASIC_JF_VERSION}) and written by hand ──`)
ok(typeof BAS === 'string' && /INPUT packed\$/.test(BAS), 'the channel example\'s BASIC, read from site/basic.html')
const compiled = compileCovenant(BAS, { state: { owner: new Array(20).fill(0), details: new Array(32).fill(0) } })
const hand = assemble(HAND)
ok(hand.length < 253, `the hand-written script is ${hand.length} bytes: under 253, so its length in an output is one byte and the details' hash sits at 36`)
ok(JSON.stringify(compiled.layout.map(f => [f.name, f.width])) === '[["owner",20],["details",32]]'
   && hex(hand.subarray(0, 59)) === hex(compiled.bytes.subarray(0, 59)),
   'both have the same head: the declaration, then the owner and the details\' hash, each one push')
const scripts = { compiled: compiled.bytes, hand }
const withState = (s, owner, details) => { const b = Uint8Array.from(s); b.set(owner, FIELDS[0].at); b.set(details, FIELDS[1].at); return b }

// ── the ticks ──
const newKey = async () => ed25519Signer(await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']))
const OWNER = await newKey(), OTHER = await newKey()
const OWNER_HASH = Uint8Array.from(ripemd160(Uint8Array.from(sha256(OWNER.publicKey))))
const packed = items => { const out = []; for (const b of items) out.push((b.length >>> 24) & 0xff, (b.length >>> 16) & 0xff, (b.length >>> 8) & 0xff, b.length & 0xff, ...b); return Uint8Array.from(out) }
const hashOf = p => Uint8Array.from(sha256(p))
const PIC = Uint8Array.from(sha256(utf8('a picture'))), AGREE = Uint8Array.from(sha256(utf8('a sealing key')))
const FIRST = packed([utf8('Evidnus'), utf8('ambient, live from Taiwan'), utf8('evidnus.example'), Uint8Array.from([...PIC, 1]), new Uint8Array(0), Uint8Array.of(1), AGREE])
const FULL = packed([utf8('音'.repeat(53) + 'a'), utf8('🎵'.repeat(300)), utf8('a'.repeat(200)), Uint8Array.from([...PIC, 1]), Uint8Array.from([...PIC, 2]), Uint8Array.of(1), AGREE])
/* [what, the tip it spends, what the tick carries, how it is built, accepted?] */
const CASES = [
  ['the first tick', 'genesis', FIRST, {}, true],
  [`every item at its limit, ${FULL.length} bytes packed`, 'first', FULL, {}, true],
  ['seven empty items', 'first', packed([[], [], [], [], [], [], []].map(x => Uint8Array.from(x))), {}, true],
  ['any bytes up to the limit: the covenant checks the size only', 'first', utf8('not packed'), {}, true],
  ['1,688 bytes: one over the limit', 'first', new Uint8Array(1688).fill(0x61), {}, false],
  ['the next tip holds the hash of other details than the tick carries', 'first', FIRST, { holds: FULL }, false],
  ['signed by another key', 'first', FIRST, { key: OTHER }, false],
  ['the value moved by 2', 'first', FIRST, { step: 2 }, false],
  ['nSequence not the next number', 'first', FIRST, { sequence: 5 }, false],
  ['a second output', 'first', FIRST, { extra: true }, false],
]
async function ticksFor(template) {
  const script = h => withState(template, OWNER_HASH, h), zero = new Uint8Array(32)
  const genesis = { hash: create(new Uint8Array(32), script(zero), utf8('channel-target'), authorisedHashes([OWNER.publicKey])).id, locking: script(zero), value: 0n }
  const on = (tip, p, { holds = p, key = OWNER, step = 1, sequence, extra } = {}) =>
    tick(tip.hash, 0, tip.locking, tip.value, [{ value: tip.value + BigInt(step), locking: script(hashOf(holds)) }, ...(extra ? [{ value: 1n, locking: script(zero) }] : [])],
         sequence ?? Number(tip.value) + step, basicUnlock(key, [p]))
  const t1 = await on(genesis, FIRST)
  const first = { hash: t1.hash, locking: script(hashOf(FIRST)), value: 1n }
  return Promise.all(CASES.map(async ([, from, p, opts]) => { const tip = from === 'genesis' ? genesis : first; return [await on(tip, p, opts), tip] }))
}

// ── both judges, and the instructions each run takes ──
let ran = 0
const exec = InterpreterJF.prototype.exec
InterpreterJF.prototype.exec = async function (...a) { try { return await exec.apply(this, a) } finally { ran = this.opCount } }
const judgePhp = list => JSON.parse(execFileSync('php', [join(ROOT, 'tools/judge-run.php'), 'judge'], { maxBuffer: 1 << 26,
  input: JSON.stringify(list.map(([t, tip]) => ({ entry: hex(t.bytes), input: 0, lock: hex(tip.locking), value: le64(tip.value) }))) }).toString())
const norm = v => v.noVerdict ? { noVerdict: v.noVerdict, message: v.message }
  : v.stack !== undefined ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.errorBytes ?? unhex(v.error)) }
async function judgeJs(t, tip) {
  try { return norm(await judge(parseEntry(t.bytes), 0, tip.locking, tip.value)) }
  catch (e) { if (e instanceof VersionError || e instanceof JfHostError) return { noVerdict: e.constructor.name, message: e.message }; throw e }
}
const said = v => v.accepted ? 'accepted' : v.error ? `refused: ${Buffer.from(v.error, 'hex').toString('latin1')}` : v.stack ? `refused, ${v.stack.length} item left` : JSON.stringify(v)

const R = {}
for (const [name, s] of Object.entries(scripts)) {
  const T = await ticksFor(s), php = judgePhp(T).map(norm), js = [], ops = []
  for (const t of T) { js.push(await judgeJs(...t)); ops.push(ran) }
  R[name] = { php, js, ops, tick: T[0][0].bytes.length }
}
for (const [k, [what, , , , want]] of CASES.entries()) {
  const c = R.compiled.php[k], h = R.hand.php[k]
  ok(c.accepted === want && h.accepted === want && JSON.stringify(R.hand.js[k]) === JSON.stringify(h) && JSON.stringify(R.compiled.js[k]) === JSON.stringify(c),
     `${what}: compiled ${said(c)}, by hand ${said(h)}; PHP and JS agree on each`)
}
console.log(`\n  ${''.padEnd(26)}${'compiled'.padStart(10)}${'by hand'.padStart(10)}`)
console.log(`  ${'the script, bytes'.padEnd(26)}${String(compiled.bytes.length).padStart(10)}${String(hand.length).padStart(10)}`)
console.log(`  ${'its code, after the head'.padEnd(26)}${String(compiled.bytes.length - 59).padStart(10)}${String(hand.length - 59).padStart(10)}`)
console.log(`  ${'the first tick, bytes'.padEnd(26)}${String(R.compiled.tick).padStart(10)}${String(R.hand.tick).padStart(10)}`)
console.log(`  ${'its instructions'.padEnd(26)}${String(R.compiled.ops[0]).padStart(10)}${String(R.hand.ops[0]).padStart(10)}`)
console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the code generator's target: the channel covenant, compiled and by hand]`)
process.exit(fail ? 1 : 0)
