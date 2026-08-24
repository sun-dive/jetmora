// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ FUZZ THE ENTRY PARSER. Canonical serialization (spec §3.1) is a SECURITY property, not a tidiness
// one: OP_PUSH_TX is secure only because a verifier recomputes the preimage and compares, so if two
// byte strings parse to ONE entry, a signer can push a preimage that does not describe what they did.
//
// ⇒ THE INVARIANT UNDER ATTACK:
//     for every byte string b — either parseEntry(b) THROWS, or serializeEntry(parseEntry(b)) === b
//   Anything else means the format admits two encodings of one entry.
import { serializeEntry, parseEntry } from './entry.mjs'

const hex = b => Buffer.from(b).toString('hex')
let seed = Number(process.env.SEED ?? 20260825)
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff
const byte = () => Math.floor(rnd() * 256)

/** A well-formed entry, to mutate. */
function goodEntry() {
  const nIn = 1 + Math.floor(rnd() * 3), nOut = 1 + Math.floor(rnd() * 3)
  return { version: Math.floor(rnd() * 1000),
    inputs: Array.from({ length: nIn }, (_, i) => ({
      prevEntry: Array.from({ length: 32 }, byte), index: Math.floor(rnd() * 5),
      unlocking: Array.from({ length: Math.floor(rnd() * 40) }, byte),
      sequence: Math.floor(rnd() * 0xffffffff) >>> 0 })),
    outputs: Array.from({ length: nOut }, () => ({
      value: BigInt(Math.floor(rnd() * 1e6)),
      locking: Array.from({ length: Math.floor(rnd() * 60) }, byte) })),
    locktime: 0 }
}

let threw = 0, roundTripped = 0, VIOLATIONS = []
const attack = (label, bytes) => {
  let parsed
  try { parsed = parseEntry(bytes) } catch { threw++; return }
  let re
  try { re = serializeEntry(parsed) } catch { threw++; return }
  if (hex(re) === hex(bytes)) { roundTripped++; return }
  // ⚠⚠ PARSED BUT DID NOT ROUND TRIP — two byte strings for one entry
  if (VIOLATIONS.length < 6) VIOLATIONS.push([label, hex(bytes).slice(0, 80), hex(re).slice(0, 80)])
}

const N = Number(process.env.N ?? 20000)
console.log(`\n  ═══ ENTRY PARSER FUZZ — ${N} cases, seed ${seed} ═══\n`)

// 1. pure noise
for (let i = 0; i < N / 4; i++)
  attack('noise', Array.from({ length: Math.floor(rnd() * 200) }, byte))

// 2. valid entries, unmutated — these MUST all round trip
let cleanFail = 0
for (let i = 0; i < N / 4; i++) {
  const b = serializeEntry(goodEntry())
  try { if (hex(serializeEntry(parseEntry(b))) !== hex(b)) cleanFail++ } catch { cleanFail++ }
  roundTripped++
}

// 3. valid entries with ONE byte flipped — the dangerous case
for (let i = 0; i < N / 4; i++) {
  const b = serializeEntry(goodEntry())
  b[Math.floor(rnd() * b.length)] ^= 1 << Math.floor(rnd() * 8)
  attack('one bit flipped', b)
}

// 4. valid entries truncated or extended
for (let i = 0; i < N / 4; i++) {
  const b = serializeEntry(goodEntry())
  attack(rnd() < 0.5 ? 'truncated' : 'extended',
         rnd() < 0.5 ? b.slice(0, Math.floor(rnd() * b.length)) : [...b, ...Array.from({ length: 1 + Math.floor(rnd() * 5) }, byte)])
}

console.log(`  refused (threw)        ${threw}`)
console.log(`  parsed and round-trip  ${roundTripped}`)
console.log(`  ⚠ well-formed failures ${cleanFail}`)
console.log(`  ⚠⚠ CANONICAL VIOLATIONS ${VIOLATIONS.length}`)
for (const [l, a, b] of VIOLATIONS) console.log(`     ${l}\n       in  ${a}\n       out ${b}`)

// ── ⚠ hand-built attacks on the specific things §3.1 forbids ─────────────────────────────────
console.log(`\n  ── the specific attacks §3.1 exists to stop ──\n`)
const base = serializeEntry({ version: 2,
  inputs: [{ prevEntry: new Array(32).fill(7), index: 0, unlocking: [0x51], sequence: 5 }],
  outputs: [{ value: 1000n, locking: [0x52] }], locktime: 0 })
const named = (label, bytes) => {
  let r = 'refused'
  try { const p = parseEntry(bytes); r = hex(serializeEntry(p)) === hex(bytes) ? 'accepted, round-trips' : '⚠⚠ ACCEPTED, DIFFERENT BYTES' }
  catch (e) { r = 'refused: ' + String(e.message).slice(0, 40) }
  console.log(`  ${label.padEnd(38)} ${r}`)
}
named('the entry itself', base)
named('one trailing zero byte', [...base, 0x00])
named('non-minimal varint for input count', [...base.slice(0,4), 0xfd, 0x01, 0x00, ...base.slice(5)])
named('truncated by one byte', base.slice(0, -1))
named('input count claims 0xffffffff', [...base.slice(0,4), 0xfe, 0xff, 0xff, 0xff, 0xff, ...base.slice(5)])
named('locktime non-zero', (() => { const b=[...base]; b[b.length-4]=1; return b })())
console.log()
if (VIOLATIONS.length || cleanFail) process.exitCode = 1
