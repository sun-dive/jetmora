// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// tools/ed25519.mjs and tools/sha512.mjs graded. ed25519.mjs must give server/ed25519.php's verdict on every input, by
// the same rule, as ed25519.php gives libsodium 1.0.22's (server/verify-ed25519.php grades that).
//   node tools/verify-ed25519.mjs [sigs=2000] [seed=20261025] [--ed25519=FILE] [--sha512=FILE]
//     sigs, seed  passed to server/verify-ed25519.php, which builds the corpus
//     --ed25519   grade FILE instead of tools/ed25519.mjs; --sha512 likewise for tools/sha512.mjs
//
// Four parts:
//   corpus  server/verify-ed25519.php's special and sweep cases, from its --export. On each, ed25519.mjs's verdict and
//           refusing rule must be ed25519.php's, and its verdict libsodium's where that PHP has the oracle loaded. At the
//           default sigs and seed the verdicts must also hash to the digests libsodium's were pinned as, so a PHP
//           without sodium still holds this file to libsodium. The rule is compared because no verdict shows rule 3.
//   node    node:crypto's Ed25519 (OpenSSL) on the same cases. Only a 64-byte signature and a 32-byte key are put to
//           it, as the engine checks those lengths before it asks: node reads a key through DER that says 32 bytes,
//           so a longer key verifies as its first 32 bytes would.
//   sha512  against node's SHA-512 on FIPS 180's examples, every length from 0 to 300, long inputs and random data.
//   edges   garbage of every length gives false and never throws; arrays of bytes give the verdicts Uint8Arrays do;
//           ed25519.mjs imports sha512.mjs and nothing else, and sha512.mjs nothing. Then the timings.
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..')
const args = process.argv.slice(2)
const plain = args.filter(a => !a.startsWith('--'))
const opt = name => args.find(a => a.startsWith(`--${name}=`))?.slice(name.length + 3) ?? null
const SIGS = Number(plain[0] ?? 2000), SEED = Number(plain[1] ?? 20261025)
const edFile = resolve(opt('ed25519') ?? join(HERE, 'ed25519.mjs'))
const shaFile = resolve(opt('sha512') ?? join(HERE, 'sha512.mjs'))
const { verify, refusal } = await import(pathToFileURL(edFile).href)
const { sha512 } = await import(pathToFileURL(shaFile).href)

let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const sha256hex = b => createHash('sha256').update(b).digest('hex')
/** Deterministic bytes for a tag, at this seed. */
const bytes = (tag, n) => {
  const out = new Uint8Array(n)
  for (let i = 0, k = 0; i < n; k++) for (const b of createHash('sha256').update(`${SEED}:${tag}/${k}`).digest()) if (i < n) out[i++] = b
  return out
}
const mixOf = m => Object.keys(m).sort().map(k => `${m[k]} ${k}`).join(', ')
console.log(`  - grading ${edFile}, with ${shaFile}`)

// ── 1. the corpus ────────────────────────────────────────────────────────────────────────────────────
console.log('\n── corpus: server/verify-ed25519.php\'s cases, against ed25519.php ──')
let t0 = performance.now()
let corpus
try {
  corpus = JSON.parse(execFileSync('php', [join(ROOT, 'server/verify-ed25519.php'), String(SIGS), String(SEED), '--export'],
                                   { maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'inherit'] }).toString())
} catch (e) {
  console.log(`⛔ server/verify-ed25519.php --export did not run: ${e.message.split('\n')[0]}`); process.exit(2)
}
console.log(`    (${corpus.special.length} special and ${corpus.sweep.length} sweep cases in ${((performance.now() - t0) / 1000).toFixed(1)} s; `
            + (corpus.oracle ? `libsodium ${corpus.oracle} loaded there, the oracle)` : `no oracle there: graded by ed25519.php and the pinned digests)`))
const cases = []                                             // [part, label, sig, msg, pub, js verdict]
for (const part of ['special', 'sweep']) {
  t0 = performance.now()
  const digest = createHash('sha256'), mix = {}, diffs = []
  let n = 0, verdicts = 0, rules = 0, oracle = 0, apart = 0
  for (const [label, sigH, msgH, pubH, phpRule, sodium] of corpus[part]) {
    const sig = unhex(sigH), msg = unhex(msgH), pub = unhex(pubH)
    const r = refusal(sig, msg, pub), v = verify(sig, msg, pub)
    n++
    if (v !== (r === null)) apart++
    if (v === (phpRule === null)) verdicts++
    if (r === phpRule) rules++
    else if (diffs.length < 8) diffs.push([label, sigH, pubH, phpRule, r])
    if (sodium === null || sodium === v) oracle++
    mix[r ?? 'accepted'] = (mix[r ?? 'accepted'] ?? 0) + 1
    // the line server/verify-ed25519.php hashes for each case: sig, key, sha256 of the message, the verdict
    digest.update(`${sigH}\0${pubH}\0${sha256hex(msg)}\0${v ? 1 : 0}\n`)
    cases.push([part, label, sig, msg, pub, v])
  }
  for (const [label, sigH, pubH, php, js] of diffs)
    console.log(`    differs: ${label}\n      sig ${sigH}\n      key ${pubH}\n      ed25519.php ${php ?? 'accepted'}, ed25519.mjs ${js ?? 'accepted'}`)
  ok(verdicts === n, `${part}: ${verdicts} of ${n} cases give ed25519.php's verdict (${((performance.now() - t0) / 1000).toFixed(1)} s)`)
  ok(rules === n, `${part}: and ${rules} of ${n} are refused by the same rule (${mixOf(mix)})`)
  if (corpus.oracle) ok(oracle === n, `${part}: and ${oracle} of ${n} give libsodium ${corpus.oracle}'s verdict, by the oracle case by case`)
  ok(apart === 0, `${part}: verify() is true exactly when refusal() names no rule, on all ${n}`)
  const d = digest.digest('hex'), pinned = corpus.digests[part]
  if (pinned) ok(d === pinned, `${part}: ed25519.mjs gives libsodium ${corpus.rules}'s pinned verdicts (${d})`)
  else console.log(`  - ${part}: not the default ${part === 'special' ? 'seed' : 'sigs and seed'}, so the pinned digest does not apply`)
}

// ── 2. node:crypto ───────────────────────────────────────────────────────────────────────────────────
console.log(`\n── node: node:crypto's Ed25519, OpenSSL ${process.versions.openssl}, on the same cases ──`)
const SPKI = Buffer.from('302a300506032b6570032100', 'hex')
const nodeVerdict = (sig, msg, pub) => {
  try { return nodeVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI, pub]), format: 'der', type: 'spki' }), sig) } catch { return false }
}
{
  let n = 0, same = 0, wrongLength = 0, nodeTrue = 0
  const diffs = []
  for (const [part, label, sig, msg, pub, v] of cases) {
    if (sig.length !== 64 || pub.length !== 32) { wrongLength++; if (nodeVerdict(sig, msg, pub)) nodeTrue++; continue }
    n++
    const w = nodeVerdict(sig, msg, pub)
    if (w === v) same++
    else diffs.push(`${part}: ${label} (node ${w ? 'accepts' : 'refuses'}, ed25519.mjs ${v ? 'accepts' : `refuses by ${refusal(sig, msg, pub)}`})`)
  }
  for (const d of diffs.slice(0, 12)) console.log(`    differs: ${d}`)
  ok(same === n, `node:crypto gives ed25519.mjs's verdict on ${same} of the ${n} cases of the right lengths`)
  console.log(`  - left out: ${wrongLength} cases of a wrong length; node accepts ${nodeTrue} of them, reading the key's first 32 bytes`)
}

// ── 3. sha512 ────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── sha512: against node\'s SHA-512 ──')
{
  const native = b => createHash('sha512').update(b).digest('hex')
  const enc = s => new TextEncoder().encode(s)
  // FIPS 180's examples, so a fault shared with node could not hide
  const fips = [
    ['the empty string', enc(''), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'],
    ['"abc"', enc('abc'), 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
    ['the 896-bit message', enc('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'),
     '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'],
    ['a million "a"', new Uint8Array(1000000).fill(0x61), 'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b'],
  ]
  const bad = fips.filter(([, m, want]) => hex(sha512(m)) !== want).map(([what]) => what)
  ok(bad.length === 0, `FIPS 180's examples: the empty string, "abc", the 896-bit message, a million "a"${bad.length ? `: wrong ${bad.join(', ')}` : ''}`)
  // every length across two block boundaries and the 112-byte point where the padding needs a second block
  let wrong = []
  for (let n = 0; n <= 300; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff)
    if (hex(sha512(b)) !== native(b) || hex(sha512(Array.from(b))) !== native(b)) wrong.push(n)
  }
  ok(wrong.length === 0, `every length from 0 to 300, as Uint8Array and as an array of numbers${wrong.length ? `: wrong at ${wrong.slice(0, 8).join(', ')}` : ''}`)
  wrong = []
  for (const n of [1023, 1024, 1025, 65535, 65536, 65537, 1048575, 1048576]) { const b = bytes(`long ${n}`, n); if (hex(sha512(b)) !== native(b)) wrong.push(n) }
  ok(wrong.length === 0, `long inputs at 2^10, 2^16 and 2^20 bytes, and a byte either side${wrong.length ? `: wrong at ${wrong.join(', ')}` : ''}`)
  let nWrong = 0
  for (let i = 0; i < 3000; i++) {
    const b = bytes(`random ${i}`, bytes(`random length ${i}`, 2).reduce((a, x) => a * 256 + x) % 1001)
    if (hex(sha512(b)) !== native(b)) nWrong++
  }
  ok(nWrong === 0, `3000 random inputs of 0 to 1000 bytes (${nWrong} wrong)`)
}

// ── 4. the edges ─────────────────────────────────────────────────────────────────────────────────────
console.log('\n── edges: no exception for any input, arrays of bytes, and no dependency ──')
{
  const small = ['0000000000000000000000000000000000000000000000000000000000000000', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
                 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', '0100000000000000000000000000000000000000000000000000000000000080'].map(unhex)
  const threw = []
  let n = 0, trues = 0
  for (const sl of [0, 1, 31, 32, 33, 63, 64, 65, 96, 128]) for (const pl of [0, 1, 31, 32, 33, 64]) for (let k = 0; k < 6; k++) {
    let s = bytes(`g s ${sl} ${pl} ${k}`, sl), p = bytes(`g p ${sl} ${pl} ${k}`, pl)
    if (k === 1 && pl === 32) p = small[sl % small.length]
    if (k === 2 && pl === 32) p = new Uint8Array(32).fill(0xff)
    if (k === 3 && sl === 64) s = new Uint8Array(64).fill(0xff)
    n++
    try { if (verify(s, bytes(`g m ${k}`, k * 7), p)) trues++ } catch (e) { threw.push(`${e.constructor.name}: ${e.message}`) }
  }
  ok(threw.length === 0 && trues === 0, `${n} garbage signatures and keys of every length: false each time, nothing thrown${threw.length ? `: ${[...new Set(threw)].slice(0, 3).join('; ')}` : ''}`)
  // the same verdicts from arrays of numbers and from node Buffers, on the special cases
  let differ = 0
  const special = cases.filter(c => c[0] === 'special' && c[3].length <= 65536)
  for (const [, , sig, msg, pub, v] of special)
    if (verify(Array.from(sig), Array.from(msg), Array.from(pub)) !== v || verify(Buffer.from(sig), Buffer.from(msg), Buffer.from(pub)) !== v) differ++
  ok(differ === 0, `arrays of numbers and node Buffers give the verdicts Uint8Arrays do, on ${special.length} special cases (${differ} differ)`)
  // what each file loads and calls: comments out, then the code read for anything not its own
  const code = f => readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '')
  const foreign = /\b(require|process|Buffer|globalThis|window|self|crypto|subtle|fetch|eval|Function)\b|import\s*\(|\bnode:/g
  const edCode = code(edFile), shaCode = code(shaFile)
  const edImports = [...edCode.matchAll(/^\s*import\b.*$/gm)].map(m => m[0].trim())
  const shaImports = [...shaCode.matchAll(/^\s*import\b.*$/gm)].map(m => m[0].trim())
  const names = [...edCode.matchAll(foreign), ...shaCode.matchAll(foreign)].map(m => m[0])
  ok(edImports.length === 1 && edImports[0] === "import { sha512 } from './sha512.mjs'" && shaImports.length === 0 && names.length === 0,
     `ed25519.mjs imports sha512.mjs and nothing else, sha512.mjs imports nothing, and neither names node, a host's crypto or a global`
     + (names.length || edImports.length !== 1 || shaImports.length ? `: ${[...edImports, ...shaImports, ...new Set(names)].join('; ')}` : ''))
}

// how long a verify takes, beside node:crypto's (OpenSSL)
{
  const k = generateKeyPairSync('ed25519'), pub = Uint8Array.from(k.publicKey.export({ format: 'der', type: 'spki' }).subarray(12))
  const time = (msg, n) => {
    const sig = Uint8Array.from(nodeSign(null, msg, k.privateKey))
    if (!verify(sig, msg, pub)) return null
    let t = performance.now(); for (let i = 0; i < n; i++) verify(sig, msg, pub); const ours = (performance.now() - t) / n
    t = performance.now(); for (let i = 0; i < n; i++) nodeVerdict(sig, msg, pub); const theirs = (performance.now() - t) / n
    return [ours, theirs]
  }
  for (let i = 0; i < 50; i++) time(bytes('warm', 32), 1)
  const [one, oneNode] = time(bytes('timing', 32), 200)
  const [long, longNode] = time(bytes('timing long', 65000), 100)
  console.log(`  - one verify: ${one.toFixed(3)} ms by ed25519.mjs, ${oneNode.toFixed(3)} ms by node:crypto`)
  console.log(`  - a tick of 100 verifies: ${(100 * one).toFixed(0)} ms; over a 65,000-byte message, ${(100 * long).toFixed(0)} ms (node:crypto ${(100 * longNode).toFixed(1)} ms)`)
}

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [Ed25519 in JavaScript · against ed25519.php and libsodium ${corpus.rules}]`)
process.exit(fail === 0 ? 0 : 1)
