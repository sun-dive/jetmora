// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// The JavaScript judge graded against the PHP one. tools/thread.mjs's judge, the preimage it builds (tools/preimage.mjs)
// and the crypto it is given (tools/jf-crypto.mjs) must give what the thread service's own code gives: CovenantThread::judge,
// Preimage::build, PHP's hash() and secp256k1.php's verifyDigest, which tools/judge-run.php runs.
//   node tools/verify-judge.mjs [ticks=1000] [seed=20261026] [--browser]
//
//   hashes     tools/sha1.mjs and tools/ripemd160.mjs against node's: the published examples, every length from 0 to 300,
//              long inputs and random data
//   secp256k1  tools/secp256k1.mjs against secp256k1.php, case by case: signatures made by PHP and by node, each altered,
//              high S, the edges of the ranges, every key form, a trailing byte, and garbage, which never throws
//   preimage   tools/preimage.mjs against Preimage::build, byte for byte, on random entries: 1 to 5 inputs and outputs, scripts
//              of each varint size, values of 0 and 2^64 - 1, every input, and an input that is not there
//   judge      tools/thread.mjs's judge against CovenantThread::judge, tick for tick: the ticks server/verify-tip.php sends
//              (its --export; an answer the service gave from its judge must be the PHP judge's), server/verify-wired.php's
//              counter, and random ticks of several inputs, each version, locks that read the preimage, hash it, sign it
//              (secp256k1 and Ed25519) or abort, each lock declaring its version, now and then another or none. The same
//              verdict, the same refusal bytes, the same stack, and no verdict in the same cases in the same words. Then
//              crypto missing or broken: no verdict, never a refusal. Then the lock's declaration case by case: a tick
//              naming another version, a lock with none or one this host does not serve, VER later in a lock or in a
//              function, and a branch back to it
//   mutants    tools/preimage.mjs altered in a copy (field order, value width, the scriptCode length varint, and more), and
//              the judge and the dispatcher altered: each copy must disagree with PHP somewhere
//   browser    what a page loads names nothing of node's; with --browser, headless Chromium runs the judge on the same
//              ticks, from the files in tools/, and must give PHP's verdicts
// basic/test/thread.mjs judges every tick of the BASIC thread's corpus (basic/test/thread-ticks.php) with this judge too.
// One temp folder per run, removed however the run ends, and a browser started here is killed with it; what a run killed
// outright left behind is cleared by the next (tools/run-folder.mjs).
import { execFileSync } from 'node:child_process'
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { rmSync, readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { sha1 } from './sha1.mjs'
import { ripemd160 } from './ripemd160.mjs'
import { verifyDigest } from './secp256k1.mjs'
import { preimage } from './preimage.mjs'
import { judge, jfCrypto, OTHER_VERSION, VER } from './thread.mjs'
import { NOT_ONE } from './thread-reader.mjs'
import { versionBuild } from './dispatch.mjs'
import { serializeEntry, parseEntry, varint } from './entry.mjs'
import { JF_WORD, JF_LIT, JF_SMALL0, JF_RESERVED0 } from './ops-jf.mjs'
import { runFolder } from './run-folder.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..')
const args = process.argv.slice(2), plain = args.filter(a => !a.startsWith('--'))
const N_TICKS = Number(plain[0] ?? 1000), SEED = Number(plain[1] ?? 20261026), BROWSER = args.includes('--browser')
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const H = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const le64 = v => { const o = new Uint8Array(8); let x = BigInt.asUintN(64, BigInt(v)); for (let k = 0; k < 8; k++) { o[k] = Number(x & 0xffn); x >>= 8n } return o }
const fromLe64 = b => b.reduceRight((v, x) => (v << 8n) | BigInt(x), 0n)
const tally = list => Object.entries(list.reduce((m, k) => (m[k] = (m[k] ?? 0) + 1, m), {})).map(([k, n]) => `${n} ${k}`).join(', ')

// ── the temp folder, and the browser, gone however the run ends; a dead run's are cleared first (tools/run-folder.mjs) ──
const RUN = runFolder('judge'), TMP = RUN.dir

/** The PHP side: tools/judge-run.php in one of its modes. */
const php = (mode, cases) => JSON.parse(execFileSync('php', [join(HERE, 'judge-run.php'), mode],
  { input: JSON.stringify(cases), maxBuffer: 1 << 30, stdio: ['pipe', 'pipe', 'inherit'] }).toString())

// ── seeded randomness ──
let st = SEED >>> 0 || 1
const rnd = () => { st ^= st << 13; st >>>= 0; st ^= st >>> 17; st ^= st << 5; st >>>= 0; return st / 2 ** 32 }
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1))
const pick = a => a[Math.floor(rnd() * a.length)]
const chance = p => rnd() < p
const rbytes = n => Uint8Array.from({ length: n }, () => int(0, 255))
const U64S = [0n, 1n, 41n, 0xffffffffn, 1n << 32n, (1n << 63n) - 1n, 1n << 63n, (1n << 64n) - 1n]
const ru64 = () => chance(0.5) ? pick(U64S) : BigInt.asUintN(64, (BigInt(int(0, 2 ** 31)) << 33n) ^ BigInt(int(0, 2 ** 31)))
const ru32 = () => chance(0.3) ? pick([0, 1, 0xfffffffe, 0xffffffff]) : int(0, 0xffffffff)

// ── 1. hashes ────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('── hashes: tools/sha1.mjs and tools/ripemd160.mjs, against node\'s ──')
{
  const enc = s => new TextEncoder().encode(s), A = new Uint8Array(1000000).fill(0x61)
  const published = [
    ['SHA-1', sha1, '', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
    ['SHA-1', sha1, 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
    ['SHA-1', sha1, 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '84983e441c3bd26ebaae4aa1f95129e5e54670f1'],
    ['SHA-1', sha1, A, '34aa973cd4c4daa4f61eeb2bdbad27316534016f'],
    ['RIPEMD-160', ripemd160, '', '9c1185a5c5e9fc54612808977ee8f548b2258d31'],
    ['RIPEMD-160', ripemd160, 'a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'],
    ['RIPEMD-160', ripemd160, 'abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
    ['RIPEMD-160', ripemd160, 'message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'],
    ['RIPEMD-160', ripemd160, 'abcdefghijklmnopqrstuvwxyz', 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'],
    ['RIPEMD-160', ripemd160, 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '12a053384a9c0c88e405a06c27dcf49ada62eb2b'],
    ['RIPEMD-160', ripemd160, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'b0e20b6e3116640286ed3a87a5713079b21f5189'],
    ['RIPEMD-160', ripemd160, '1234567890'.repeat(8), '9b752e45573d4b39f4dbd3323cab82bf63326bfb'],
    ['RIPEMD-160', ripemd160, A, '52783243c1697bdbe16d37f97f68f08325dc1528'],
  ]
  const bad = published.filter(([, f, m, want]) => hex(f(typeof m === 'string' ? enc(m) : m)) !== want).map(([n, , m]) => `${n} of ${typeof m === 'string' ? JSON.stringify(m) : 'a million "a"'}`)
  ok(bad.length === 0, `the published examples: FIPS 180's for SHA-1 (4), the designers' for RIPEMD-160 (9)${bad.length ? `: wrong ${bad.join('; ')}` : ''}`)
  for (const [name, f, alg] of [['sha1.mjs', sha1, 'sha1'], ['ripemd160.mjs', ripemd160, 'ripemd160'], ['jfCrypto.sha256', jfCrypto.sha256, 'sha256']]) {
    const native = H(alg), wrong = []
    for (let n = 0; n <= 300; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff)
      if (hex(f(b)) !== hex(native(b)) || hex(f(Array.from(b))) !== hex(native(b))) wrong.push(n)
    }
    for (const n of [1023, 1024, 1025, 65535, 65536, 65537, 1048576]) { const b = rbytes(n); if (hex(f(b)) !== hex(native(b))) wrong.push(n) }
    let rWrong = 0
    for (let i = 0; i < 2000; i++) { const b = rbytes(int(0, 1000)); if (hex(f(b)) !== hex(native(b))) rWrong++ }
    const out = f(new Uint8Array(3))
    ok(wrong.length === 0 && rWrong === 0 && out instanceof Uint8Array && out.length === native(new Uint8Array(3)).length,
       `${name}: every length 0 to 300 (Uint8Array and array of numbers), 2^10, 2^16 and 2^20 bytes and either side, 2000 random: node's bytes`
       + (wrong.length || rWrong ? `: wrong at ${wrong.slice(0, 8).join(', ')}, and ${rWrong} random` : ''))
  }
}

// ── 2. secp256k1 ─────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── secp256k1: tools/secp256k1.mjs against secp256k1.php\'s verifyDigest ──')
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const be32 = v => Uint8Array.from({ length: 32 }, (_, k) => Number((v >> BigInt(8 * (31 - k))) & 0xffn))
/** v big-endian in as few bytes as hold it, one at least: wider than 32 bytes when v is */
const beMin = v => { const o = []; do { o.unshift(Number(v & 0xffn)); v >>= 8n } while (v > 0n); return Uint8Array.from(o) }
const fromBe = b => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n)
/** DER of two INTEGERs given as their content bytes */
const der = (r, s) => { const ir = [0x02, r.length, ...r], is = [0x02, s.length, ...s]; return Uint8Array.from([0x30, ir.length + is.length, ...ir, ...is]) }
const derNum = v => { const b = beMin(v); return b[0] & 0x80 ? Uint8Array.from([0, ...b]) : b }
const derOf = (r, s) => der(derNum(r), derNum(s))
const parseDer = sig => { const lr = sig[3]; const r = sig.subarray(4, 4 + lr), s = sig.subarray(6 + lr, 6 + lr + sig[5 + lr]); return [r, s].map(b => b.reduce((v, x) => (v << 8n) | BigInt(x), 0n)) }
const compress = pub65 => Uint8Array.from([2 + (pub65[64] & 1), ...pub65.subarray(1, 33)])
const nodeKeys = Array.from({ length: 4 }, () => { const k = generateKeyPairSync('ec', { namedCurve: 'secp256k1' })
  return { priv: k.privateKey, pub65: Uint8Array.from(k.publicKey.export({ format: 'der', type: 'spki' }).subarray(-65)) } })
nodeKeys.forEach(k => { k.pub33 = compress(k.pub65) })
/** an ECDSA signature by node over HASH256-style input: node hashes `data` once with SHA-256, so the digest is sha256(data) */
const nodeEcdsa = (k, data) => Uint8Array.from(nodeSign('sha256', data, k.priv))
const SECP = []                                               // { sig, pub, digest, trailing, want }, kept for the mutants
{
  const special = [new Uint8Array(32), be32(N), new Uint8Array(32).fill(0xff), be32(1n), be32(N - 1n), be32(N + 1n)]
  const phpKeys = Array.from({ length: 8 }, (_, k) => hex(H('sha256')(Buffer.from(`${SEED} key ${k}`))))
  const toSign = []
  for (const key of phpKeys) for (let k = 0; k < 4; k++) toSign.push({ key, digest: hex(k < 2 ? rbytes(32) : pick(special)) })
  const signed = php('ecdsa-sign', toSign).map((x, k) => ({ sig: unhex(x.sig), pub33: unhex(x.pub33), pub65: unhex(x.pub65), digest: unhex(toSign[k].digest) }))
  for (const k of nodeKeys) for (let j = 0; j < 4; j++) { const data = rbytes(int(0, 100)); signed.push({ sig: nodeEcdsa(k, data), pub33: k.pub33, pub65: k.pub65, digest: H('sha256')(data) }) }
  const cases = []                                            // [what, sig, pub, digest, trailing, expected or null]
  const flip = (b, i) => { const c = Uint8Array.from(b); c[i % c.length] ^= 1 << (i % 8); return c }
  for (const [n, x] of signed.entries()) {
    const [r, s] = parseDer(x.sig), other = signed[(n + 1) % signed.length]
    cases.push(['valid, compressed key', x.sig, x.pub33, x.digest, false, true],
               ['valid, uncompressed key', x.sig, x.pub65, x.digest, false, true],
               ['high and low S swapped: no LOW_S rule', derOf(r, N - s), x.pub33, x.digest, false, true],
               ['the digest altered', x.sig, x.pub33, flip(x.digest, int(0, 255)), false, false],
               ['r altered', derOf(r ^ 1n, s), x.pub33, x.digest, false, false],
               ['s altered', derOf(r, s ^ 2n), x.pub33, x.digest, false, false],
               ['another key', x.sig, other.pub33, x.digest, false, other.pub33.every((b, i) => b === x.pub33[i])],
               // −Q: it verifies only when the digest is 0 mod n, where u1 = 0 and R = ±u2·Q have the same x
               ['the key\'s parity flipped', x.sig, Uint8Array.from([x.pub33[0] ^ 1, ...x.pub33.subarray(1)]), x.digest, false, fromBe(x.digest) % N === 0n],
               ['a hybrid key (06 or 07)', x.sig, Uint8Array.from([6 + (x.pub65[64] & 1), ...x.pub65.subarray(1)]), x.digest, false, false],
               ['a trailing byte, strict', Uint8Array.from([...x.sig, 1]), x.pub33, x.digest, false, false],
               ['a trailing byte, allowed', Uint8Array.from([...x.sig, 1]), x.pub33, x.digest, true, true],
               ['r padded with a needless 0x00: read as its value', der(Uint8Array.from([0, ...derNum(r)]), derNum(s)), x.pub33, x.digest, false, true],
               ['r with its sign byte dropped: negative', der(beMin(r), derNum(s)), x.pub33, x.digest, false, (beMin(r)[0] & 0x80) === 0],
               ['truncated', x.sig.subarray(0, x.sig.length - 1), x.pub33, x.digest, false, false],
               ['the sequence length one more', Uint8Array.from([0x30, x.sig[1] + 1, ...x.sig.subarray(2)]), x.pub33, x.digest, false, false],
               ['a 31-byte digest', x.sig, x.pub33, x.digest.subarray(0, 31), false, false],
               ['a 33-byte digest', x.sig, x.pub33, Uint8Array.from([...x.digest, 0]), false, false])
    if (n < 4) for (const [what, rr, ss] of [['r = 0', 0n, s], ['s = 0', r, 0n], ['r = n', N, s], ['s = n', r, N], ['r = n − 1', N - 1n, s],
                                              ['r = r + n', r + N, s], ['r of 33 significant bytes', (1n << 256n) + r, s]])
      cases.push([what, derOf(rr, ss), x.pub33, x.digest, false, false])
  }
  // keys that are not points: x = p, x of no point, y off the curve
  const k0 = signed[0]
  const powP = (b, e) => { let r = 1n; for (b %= P; e > 0n; e >>= 1n) { if (e & 1n) r = r * b % P; b = b * b % P } return r }
  // ★ Signatures for keys nobody holds, by a curve of the test's own (affine, BigInt): R = a·G + b·Q, r = x(R), s = r/b and
  //   the digest a·s, so u1 = a and u2 = b. With a = 0 the digest is 0 and R = b·Q, which is defined on whatever curve
  //   y² = x³ + c the point lies on: a point off secp256k1 then gets a signature that verifies if, and only if, the
  //   verifier does not check the curve. So each rule about keys is shown to be what refuses them.
  const m = (a, q) => ((a % q) + q) % q
  const invQ = (a, q) => { let r = 1n, b = m(a, q), e = q - 2n; for (; e > 0n; e >>= 1n) { if (e & 1n) r = r * b % q; b = b * b % q } return r }
  const aAdd = (p1, p2) => {
    if (!p1) return p2; if (!p2) return p1
    let l
    if (p1.x === p2.x) { if (m(p1.y + p2.y, P) === 0n) return null; l = 3n * p1.x * p1.x % P * invQ(2n * p1.y, P) % P }
    else l = m(p2.y - p1.y, P) * invQ(p2.x - p1.x, P) % P
    const x = m(l * l - p1.x - p2.x, P)
    return { x, y: m(l * (p1.x - x) - p1.y, P) }
  }
  const aMul = (k, pt) => { let r = null; for (let b = pt; k > 0n; k >>= 1n) { if (k & 1n) r = aAdd(r, b); b = aAdd(b, b) } return r }
  const G0 = { x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n }
  const forge = (Q, a) => {
    const b = 1n + BigInt('0x' + hex(rbytes(31))), R = aAdd(aMul(a, G0), aMul(b, Q))
    const r = R.x % N, s = r * invQ(b, N) % N
    return { sig: derOf(r, s), digest: be32(a * s % N) }
  }
  // the smallest x0 of a point whose x0 + p still fits 32 bytes, and a point off the curve
  let x0 = 1n
  while (powP((x0 ** 3n + 7n) % P, (P - 1n) / 2n) !== 1n) x0++
  const y0 = powP((x0 ** 3n + 7n) % P, (P + 1n) / 4n), Q0 = { x: x0, y: y0 }, f0 = forge(Q0, 1n + BigInt(int(1, 1e9)))
  const par = y => 2 + Number(y & 1n)
  const OFF = { x: G0.x, y: G0.y + 1n }, fOff = forge(OFF, 0n)
  cases.push(['forged: a key nobody holds, compressed', f0.sig, Uint8Array.from([par(y0), ...be32(x0)]), f0.digest, false, true],
             ['forged: the same, uncompressed', f0.sig, Uint8Array.from([4, ...be32(x0), ...be32(y0)]), f0.digest, false, true],
             ['forged: its x given as x + p, compressed', f0.sig, Uint8Array.from([par(y0), ...be32(x0 + P)]), f0.digest, false, false],
             ['forged: its x given as x + p, uncompressed', f0.sig, Uint8Array.from([4, ...be32(x0 + P), ...be32(y0)]), f0.digest, false, false],
             ['forged: a point off the curve, with a digest of 0', fOff.sig, Uint8Array.from([4, ...be32(OFF.x), ...be32(OFF.y)]), fOff.digest, false, false])
  let xBad = 5n
  while (powP((xBad ** 3n + 7n) % P, (P - 1n) / 2n) === 1n) xBad++   // Euler's criterion: x³ + 7 is not a square, so no point has this x
  const yFlip = Uint8Array.from(k0.pub65); yFlip[64] ^= 1
  cases.push(['x = p', k0.sig, Uint8Array.from([2, ...be32(P)]), k0.digest, false, false],
             ['x of no point', k0.sig, Uint8Array.from([2, ...be32(xBad)]), k0.digest, false, false],
             ['x of no point, uncompressed', k0.sig, Uint8Array.from([4, ...be32(xBad), ...k0.pub65.subarray(33)]), k0.digest, false, false],
             ['y with its low bit changed: off the curve', k0.sig, yFlip, k0.digest, false, false],
             ['y = p', k0.sig, Uint8Array.from([4, ...k0.pub65.subarray(1, 33), ...be32(P)]), k0.digest, false, false])
  // garbage of every length
  for (const sl of [0, 1, 7, 8, 9, 40, 70, 71, 72, 73, 100]) for (const pl of [0, 32, 33, 64, 65, 66]) for (const dl of [0, 32]) {
    const sig = rbytes(sl); if (sl >= 8 && chance(0.5)) { sig[0] = 0x30; sig[1] = sl - 2; sig[2] = 2 }
    const pub = rbytes(pl); if (pl === 33) pub[0] = pick([2, 3]); if (pl === 65) pub[0] = 4
    cases.push(['garbage', sig, pub, rbytes(dl), chance(0.3), false])
  }
  const want = php('ecdsa', cases.map(([, sig, pub, digest, trailing]) => ({ sig: hex(sig), pub: hex(pub), digest: hex(digest), trailing })))
  cases.forEach(([, sig, pub, digest, trailing], k) => SECP.push({ sig, pub, digest, trailing, want: want[k] }))
  let same = 0, labelled = 0, threw = 0
  const diffs = [], mislabels = []
  const t0 = performance.now()
  cases.forEach(([what, sig, pub, digest, trailing, expect], k) => {
    let v
    // strict cases through the default, as tools/jf-crypto.mjs calls it
    try { v = trailing ? verifyDigest(sig, pub, digest, true) : verifyDigest(sig, pub, digest) } catch (e) { threw++; v = `threw ${e.message}` }
    if (v === want[k]) same++; else if (diffs.length < 6) diffs.push(`${what}: php ${want[k]}, js ${v}`)
    if (expect !== null && want[k] !== expect && mislabels.length < 6) mislabels.push(`${what}: php ${want[k]}, expected ${expect}`)
    if (expect !== null) labelled++
  })
  const ms = (performance.now() - t0) / cases.length
  for (const d of diffs) console.log(`    differs: ${d}`)
  ok(same === cases.length && threw === 0, `secp256k1.php's verdict on every one of ${cases.length} cases (${signed.length} signatures, ${signed.length - 16} by PHP and 16 by node, each altered, and garbage); nothing thrown`)
  ok(mislabels.length === 0, `and each case's verdict is the one its construction calls for (${labelled} cases)${mislabels.length ? `: ${mislabels.join('; ')}` : ''}`)
  ok(want.filter(Boolean).length > signed.length * 3, `the corpus is not all refusals: ${want.filter(Boolean).length} verify (${ms.toFixed(2)} ms a case in JavaScript)`)
}

// ── 3. preimage ──────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── preimage: tools/preimage.mjs against Preimage::build, byte for byte ──')
const LENGTHS = [0, 1, 25, 72, 252, 253, 254, 300, 0xffff, 0x10000]
const rlen = big => chance(big ? 0.12 : 0) ? pick([0xffff, 0x10000, 70000]) : chance(0.5) ? pick(LENGTHS.slice(0, 8)) : int(0, 400)
/** A random entry for the preimage alone: unlocking scripts play no part in it, and locktime is any u32 here. */
function preEntry(big) {
  return { version: chance(0.5) ? versionBuild('JF', 3) : ru32(), locktime: chance(0.7) ? 0 : ru32(),
           inputs: Array.from({ length: int(1, 5) }, () => ({ prevEntry: rbytes(32), index: ru32(), unlocking: [], sequence: ru32() })),
           outputs: Array.from({ length: int(1, 5) }, () => ({ value: ru64(), locking: rbytes(rlen(big)) })) }
}
const PRE = []                                                // { entry, input, scriptCode, value, php }
{
  const entries = Array.from({ length: 300 }, (_, k) => preEntry(k % 25 === 0))
  for (const e of entries) {
    for (let i = 0; i <= e.inputs.length; i++)                // every input, and one past the last
      if (i < e.inputs.length || chance(0.2)) PRE.push({ entry: e, input: i, scriptCode: rbytes(rlen(PRE.length % 40 === 0)), value: ru64() })
  }
  const res = php('preimage', PRE.map(c => ({
    entry: { version: c.entry.version, locktime: c.entry.locktime,
             inputs: c.entry.inputs.map(i => ({ prevEntry: hex(i.prevEntry), index: i.index, sequence: i.sequence })),
             outputs: c.entry.outputs.map(o => ({ value: hex(le64(o.value)), locking: hex(o.locking) })) },
    input: c.input, scriptCode: hex(c.scriptCode), value: hex(le64(c.value)) })))
  res.forEach((r, k) => { PRE[k].php = r })
}
/** A preimage case, in the PHP helper's form: { preimage } or { thrown, message } */
const preJs = (build, c) => { try { return { preimage: hex(build({ entry: c.entry, inputIndex: c.input, scriptCode: c.scriptCode, value: c.value })) } }
                              catch (e) { return { thrown: e.constructor.name, message: e.message } } }
{
  const differ = PRE.filter(c => JSON.stringify(preJs(preimage, c)) !== JSON.stringify(c.php))
  const vsize = n => n < 0xfd ? 1 : n <= 0xffff ? 3 : 5
  const sizes = tally(PRE.filter(c => c.php.preimage).map(c => `${vsize(c.scriptCode.length)}-byte`))
  for (const c of differ.slice(0, 4)) console.log(`    differs at input ${c.input}: php ${JSON.stringify(c.php).slice(0, 120)}`)
  ok(differ.length === 0, `Preimage::build's bytes on every one of ${PRE.length} cases: ${PRE.filter(c => c.php.preimage).length} preimages, `
     + `${PRE.filter(c => c.php.thrown).length} inputs that are not there (the same PreimageError, the same words)`)
  ok(PRE.some(c => c.entry.inputs.length > 1 && c.input > 0) && PRE.some(c => c.value === 0n) && PRE.some(c => c.entry.outputs.some(o => o.value === 0n))
     && PRE.some(c => c.value === (1n << 64n) - 1n) && PRE.some(c => c.scriptCode.length === 0),
     `the corpus has several inputs judged past the first, zero values, 2^64 - 1, an empty scriptCode, and scriptCode varints of ${sizes}`)
}

// ── 4. the judge ─────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── judge: tools/thread.mjs against CovenantThread::judge, tick for tick ──')
const W = JF_WORD, L = JF_LIT
const small = n => JF_SMALL0 + n
/** A number as the shortest literal that holds it, signed */
const num = n => n <= 8 ? [small(n)] : n < 0x80 ? [L.LIT8, n] : n < 0x8000 ? [L.LIT16, n & 0xff, n >> 8]
                       : [L.LIT32, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]
/** One byte push: direct up to 72 bytes, then STR8, STR16 */
const push = b => b.length <= 72 ? [b.length, ...b] : b.length <= 255 ? [L.STR8, b.length, ...b] : [L.STR16, b.length & 0xff, b.length >> 8, ...b]
const pushAny = b => b.length <= 72 && chance(0.7) ? [b.length, ...b] : b.length <= 255 && chance(0.6) ? [L.STR8, b.length, ...b]
                   : [L.STR16, b.length & 0xff, b.length >> 8, ...b]
/** The judge's answer in one form for both: a verdict, no verdict, or the caller's mistake */
const normJs = async (j, c, crypto) => {
  try {
    const v = await j(parseEntry(unhex(c.entry)), c.input, unhex(c.lock), fromLe64(unhex(c.value)), crypto)
    return v.stack ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.errorBytes) }
  } catch (e) {
    const name = e?.constructor?.name
    return name === 'VersionError' || name === 'JfHostError' ? { noVerdict: name, message: e.message } : { thrown: name, message: e?.message }
  }
}
const kindOf = r => r.noVerdict ? `no verdict (${r.noVerdict})` : r.thrown ? `thrown (${r.thrown})` : r.accepted ? 'accepted' : 'refused'
/** Judge cases with both, and count where they differ. Each case: { what, entry, input, lock, value } in hex, php filled in. */
async function compare(cases, j = judge, crypto = undefined, show = 4) {
  let same = 0
  const diffs = []
  for (const c of cases) {
    const js = await normJs(j, c, crypto)
    if (JSON.stringify(js) === JSON.stringify(c.php)) same++
    else { diffs.push(c); if (diffs.length <= show) console.log(`    differs: ${c.what}\n      php ${JSON.stringify(c.php).slice(0, 160)}\n      js  ${JSON.stringify(js).slice(0, 160)}`) }
  }
  return { same, diffs }
}
const withPhp = cases => { php('judge', cases.map(({ entry, input, lock, value }) => ({ entry, input, lock, value }))).forEach((r, k) => { cases[k].php = r }); return cases }

// 4a. the ticks server/verify-tip.php sends, and what the service answered
const TIP = []
{
  const file = join(TMP, 'tip.json')
  let ran = true
  try { execFileSync('php', [join(ROOT, 'server/verify-tip.php'), `--export=${file}`], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 26 }) }
  catch (e) { ran = false; console.log(`    server/verify-tip.php failed:\n${(e.stdout ?? '').toString().split('\n').filter(l => l.includes('✗')).join('\n')}`) }
  ok(ran, 'server/verify-tip.php passes, and exports the ticks it sent')
  for (const [k, r] of (ran ? JSON.parse(readFileSync(file, 'utf8')) : []).entries())
    TIP.push({ what: `verify-tip tick ${k} (${r.status} ${r.error ?? ''})`, entry: r.entry, input: 0, lock: r.lock, value: r.value, service: r })
  withPhp(TIP)
  const { same } = await compare(TIP)
  // what the service said, where its answer came from its judge
  const served = TIP.map(c => {
    const s = c.service, p = c.php
    if (s.status === 201) return p.accepted === true ? 'accepted' : 'MISMATCH'
    // a run that ends without exactly one non-zero item gives the judge's stack and no error: the service's reason
    // is then append.php's own words, which the reader gives too
    const why = p.error ?? (p.accepted === false && p.stack ? hex(new TextEncoder().encode(NOT_ONE)) : null)
    if (s.status === 422 && s.reason_hex !== null) return p.accepted === false && why === s.reason_hex ? `refused: ${Buffer.from(s.reason_hex, 'hex').toString('latin1').replace(/[^\x20-\x7e]/g, '?')}` : 'MISMATCH'
    if (s.status === 501 && p.noVerdict && s.error === `no verdict: ${p.message}`) return 'no verdict'
    // a host that does not ship a set says so, where the repository's PHP has the set and says it judges no ticks
    if (s.status === 501 && p.noVerdict && /^no verdict: family `\w\w` is registered, but this host does not ship /.test(s.error)) return 'no verdict (the set not shipped there)'
    return `the service's own check (${s.status})`
  })
  ok(same === TIP.length, `the PHP judge's answer on every tick verify-tip.php sent (${same}/${TIP.length})`)
  ok(!served.includes('MISMATCH') && served.some(x => x === 'accepted') && served.some(x => x.startsWith('refused')) && served.some(x => x.startsWith('no verdict')),
     `each answer the service gave from its judge is the PHP judge's, and so the JavaScript's: ${tally(served)}`)
}

// 4b. the counter of server/verify-wired.php
const COUNTER = []
{
  const script = unhex(execFileSync('php', [join(HERE, 'judge-run.php'), 'counter']).toString().trim())
  const tip = rbytes(32), JF3 = versionBuild('JF', 3), P2PKH = unhex('76a914' + '99'.repeat(20) + '88ac')
  // as verify-wired.php ticks it: one byte push the lock drops, nSequence 1, the successor in output 0
  const mine = { prevEntry: tip, index: 0, unlocking: Uint8Array.of(1, 1), sequence: 1 }
  const another = { prevEntry: rbytes(32), index: 1, unlocking: Uint8Array.of(1, 2), sequence: 7 }
  const tick = (what, from, outputs, expect, inputs = [mine], input = 0) => {
    const e = { version: JF3, inputs, outputs: outputs.map(([v, l]) => ({ value: BigInt(v), locking: l ?? script })), locktime: 0 }
    COUNTER.push({ what: `counter: ${what}`, entry: hex(serializeEntry(e)), input, lock: hex(script), value: hex(le64(from)), expect })
  }
  tick('41 → 42', 41n, [[42]], true)
  tick('41 → 43 skips a value', 41n, [[43]], false)
  tick('41 → 41 does not advance', 41n, [[41]], false)
  tick('41 → 40 goes back', 41n, [[40]], false)
  tick('the successor another script', 41n, [[42, P2PKH]], false)
  tick('an extra output', 41n, [[42], [1, Uint8Array.of(0x51)]], false)
  for (let n = 0n; n < 5n; n++) tick(`the thread, ${n} → ${n + 1n}`, n, [[n + 1n]], true)
  tick('2^63 − 1 → 2^63', (1n << 63n) - 1n, [[1n << 63n]], null)
  tick('2^64 − 1 → 0', (1n << 64n) - 1n, [[0n]], null)
  tick('2^32 − 1 → 2^32', 0xffffffffn, [[1n << 32n]], true)
  tick('another input before it: the counter judged at input 1', 41n, [[42]], null, [another, mine], 1)
  tick('another input after it: the counter judged at input 0', 41n, [[42]], null, [mine, another], 0)
  withPhp(COUNTER)
  const { same } = await compare(COUNTER)
  const wrong = COUNTER.filter(c => c.expect !== null && c.php.accepted !== c.expect).map(c => c.what)
  ok(same === COUNTER.length, `the PHP judge's answer on every tick of verify-wired.php's counter (${same}/${COUNTER.length}: ${tally(COUNTER.map(c => kindOf(c.php)))})`)
  ok(wrong.length === 0, `and the verdicts verify-wired.php asserts: 41 → 42 and the thread of five accepted, the rest refused${wrong.length ? `: wrong ${wrong.join('; ')}` : ''}`)
}

// 4c. random ticks
const RANDOM = []
const edKeys = Array.from({ length: 3 }, () => { const k = generateKeyPairSync('ed25519'); return { priv: k.privateKey, pub: Uint8Array.from(k.publicKey.export({ format: 'der', type: 'spki' }).subarray(12)) } })
const VERSIONS = [() => versionBuild('JF', 2), () => versionBuild('JF', 1), () => versionBuild('JF', 4), () => versionBuild('SV', 1), () => versionBuild('BT', 1),
                  () => 103, () => 0, () => versionBuild('ZZ', 1), () => 0x00610000, () => 0x41000000, () => (versionBuild('JF', 3) | 0x80) >>> 0]
const KINDS = ['hash256', 'slice', 'hashes', 'ecdsa', 'ed25519', 'abort', 'random', 'true']
const plainWords = Object.keys(W).filter(w => !['BRANCH', '0BRANCH', '(?DO)', '(LOOP)', '(+LOOP)', 'LEAVE', 'CALL', 'EXECUTE', '(FRAME)', '(LOCAL@)', '(LOCAL!)', 'INVOKE', '(ABORT")', 'LIT8', 'LIT16', 'LIT32', 'LIT64', 'LITBIG', 'STR8', 'STR16', 'STR32'].includes(w) && W[w] !== undefined)
/** A random token for the 'random' locks, as verify-jf.mjs makes them: no loops, so every one ends */
const token = () => {
  const r = rnd()
  if (r < 0.2) return [small(int(0, 8))]
  if (r < 0.3) return num(int(0, 3000))
  if (r < 0.36) return push(rbytes(pick([0, 1, 8, 20, 32])))
  if (r < 0.40) return [W['0BRANCH'], int(0, 6), 0]
  if (r < 0.43) return [...num(1000), W.PREIMAGE]
  if (r < 0.45) return [W['(ABORT")'], 2, 0x6f, 0xff]
  if (r < 0.46) return [int(0, 255)]
  return [W[pick(plainWords)]]
}
/** Fields of a preimage that the lock does not change: [name, bytes, offset from the start, or from the end when negative] */
const FIELDS = [['version', 4, 0], ['hashPrevouts', 32, 4], ['hashSequence', 32, 36], ['the outpoint', 36, 68], ['the outpoint\'s index', 4, 100],
                ['the value', 8, -52], ['nSequence', 4, -44], ['the value and nSequence', 12, -52], ['hashOutputs', 32, -40], ['locktime', 4, -8], ['the sighash type', 4, -4]]
const DIGEST = { SHA256: H('sha256'), SHA1: H('sha1'), RIPEMD160: H('ripemd160'), HASH160: b => H('ripemd160')(H('sha256')(b)), HASH256: b => H('sha256')(H('sha256')(b)) }
const lit32 = n => [L.LIT32, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]
const u32le = n => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24]
/** The lock's declaration, VER and a version: VER JF 3 */
const declare = (v = versionBuild('JF', 3)) => [W.VER, ...u32le(v)]
/** A random lock's declaration: VER JF 3 mostly; now and then a version nothing here judges, four random bytes, or none */
const DECLARATIONS = [() => declare(versionBuild('JF', 2)), () => declare(versionBuild('JF', 4)), () => declare(versionBuild('SV', 1)),
                      () => declare(103), () => declare(0x62610003), () => [W.VER, ...rbytes(4)], () => []]
const declaration = () => chance(0.9) ? declare() : pick(DECLARATIONS)()
for (let t = 0; t < N_TICKS; t++) {
  const kind = pick(KINDS)
  const nIn = chance(0.6) ? 1 : int(2, 4)
  const version = chance(0.9) ? versionBuild('JF', 3) : pick(VERSIONS)()
  const outputs = Array.from({ length: int(1, 3) }, () => ({ value: ru64(), locking: rbytes(chance(0.1) ? int(253, 600) : int(1, 120)) }))
  const randomPushes = () => { const u = []; for (let k = int(1, 3); k > 0; k--) u.push(...pushAny(rbytes(pick([0, 1, 20, 32, 72, 100, 300])))); return u }
  const inputs = Array.from({ length: nIn }, () => ({ prevEntry: rbytes(32), index: ru32(), unlocking: Uint8Array.from(randomPushes()), sequence: ru32() }))
  const at = chance(0.04) ? nIn : int(0, nIn - 1)            // now and then an input that is not there
  const value = ru64()
  const entry = { version, inputs, outputs, locktime: 0 }
  // now and then a long lock, so that its scriptCode varint takes 3 bytes
  const pad = chance(0.25) ? [...push(rbytes(int(180, 255))), W['2DROP']] : []
  const decl = declaration()                                 // at the head of the lock, before anything else
  /** The judged input's preimage over a lock. It covers the lock, never an unlocking script. */
  const pre = lock => Uint8Array.from(preimage({ entry, inputIndex: Math.min(at, nIn - 1), scriptCode: lock, value }))
  /** 2DROP for each push of the unlocking script; now and then one too few, so two items are left */
  const dropsFor = u => Array(Math.max(0, countPushes(u) - (chance(0.06) ? 1 : 0))).fill(W['2DROP'])
  const extra = () => chance(0.05) ? push(rbytes(3)) : []      // one push too many
  let unlock, lock, alg = null
  if (kind === 'ecdsa' || kind === 'ed25519') {
    // the lock is made first, then the signature over the preimage that covers it
    const key = kind === 'ecdsa' ? pick(nodeKeys) : pick(edKeys)
    const pub = kind === 'ecdsa' ? (chance(0.5) ? key.pub33 : key.pub65) : key.pub
    const whole = kind === 'ed25519' && chance(0.5)           // Ed25519 over the whole preimage, or over its HASH256
    const verify = kind === 'ecdsa' ? (chance(0.8) ? 'CHECKSIG' : 'CHECKSIGVERIFY') : (chance(0.8) ? 'ED25519-CHECKSIG' : 'ED25519-CHECKSIGVERIFY')
    lock = Uint8Array.from([...decl, ...pad, ...push(pub), ...num(1000), W.PREIMAGE, ...(whole ? [] : [...num(3000), W.HASH256, ...num(3000), ...num(32)]),
                            W[verify], ...(verify.endsWith('VERIFY') ? [W.TRUE] : [])])
    const p = pre(lock), how = rnd()
    const other = Uint8Array.from(p).map((b, i) => i === p.length - 5 ? b ^ 1 : b)   // the preimage of another tick
    let sig = kind === 'ecdsa' ? nodeEcdsa(key, H('sha256')(how < 0.88 || how > 0.92 ? p : other))  // node hashes once more: HASH256
                               : Uint8Array.from(nodeSign(null, (m => whole ? m : DIGEST.HASH256(m))(how < 0.85 || how > 0.92 ? p : other), key.priv))
    if (kind === 'ecdsa' && how >= 0.75 && how < 0.85) { const [r, s] = parseDer(sig); sig = derOf(r, N - s) }      // high S: no LOW_S rule
    if (kind === 'ecdsa' && how >= 0.85 && how < 0.88) { const [r, s] = parseDer(sig); sig = der(Uint8Array.from([0, ...derNum(r)]), derNum(s)) }   // not strict DER
    if (how > 0.92) sig = sig.map((b, i) => i === 10 ? b ^ 1 : b)
    unlock = [...pushAny(sig), ...extra()]
  } else if (kind === 'hash256' || kind === 'hashes') {
    // the digest is pushed by the unlocking script: the lock cannot hold the hash of a preimage that covers the lock
    alg = kind === 'hash256' ? 'HASH256' : pick(['SHA256', 'SHA1', 'RIPEMD160', 'HASH160', 'HASH256'])
    const len = alg === 'SHA256' || alg === 'HASH256' ? 32 : 20
    lock = Uint8Array.from([...decl, ...pad, ...num(1000), W.PREIMAGE, ...num(3000), W[alg], ...num(3000), ...num(len), W['BYTES=']])
    unlock = [...pushAny(chance(0.85) ? DIGEST[alg](pre(lock)) : rbytes(len)), ...extra()]
  } else if (kind === 'slice') {
    // a field the lock does not change, read with SUBSTR and compared with the bytes the lock carries
    unlock = randomPushes()
    const drops = dropsFor(unlock), [, cnt, from] = pick(FIELDS)
    const build = (off, want) => Uint8Array.from([...decl, ...pad, ...drops, ...num(1000), W.PREIMAGE, ...lit32(off), ...num(cnt), ...num(3000), W.SUBSTR,
                                                  ...push(want), W['BYTES='], ])
    const p = pre(build(0, new Uint8Array(cnt)))               // the same length whatever the offset and bytes: lit32 and a fixed push
    const off = from >= 0 ? from : p.length + from
    const want = p.slice(off, off + cnt)
    if (chance(0.15)) want[int(0, cnt - 1)] ^= 1
    lock = build(off, want)
  } else {
    unlock = randomPushes()
    if (chance(0.05)) unlock.push(...num(5))                  // not byte pushes only
    const drops = dropsFor(unlock)
    if (kind === 'true') lock = Uint8Array.from([...decl, ...pad, ...drops, W.TRUE])
    else if (kind === 'abort')
      lock = Uint8Array.from([...decl, ...pad, ...drops, ...num(1000), W.PREIMAGE, W.NIP, ...num(int(100, 400)), W['>'], W['(ABORT")'], 4, 0xff, 0x6e, 0x6f, int(0, 255), W.TRUE])
    else { const body = chance(0.5) ? drops : []; for (let n = int(1, 20); n > 0; n--) body.push(...token()); lock = Uint8Array.from([...decl, ...pad, ...body]) }
  }
  if (at < nIn) inputs[at].unlocking = Uint8Array.from(unlock)
  RANDOM.push({ what: `random tick ${t} (${kind}${alg ? ` ${alg}` : ''}, ${nIn} input${nIn > 1 ? 's' : ''}, judged at ${at})`, kind, alg,
                entry: hex(serializeEntry(entry)), input: at, lock: hex(lock), value: hex(le64(value)) })
}
/** How many pushes a byte-push script holds (the lock drops each one's two cells) */
function countPushes(s) {
  let n = 0
  for (let p = 0; p < s.length; n++) {
    const op = s[p++]
    if (op <= 72) p += op
    else if (op === L.STR8) p += 1 + s[p]
    else if (op === L.STR16) p += 2 + (s[p] | (s[p + 1] << 8))
    else return n                                             // not a push: the tick is refused before the lock runs
  }
  return n
}
{
  withPhp(RANDOM)
  const { same } = await compare(RANDOM)
  ok(same === RANDOM.length, `the PHP judge's answer on every one of ${RANDOM.length} random ticks (seed ${SEED}): ${tally(RANDOM.map(c => kindOf(c.php)))}`)
  const accepted = KINDS.filter(k => RANDOM.some(c => c.kind === k && c.php.accepted))
  const algs = ['SHA256', 'SHA1', 'RIPEMD160', 'HASH160', 'HASH256'].filter(a => RANDOM.some(c => c.alg === a && c.php.accepted))
  ok(['hash256', 'slice', 'hashes', 'ecdsa', 'ed25519', 'true'].every(k => accepted.includes(k)) && algs.length === 5
     && RANDOM.some(c => c.php.accepted && parseEntry(unhex(c.entry)).inputs.length > 1 && c.input > 0)
     && RANDOM.some(c => c.php.accepted && unhex(c.lock).length >= 253),
     `accepted among them: every kind of lock (${accepted.join(', ')}), each hash (${algs.join(', ')}), a tick judged past its first input, and locks of 253 bytes and more`)
  const reasons = new Set(RANDOM.filter(c => c.php.error).map(c => Buffer.from(c.php.error, 'hex').toString('latin1').replace(/: .*$|[0-9]+/g, '').slice(0, 40)))
  console.log(`  - ${reasons.size} kinds of refusal among them, e.g. ${[...reasons].slice(0, 6).map(r => JSON.stringify(r)).join(', ')}`)
}

// 4d. crypto missing or broken: no verdict, never a refusal
console.log('\n── crypto missing or broken: no verdict, never a refusal ──')
{
  const ALL = [...TIP, ...COUNTER, ...RANDOM]
  const NAMES = ['sha256', 'sha1', 'ripemd160', 'ed25519Verify', 'ecdsaVerify']
  // every tick, with each function taken away, and with none at all
  for (const drop of [...NAMES.map(n => [n]), NAMES]) {
    const crypto = Object.fromEntries(Object.entries(jfCrypto).filter(([n]) => !drop.includes(n)))
    let sameVerdict = 0, noVerdict = 0
    const other = []
    for (const c of ALL) {
      const r = await normJs(judge, c, crypto)
      if (JSON.stringify(r) === JSON.stringify(c.php)) sameVerdict++
      else if (r.noVerdict === 'JfHostError' && !c.php.noVerdict) noVerdict++
      else other.push(c.what)
    }
    ok(other.length === 0 && noVerdict > 0, `without ${drop.length === NAMES.length ? 'any crypto' : drop[0]}: ${sameVerdict} ticks get the same verdict, ${noVerdict} no verdict (JfHostError), ${other.length} anything else`
       + (other.length ? `: ${other.slice(0, 3).join('; ')}` : ''))
  }
  // a function that fails, or is not one
  const accepted = k => ALL.find(c => c.kind === k && c.php.accepted)
  const ecdsaTick = accepted('ecdsa'), edTick = accepted('ed25519')
  const hashTick = alg => RANDOM.find(c => c.alg === alg && c.php.accepted)
  const broken = [
    ['ecdsaVerify throws', ecdsaTick, { ecdsaVerify: () => { throw new Error('no curve') } }],
    ['ecdsaVerify is not a function', ecdsaTick, { ecdsaVerify: 'yes' }],
    ['ed25519Verify throws', edTick, { ed25519Verify: () => { throw new Error('no curve') } }],
    ['ed25519Verify rejects its promise', edTick, { ed25519Verify: async () => { throw new Error('no curve') } }],
    ['sha256 throws', hashTick('SHA256') ?? accepted('hash256'), { sha256: () => { throw new Error('no hash') } }],
    ['sha1 gives 32 bytes', hashTick('SHA1'), { sha1: () => new Uint8Array(32) }],
    ['ripemd160 is async', hashTick('RIPEMD160') ?? hashTick('HASH160'), { ripemd160: async b => jfCrypto.ripemd160(b) }],
    ['crypto is null', accepted('true'), null],
  ]
  for (const [what, c, change] of broken) {
    if (!c) { ok(false, `${what}: no accepted tick of that kind in the corpus to try it on`); continue }
    const r = await normJs(judge, c, change === null ? null : { ...jfCrypto, ...change })
    ok(r.noVerdict === 'JfHostError', `${what}: no verdict, ${r.message ?? JSON.stringify(r)}`)
  }
  const t = accepted('true'), r = await normJs(judge, t, {})
  ok(r.accepted === true, 'a tick that needs no crypto is judged with none supplied: a host fault is raised only where a word needs it')
}

// 4e. bytes CovenantEntry::decode refuses: PHP's judging path decodes first, so it gives no verdict on them, and nor may this
console.log('\n── bytes that are not a covenant entry: refused before any verdict, as CovenantEntry::decode refuses them ──')
const DECODE = []
{
  // laid out by hand: serializeEntry refuses to write these shapes, which is the point
  const u32b = n => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24]
  const raw = (version, inputs, outputs) => Uint8Array.from([...u32b(version), ...varint(inputs.length),
    ...inputs.flatMap(i => [...i.prev, ...u32b(i.index), ...varint(i.unlocking.length), ...i.unlocking, ...u32b(i.seq)]),
    ...varint(outputs.length), ...outputs.flatMap(o => [...le64(o.value), ...varint(o.locking.length), ...o.locking]), 0, 0, 0, 0])
  const TRUE = Uint8Array.of(W.TRUE), JF3 = versionBuild('JF', 3)
  const signed = { prev: new Uint8Array(32).fill(0x11), index: 0, unlocking: Uint8Array.of(1, 1), seq: 1 }
  const bare = { ...signed, unlocking: new Uint8Array(0) }
  const kept = { value: 1n, locking: TRUE }, blank = { value: 1n, locking: new Uint8Array(0) }
  const add = (what, version, inputs, outputs, input = 0, lock = Uint8Array.from([...declare(), W.TRUE])) =>
    DECODE.push({ what, entry: hex(raw(version, inputs, outputs)), input, lock: hex(lock), value: hex(le64(0)) })
  add('one input, no unlocking script, a lock that accepts anything', JF3, [bare], [kept])
  add('an output with no locking script', JF3, [signed], [blank])
  add('input 1 has no unlocking script, input 0 judged', JF3, [signed, bare], [kept])
  add('output 1 has no locking script', JF3, [signed], [kept, blank])
  add('both: the input is refused first, in decode\'s order', JF3, [bare], [blank])
  add('JF revision 2 and no unlocking script: refused before the version is looked at', versionBuild('JF', 2), [bare], [kept])
  add('a legacy version and no locking script', 103, [signed], [blank])
  add('judged at an input that is not there', JF3, [bare], [kept], 3)
  withPhp(DECODE)
  const rows = []
  for (const c of DECODE) {
    const js = await normJs(judge, c), part = m => /^(?:input|output)/.exec(m ?? '')?.[0]
    rows.push({ c, js, same: c.php.thrown === 'CovenantEntryError' && js.thrown === 'CovenantEntryError' && part(c.php.message) === part(js.message) })
  }
  const parsed = DECODE.every(c => { try { parseEntry(unhex(c.entry)); return true } catch { return false } })
  for (const { c, js, same } of rows)
    ok(same && parsed, `${c.what}: PHP ${c.php.thrown ?? kindOf(c.php)}, JS ${js.thrown ?? kindOf(js)} (${js.message ?? ''})${same ? ', the same part refused' : ''}`)
}

// 4f. the lock's declaration: it names the engine, the tick names the same version, and VER is a lock's first instruction
console.log('\n── the lock\'s declaration: the version a lock is written for, and the engine that runs it ──')
const DECLARE = []
{
  const JF3 = versionBuild('JF', 3), tip = rbytes(32), utf8 = s => new TextEncoder().encode(s)
  /** A tick of one input, its unlocking script one push, and what the PHP judge must answer: accepted, refused, refused
   *  for naming another version than the lock declares (OTHER_VERSION), or no verdict */
  const add = (what, lock, expect, version = JF3, input = 0) => {
    const e = { version, locktime: 0, outputs: [{ value: 1n, locking: Uint8Array.of(W.TRUE) }],
                inputs: [{ prevEntry: tip, index: 0, unlocking: Uint8Array.of(1, 1), sequence: 1 }] }
    DECLARE.push({ what, expect, entry: hex(serializeEntry(e)), input, lock: hex(Uint8Array.from(lock)), value: hex(le64(0)) })
  }
  const body = [W['2DROP'], W.TRUE]
  /** a DEFS header of one function, ( -- x ), whose body is given */
  const defs1 = fn => [JF_RESERVED0, 1, 0, 1, 0, 0, fn.length, ...fn]
  add('VER JF 3, the tick naming JF 3: judged, and accepted', [...declare(), ...body], 'accepted')
  add('...the tick naming JF 2: refused, its script never run', [...declare(), ...body], 'another version', versionBuild('JF', 2))
  add('...the tick naming JF 4', [...declare(), ...body], 'another version', versionBuild('JF', 4))
  add('...the tick naming legacy 103', [...declare(), ...body], 'another version', 103)
  add('...the tick naming SV 1, judged at an input that is not there: refused before the input is looked at', [...declare(), ...body],
      'another version', versionBuild('SV', 1), 3)
  add('a lock with no declaration', body, 'no verdict')
  add('a lock of no bytes', [], 'no verdict')
  add('VER and three bytes, a lock of four', [W.VER, 3, 0, 0x4a], 'no verdict')
  add('VER JF 3 alone, a lock of five bytes: judged, and refused', declare(), 'refused')
  add('the four version bytes pushed, the lock starting with a push and not VER: no declaration',
      [4, ...u32le(JF3), W['2DROP'], W['2DROP'], W.TRUE], 'no verdict')
  add('VER JF 2, a version this host does not serve, the tick naming it too', [...declare(versionBuild('JF', 2)), ...body], 'no verdict', versionBuild('JF', 2))
  add('VER SV 1, a set that judges no ticks', [...declare(versionBuild('SV', 1)), ...body], 'no verdict', versionBuild('SV', 1))
  add('VER 103, a legacy version', [...declare(103), ...body], 'no verdict', 103)
  add('VER and a family in lowercase', [...declare(0x62610003), ...body], 'no verdict', 0x62610003)
  add('VER a second time, after the first instruction: refused', [...declare(), W['2DROP'], ...declare(), W.TRUE], 'refused')
  add('VER in a function: refused', [...declare(), ...defs1([...declare(), W.TRUE]), W['2DROP'], W.INVOKE, 0], 'refused')
  add('...the same function without it: accepted', [...declare(), ...defs1([W.TRUE]), W['2DROP'], W.INVOKE, 0], 'accepted')
  // pushes 1 and branches back to offset 0 until five items are held, then adds the three ones and drops the push
  add('a branch back to the declaration steps over it: a loop of three, then 3', [...declare(), small(1), W.DEPTH, small(5), W['<'],
      W['0BRANCH'], 3, 0, W.BRANCH, -15 & 0xff, 0xff, W['+'], W['+'], W.NIP, W.NIP], 'accepted')
  ok(VER === W.VER, `the byte the judge reads the declaration by is the JF table's VER, 0x${W.VER.toString(16)}`)
  withPhp(DECLARE)
  for (const c of DECLARE) {
    const js = await normJs(judge, c), same = JSON.stringify(js) === JSON.stringify(c.php)
    const right = c.expect === 'another version' ? c.php.accepted === false && c.php.error === hex(utf8(OTHER_VERSION))
                : c.expect === 'refused' ? c.php.accepted === false && c.php.error !== hex(utf8(OTHER_VERSION))
                : c.expect === 'accepted' ? c.php.accepted === true : c.php.noVerdict === 'VersionError'
    ok(same && right, `${c.what}: ${kindOf(c.php)}${c.php.error ? `, "${Buffer.from(c.php.error, 'hex').toString('latin1')}"` : c.php.message ? `, ${c.php.message}` : ''}`
       + (same ? '' : ` · JS ${JSON.stringify(js).slice(0, 100)}`))
  }
}

// ── 5. mutants ───────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── mutants: each file the judge loads, altered in a copy, must disagree with PHP or node somewhere ──')
const stripComments = text => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '')
/** The files a page loads to judge, from tools/thread.mjs, by their static imports */
function importGraph(dir, start) {
  const seen = new Set(), queue = [start]
  while (queue.length) {
    const f = queue.shift()
    if (seen.has(f)) continue
    seen.add(f)
    for (const m of stripComments(readFileSync(join(dir, f), 'utf8')).matchAll(/^\s*(?:import|export)\b[^'"]*?\bfrom\s*['"]\.\/([^'"]+)['"]/gm)) queue.push(m[1])
  }
  return [...seen]
}
/** What in these files a browser could not load: an import that is not a file beside it, or anything of node's or a host's */
function foreignIn(dir, files) {
  const foreign = /\b(require|process|Buffer|globalThis|window|document|importScripts|eval)\b|\bimport\s*\(|['"]node:/g
  const problems = []
  for (const f of files) {
    const code = stripComments(readFileSync(join(dir, f), 'utf8'))
    for (const m of code.matchAll(/\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm)) if (!/^\.\/[\w-]+\.mjs$/.test(m[1] ?? m[2])) problems.push(`${f} imports ${m[1] ?? m[2]}`)
    for (const m of code.matchAll(foreign)) problems.push(`${f} names ${m[0]}`)
  }
  return [...new Set(problems)]
}
const GRAPH = importGraph(HERE, 'thread.mjs')
{
  const MUTANTS = [
    ['preimage.mjs', 'field order: hashSequence before hashPrevouts', '    ...hashPrevouts,\n    ...hashSequence,', '    ...hashSequence,\n    ...hashPrevouts,'],
    ['preimage.mjs', 'field order: nSequence before the value', '    ...u64(value),\n    ...u32(input.sequence),', '    ...u32(input.sequence),\n    ...u64(value),'],
    ['preimage.mjs', 'value width: 4 bytes, not 8', '    ...u64(value),', '    ...u64(value).slice(0, 4),'],
    ['preimage.mjs', 'scriptCode length: one byte, not a varint', '...varint(scriptCode.length), ...scriptCode,', 'scriptCode.length & 0xff, ...scriptCode,'],
    ['preimage.mjs', 'the outpoint of input 0, whatever the input', '    ...outpointBytes(input),', '    ...outpointBytes(entry.inputs[0]),'],
    ['preimage.mjs', 'output values in hashOutputs: 4 bytes', 'const outputBytes = o => [...u64(o.value),', 'const outputBytes = o => [...u32(Number(o.value & 0xffffffffn)),'],
    ['thread.mjs', 'judge: input 0\'s unlocking script, whatever the input', 'unlocking: bytes(input.unlocking)', 'unlocking: bytes(entry.inputs[0].unlocking)'],
    ['thread.mjs', 'judge: the spent value left out of the preimage', 'scriptCode: prevLocking, value })', 'scriptCode: prevLocking, value: 0n })'],
    ['thread.mjs', 'judge: a verify that throws read as a failed check', 'if (host.fault) throw host.fault', 'if (false) throw host.fault'],
    ['thread.mjs', 'judge: bytes decode refuses judged anyway', '  isCovenantEntry(entry)\n', ''],
    ['thread.mjs', 'judge: the engine the tick names run, not the one its lock declares', 'const vm = interpreterFor(declared)', 'const vm = interpreterFor(entry.version)'],
    ['thread.mjs', 'judge: a tick naming another version than its lock declares, run anyway', '  if (entry.version !== declared) return', '  if (false) return'],
    ['thread.mjs', 'judge: a lock that does not start with VER read as declaring a version', '  if (lock.length < 5 || lock[0] !== VER) throw', '  if (false) throw'],
    ['dispatch.mjs', 'dispatch: every JF revision judged', "registerSet('JF', { name: 'InterpreterJF', verifyTick }, [3])", "registerSet('JF', { name: 'InterpreterJF', verifyTick }, [1, 2, 3, 4])"],
    ['sha1.mjs', 'SHA-1: a round constant', 'k = 0x6ed9eba1', 'k = 0x6ed9eba2'],
    ['sha1.mjs', 'SHA-1: the padding one byte short', 'len - whole + 9 <= 64', 'len - whole + 8 <= 64'],
    ['ripemd160.mjs', 'RIPEMD-160: one rotation', '  11, 14, 15, 12, 5, 8, 7, 9,', '  11, 14, 15, 12, 5, 8, 7, 8,'],
    ['ripemd160.mjs', 'RIPEMD-160: the length big-endian', 'tail[n - 8] = lo & 0xff;', 'tail[n - 1] = lo & 0xff;'],
    ['secp256k1.mjs', 'secp256k1: LOW_S required', '  if (!inRange(r) || !inRange(s)) return false', '  if (!inRange(r) || !inRange(s) || s > N / 2n) return false'],
    ['secp256k1.mjs', 'secp256k1: the key not checked to be on the curve', 'return y * y % P === curveY2(x) ? { x, y, z: 1n } : null', 'return { x, y, z: 1n }'],
    ['secp256k1.mjs', 'secp256k1: a compressed key\'s x not checked below p', '    x = num(pub, 1, 33)\n    if (x >= P) return null', '    x = num(pub, 1, 33)'],
    ['secp256k1.mjs', 'secp256k1: an uncompressed key\'s x and y not checked below p', '    if (x >= P || y >= P) return null', ''],
    ['secp256k1.mjs', 'secp256k1: a negative integer read as positive', '  if (b[i + 2] & 0x80) return null', '  if (false) return null'],
    ['secp256k1.mjs', 'secp256k1: a trailing byte allowed by default', 'digest32, allowTrailing = false)', 'digest32, allowTrailing = true)'],
    ['jf-crypto.mjs', 'Ed25519: the key and the message swapped', 'ed25519(sig, msg, pub)', 'ed25519(sig, pub, msg)'],
  ]
  const TICKS = [...TIP, ...COUNTER, ...RANDOM, ...DECLARE]
  const native = { sha256: H('sha256'), sha1: H('sha1'), ripemd160: H('ripemd160') }
  const HASHED = [...Array.from({ length: 301 }, (_, n) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff)), rbytes(65537)]
  for (const [k, [file, what, from, to]] of MUTANTS.entries()) {
    const dir = join(TMP, `mutant-${k}`)
    mkdirSync(dir)
    for (const f of GRAPH) copyFileSync(join(HERE, f), join(dir, f))
    const src = readFileSync(join(dir, file), 'utf8')
    if (!src.includes(from)) { ok(false, `${what}: the text to alter is not in ${file}, so the copy would be the original`); continue }
    writeFileSync(join(dir, file), src.replace(from, to))
    const load = f => import(pathToFileURL(join(dir, f)).href)
    const [m, p, sec, jc] = await Promise.all(['thread.mjs', 'preimage.mjs', 'secp256k1.mjs', 'jf-crypto.mjs'].map(load))
    const found = []
    const preDiff = PRE.filter(c => JSON.stringify(preJs(p.preimage, c)) !== JSON.stringify(c.php)).length
    if (preDiff) found.push(`${preDiff} of ${PRE.length} preimages`)
    const hashDiff = Object.keys(native).filter(h => HASHED.some(b => hex(jc.jfCrypto[h](b)) !== hex(native[h](b))))
    if (hashDiff.length) found.push(`${hashDiff.join(', ')} against node's`)
    const secDiff = SECP.filter(c => { try { return (c.trailing ? sec.verifyDigest(c.sig, c.pub, c.digest, true) : sec.verifyDigest(c.sig, c.pub, c.digest)) !== c.want } catch { return true } }).length
    if (secDiff) found.push(`${secDiff} of ${SECP.length} secp256k1 verdicts`)
    // a verify that throws: the original gives no verdict (4d); this copy must not
    if (file === 'thread.mjs' && from.includes('host.fault')) {
      const c = RANDOM.find(x => x.kind === 'ecdsa' && x.php.accepted)
      const r = await normJs(m.judge, c, { ...jfCrypto, ecdsaVerify: () => { throw new Error('no curve') } })
      if (r.noVerdict !== 'JfHostError') found.push(`a throwing ecdsaVerify gives ${kindOf(r)}`)
    }
    const { diffs } = await compare(TICKS, m.judge, undefined, 0)
    if (diffs.length) found.push(`${diffs.length} of ${TICKS.length} verdicts`)
    let judgedAnyway = 0
    for (const c of DECODE) if ((await normJs(m.judge, c)).thrown !== 'CovenantEntryError') judgedAnyway++
    if (judgedAnyway) found.push(`${judgedAnyway} of ${DECODE.length} answers on entries decode refuses`)
    ok(found.length > 0, `${what} (${file}): ${found.length ? `caught: ${found.join(', ')} differ` : 'NOT caught'}`)
  }
}

// ── 6. what a page loads ─────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── browser: what a page loads to judge ──')
{
  const problems = foreignIn(HERE, GRAPH)
  ok(problems.length === 0 && GRAPH.includes('jf-crypto.mjs') && GRAPH.includes('preimage.mjs'),
     `tools/thread.mjs and the ${GRAPH.length - 1} files it loads (${GRAPH.slice(1).join(', ')}) import only each other, and name nothing of node's or a host's`
     + (problems.length ? `: ${problems.join('; ')}` : ''))
  // the check itself, on a copy of preimage.mjs given back the import it had
  const dir = join(TMP, 'node-import')
  mkdirSync(dir)
  for (const f of GRAPH) copyFileSync(join(HERE, f), join(dir, f))
  writeFileSync(join(dir, 'preimage.mjs'), "import { createHash } from 'node:crypto'\n" + readFileSync(join(dir, 'preimage.mjs'), 'utf8'))
  const caught = foreignIn(dir, importGraph(dir, 'thread.mjs'))
  ok(caught.some(x => x.includes('node:crypto')), `and the check finds node:crypto put back into a copy of preimage.mjs: ${caught.join('; ')}`)
  if (!BROWSER) console.log('  - headless Chromium not run: pass --browser to run the judge in it')
  else await inBrowser([...TIP, ...COUNTER, ...DECLARE, ...RANDOM.slice(0, 300)])
}

/** Judge the cases in headless Chromium, from the files in tools/, and compare with PHP's answers. */
async function inBrowser(cases) {
  const page = join(TMP, 'page'), profile = join(TMP, 'profile')
  mkdirSync(page); mkdirSync(profile)
  writeFileSync(join(page, 'cases.mjs'), `export default ${JSON.stringify(cases.map(({ entry, input, lock, value }) => ({ entry, input, lock, value })))}\n`)
  const tool = f => pathToFileURL(join(HERE, f)).href
  writeFileSync(join(page, 'judge.html'), `<!doctype html><meta charset="utf-8"><title>judge</title><script type="module">
import cases from './cases.mjs'
import { judge } from '${tool('thread.mjs')}'
import { parseEntry } from '${tool('entry.mjs')}'
const unhex = h => Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16)), hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
window.done = (async () => {
  const out = [], t0 = performance.now()
  for (const c of cases) {
    try {
      const v = await judge(parseEntry(unhex(c.entry)), c.input, unhex(c.lock), unhex(c.value).reduceRight((v, x) => (v << 8n) | BigInt(x), 0n))
      out.push(v.stack ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.errorBytes) })
    } catch (e) {
      const name = e?.constructor?.name
      out.push(name === 'VersionError' || name === 'JfHostError' ? { noVerdict: name, message: e.message } : { thrown: name, message: e?.message })
    }
  }
  return { out, node: typeof process !== 'undefined', agent: navigator.userAgent, ms: performance.now() - t0 }
})()
</script>`)
  const port = await new Promise(res => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
  const browser = RUN.start('chromium', ['--headless', '--disable-gpu', '--no-sandbox', '--allow-file-access-from-files', `--user-data-dir=${profile}`,
                                         `--remote-debugging-port=${port}`, pathToFileURL(join(page, 'judge.html')).href], { stdio: 'ignore' })
  const gone = new Promise(res => browser.exitCode !== null ? res() : browser.once('exit', res))
  let result = null, why = null
  try {
    let target = null
    for (let k = 0; k < 150 && !target; k++) {
      try { target = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find(t => t.type === 'page' && t.url.endsWith('judge.html')) } catch {}
      if (!target) await new Promise(r => setTimeout(r, 100))
    }
    if (!target) throw new Error('Chromium did not open the page')
    const ws = new WebSocket(target.webSocketDebuggerUrl)
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('no DevTools connection')) })
    const reply = await new Promise((res, rej) => {
      const timer = setTimeout(() => rej(new Error('no answer in 300 s')), 300000)
      ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id === 1) { clearTimeout(timer); res(d) } }
      // the module may not have run yet when the page target appears: wait for window.done
      ws.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: {
        expression: 'new Promise(r => { const w = () => window.done ? r(window.done) : setTimeout(w, 50); w() })', awaitPromise: true, returnByValue: true } }))
    })
    ws.close()
    if (reply.result?.exceptionDetails) throw new Error(reply.result.exceptionDetails.exception?.description ?? 'the page threw')
    result = reply.result.result.value
  } catch (e) { why = e.message }
  RUN.stop(browser)
  await gone
  rmSync(profile, { recursive: true, force: true })
  if (!result) { ok(false, `headless Chromium: ${why}`); return }
  const same = result.out.filter((r, k) => JSON.stringify(r) === JSON.stringify(cases[k].php)).length
  ok(same === cases.length && !result.node, `headless Chromium (${result.agent.match(/Chrome\/[\d.]+/)?.[0] ?? result.agent}), no node in the page: `
     + `the PHP judge's answer on ${same} of ${cases.length} ticks, judged there in ${(result.ms / 1000).toFixed(2)} s`)
}

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the judge in JavaScript · against CovenantThread::judge]`)
process.exit(fail === 0 ? 0 : 1)
