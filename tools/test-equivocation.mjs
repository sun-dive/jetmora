// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
// ★★★ Try to fool the equivocation detector. A MALICIOUS log does not run our code, so this one does
// not either: it builds trees in memory and signs whatever it likes.
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import * as M from './merkle.mjs'
import { checkSameSize, checkConsistency, checkAuthor, parseHead, checkForkClaim } from './equivocation.mjs'
import { createHash } from 'node:crypto'
const hash256 = b => [...createHash('sha256').update(createHash('sha256').update(Buffer.from(b)).digest()).digest()]

const op = generateKeyPairSync('ed25519')
const pk = [...op.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const sign = m => [...nodeSign(null, Buffer.from(m), op.privateKey)]
const u64 = n => { const o = new Array(8).fill(0); let v = BigInt(n)
  for (let i = 7; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n } return o }
/* ⚠ 122 bytes since 25 Aug: `log_id` sits between the version and the tree size (spec §5.2).
   ★ Default LOG_A, because almost every case here is about ONE history — the branch cases pass
   LOG_B explicitly, and the undeclared case passes zeroes. */
const LOG_A = new Array(32).fill(0xa1)
const LOG_B = new Array(32).fill(0xb2)
const head = (size, root, ts = 1756000000, logId = LOG_A) =>
  [1, ...logId, ...u64(size), ...root, ...u64(ts), ...new Array(32).fill(0), ...u64(0), 0]
const E = (n, tag = 'a') => Array.from({ length: n }, (_, i) => [...Buffer.from(`${tag}-${i}`)])

let pass = 0, fail = 0
const t = (label, got, want) => {
  const ok = got.equivocated === want
  console.log(`  ${ok ? 'ok  ' : '⚠ FAIL'}  ${label.padEnd(46)} ${got.equivocated ? 'PROVEN: ' + got.form : (got.suspicious ? 'suspicious' : 'clean')}`)
  if (!ok) console.log(`          wanted ${want}, got ${got.equivocated} — ${got.reason ?? got.statement}`)
  ok ? pass++ : fail++
}

console.log('\n  ═══ CAN THE DETECTOR BE FOOLED? ═══\n')
console.log('  ── an HONEST log must never be convicted ──\n')
const honest = E(20)
const h5 = head(5, M.root(honest.slice(0,5))), h20 = head(20, M.root(honest))
t('honest: same head twice', checkSameSize(h5, sign(h5), h5, sign(h5), pk), false)
t('honest: growing, with a valid proof',
  checkConsistency(h5, sign(h5), h20, sign(h20), pk, M.consistencyProof(5, honest)), false)
t('honest: log offline, no proof offered',
  checkConsistency(h5, sign(h5), h20, sign(h20), pk, null), false)
const other = generateKeyPairSync('ed25519')
const opk = [...other.publicKey.export({ format:'der', type:'spki' }).subarray(-32)]
const hx = head(5, M.root(E(5,'x')))
t('someone forges a head in my name', checkSameSize(h5, sign(h5), hx, sign(hx), opk), false)

console.log('\n  ── a CHEATING log must be convicted ──\n')
// form 1 — the obvious one
const fake5 = head(5, M.root(E(5, 'b')))
t('form 1: two roots at one size', checkSameSize(h5, sign(h5), fake5, sign(fake5), pk), true)
// form 2 — ★★ the clever operator avoids form 1 entirely
const branchA = E(20), branchB = [...E(5, 'b'), ...E(15).slice(5)]
const hA5 = head(5, M.root(branchA.slice(0,5))), hB20 = head(20, M.root(branchB))
t('form 2: history that is not a prefix',
  checkConsistency(hA5, sign(hA5), hB20, sign(hB20), pk, M.consistencyProof(5, branchB)), true)
// ★★★ and the cleverest: offer a proof from a DIFFERENT, genuine pair of trees
t('form 2: proof borrowed from another tree',
  checkConsistency(hA5, sign(hA5), hB20, sign(hB20), pk, M.consistencyProof(5, honest)), true)

console.log('\n  ── an AUTHOR convicting themselves (spec §8/§4b.5) ──\n')
const au = generateKeyPairSync('ed25519')
const apk = [...au.publicKey.export({ format:'der', type:'spki' }).subarray(-32)]
const asign = m => [...nodeSign(null, Buffer.from(m), au.privateKey)]
const entry = (seq, tag) => [...u64(seq), ...Buffer.from(tag)]
const seqOf = e => Number(BigInt('0x' + Buffer.from(e.slice(0,8)).toString('hex')))
const e5a = entry(5, 'i-won'), e5b = entry(5, 'no-i-won'), e6 = entry(6, 'next')
t('author advancing normally', checkAuthor(e5a, asign(e5a), e6, asign(e6), apk, seqOf), false)
t('author signs the same entry twice', checkAuthor(e5a, asign(e5a), e5a, asign(e5a), apk, seqOf), false)
t('author REWINDS — two entries at seq 5', checkAuthor(e5a, asign(e5a), e5b, asign(e5b), apk, seqOf), true)
t('someone else signed it, not the author', checkAuthor(e5a, sign(e5a), e5b, sign(e5b), apk, seqOf), false)


// ════ ★★★ BRANCHES — the cases the detector could not previously EXPRESS ════════════════════════
// ⚠⚠ A key is not a history. One operator key runs many branches, so before 25 Aug two heads from two
//    legitimate branches looked EXACTLY like a lie. A detector that convicts every fork is worse than
//    none, because it makes every accusation worthless (§4d.2).
console.log('\n  ── a FORK must not be convicted, and a FAKE fork must not escape ──\n')

const bA = head(5, M.root(E(5, 'a')), 1756000000, LOG_A)
const bB = head(5, M.root(E(5, 'b')), 1756000000, LOG_B)
t('two branches, same size, different roots', checkSameSize(bA, sign(bA), bB, sign(bB), pk), false)

const undeclared = head(5, M.root(E(5, 'b')), 1756000000, new Array(32).fill(0))
t('one head declares NO log id', checkSameSize(bA, sign(bA), undeclared, sign(undeclared), pk), false)

/* ★★★ AND NOW THE ESCAPE HATCH ITSELF. §4bis.4: a fork must be declared AT OR BEFORE the divergence
   and never claimed afterwards — or an operator signs two histories, is caught, and says "that was a
   fork." It is refused only because an anchor cannot be backdated. */
console.log('\n  ── the fork CLAIM, which is where a liar hides ──\n')
const genesis = new Array(32).fill(0x11), branchId = new Array(32).fill(0x22)
const realLogId = hash256([...genesis, ...branchId])
const realB = head(5, M.root(E(5, 'b')), 1756000000, realLogId)

const f = (label, got, want) => {
  const ok = got.verdict === want
  console.log(`  ${ok ? 'ok  ' : '⚠ FAIL'}  ${label.padEnd(46)} ${got.verdict}`)
  if (!ok) console.log(`          wanted ${want}, got ${got.verdict} — ${got.reason}`)
  ok ? pass++ : fail++
}
f('declared BEFORE the divergence ⇒ a real fork',
  checkForkClaim(bA, realB, { genesis, branch: branchId }, 3, 5), 'fork')
f('★★★ declared AFTER ⇒ a rewrite, and convicted',
  checkForkClaim(bA, realB, { genesis, branch: branchId }, 9, 5), 'refuted')
f('no anchor offered ⇒ unproven, NEVER disproven',
  checkForkClaim(bA, realB, { genesis, branch: branchId }, null, 5), 'unproven')
f('the branch pointed at is not these heads\'',
  checkForkClaim(bA, bB, { genesis, branch: branchId }, 3, 5), 'refuted')
f('same log id ⇒ not a fork question at all',
  checkForkClaim(bA, bA, { genesis, branch: branchId }, 3, 5), 'not-a-fork')

console.log(`\n  ${pass} correct, ${fail} wrong\n`)
if (fail) process.exitCode = 1
