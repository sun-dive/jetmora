// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
// ★★★ Try to fool the equivocation detector. A MALICIOUS log does not run our code, so this one does
// not either: it builds trees in memory and signs whatever it likes.
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import * as M from './merkle.mjs'
import { checkSameSize, checkConsistency, checkAuthor, parseHead } from './equivocation.mjs'

const op = generateKeyPairSync('ed25519')
const pk = [...op.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const sign = m => [...nodeSign(null, Buffer.from(m), op.privateKey)]
const u64 = n => { const o = new Array(8).fill(0); let v = BigInt(n)
  for (let i = 7; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n } return o }
const head = (size, root, ts = 1756000000) =>
  [1, ...u64(size), ...root, ...u64(ts), ...new Array(32).fill(0), ...u64(0), 0]
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

console.log(`\n  ${pass} correct, ${fail} wrong\n`)
if (fail) process.exitCode = 1
