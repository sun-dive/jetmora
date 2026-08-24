// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ TEST: PORTABLE STATE DEFEATS A CENSORING OPERATOR — spec §4b, §4a.1.
//
// ⚠ This is the most specified and least exercised thing in the design. If it does not work, §4a.1's
//   fix is decorative and §1 is rebuilt with a new lever: an operator who refuses your tick freezes
//   your covenant forever.
//
// Two logs. A takes some entries, publishes a head, then REFUSES. The covenant continues on B.
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { serializeEntry, entryHash } from './entry.mjs'
import * as M from './merkle.mjs'

const A = process.env.LOG_A ?? 'http://127.0.0.1:8787/log.php'
const B = process.env.LOG_B ?? 'http://127.0.0.1:8788/log.php'
const hex = b => Buffer.from(b).toString('hex')
const unhex = h => [...Buffer.from(h, 'hex')]
const sha = b => [...createHash('sha256').update(Buffer.from(b)).digest()]
const call = async (base, p, b) => { const r = await fetch(base + p, b ? { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) } : {})
  return { status: r.status, body: await r.json() } }

const author = generateKeyPairSync('ed25519')
const apk = [...author.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const asign = m => [...nodeSign(null, Buffer.from(m), author.privateKey)]

const gf = { source_hash: hex(sha(Buffer.from('a covenant'))), script: hex([0x51, 0x52, 0x93]),
             state: hex([0x00]), authorised: [hex(apk)] }

console.log('\n  ═══ PORTABLE STATE — does a covenant survive a hostile log? ═══\n')

// ── log A takes three entries ────────────────────────────────────────────────────────────────
const ga = await call(A, '?op=register', gf)
const genesis = ga.body.genesis
console.log(`  genesis         ${genesis.slice(0, 24)}…  (identity travels; it is not log A's)`)

let prevHash = new Array(32).fill(0)
const entries = []
for (let i = 0; i < 3; i++) {
  const e = { version: 103, inputs: [{ prevEntry: prevHash, index: 0, unlocking: [], sequence: i }],
              outputs: [{ value: BigInt(i), locking: [0x51, i] }], locktime: 0 }
  const bytes = serializeEntry(e)
  const r = await call(A, '?op=append', { genesis, entry: hex(bytes), pubkey: hex(apk), signature: hex(asign(bytes)) })
  entries.push({ seq: r.body.seq, bytes, e }); prevHash = entryHash(e)
}
console.log(`  log A           ${entries.length} entries appended`)

// ── A publishes a head. ⚠ Without it there is nothing to port AGAINST. ──────────────────────
const opA = generateKeyPairSync('ed25519')
const opApk = [...opA.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const infoA = (await call(A, '?op=info')).body
// build the head the same way the operator would (89+1 bytes, spec §5.2)
const u64 = n => { const o = new Array(8).fill(0); let v = BigInt(n)
  for (let i = 7; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n } return o }
const head = [1, ...u64(infoA.size), ...unhex(infoA.root), ...u64(Math.floor(Date.now()/1000)),
              ...new Array(32).fill(0), ...u64(0), 0]
const headSig = [...nodeSign(null, Buffer.from(head), opA.privateKey)]
console.log(`  log A head      size ${infoA.size}, signed by the operator (${head.length} bytes)`)

// ── ⚠ AND NOW A REFUSES. A hostile operator simply stops appending. ─────────────────────────
console.log(`\n  ⚠ log A now REFUSES to append anything further — the covenant is frozen there\n`)

// ── the covenant continues on B ──────────────────────────────────────────────────────────────
const last = entries[entries.length - 1]
const proof = (await call(A, `?op=inclusion&leaf=${last.seq}&size=${infoA.size}`)).body

const next = { version: 103, inputs: [{ prevEntry: entryHash(last.e), index: 0, unlocking: [], sequence: 3 }],
               outputs: [{ value: 99n, locking: [0x51, 0x63] }], locktime: 0 }
const nextBytes = serializeEntry(next)

const port = await call(B, '?op=port', {
  genesis_fields: gf,
  entry: hex(last.bytes),                 // ⚠ the entry being ported IS the last state A witnessed
  sequence: last.seq,
  source_pubkey: hex(opApk), source_head: hex(head), source_head_sig: hex(headSig),
  inclusion_proof: proof.proof,
  author_pubkey: hex(apk), author_sig: hex(asign(last.bytes)),
})
console.log(`  port to log B   ${port.status === 201 ? 'ACCEPTED' : 'REFUSED — ' + JSON.stringify(port.body)}`)
if (port.status === 201) {
  console.log(`                  seq ${port.body.seq} · ${port.body.note}`)
  const cont = await call(B, '?op=append', { genesis: port.body.genesis, entry: hex(nextBytes),
                                             pubkey: hex(apk), signature: hex(asign(nextBytes)) })
  console.log(`  continue on B   ${cont.status === 201 ? 'ACCEPTED at seq ' + cont.body.seq : 'REFUSED ' + JSON.stringify(cont.body)}`)
  console.log(`\n  ⇒ the covenant survived a hostile operator.\n`)
}

// ── ⚠⚠ AND THE NEGATIVES — a port that should NOT be accepted ────────────────────────────────
console.log(`  ── what log B must refuse ──\n`)
const bad = async (label, patch) => {
  const base = { genesis_fields: gf, entry: hex(last.bytes), sequence: last.seq,
                 source_pubkey: hex(opApk), source_head: hex(head), source_head_sig: hex(headSig),
                 inclusion_proof: proof.proof, author_pubkey: hex(apk), author_sig: hex(asign(last.bytes)) }
  const r = await call(B, '?op=port', { ...base, ...patch })
  console.log(`  ${label.padEnd(34)} ${r.status === 201 ? '⚠ ACCEPTED' : 'refused (' + r.status + ')'}`)
}
const stranger = generateKeyPairSync('ed25519')
const spk = [...stranger.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
await bad('a stranger ports my covenant', { author_pubkey: hex(spk),
  author_sig: hex([...nodeSign(null, Buffer.from(last.bytes), stranger.privateKey)]) })
await bad('forged source head signature', { source_head_sig: hex(new Array(64).fill(7)) })
await bad('inclusion proof for another leaf', { inclusion_proof: (await call(A, `?op=inclusion&leaf=0&size=${infoA.size}`)).body.proof })
await bad('entry that was never in log A', { entry: hex(serializeEntry(next)) })
