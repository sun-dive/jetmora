// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ FORK A LOG — replicate it to yourself. YOU NEED NOBODY'S PERMISSION.
//
//   GENESIS=<txid> MINE=<your address> npx tsx covenant/fork.mts
//   …then --broadcast, with FORKER_WIF set IN YOUR OWN SHELL.
//
// ⚠⚠ THE HOLDER OF THE LOG DOES NOT SIGN THIS AND CANNOT STOP IT. Their copy comes back untouched —
//    same state, same satoshis — because a fork COPIES rather than takes.
//
// ★ What it costs you: the miner's fee, and the royalties. **The royalties are the point.** The
//   creator is paid, and so is the lineage you are joining. Nobody has to be trusted to send it, and
//   nobody can decide not to: the transaction is INVALID without those outputs.
import { PrivateKey, Transaction, P2PKH, Hash, Utils, UnlockingScript,
         TransactionSignature, Spend }
  from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { pushData } from '../../grafverse/mint/src/pushtx.ts'
import { buildAnchorLock, ANCHOR_SCOPE, anchorUnlock } from './anchorFrame.mts'
import { decodeState } from './decodeState.mts'

const WOC = 'https://api.whatsonchain.com/v1/bsv/main'
const FEE_PER_KB = 100
const LIVE = process.argv.includes('--broadcast')
const hx = (b: any) => Buffer.from(b).toString('hex')
const u64le = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return [...b] }
const u32le = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return [...b] }
const die = (m: string) => { console.error('\n  ⚠ ' + m + '\n'); process.exit(1) }
const NUM = (n: number): any => {
  if (n === 0) return { op: 0 }
  if (n >= 1 && n <= 16) return { op: 0x50 + n }
  const b: number[] = []; let v = Math.abs(n)
  while (v > 0) { b.push(v & 0xff); v >>>= 8 }
  if (b[b.length-1] & 0x80) b.push(n < 0 ? 0x80 : 0)
  else if (n < 0) b[b.length-1] |= 0x80
  return pushData(b)
}
function toHash160(v: string, what: string): number[] {
  const t = (v ?? '').trim()
  if (!t) die(`${what} is required — an ADDRESS, never a private key`)
  if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,}$/.test(t)) {
    die(`⚠⚠ ${what} looks like a PRIVATE KEY. This wants the ADDRESS. Nothing was used.`)
  }
  if (/^[0-9a-fA-F]{40}$/.test(t)) return [...Buffer.from(t, 'hex')]
  try {
    const d: any = Utils.fromBase58Check(t)
    const h = Array.isArray(d.data) ? d.data : [...d.data]
    if (h.length !== 20) throw new Error('wrong length')
    return h
  } catch { die(`${what}: not a valid address`); return [] }
}

const mine = toHash160(process.env.MINE!, 'MINE')
const payTo = process.env.PAYTO ? toHash160(process.env.PAYTO, 'PAYTO') : mine
const wif = process.env.FORKER_WIF
if (LIVE && !wif) die('--broadcast needs FORKER_WIF set in your own shell. It is never asked for.')
const priv = wif ? PrivateKey.fromWif(wif) : PrivateKey.fromRandom()

const woc = async (p: string) => {
  const r = await fetch(WOC + p); if (!r.ok) throw new Error(`WoC ${r.status} on ${p}`); return r.json()
}
const rawTx = async (t: string) => Transaction.fromHex(await (await fetch(`${WOC}/tx/${t}/hex`)).text())

console.log('\n  ═══ FORK — replicate this log to yourself ═══' + (LIVE ? '  ⚠ LIVE' : '  · dry run'))

/* ── ★ WALK TO THE TIP. The unspent one is the current state (the computation walk). ────────── */
/* ⚠ PARENT_HEX is the OFFLINE path — a raw transaction handed straight in, so the whole tool can be
   exercised without a chain. ⇒ Used to test this BEFORE it matters, rather than discovering a bug
   with an audience watching. */
let parentTx: any, txid: string, vout = 0
if (process.env.PARENT_HEX) {
  const { readFileSync, existsSync } = await import('node:fs')
  const h = existsSync(process.env.PARENT_HEX)
    ? readFileSync(process.env.PARENT_HEX, 'utf8').trim() : process.env.PARENT_HEX.trim()
  parentTx = Transaction.fromHex(h); txid = parentTx.id('hex')
  console.log(`  ⚠ OFFLINE — parent supplied directly, no walk  ${txid.slice(0, 16)}…:0`)
} else {
  const start = process.env.GENESIS ?? die('GENESIS=<the mint txid> is required')
  txid = start as string
  let hops = 0
  for (;;) {
    const r = await fetch(`${WOC}/tx/${txid}/out/${vout}/spent`)
    if (r.status === 404) break
    if (!r.ok) die(`WhatsOnChain ${r.status} while walking from ${txid}`)
    const s: any = await r.json(); txid = s.txid; vout = 0; hops++
    if (hops > 5000) die('walk did not terminate')
  }
  console.log(`  walked ${hops} hop${hops === 1 ? '' : 's'} to the tip  ${txid.slice(0, 16)}…:${vout}`)
  parentTx = await rawTx(txid)
}
const parentOut = parentTx.outputs[vout]
const st = decodeState(parentOut.lockingScript.toBinary())
if (!st) die('that output is not a jetmora anchor covenant')
if (!st.forkable) die('⚠⚠ this log was minted NON-FORKABLE. It cannot be replicated, ever.')

const N = st.payees.length, OWNERS = st.owners.length
console.log(`  depth ${st.depth} · ${st.treesize.toLocaleString()} entries · royalty ${st.royalty} sat` +
            ` · ${OWNERS}-of-${OWNERS} · N=${N}`)

/* ── the child: depth + 1, a branch id derived from the outpoint we are consuming ───────────── */
const childBranch = [...Hash.hash256([...Buffer.from(txid, 'hex').reverse(), ...u32le(vout)])]
const childState: any = {
  genesis: st.genesis, branch: childBranch, depth: st.depth + 1, treesize: st.treesize,
  royalty: st.royalty, forkable: st.forkable, leafcovers: st.leafcovers,
  ...Object.fromEntries(Array.from({ length: OWNERS }, (_, i) => ['owner' + 'abcd'[i], mine])),
  ...Object.fromEntries([payTo, ...st.payees.slice(0, N - 1)]
    .map((h, i) => ['p' + 'abcdefgh'[i], h])),
}
const mk = (s: any) => buildAnchorLock({ levels: N, owners: OWNERS, creator: st.creator, state: s })

/* ── funding ───────────────────────────────────────────────────────────────────────────────── */
const addr = priv.toPublicKey().toAddress()
let fundTx: any, fVout = 0
if (LIVE) {
  const u: any[] = await woc(`/address/${addr}/unspent`)
  if (!u.length) die(`no funds at ${addr} — a fork costs about 500 sat plus the royalties`)
  const p = u.sort((a, b) => b.value - a.value)[0]
  fundTx = await rawTx(p.tx_hash); fVout = p.tx_pos
} else {
  fundTx = new Transaction()
  fundTx.addOutput({ lockingScript: new P2PKH().lock(priv.toPublicKey().toHash()), satoshis: 50_000 })
}

const tx = new Transaction()
tx.addInput({ sourceTransaction: parentTx, sourceOutputIndex: vout, sequence: 0xffffffff })
tx.addInput({ sourceTransaction: fundTx, sourceOutputIndex: fVout,
              unlockingScriptTemplate: new P2PKH().unlock(priv), sequence: 0xffffffff })
tx.addOutput({ lockingScript: parentOut.lockingScript, satoshis: parentOut.satoshis })  // ★ untouched
tx.addOutput({ lockingScript: mk(childState), satoshis: 1 })                            // the replica
tx.addOutput({ lockingScript: new P2PKH().lock(st.creator), satoshis: st.royalty })      // ★ the creator
for (const p of st.payees) {
  tx.addOutput({ lockingScript: new P2PKH().lock(p), satoshis: st.royalty })             // the lineage
}
const change = new P2PKH().lock(priv.toPublicKey().toHash())
const fundSats = (fundTx.outputs[fVout] as any).satoshis
const outSoFar = parentOut.satoshis + 1 + st.royalty * (1 + N)
tx.addOutput({ lockingScript: change, satoshis: 1 })                                     // sized below

/* size it, then set the change, then build the unlocking script over the final outputs */
const est = 10 + (36 + 1500 + 4) + (36 + 148 + 4) +
            tx.outputs.reduce((s: number, o: any) => s + 8 + 3 + o.lockingScript.toBinary().length, 0)
const fee = Math.ceil(est / 1000 * FEE_PER_KB)
const changeSats = fundSats - (1 + st.royalty * (1 + N)) - fee
if (changeSats < 1) die(`not enough funds: need about ${1 + st.royalty*(1+N) + fee} sat, have ${fundSats}`)
;(tx.outputs[tx.outputs.length - 1] as any).satoshis = changeSats

const spenderOutputs = [...u64le(changeSats), change.toBinary().length, ...change.toBinary()]
const preimage = TransactionSignature.format({
  sourceTXID: txid, sourceOutputIndex: vout, sourceSatoshis: parentOut.satoshis,
  transactionVersion: tx.version, otherInputs: [tx.inputs[1]], inputIndex: 0, outputs: tx.outputs,
  inputSequence: 0xffffffff, subscript: parentOut.lockingScript, lockTime: tx.lockTime,
  scope: ANCHOR_SCOPE,
})
/* ⚠ A FORK NEEDS NO OWNER SIGNATURE. These are the FORKER's own, and the covenant accepts them
   because on a fork it checks nothing — `authOk OR forking`. */
const sig = (() => { const r = priv.sign(Hash.sha256(preimage))
  return [...new TransactionSignature(r.r, r.s, ANCHOR_SCOPE).toChecksigFormat()] })()
const pubB = [...(priv.toPublicKey().encode(true) as number[])]
tx.inputs[0].unlockingScript = new UnlockingScript([
  ...Array.from({ length: OWNERS }, () => [pushData(sig), pushData(pubB)]).flat(),
  ...Array.from({ length: OWNERS }, () => pushData(mine)),
  pushData(payTo), NUM(st.royalty), NUM(2), NUM(st.treesize),
  pushData(spenderOutputs), pushData(u64le(parentOut.satoshis)), pushData([...preimage]),
])
await tx.sign()

/* ── ⚠ VALIDATE IT LOCALLY BEFORE ASKING A NODE ────────────────────────────────────────────── */
let ok = false, why = ''
try {
  ok = new Spend({
    sourceTXID: txid, sourceOutputIndex: vout, sourceSatoshis: parentOut.satoshis,
    lockingScript: parentOut.lockingScript, transactionVersion: tx.version,
    otherInputs: [tx.inputs[1]], outputs: tx.outputs, inputIndex: 0,
    unlockingScript: tx.inputs[0].unlockingScript!, inputSequence: 0xffffffff,
    lockTime: tx.lockTime, verifyFlags: ['UTXO_AFTER_CHRONICLE'],
  }).validate()
} catch (e: any) { why = (e.message ?? String(e)).slice(0, 120) }

const raw = tx.toHex(), bytes = raw.length / 2
const line = (k: string, v: any, n = '') => console.log(`  ${k.padEnd(13)} ${String(v).padEnd(30)} ${n}`)
console.log('\n  ── what this transaction does ──\n')
line('out0', 'the log, UNTOUCHED', `${parentOut.satoshis} sat — the holder loses nothing`)
line('out1', `YOUR replica, depth ${childState.depth}`, 'you control it, nobody else')
line('out2', `${st.royalty} sat → the CREATOR`, '★ they cannot be cut out. Ever.')
for (let k = 0; k < N; k++) line(`out${3+k}`, `${st.royalty} sat → ${hx(st.payees[k]).slice(0,12)}…`,
  k === 0 ? 'the holder you forked from' : `lineage, tier ${k+1}`)
console.log()
line('size', bytes + ' B', '')
line('you pay', `${fee + st.royalty * (1 + N)} sat`, `fee ${fee} + royalties ${st.royalty*(1+N)}`)
line('script check', ok ? '✓ VALID' : '⚠ INVALID', why)
line('txid', tx.id('hex'), '')

if (!ok) die('the covenant refused this spend locally. Nothing was broadcast.')
if (!LIVE) {
  console.log('\n  ⇒ DRY RUN. Nothing was broadcast. Add --broadcast with FORKER_WIF set.\n')
  process.exit(0)
}
const r = await fetch(`${WOC}/tx/raw`, { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ txhex: raw }) })
const body = await r.text()
if (!r.ok) die(`broadcast refused: ${body}`)
console.log(`\n  ★★★ FORKED — the creator has been paid, and nobody could stop it.`)
console.log(`     https://whatsonchain.com/tx/${tx.id('hex')}\n`)
