// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// BROADCAST AN ANCHOR — spec §6.
//
// ⚠⚠ THE KEY IS NEVER ASKED FOR, NEVER STORED, NEVER PASSED AS AN ARGUMENT.
//    Set it in your own shell:  read -s JETMORA_WIF   (arguments appear in `ps`; env does not.)
//
// ⚠⚠ DRY RUN BY DEFAULT. Nothing is broadcast without `--send`, and even then the fee rate is checked
//    against the project's policy first and the transaction is refused if it is wrong.
//
//   node tools/broadcast.mjs address            → the address to fund
//   node tools/broadcast.mjs status             → what that address holds
//   node tools/broadcast.mjs anchor <root> <n>  → build and show; add --send to broadcast
import { readFileSync, existsSync, writeFileSync } from 'node:fs'
import { anchorLock, pushDropUnlock, decodeAnchor, FEE_PER_KB } from './anchor.mjs'

const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { PrivateKey, P2PKH, Transaction, SatoshisPerKilobyte, Script } = await import(SDK)
const WOC = 'https://api.whatsonchain.com/v1/bsv/main'
const STATE = new URL('../server/data/anchors.json', import.meta.url)

const wif = process.env.JETMORA_WIF
if (!wif) {
  console.error(`\n⚠ JETMORA_WIF is not set. Set it in your own shell — never on the command line:\n` +
                `    read -s JETMORA_WIF && export JETMORA_WIF\n`)
  process.exit(1)
}
let priv
try { priv = PrivateKey.fromWif(wif) } catch { console.error('⚠ JETMORA_WIF is not a valid WIF'); process.exit(1) }
const pub = priv.toPublicKey()
const address = pub.toAddress()

const woc = async p => { const r = await fetch(WOC + p); if (!r.ok) throw new Error(`WoC ${r.status} on ${p}`); return r.json() }
const utxos = async () => woc(`/address/${address}/unspent`)
const hexOf = b => Buffer.from(b).toString('hex')
const load = () => existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : { anchors: [] }
const save = s => writeFileSync(STATE, JSON.stringify(s, null, 2) + '\n')

const [cmd, ...rest] = process.argv.slice(2)
const send = rest.includes('--send')

if (cmd === 'address') {
  console.log(`\n  fund this address:  ${address}`)
  console.log(`  ⚠ a few thousand satoshis is plenty — an anchor costs ~41 sat\n`)
  process.exit(0)
}

if (cmd === 'status') {
  const u = await utxos()
  const total = u.reduce((s, x) => s + x.value, 0)
  console.log(`\n  ${address}`)
  console.log(`  ${u.length} utxo${u.length === 1 ? '' : 's'}, ${total} sat total`)
  for (const x of u.slice(0, 8)) console.log(`    ${x.tx_hash.slice(0,20)}…:${x.tx_pos}  ${x.value} sat`)
  const st = load()
  console.log(`  anchors so far: ${st.anchors.length}` + (st.anchors.length ? `  last ${st.anchors.at(-1).txid.slice(0,20)}…` : ''))
  console.log()
  process.exit(0)
}

if (cmd !== 'anchor') {
  console.log('\n  usage: address | status | anchor <root-hex> <tree-size> [--send]\n')
  process.exit(0)
}

const rootHex = rest[0], treeSize = Number(rest[1])
if (!/^[0-9a-f]{64}$/i.test(rootHex ?? '') || !Number.isFinite(treeSize)) {
  console.error('⚠ anchor needs a 64-hex root and a tree size'); process.exit(1)
}
const root = [...Buffer.from(rootHex, 'hex')]

const st = load()
const prev = st.anchors.at(-1) ?? null
const u = await utxos()
if (!u.length) { console.error(`⚠ no funds at ${address} — run \`address\` and send a few thousand sat`); process.exit(1) }

const tx = new Transaction()
// ⚠⚠ INPUT 0 IS THE PREVIOUS ANCHOR when there is one. Consuming it is what makes the sequence
//    unforgeable: two anchors claiming one predecessor would be a double spend.
if (prev) {
  const src = Transaction.fromHex(await (await fetch(`${WOC}/tx/${prev.txid}/hex`)).text())
  tx.addInput({ sourceTransaction: src, sourceOutputIndex: prev.vout,
                unlockingScriptTemplate: pushDropUnlock(priv), sequence: 0xffffffff })
}
// fund from the largest utxo that is not the previous anchor's 1-sat output
const fundUtxo = u.filter(x => !(prev && x.tx_hash === prev.txid && x.tx_pos === prev.vout))
                  .sort((a, b) => b.value - a.value)[0]
if (!fundUtxo) { console.error('⚠ no funding utxo besides the previous anchor'); process.exit(1) }
const fundTx = Transaction.fromHex(await (await fetch(`${WOC}/tx/${fundUtxo.tx_hash}/hex`)).text())
tx.addInput({ sourceTransaction: fundTx, sourceOutputIndex: fundUtxo.tx_pos,
              unlockingScriptTemplate: new P2PKH().unlock(priv), sequence: 0xffffffff })
tx.addOutput({ lockingScript: anchorLock(pub.toString(), root, treeSize), satoshis: 1 })
tx.addOutput({ lockingScript: new P2PKH().lock(pub.toHash()), change: true })

await tx.fee(new SatoshisPerKilobyte(FEE_PER_KB))
await tx.sign()

// ⚠⚠ MEASURE THE FEE BY SERIALIZING THE SIGNED TRANSACTION. Never hand-count, and never trust the
//    figure computed before signing — this project has been bitten by a stale serialization before.
const raw = tx.toHex()
const bytes = raw.length / 2
const inSats = tx.inputs.reduce((s, x) => s + (x.sourceTransaction?.outputs[x.sourceOutputIndex]?.satoshis ?? 0), 0)
const outSats = tx.outputs.reduce((s, o) => s + (o.satoshis ?? 0), 0)
const fee = inSats - outSats
const rate = fee / bytes * 1000

console.log(`\n  ── anchor ${st.anchors.length} ──\n`)
console.log(`  root        ${rootHex}`)
console.log(`  tree size   ${treeSize}`)
console.log(`  spends      ${prev ? `anchor ${st.anchors.length - 1} (${prev.txid.slice(0,20)}…)` : 'nothing — this is the first'}`)
console.log(`  funding     ${fundUtxo.tx_hash.slice(0,20)}…:${fundUtxo.tx_pos}  ${fundUtxo.value} sat`)
console.log(`  size        ${bytes} B`)
console.log(`  fee         ${fee} sat  ⇒  ${rate.toFixed(1)} sat/KB`)
console.log(`  txid        ${tx.id('hex')}`)
// ⚠ the commitment must be readable back off the output, or the anchor is useless
const back = decodeAnchor(tx.outputs[0].lockingScript.toHex())
console.log(`  readable    ${back && back.root === rootHex && back.treeSize === treeSize ? 'yes — root and size decode correctly' : '⚠ NO'}`)

// ⚠⚠ FEE POLICY GUARD. 100 sat/KB is the project's rate; a transaction below the floor will not relay
//    and one far above it is money thrown away. Refuse rather than broadcast something wrong.
if (rate < FEE_PER_KB * 0.99) { console.error(`\n  ⚠ REFUSING: ${rate.toFixed(1)} sat/KB is below the ${FEE_PER_KB} floor — it will not relay\n`); process.exit(1) }
if (rate > FEE_PER_KB * 3) { console.error(`\n  ⚠ REFUSING: ${rate.toFixed(1)} sat/KB is more than 3x the policy rate\n`); process.exit(1) }

if (!send) {
  console.log(`\n  ⇒ DRY RUN. Nothing broadcast. Add --send when you are satisfied.\n`)
  process.exit(0)
}

const r = await fetch(`${WOC}/tx/raw`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({ txhex: raw }) })
const body = (await r.text()).trim()
if (!r.ok) { console.error(`\n  ⚠ BROADCAST REFUSED (${r.status}): ${body}\n`); process.exit(1) }
const txid = body.replace(/^"|"$/g, '')
st.anchors.push({ txid, vout: 0, root: rootHex, treeSize, at: new Date().toISOString(), fee, bytes })
save(st)
console.log(`\n  ★ BROADCAST: ${txid}`)
console.log(`    https://whatsonchain.com/tx/${txid}\n`)
