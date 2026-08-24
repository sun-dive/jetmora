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
import { anchorLock, pushDropUnlock, decodeAnchor, buildAnchor, FEE_PER_KB } from './anchor.mjs'

const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { PrivateKey, P2PKH, Transaction, SatoshisPerKilobyte, Script } = await import(SDK)
const WOC = 'https://api.whatsonchain.com/v1/bsv/main'
// ⚠⚠ THE ONLY DURABLE FACT IS THE FIRST ANCHOR'S TXID. Everything else is derived by WALKING THE
//    CHAIN: anchor n+1 is whatever spent anchor n's output 0, and the tip is the one still unspent.
//    ⇒ `computation-walk-tip-discovery` — the tip is the UNSPENT one; walk /spent until it 404s.
//    So there is no state blob to keep in step with reality and nothing fragile to lose. A JSON file
//    of anchor history would have been a second source of truth, and a second source of truth is a
//    disagreement waiting to happen.
const FIRST = new URL('../server/data/anchor0.txid', import.meta.url)

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
const firstTxid = () => existsSync(FIRST) ? readFileSync(FIRST, 'utf8').trim() : (process.env.JETMORA_ANCHOR0 ?? null)
const rememberFirst = t => { if (!existsSync(FIRST)) writeFileSync(FIRST, t + '\n') }

/** ⇒ Follow the spends to the tip. Returns [] if no chain has been started. */
async function walkChain() {
  const first = firstTxid()
  if (!first) return []
  const chain = []
  let txid = first
  for (let i = 0; i < 10_000; i++) {
    const tx = await woc(`/tx/hash/${txid}`)
    const out = tx.vout[0]
    const c = decodeAnchor(out.scriptPubKey.hex)
    chain.push({ txid, vout: 0, root: c?.root ?? null, treeSize: c?.treeSize ?? null,
                 confirmations: tx.confirmations ?? 0 })
    const r = await fetch(`${WOC}/tx/${txid}/out/0/spent`)
    if (r.status === 404) break                       // ★ unspent ⇒ this is the tip
    if (!r.ok) throw new Error(`WoC ${r.status} walking from ${txid}`)
    const spent = await r.json()
    txid = spent.txid ?? spent.hash
    if (!txid) break
  }
  return chain
}

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
  const chain = await walkChain()
  console.log(`  anchor chain: ${chain.length}` + (chain.length ? '' : '  (none started)'))
  for (const a of chain.slice(-4)) console.log(
    `    ${a.txid.slice(0,20)}…  size ${String(a.treeSize).padStart(6)}  ${a.confirmations} conf` +
    (a === chain.at(-1) ? '   ← tip, unspent' : ''))
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

// ⚠ derived from the chain, never from a local record of what we think we did
const chain = await walkChain()
const prev = chain.at(-1) ?? null
const u = await utxos()
if (!u.length) { console.error(`⚠ no funds at ${address} — run \`address\` and send a few thousand sat`); process.exit(1) }

const srcOf = async txid => Transaction.fromHex(await (await fetch(`${WOC}/tx/${txid}/hex`)).text())

// fund from the largest utxo that is not the previous anchor's 1-sat output
const fundUtxo = u.filter(x => !(prev && x.tx_hash === prev.txid && x.tx_pos === prev.vout))
                  .sort((a, b) => b.value - a.value)[0]
if (!fundUtxo) { console.error('⚠ no funding utxo besides the previous anchor'); process.exit(1) }

// ★ ONE implementation, in anchor.mjs, exercised by tools/anchor-chain-test.mjs. This file used to
//   carry its own copy; they disagreed, and the copy here was the only one that worked.
const { tx } = await buildAnchor({
  key: priv, root, treeSize,
  prev: prev ? { sourceTransaction: await srcOf(prev.txid), vout: prev.vout } : null,
  funding: { sourceTransaction: await srcOf(fundUtxo.tx_hash), vout: fundUtxo.tx_pos },
})

// ⚠⚠ MEASURE THE FEE BY SERIALIZING THE SIGNED TRANSACTION. Never hand-count, and never trust the
//    figure computed before signing — this project has been bitten by a stale serialization before.
const raw = tx.toHex()
const bytes = raw.length / 2
const inSats = tx.inputs.reduce((s, x) => s + (x.sourceTransaction?.outputs[x.sourceOutputIndex]?.satoshis ?? 0), 0)
const outSats = tx.outputs.reduce((s, o) => s + (o.satoshis ?? 0), 0)
const fee = inSats - outSats
const rate = fee / bytes * 1000

console.log(`\n  ── anchor ${chain.length} ──\n`)
console.log(`  root        ${rootHex}`)
console.log(`  tree size   ${treeSize}`)
console.log(`  spends      ${prev ? `anchor ${chain.length - 1} (${prev.txid.slice(0,20)}…, ${prev.confirmations} conf)` : 'nothing — this is the first'}`)
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
rememberFirst(chain.length === 0 ? txid : firstTxid())   // ⚠ the ONLY thing worth remembering
console.log(`\n  ★ BROADCAST: ${txid}`)
console.log(`    https://whatsonchain.com/tx/${txid}\n`)
