// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ MINT THE GENESIS COVENANT — dry-run by default, and it says NO unless you mean it.
//
//   CREATOR=<address> OWNERS=<addr,addr> FUND=<address> npx tsx covenant/mint.mts
//   …then add --broadcast, with JETMORA_WIF set IN YOUR OWN SHELL, to send it.
//
// ⚠⚠ THE KEY COMES FROM THE ENVIRONMENT AND IS NEVER PRINTED, NEVER LOGGED, NEVER A FLAG.
// ⚠ Everything this mints is PERMANENT. The creator address, the fork rule, N and the owner count can
//   never change — for this log or for any branch anyone ever forks from it.
import { PrivateKey, Transaction, P2PKH, Hash, Utils, SatoshisPerKilobyte }
  from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { buildAnchorLock } from './anchorFrame.mts'

const WOC = 'https://api.whatsonchain.com/v1/bsv/main'
const FEE_PER_KB = 100
const LEVELS = Number(process.env.N ?? 3)
/* ⚠ 1 by DEFAULT. The owner key is the log's OPERATIONAL key — it signs every anchor — so n-of-n
   doubles the ceremony on a routine action. ⇒ Raise it only where anchoring is rare and deliberate;
   a log can also start at 1 and fork to an n-of-n branch later (spec §4bis.4i). */
const NOWNERS = Number(process.env.NOWNERS ?? 1)
const FORKABLE = Number(process.env.FORKABLE ?? 1)
const LEAFCOVERS = Number(process.env.LEAFCOVERS ?? 1)
const ROYALTY = Number(process.env.ROYALTY ?? 1)
const LIVE = process.argv.includes('--broadcast')

const hx = (b: any) => Buffer.from(b).toString('hex')
const u32le = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return [...b] }
const die = (m: string) => { console.error('\n  ⚠ ' + m + '\n'); process.exit(1) }

/** ⚠ ADDRESS ONLY. Anything shaped like a WIF is refused before it is read. */
function toHash160(v: string, what: string): number[] {
  const t = (v ?? '').trim()
  if (!t) die(`${what} is required — an ADDRESS, never a private key`)
  if (/^[5KL9c][1-9A-HJ-NP-Za-km-z]{50,}$/.test(t)) {
    die(`⚠⚠ ${what} looks like a PRIVATE KEY (WIF). This wants the ADDRESS. Nothing was used.`)
  }
  if (/^[0-9a-fA-F]{40}$/.test(t)) return [...Buffer.from(t, 'hex')]
  try {
    const d: any = Utils.fromBase58Check(t)
    const h = Array.isArray(d.data) ? d.data : [...d.data]
    if (h.length !== 20) throw new Error(`decoded to ${h.length} bytes`)
    return h
  } catch (e: any) { die(`${what}: not a valid address — ${e.message}`) ; return [] }
}

const creator = toHash160(process.env.CREATOR!, 'CREATOR')
const ownerList = (process.env.OWNERS ?? '').split(',').filter(Boolean)
if (ownerList.length !== NOWNERS) {
  die(`OWNERS must list ${NOWNERS} addresses, comma separated (got ${ownerList.length}). ` +
      `⚠ ${NOWNERS}-of-${NOWNERS} — every one is required to anchor, and losing any of them means ` +
      `the branch can only be recovered by forking.`)
}
const owners = Object.fromEntries(
  ownerList.map((a, i) => ['owner' + 'abcd'[i], toHash160(a, `OWNERS[${i}]`)]))

/* ⚠ The key that FUNDS and signs the mint. Never printed. */
const wif = process.env.JETMORA_WIF
if (LIVE && !wif) die('--broadcast needs JETMORA_WIF set in your own shell. It is never asked for.')
const priv = wif ? PrivateKey.fromWif(wif) : PrivateKey.fromRandom()
const fundAddr = process.env.FUND ?? priv.toPublicKey().toAddress()

const woc = async (p: string) => {
  const r = await fetch(WOC + p)
  if (!r.ok) throw new Error(`WhatsOnChain ${r.status} on ${p}`)
  return r.json()
}

console.log('\n  ═══ MINT THE GENESIS ═══' + (LIVE ? '  ⚠ LIVE' : '  · dry run'))

/* ── the funding outpoint, which BECOMES the log's identity ─────────────────────────────────── */
let src: any, vout = 0, sats = 0
if (LIVE || process.env.FUND) {
  const u: any[] = await woc(`/address/${fundAddr}/unspent`)
  if (!u.length) die(`no funds at ${fundAddr}`)
  const pick = u.sort((a, b) => b.value - a.value)[0]
  src = Transaction.fromHex(await (await fetch(`${WOC}/tx/${pick.tx_hash}/hex`)).text())
  vout = pick.tx_pos; sats = pick.value
  console.log(`  funding      ${pick.tx_hash.slice(0, 16)}…:${vout}  ${sats.toLocaleString()} sat`)
} else {
  src = new Transaction()
  src.addOutput({ lockingScript: new P2PKH().lock(priv.toPublicKey().toHash()), satoshis: 50_000 })
  console.log('  funding      ⚠ SIMULATED — set FUND=<address> to use a real utxo')
}

/* ★★★ genesis = HASH256(the outpoint this mint CONSUMES).
   ⚠ NOT this transaction's own txid — a transaction cannot carry its own txid (spec §4bis.0). */
const outpoint = [...Buffer.from(src.id('hex'), 'hex').reverse(), ...u32le(vout)]
const genesis = [...Hash.hash256(outpoint)]

const lock = buildAnchorLock({
  levels: LEVELS, owners: NOWNERS, creator,
  state: { genesis, branch: Array(32).fill(0), depth: 0, treesize: 0,
           royalty: ROYALTY, forkable: FORKABLE, leafcovers: LEAFCOVERS, ...owners,
           ...Object.fromEntries(Array.from({ length: LEVELS }, (_, i) =>
             ['p' + 'abcdefgh'[i], creator])) },
})

const tx = new Transaction()
tx.addInput({ sourceTransaction: src, sourceOutputIndex: vout,
              unlockingScriptTemplate: new P2PKH().unlock(priv), sequence: 0xffffffff })
tx.addOutput({ lockingScript: lock, satoshis: 1 })
tx.addOutput({ lockingScript: new P2PKH().lock(priv.toPublicKey().toHash()), change: true })
await tx.fee(new SatoshisPerKilobyte(FEE_PER_KB))
await tx.sign()

/* ⚠⚠ MEASURE THE FEE BY SERIALIZING THE SIGNED TRANSACTION. Never hand-count. */
const raw = tx.toHex(), bytes = raw.length / 2
const inSats = (src.outputs[vout] as any).satoshis
const outSats = tx.outputs.reduce((s: number, o: any) => s + (o.satoshis ?? 0), 0)
const fee = inSats - outSats, rate = fee / bytes * 1000

const line = (k: string, v: any, n = '') => console.log(`  ${k.padEnd(13)} ${String(v).padEnd(30)} ${n}`)
console.log('\n  ── ⚠ PERMANENT, FOR THIS LOG AND EVERY BRANCH EVER FORKED FROM IT ──\n')
line('creator', hx(creator).slice(0, 24) + '…', '★ paid by every fork, forever')
line('owners', `${NOWNERS}-of-${NOWNERS}`, '⚠ all required to anchor')
line('levels (N)', LEVELS, 'the lineage payment window')
line('forkable', FORKABLE ? 'YES' : '⚠⚠ NO — ONE CUSTODIAN FOREVER', '')
line('leafcovers', LEAFCOVERS ? 'plaintext' : 'stored bytes', '')
console.log('\n  ── derived ──\n')
line('genesis id', hx(genesis).slice(0, 24) + '…', 'HASH256(the outpoint consumed)')
console.log('\n  ── the transaction ──\n')
line('size', bytes + ' B', '')
line('fee', fee + ' sat', `${rate.toFixed(1)} sat/KB`)
line('txid', tx.id('hex'), '')

/* ⚠ THE FEE GUARD. A rate far off policy means something is wrong; refuse rather than overpay. */
if (rate < 90 || rate > 300) die(`fee rate ${rate.toFixed(1)} sat/KB is outside 90–300. Refusing.`)

/* ★ A LOCAL RECORD, so a test mint can be found again without hunting shell history.
   ⚠⚠ NOT WRITTEN INTO THE REPO BY DEFAULT — jetmora is PUBLIC, and a record like this collects
   addresses. Set MINTLOG=<path> to somewhere of your own; unset, nothing is written. */
if (process.env.MINTLOG) {
  const { writeFileSync, existsSync, readFileSync } = await import('node:fs')
  const prior = existsSync(process.env.MINTLOG)
    ? JSON.parse(readFileSync(process.env.MINTLOG, 'utf8')) : []
  prior.push({
    txid: tx.id('hex'), broadcast: LIVE, genesis: hx(genesis),
    creator: process.env.CREATOR, owners: ownerList,
    levels: LEVELS, nowners: NOWNERS, forkable: FORKABLE, leafcovers: LEAFCOVERS, royalty: ROYALTY,
    bytes, fee, note: process.env.NOTE ?? '',
  })
  writeFileSync(process.env.MINTLOG, JSON.stringify(prior, null, 2))
  console.log(`\n  ★ recorded in ${process.env.MINTLOG} (${prior.length} mint${prior.length===1?'':'s'})`)
}
if (process.env.OUT) {
  const { writeFileSync } = await import('node:fs')
  writeFileSync(process.env.OUT, raw)
  console.log(`\n  ★ raw transaction written to ${process.env.OUT} — feed it to fork.mts as PARENT_HEX`)
}
if (!LIVE) {
  console.log('\n  ⇒ DRY RUN. Nothing was broadcast.')
  console.log('     Add --broadcast, with JETMORA_WIF set in your own shell, to send it.\n')
  process.exit(0)
}

const r = await fetch(`${WOC}/tx/raw`, { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ txhex: raw }) })
const body = await r.text()
if (!r.ok) die(`broadcast refused: ${body}`)
console.log(`\n  ★★★ MINTED — ${body.trim().replace(/"/g, '')}`)
console.log(`     https://whatsonchain.com/tx/${tx.id('hex')}\n`)
