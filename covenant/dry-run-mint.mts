// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ DRY-RUN GENESIS MINT — build the real transaction, change nothing, spend nothing.
//
// ⚠⚠ NO KEY IS USED AND NOTHING IS BROADCAST. Its only job is to put every value that is about to
//    become PERMANENT in one place, at real size, with a real fee — before any of it is unamendable.
//
// ⚠ Run it and read the OUTPUT, not this file. The point is the numbers.
import { PrivateKey, Transaction, P2PKH, Hash }
  from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { buildAnchorLock } from './anchorFrame.mts'

const FEE_PER_KB = 100                    // ⚠ never inflated, never a broadcaster's suggestion

/* ── the parameters a mint FREEZES ───────────────────────────────────────────────────────────── */
const LEVELS = Number(process.env.N ?? 3)          // lineage payment window — ⚠ script SHAPE
const OWNERS = Number(process.env.OWNERS ?? 2)     // n-of-n control        — ⚠ script SHAPE
const FORKABLE = Number(process.env.FORKABLE ?? 1)
const LEAFCOVERS = Number(process.env.LEAFCOVERS ?? 1)
const ROYALTY = Number(process.env.ROYALTY ?? 1)

const hx = (b: any) => Buffer.from(b).toString('hex')
const u32le = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return [...b] }

/* Stand-in addresses. ⚠ A real mint uses HIS addresses; none of these are keys anyone holds. */
const addr = (tag: number) => [...Hash.hash160([...Buffer.from(`dry-run-${tag}`)])] as number[]
const creator = addr(0)
const owners = Object.fromEntries(
  Array.from({ length: OWNERS }, (_, i) => ['owner' + 'abcd'[i], addr(10 + i)]))
const payees = Object.fromEntries(
  Array.from({ length: LEVELS }, (_, i) => ['p' + 'abcdefgh'[i], creator]))

/* ── ⚠⚠⚠ THE CIRCULARITY, WHICH IS THE POINT OF DOING THIS ───────────────────────────────────────
   `genesis` was specified as SHA256(genesisTxId ‖ outputIndex) — the txid of the transaction that
   CREATES this covenant. But the covenant's script CONTAINS `genesis`, and the script determines the
   output, and the output determines the txid. ⇒ **A transaction cannot carry its own txid.**

   ★ BRC-113 never had this problem: its Token ID is computed by OBSERVERS, after the fact, and is
   NEVER STORED IN THE TOKEN. Putting it in the script is my addition, and it does not close.

   ⇒ THE FIX IS ALREADY IN THE COVENANT, one field along: `branch` is HASH256 of the outpoint a FORK
   consumed. So let `genesis` be HASH256 of the outpoint the MINT consumed. Both are derived from a
   spent outpoint — knowable before signing, unique because an outpoint is spendable once, and
   unforgeable for the same reason. */
const fundingTxid = process.env.FUNDING_TXID ??
  '0000000000000000000000000000000000000000000000000000000000000000'
const fundingVout = Number(process.env.FUNDING_VOUT ?? 0)
const outpoint = [...Buffer.from(fundingTxid, 'hex').reverse(), ...u32le(fundingVout)]
const genesis = [...Hash.hash256(outpoint)]

const lock = buildAnchorLock({
  levels: LEVELS, owners: OWNERS, creator,
  state: {
    genesis,
    branch: Array(32).fill(0),            // ★ zeroes: the TRUNK has no parent outpoint to name
    depth: 0, treesize: 0,
    royalty: ROYALTY, forkable: FORKABLE, leafcovers: LEAFCOVERS,
    ...owners, ...payees,
  },
})

/* ── the mint transaction, at real size ───────────────────────────────────────────────────────── */
const funder = new Transaction()
funder.addOutput({ lockingScript: new P2PKH().lock(addr(99)), satoshis: 50_000 })
const mint = new Transaction()
mint.addInput({ sourceTransaction: funder, sourceOutputIndex: 0, sequence: 0xffffffff })
mint.addOutput({ lockingScript: lock, satoshis: 1 })
mint.addOutput({ lockingScript: new P2PKH().lock(addr(99)), satoshis: 48_000 })
/* ⚠ unlocking scripts are absent, so add a realistic P2PKH unlock (~107 B) to the size. */
const bytes = mint.toHex ? 0 : 0
const size = lock.toBinary().length + 34 + 148 + 10
const fee = Math.ceil(size / 1000 * FEE_PER_KB)

const line = (k: string, v: string, note = '') =>
  console.log(`  ${k.padEnd(16)} ${String(v).padEnd(34)} ${note}`)

console.log('\n  ═══ DRY RUN — NOTHING IS SIGNED, NOTHING IS BROADCAST ═══\n')
console.log('  ── ⚠ FROZEN AT MINT, FOR THE LIFE OF THE LOG AND EVERY BRANCH ──\n')
line('levels (N)', String(LEVELS), '⚠ script SHAPE — payment window width')
line('owners (n-of-n)', String(OWNERS), '⚠ script SHAPE — every key required')
line('forkable', FORKABLE ? '1 — CAN be forked' : '0 — CANNOT EVER be forked',
     FORKABLE ? 'sellable, replicable, backed up by its forks' : '⚠⚠ ONE CUSTODIAN, FOREVER')
line('leafcovers', LEAFCOVERS ? '1 — plaintext' : '0 — stored bytes', 'only bites if encrypted')
line('creator', hx(creator).slice(0, 20) + '…', '★ baked literal — paid by EVERY branch, forever')
console.log()
console.log('  ── mutable, but starting here ──\n')
line('royalty', String(ROYALTY) + ' sat', 'per payee per anchor · trunk may change it')
for (const [k, v] of Object.entries(owners)) line(k, hx(v as number[]).slice(0, 20) + '…', 'control')
console.log()
console.log('  ── derived, and NOT chooseable ──\n')
line('genesis', hx(genesis).slice(0, 20) + '…', 'HASH256(the outpoint this mint consumes)')
line('branch', '00000000…', '★ zeroes — the TRUNK has no parent')
console.log()
console.log('  ── size and cost ──\n')
line('locking script', lock.toBinary().length + ' B', '')
line('mint tx', '≈ ' + size + ' B', '')
line('fee at 100 sat/KB', fee + ' sat', '⇒ ' + (fee / 100000000 * 60000).toFixed(4) + ' USD at $60k')
line('covenant value', '1 sat', '⚠ never 0 — dust is refused before the script runs')
console.log()
console.log('  ⚠⚠ THE CIRCULARITY THIS RUN EXISTS TO SURFACE:')
console.log('     `genesis` was specified as SHA256(genesisTxId ‖ index) — this transaction\'s OWN txid.')
console.log('     A transaction cannot carry its own txid. ⇒ BRC-113 never had the problem, because')
console.log('     its Token ID is computed by OBSERVERS and never stored in the token.')
console.log('     ★ Above it is HASH256(the outpoint the mint CONSUMES) — the same rule `branch`')
console.log('       already uses, knowable before signing and unique because an outpoint spends once.')
console.log()
