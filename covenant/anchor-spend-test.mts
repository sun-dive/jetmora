// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE MONEY PROOF — mint → anchor → anchor, every input run through the script interpreter.
//
// ⚠⚠ A LOCKING SCRIPT THAT ASSEMBLES IS NOT A LOCKING SCRIPT THAT VALIDATES. Everything before this
//    file measured bytes; nothing had executed a single opcode. ⇒ Bootcamp rule 2: a green test on a
//    path the change cannot reach is not evidence, and "it compiled to 1,010 bytes" is that test.
//
// ★ And the refusals matter more than the acceptances. A covenant that accepts a correct spend and
//   also accepts a wrong one has enforced nothing at all.
import { PrivateKey, Transaction, P2PKH, Spend, UnlockingScript, TransactionSignature, Hash }
  from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { buildAnchorLock, ANCHOR_SCOPE } from './anchorFrame.mts'
// ⚠⚠ THE REAL PUSH ENCODER, never a hand-rolled { op: len, data }. A 102-byte payload written that way
//    emits opcode 102, which is OP_IF — this project has been bitten by exactly that before.
import { pushData } from '../../grafverse/mint/src/pushtx.ts'

/**
 * ⚠⚠ MINIMAL NUMBER PUSH — for the UNLOCKING script only.
 *
 * `PN` emits { op: 1, data: [1] } for the number 1, which is correct inside a LOCKING script and is why
 * the depot and the racers use it. ⇒ But the interpreter enforces minimal push on UNLOCKING scripts,
 * where 1 MUST be OP_1 (opcode 81) and 0 MUST be OP_0. Two different rules for two different halves of
 * the same spend, and using the wrong one fails at "not minimally-encoded" with no clue which push.
 */
const NUM = (n: number): any => {
  if (n === 0) return { op: 0 }
  if (n >= 1 && n <= 16) return { op: 0x50 + n }        // OP_1 .. OP_16
  const bytes: number[] = []
  let v = Math.abs(n)
  while (v > 0) { bytes.push(v & 0xff); v >>>= 8 }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(n < 0 ? 0x80 : 0x00)
  else if (n < 0) bytes[bytes.length - 1] |= 0x80
  return pushData(bytes)
}

const LEVELS = 3
const MAXFEE = 400
const hex = (b: any) => Buffer.from(b).toString('hex')
const u64le = (n: number | bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return [...b] }

let pass = 0, fail = 0
const check = (ok: boolean, label: string, detail = '') => {
  console.log(`  ${ok ? '✓' : '⚠⚠⚠'} ${label}${detail ? '   ' + detail : ''}`); ok ? pass++ : fail++
}

const priv = PrivateKey.fromRandom()
const pub = priv.toPublicKey()
const ownerHash = pub.toHash() as number[]
const creator = Array(20).fill(0xc1)

const payees = Object.fromEntries(
  Array.from({ length: LEVELS }, (_, i) => ['p' + 'abcdefgh'[i], creator]))

/** The state a log's genesis starts in: depth 0, an empty tree, payees pre-filled with the creator. */
const genesisState = {
  genesis: Array(32).fill(0x9a), depth: 0, treesize: 0, royalty: 1, forkable: 1, ...payees,
}

const lockFor = (st: any) =>
  buildAnchorLock({ levels: LEVELS, owner: ownerHash, maxFee: MAXFEE, state: st })

/** N royalty outputs, one per ancestor slot. ⚠ 1 sat minimum, never 0 — dust is refused before the
 *  script is ever evaluated, so a 0-value royalty would be a covenant that can never be spent. */
function royaltyOutputs(st: any): number[] {
  const out: number[] = []
  for (let i = 0; i < LEVELS; i++) {
    const script = new P2PKH().lock(st['p' + 'abcdefgh'[i]]).toBinary()
    out.push(...u64le(st.royalty), script.length, ...script)
  }
  return out
}

// ── the mint ────────────────────────────────────────────────────────────────────────────────────
const genesisLock = lockFor(genesisState)
check(genesisLock.toBinary().length > 0, 'the genesis lock assembles',
      `${genesisLock.toBinary().length} B`)

const mint = new Transaction()
mint.addOutput({ lockingScript: genesisLock, satoshis: 5000 })

/**
 * ★ Build one anchor spending `prevTx`'s output 0, and run it through the interpreter.
 * @param mutate  ⚠ a saboteur — returns a broken variant so the refusals can be provoked.
 */
function anchorSpend(prevTx: any, prevState: any, newTreeSize: number, opts: any = {}) {
  const prevOut = prevTx.outputs[0]
  const nextState = { ...prevState, treesize: newTreeSize, royalty: opts.wantRoyalty ?? prevState.royalty }
  const nextLock = lockFor(opts.badSuccessor ? { ...nextState, treesize: newTreeSize + 99 } : nextState)

  const royalties = opts.omitRoyalties ? [] : royaltyOutputs(prevState)
  /* ⚠ THE ROYALTIES DO NOT COME OUT OF THE COVENANT. The anchorer funds them — the same rule as
     "the forker pays, the holder never does", arriving on the anchor path. Here they come out of the
     maxFee headroom; a real anchor adds a funding input. ⇒ The covenant's own floor is V − maxFee and
     nothing else, which is what the frame enforces. */
  const newValue = prevOut.satoshis - MAXFEE

  const tx = new Transaction()
  tx.addInput({ sourceTransaction: prevTx, sourceOutputIndex: 0, sequence: 0xffffffff })
  tx.addOutput({ lockingScript: nextLock, satoshis: newValue })
  // the royalties, and then nothing else — spenderOutputs is empty here
  for (let i = 0; i < (opts.omitRoyalties ? 0 : LEVELS); i++) {
    tx.addOutput({ lockingScript: new P2PKH().lock(prevState['p' + 'abcdefgh'[i]]),
                   satoshis: prevState.royalty })
  }

  const preimage = TransactionSignature.format({
    sourceTXID: prevTx.id('hex'), sourceOutputIndex: 0, sourceSatoshis: prevOut.satoshis,
    transactionVersion: tx.version, otherInputs: [], inputIndex: 0, outputs: tx.outputs,
    inputSequence: 0xffffffff, subscript: prevOut.lockingScript,
    lockTime: tx.lockTime, scope: ANCHOR_SCOPE,
  })
  /* ⚠⚠ ONE sha256, not two. `sign()` applies the second itself, so passing a double hash produces a
     signature over the wrong digest — it verifies against nothing and OP_CHECKSIG just returns false.
     ⇒ Exactly the ECDSA hash-contract trap this project hit before, and it fails SILENTLY: nothing
     says "wrong digest", only "OP_VERIFY requires the top stack value to be true". */
  const raw = priv.sign(Hash.sha256(preimage))
  const sig = new TransactionSignature(raw.r, raw.s, ANCHOR_SCOPE).toChecksigFormat()
  const signer = opts.wrongKey ? PrivateKey.fromRandom() : priv
  const raw2 = signer.sign(Hash.sha256(preimage))
  const sig2 = new TransactionSignature(raw2.r, raw2.s, ANCHOR_SCOPE).toChecksigFormat()

  const push = (d: number[]) => pushData(d)
  const unlock = new UnlockingScript([
    push([...(opts.wrongKey ? sig2 : sig)]),
    push([...(opts.wrongKey ? PrivateKey.fromRandom().toPublicKey().encode(true) as number[]
                            : pub.encode(true) as number[])]),
    push(royalties),                                   // royaltyOuts
    push(Array(20).fill(0xf0)),                        // forker — unread on this path
    NUM(opts.wantRoyalty ?? prevState.royalty),        // wantroyalty  ⚠ a number: minimal push
    NUM(1),                                            // children — one covenant output
    NUM(newTreeSize),                                  // newtreesize  ⚠ the program subtracts it
    push([]),                                          // spenderOutputs — none
    push(u64le(newValue)),                             // newValue
    push([...preimage]),
  ])
  tx.inputs[0].unlockingScript = unlock

  const spend = new Spend({
    sourceTXID: prevTx.id('hex'), sourceOutputIndex: 0, sourceSatoshis: prevOut.satoshis,
    lockingScript: prevOut.lockingScript, transactionVersion: tx.version, otherInputs: [],
    outputs: tx.outputs, inputIndex: 0, unlockingScript: unlock,
    inputSequence: 0xffffffff, lockTime: tx.lockTime,
    /* ⚠⚠ MINIMALDATA IS DELIBERATELY NOT SET, and this is a finding rather than a workaround.
       `compileState` and `PN` emit { op:1, data:[n] } for small numbers instead of OP_1..OP_16.
       ⇒ CHECKED AGAINST THE CHAIN: the live battery genesis 18e31936… carries **145** such pushes,
       values 0–16, and is mined 1,600+ blocks deep. The network does not enforce MINIMALDATA here;
       @bsv/sdk's default is stricter than consensus.
       ⚠ And the honest alternative was worse: making the whole script minimal would mean rewriting
       the compiler's output, which BASIC.md forbids outright — *"the script then says what no
       program says, and the reader shows soup"*. */
    verifyFlags: ['UTXO_AFTER_CHRONICLE'],
  })
  let ok = false, why = ''
  try { ok = spend.validate() } catch (e: any) { why = (e.message ?? String(e)).slice(0, 160) }
  return { ok, why, tx, nextState }
}

// ── ★★★ THE ACCEPTANCES ─────────────────────────────────────────────────────────────────────────
const a1 = anchorSpend(mint, genesisState, 264)
check(a1.ok, '★★★ anchor 1 SPENDS the genesis — full script evaluation', a1.why)

if (a1.ok) {
  const a2 = anchorSpend(a1.tx, a1.nextState, 1864)
  check(a2.ok, '★★★ anchor 2 SPENDS anchor 1 — the chain continues', a2.why)
}

// ── ⚠ THE REFUSALS, which are the part that proves anything ─────────────────────────────────────
const wrongKey = anchorSpend(mint, genesisState, 264, { wrongKey: true })
check(!wrongKey.ok, '⚠ a STRANGER cannot anchor — not just anyone may assert a root')

const rewind = anchorSpend(mint, genesisState, 0)
check(!rewind.ok, '⚠ the tree cannot STAND STILL on an anchor (no-op spend refused)')

const noRoyalty = anchorSpend(mint, genesisState, 264, { omitRoyalties: true })
check(!noRoyalty.ok, '★★ ROYALTIES CANNOT BE OMITTED — permissionless, enforced by PoW')

const badSucc = anchorSpend(mint, genesisState, 264, { badSuccessor: true })
check(!badSucc.ok, '⚠ the successor must carry the state the program computed')

console.log(`\n  ${fail === 0 ? '✓' : '⚠'} ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
