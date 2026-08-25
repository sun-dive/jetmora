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
  buildAnchorLock({ levels: LEVELS, owner: ownerHash, creator, maxFee: MAXFEE, state: st })

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
  const newValue = prevOut.satoshis - MAXFEE - (opts.drain ? 1 : 0)

  const tx = new Transaction()
  tx.addInput({ sourceTransaction: prevTx, sourceOutputIndex: 0, sequence: 0xffffffff })
  tx.addOutput({ lockingScript: nextLock, satoshis: newValue })
  /* ★ THE CREATOR'S OUTPUT COMES FIRST — paid on every anchor of every branch, from a literal that
     no shift can evict. */
  if (!opts.omitCreator) {
    tx.addOutput({ lockingScript: new P2PKH().lock(opts.wrongCreator ? Array(20).fill(0xdd) : creator),
                   satoshis: prevState.royalty })
  }
  // then the lineage, and nothing else — spenderOutputs is empty here
  for (let i = 0; i < (opts.omitRoyalties ? 0 : LEVELS); i++) {
    /* ⚠ the saboteurs: pay somebody else, or pay them less. These are the ACTUAL attacks on a
       royalty — omitting it outright is the naive one. */
    const to = (opts.wrongPayee && i === 0) ? Array(20).fill(0xee) : prevState['p' + 'abcdefgh'[i]]
    const sats = (opts.shortPay && i === 0) ? 0 : prevState.royalty
    if (sats === 0) continue                                  // a 0-sat output is simply not created
    tx.addOutput({ lockingScript: new P2PKH().lock(to), satoshis: sats })
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
    push(Array(20).fill(0xf0)),                        // forker — unread on this path
    NUM(opts.wantRoyalty ?? prevState.royalty),        // wantroyalty  ⚠ a number: minimal push
    NUM(opts.children ?? 1),                           // children — covenant outputs created
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

/* ★★ THE ATTACKS THAT MATTER. Omitting the royalty is the naive move; paying the wrong person, or
   paying them less, is what someone would actually try. */
const wrongPayee = anchorSpend(mint, genesisState, 264, { wrongPayee: true })
check(!wrongPayee.ok, '★★★ the royalty cannot be REDIRECTED to another address')

const shortPay = anchorSpend(mint, genesisState, 264, { shortPay: true })
check(!shortPay.ok, '★★★ the royalty cannot be SHORT-PAID')

const drained = anchorSpend(mint, genesisState, 264, { drain: true })
check(!drained.ok, '⚠ the covenant cannot be DRAINED past its value floor')

/* ⚠ and a non-forkable log must refuse a fork outright */
const noFork = anchorSpend(mint, { ...genesisState, forkable: 0 }, 264, { children: 2 })
check(!noFork.ok, '★★ a NON-FORKABLE log refuses a second covenant output')

/* ★★★ THE CREATOR'S ROYALTY — the rule the whole design rests on, and the one the shift register
   silently broke. It is a baked literal now, so no shift can evict it. */
const noCreator = anchorSpend(mint, genesisState, 264, { omitCreator: true })
check(!noCreator.ok, '★★★ the CREATOR cannot be left unpaid')

const badCreator = anchorSpend(mint, genesisState, 264, { wrongCreator: true })
check(!badCreator.ok, '★★★ the CREATOR\'s royalty cannot be redirected')


// ════ ★★★ THE FORK PATH — permissionless replication ════════════════════════════════════════════
// ⚠⚠ NOTHING IN THIS SUITE FORKED UNTIL NOW, WHICH IS HOW THE CREATOR-EVICTION BUG HID.
console.log('\n  ── forks ──')

const forkerKey = PrivateKey.fromRandom()
const forkerHash = forkerKey.toPublicKey().toHash() as number[]

async function forkSpend(prevTx: any, prevState: any, opts: any = {}) {
  /* ⚠ vout: forking a FORK spends the child, which is output 1 of the previous fork transaction. */
  const vout = opts.vout ?? 0
  const prevOut = prevTx.outputs[vout]
  const V = prevOut.satoshis

  /* ★ out0 — THE PARENT, COMPLETELY UNCHANGED. Same state, and its value must come back WHOLE. */
  const parentBack = opts.drainParent ? V - 1 : V
  /* ★ out1 — the child: depth + 1, the forker shifted into slot 0, everything else carried across. */
  const childState = opts.badChild
    ? { ...prevState, depth: prevState.depth + 1, pa: forkerHash, pb: prevState.pa,
        pc: prevState.pb, forkable: 0 }                                  // ⚠ relaxes the fork rule
    : { ...prevState, depth: prevState.depth + 1,
        pa: opts.childNotForker ? Array(20).fill(0xbb) : forkerHash,
        pb: prevState.pa, pc: prevState.pb }

  const funder = new Transaction()
  funder.addOutput({ lockingScript: new P2PKH().lock(forkerHash), satoshis: 20_000 })

  const tx = new Transaction()
  tx.addInput({ sourceTransaction: prevTx, sourceOutputIndex: vout, sequence: 0xffffffff })
  tx.addInput({ sourceTransaction: funder, sourceOutputIndex: 0, sequence: 0xffffffff })
  tx.addOutput({ lockingScript: lockFor(prevState), satoshis: parentBack })
  if (!opts.omitChild) tx.addOutput({ lockingScript: lockFor(childState), satoshis: 1 })
  tx.addOutput({ lockingScript: new P2PKH().lock(creator), satoshis: prevState.royalty })
  for (let i = 0; i < LEVELS; i++) {
    tx.addOutput({ lockingScript: new P2PKH().lock(prevState['p' + 'abcdefgh'[i]]),
                   satoshis: prevState.royalty })
  }
  const change = new P2PKH().lock(forkerHash)
  tx.addOutput({ lockingScript: change, satoshis: 15_000 })
  const spenderOutputs = [...u64le(15_000), change.toBinary().length, ...change.toBinary()]

  const preimage = TransactionSignature.format({
    sourceTXID: prevTx.id('hex'), sourceOutputIndex: vout, sourceSatoshis: V,
    transactionVersion: tx.version, otherInputs: [tx.inputs[1]], inputIndex: 0, outputs: tx.outputs,
    inputSequence: 0xffffffff, subscript: prevOut.lockingScript, lockTime: tx.lockTime,
    scope: ANCHOR_SCOPE,
  })
  /* ⚠⚠ A FORK NEEDS NO OWNER SIGNATURE. These are the FORKER's own key — a stranger's — and the
     covenant must accept them, because "permissionless" is the claim being tested. */
  const raw = forkerKey.sign(Hash.sha256(preimage))
  const sig = new TransactionSignature(raw.r, raw.s, ANCHOR_SCOPE).toChecksigFormat()

  const unlock = new UnlockingScript([
    pushData([...sig]),
    pushData([...(forkerKey.toPublicKey().encode(true) as number[])]),
    pushData(forkerHash),                              // forker → the child's slot 0
    NUM(prevState.royalty),                            // wantroyalty — unchanged on a fork
    NUM(opts.children ?? 2),                           // ★ TWO covenant outputs
    NUM(prevState.treesize),                           // ⚠ tree size does NOT move on a fork
    pushData(spenderOutputs),
    pushData(u64le(parentBack)),
    pushData([...preimage]),
  ])
  tx.inputs[0].unlockingScript = unlock
  /* ⚠ The FUNDING input must be signed too, or the transaction cannot serialize — which only bites
     once a fork is forked, because `Spend` never serializes the whole thing.
     ★ Safe to do after input 0: unlocking scripts are not part of the preimage. */
  tx.inputs[1].unlockingScript = await new P2PKH().unlock(forkerKey).sign(tx, 1)

  const spend = new Spend({
    sourceTXID: prevTx.id('hex'), sourceOutputIndex: vout, sourceSatoshis: V,
    lockingScript: prevOut.lockingScript, transactionVersion: tx.version,
    otherInputs: [tx.inputs[1]], outputs: tx.outputs, inputIndex: 0, unlockingScript: unlock,
    inputSequence: 0xffffffff, lockTime: tx.lockTime, verifyFlags: ['UTXO_AFTER_CHRONICLE'],
  })
  let ok = false, why = ''
  try { ok = spend.validate() } catch (e: any) { why = (e.message ?? String(e)).slice(0, 90) }
  return { ok, why, tx, childState }
}

const f1 = await forkSpend(mint, genesisState)
check(f1.ok, '★★★ a STRANGER forks the log — no owner signature anywhere', f1.why)

const fDrain = await forkSpend(mint, genesisState, { drainParent: true })
check(!fDrain.ok, '★★★ a fork cannot take ONE SATOSHI from the holder')

const fNoChild = await forkSpend(mint, genesisState, { omitChild: true })
check(!fNoChild.ok, '⚠ claiming two children while creating one is refused')

const fBadChild = await forkSpend(mint, genesisState, { badChild: true })
check(!fBadChild.ok, '★★★ a fork CANNOT RELAX ITS OWN RULES (forkable flipped)')

const fNotForker = await forkSpend(mint, genesisState, { childNotForker: true })
check(!fNotForker.ok, '⚠ the child must carry the lineage the covenant computed')


// ════ ★★★ DEEPER THAN N — the test that would have caught the eviction ══════════════════════════
// ⚠⚠ With N=3 the lineage register is full after three forks. If the creator lived in that register
//    he would be shifted out at fork 3 and never paid again. He is a BAKED LITERAL instead, so this
//    walks past the point where that used to happen and demands he still be paid.
console.log('\n  ── a lineage deeper than the register ──')

let cur = mint, curState: any = genesisState, forked = 0, vout = 0
for (let k = 1; k <= LEVELS + 2; k++) {
  const r = await forkSpend(cur, curState, { vout })
  if (!r.ok) { check(false, `fork ${k} from depth ${curState.depth}`, r.why); break }
  forked++
  cur = r.tx; curState = r.childState
  vout = 1                     // ⚠ from here on, the thing being forked is the CHILD: output 1
}
check(forked === LEVELS + 2, `★★★ forked ${forked} deep — ${LEVELS + 2} levels, register is ${LEVELS}`,
      `depth reached ${curState.depth}`)

/* ⚠⚠ AND SAY WHAT THAT PROVES, rather than leaving it implied. At this depth the creator is NOT in
   the lineage register any more — he has been shifted out of every slot — and the covenant still
   demanded his output, because it comes from a baked literal instead. That is exactly the case the
   old design got wrong, and no test could reach it until forking worked. */
const regHasCreator = [...Array(LEVELS)].some(
  (_, i) => hex(curState['p' + 'abcdefgh'[i]]) === hex(creator))
check(!regHasCreator, '⚠ the creator has been shifted out of EVERY register slot by now',
      `register: ${[...Array(LEVELS)].map((_, i) => hex(curState['p' + 'abcdefgh'[i]]).slice(0, 6)).join(' ')}`)
check(f1.ok && forked === LEVELS + 2,
      '★★★ …and every one of those forks still PAID THE CREATOR, or none would have validated')

console.log(`\n  ${fail === 0 ? '✓' : '⚠'} ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
