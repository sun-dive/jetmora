// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE ANCHOR COVENANT'S FRAME — the part BASIC cannot say.
//
// ⚠ LICENCE. An anchor IS a BSV transaction, so using the Open BSV v6 compiler and SDK here is use ON
//   BSV. The compiler is USED, never edited, and no bundle any page loads is rebuilt from here.
//
// `basicCovenant.ts` is explicit that its own frame is a default rather than a law: *"the shell, the
// depot and the battery each answer 'what must my output be?' differently."* ⇒ The anchor's answer is
// its own, and it differs from the default in exactly two ways:
//
//   1 ★ IT NEEDS A SIGNATURE, and the reason is precise. A covenant can check anything it can COMPUTE,
//     and it cannot compute a merkle root — the tree is not in the transaction. A root is ASSERTED,
//     not determined. ⇒ So the covenant AUTHORISES the anchorer instead of validating the claim, which
//     is the same shape as §4.1, where the log does not validate either.
//     ⚠⚠ Without this, ANY passer-by could anchor ANY root, and a single vandal spending the tip would
//     permanently kill a non-forkable log — its successor output is gone and cannot be recreated.
//
//   2 ★★ ROYALTY OUTPUTS. N ancestors are paid on every anchor, and `hashOutputs` is what makes that
//     unavoidable rather than merely agreed. ⇒ Permissionless royalties enforced by proof of work.
//
// ── ⏭ WHAT THIS FILE DOES NOT YET DO ──────────────────────────────────────────────────────────────
// The FORK path. ⇒ When it lands it will VERIFY the child the forker supplies rather than CONSTRUCT
// it — the runbook's own closing lesson, *"branches can become assertions … it enforces the same thing
// by refusing instead of choosing"*. A wrong child then produces NO FORK rather than a wrong one, and
// it is far cheaper in script than a second rebuild.
import {
  compileState, stateChunks, scriptCodeVarIntSize,
} from '../../grafverse/mint/src/basic.ts'
import { pushTxConstants, pushTxVerifyOps, pushData } from '../../grafverse/mint/src/pushtx.ts'
import { extractHashOutputsOps, extractScriptCodeFieldOps } from '../../grafverse/mint/src/covenant.ts'
import { PN } from '../../grafverse/mint/src/covenantAsm.ts'
import { OP, LockingScript } from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { anchorSrc, ANCHOR_STACK } from './anchorSrc.mjs'

const op = (c: number) => ({ op: c })

/**
 * ⚠⚠ THE UNLOCKING CONTRACT, WRITTEN ONCE. Bottom first.
 *
 * Both the compiler's model and the pre-program signature check measure depths against this, so it
 * MUST have exactly one definition. ⇒ Writing it twice is how the depot's predecessor got three bugs
 * in one sitting: two lists that agree today and drift the moment a name is added.
 */
export const ANCHOR_UNLOCK_BASE = [...ANCHOR_STACK, 'spenderOutputs', 'newValue'] as const

/**
 * ⚠ The unlocking contract for `owners` keys. Bottom first: every (sig, pub) pair, then the child's
 * OWN owner hashes — which the FORKER chooses and the covenant does not check, exactly as it does not
 * check who the root's owner was.
 */
export const anchorUnlock = (owners: number) => [
  ...Array.from({ length: owners }, (_, i) => [`sig${i}`, `pub${i}`]).flat(),
  ...Array.from({ length: owners }, (_, i) => `childowner${i}`),
  ...ANCHOR_UNLOCK_BASE,
]

/** ⚠ Kept for the single-owner default, which is what every existing caller means. */
export const ANCHOR_UNLOCK = anchorUnlock(1)

/**
 * ★★ SIGHASH_ANYONECANPAY | ALL | FORKID — BRC-226's own scope, and for BRC-226's own reason:
 * **any funder may add their own input without invalidating the spend.**
 *
 * ⇒ PROVED, not assumed: the suite adds a LATE FUNDER after the covenant's unlocking data is fixed
 * and requires it to be accepted here and REFUSED under 0x41. A suite that passes under both scopes
 * says nothing about either.
 *
 * ⚠⚠⚠ THIS IS SAFE **ONLY BECAUSE TWINS ARE IMPOSSIBLE**, and that coupling must not be forgotten.
 * Under ANYONECANPAY `hashPrevouts` is zeroed, so the covenant is not bound to a particular outpoint
 * by the preimage — two instances identical in scriptCode AND value would be interchangeable, and one
 * preimage would satisfy both. ⇒ The `branch` field closes that: it is HASH256 of the parent outpoint
 * a fork consumed, an outpoint is spendable once, and a parent's tip moves with every fork.
 * ★ IF THE BRANCH FIELD IS EVER REMOVED, THIS MUST GO BACK TO 0x41 IN THE SAME COMMIT.
 *
 * ⚠ And a correction worth carrying: `betaFrame.ts` says such a covenant *"cannot see which outpoint
 * it is spending."* MEASURED 25 Aug — the BIP143 `outpoint` field at offset 68 survives ANYONECANPAY
 * intact; only `hashPrevouts` and `hashSequence` are zeroed. ⇒ The warning describes a consequence of
 * not LOOKING, not an inability to look. This covenant looks.
 */
export const ANCHOR_SCOPE = 0xc1

export interface AnchorFrameParams {
  /** One entry per DIM, by name: genesis, depth, treesize, royalty, forkable, and the N payees. */
  state: Record<string, number | number[]>
  /** N — lineage levels. ⚠ Fixed at genesis; it changes the script's SHAPE, not just its contents. */
  levels: number
  /** ⚠ n-of-n. 1 is the plain case; 2 is a cold key plus a hot one. Frozen at genesis. */
  owners?: number
  /**
   * ★★★ hash160 of the log's ORIGINAL CREATOR — paid on every anchor of every branch, forever.
   *
   * ⚠⚠ A BAKED LITERAL, DELIBERATELY, AND NOT A REGISTER SLOT. The lineage register shifts, and a
   *    shift EVICTS its oldest entry: with N=3 the creator fell out at fork 3 and was never paid
   *    again. That was a silent bug in a rule the whole design rests on. ⇒ A literal cannot be
   *    shifted out, because it is not in the register. Structural, not logical.
   * ★ His pattern, from Phar Lap's `bundleCovenant`: convert what cannot change into an absolute at
   *   the edge and let the covenant stay simple.
   */
  creator: number[]
  fieldOffset?: number
}

/**
 * The locking script, as ops.
 *
 * ── the stack the unlocking script must leave, bottom first ────────────────────────────────────────
 * ```
 *   sig            the owner's signature      ⚠ the anchor path's authorisation
 *   pub            the owner's public key
 *   royaltyOuts    the N serialized royalty outputs, already concatenated
 *   forker         hash160 — unread on this path, but the model must know it is there
 *   wantroyalty    what the spender asks the royalty to become (⚠ only the trunk may move it)
 *   children       how many covenant outputs this spend creates. 1 on the anchor path
 *   newtreesize    the tree size being anchored
 *   spenderOutputs the outputs after ours — change, or nothing
 *   newValue       8 bytes LE: what our own output will carry
 *   preimage       the sighash preimage
 * ```
 */
export function anchorLockOps(p: AnchorFrameParams): { ops: any[]; state: any; layout: any[] } {
  const c = pushTxConstants(ANCHOR_SCOPE)
  const fieldOffset = p.fieldOffset ?? 1
  if (p.creator.length !== 20) throw new Error(`the creator must be a 20-byte hash160, got ${p.creator.length}`)

  /* ⚠ The BASIC program's own stack contract, plus the two the frame's value rule and output binding
     reach for. Depths are read from the compiler's model BY NAME below — never counted by hand, which
     is what this project's predecessors did and it cost three bugs in one sitting. */
  /* ⚠⚠ 'preimageCopy' IS NAMED IN THE COMPILER'S MODEL, not left as an anonymous extra item.
     `extractScriptCodeFieldOps` CONSUMES the preimage, and the fork path needs it a second time to
     copy the parent's own script. ⇒ So a copy is kept — and because the compiler is told about it,
     every depth after this point is still measured BY NAME rather than adjusted by hand.
     ★ Naming it is the difference between a stack the model describes and one it merely tolerates. */
  const owners = p.owners ?? 1
  const probe: any = compileState(anchorSrc(p.levels, owners), {
    fieldOffset, stack: [...anchorUnlock(owners), 'preimageCopy'],
  })

  /* ⚠ THE STATE GOES IN FIRST as literal pushes — the only part of this script that differs between
     two instances of the same program. Everything after is identical, which is what makes a genesis
     and its successors THE SAME COVENANT. */
  const head: any[] = [...stateChunks(probe.layout, p.state)]
  /* …and is dropped immediately. The script does not READ its own literals; it reads its scriptCode
     out of the preimage, which is the only copy a miner has verified. */
  const pairs = Math.floor(probe.layout.length / 2)
  for (let i = 0; i < pairs; i++) head.push(op(OP.OP_2DROP))
  if (probe.layout.length % 2) head.push(op(OP.OP_DROP))

  const ops: any[] = [
    ...head,

    ...pushTxVerifyOps(c),                                   // the preimage is now genuine

    op(OP.OP_DUP), ...extractHashOutputsOps(), op(OP.OP_TOALTSTACK),          // alt: [HO]
    /* The value of the output being SPENT sits 52 bytes from the end of the preimage — the covenant's
       current balance, and the only place it can be read from honestly. */
    op(OP.OP_DUP),
    op(OP.OP_SIZE), pushData([52]), op(OP.OP_SUB), op(OP.OP_SPLIT), op(OP.OP_NIP),
    pushData([8]), op(OP.OP_SPLIT), op(OP.OP_DROP), op(OP.OP_BIN2NUM), op(OP.OP_TOALTSTACK),  // alt: [HO, V]

    op(OP.OP_DUP),                                           // ⚠ keep the preimage: the fork path re-reads it
    ...extractScriptCodeFieldOps(),                          // the scriptCode field, varint and all
    ...probe.ops,                                            // ← the BASIC: peel, run, rebuild
  ]

  /* ── THE VALUE RULE ─────────────────────────────────────────────────────────────────────────────
     The only thing standing between a covenant and being emptied one fee at a time. */
  const a: string[] = probe.stack.slice()
  const d = (name: string): number => {
    const i = a.lastIndexOf(name)
    if (i < 0) throw new Error(`anchorFrame: the compiler's model has no '${name}' — the contract drifted`)
    return a.length - 1 - i
  }
  ops.push(
    /* ── ★★ AUTHORISE THE ANCHORER — from the PEELED STATE, and only on the anchor path ─────────
       ⚠⚠ This runs AFTER the program, because `owner` is now a FIELD rather than a literal and the
       peel is what puts it on the stack. ★ That is also where the runbook wants it: *"put
       verification and binding ADJACENT, as one unbroken run."*
         ANCHOR  needs the owner's key — SCRIPT CANNOT VALIDATE A ROOT, so the covenant authorises
                 the anchorer instead.
         FORK    needs nothing: out0 returns the parent untouched, so there is nothing to consent to.
       ⇒ Arithmetic, not a branch: `authOk OR forking`. */
    /* ⚠⚠ N-OF-N: EVERY owner slot must match AND sign. Folded with BOOLAND so one missing share
       fails the whole check — which is the point of splitting a key at all. */
    ...Array.from({ length: owners }, (_, i) => [
      PN(d(`pub${i}`) + i), op(OP.OP_PICK), op(OP.OP_HASH160),          // +1  (+i already held)
      PN(d(`payowner${'abcd'[i]}`) + i + 1), op(OP.OP_PICK), op(OP.OP_EQUAL),
      PN(d(`sig${i}`) + i + 1), op(OP.OP_PICK),
      PN(d(`pub${i}`) + i + 2), op(OP.OP_PICK),
      op(OP.OP_CHECKSIG),
      op(OP.OP_BOOLAND),                                               // +1  this owner is good
      ...(i > 0 ? [op(OP.OP_BOOLAND)] : []),                           // fold into the running AND
    ]).flat(),
    PN(d('children') + 1), op(OP.OP_PICK),                   // +2
    op(OP.OP_1), op(OP.OP_SUB),                              // +2  forking
    op(OP.OP_BOOLOR), op(OP.OP_VERIFY),                      //  0

    PN(d('newValue')), op(OP.OP_PICK), op(OP.OP_BIN2NUM),    // +1  what the spender claims
    op(OP.OP_FROMALTSTACK),                                  // +2  V, from the preimage
    /* ★★★ THE SPENDER PAYS. ALWAYS. THERE IS NO DRAIN SURFACE AT ALL.
       ⚠⚠ There was a `maxFee` here, bounding how much of the covenant's OWN value a spend could hand
       a miner. ⇒ His call, 25 Aug: that bound only exists if the covenant pays its own fee, and it
       never has to — an anchorer and a forker both bring a funding input. **If the fee is too low the
       network simply refuses the transaction**, so the covenant was duplicating a rule it does not
       own, using a constant frozen at mint. Same shape as the fee floor and MAX_MEMORY.
       ⇒ `newValue >= V` on BOTH paths. The parent always comes out whole, so "the forker pays, the
       holder never does" stops being a fork rule and becomes the only rule there is. */
    op(OP.OP_GREATERTHANOREQUAL), op(OP.OP_VERIFY),          //  0

    /* ── AND BIND IT ────────────────────────────────────────────────────────────────────────────
       out0 = value(8) ‖ varint(len) ‖ script. The rebuilt scriptCode FIELD already carries its own
       varint, which is why `extractScriptCodeFieldOps` hands back the field rather than the script. */
    PN(d('newValue')), op(OP.OP_PICK), op(OP.OP_SWAP), op(OP.OP_CAT),

    /* ── ★★★ AND ON A FORK, THE CHILD ───────────────────────────────────────────────────────────
       Built from the PARENT'S OWN scriptCode, re-extracted from the preimage, with exactly two
       substitutions: depth + 1, and the shifted lineage register.
       ⇒ Everything else — the genesis, the tree size, the royalty, the fork rule and the covenant
       code itself — is carried across VERBATIM as byte slices. **A fork therefore cannot relax its
       own rules**, because the rules are not rebuilt, they are copied. */
    ...childOps(d, probe.layout, fieldOffset, p.levels, owners),

    /* ── ★★★ THEN THE ROYALTIES — CONSTRUCTED HERE, NOT ACCEPTED FROM THE SPENDER ────────────────
       ⚠⚠ BINDING IS NOT ENFORCING, and the first version of this got it wrong. Taking the serialized
       royalty outputs from the unlocking script and folding them into the hash means they cannot be
       ALTERED — but nothing requires them to be PRESENT. A spender who pushes nothing and builds a
       transaction with no royalty outputs satisfies it perfectly.
       ⇒ Caught the moment the acceptance case started working, by a refusal that had been "passing"
       for the wrong reason all along.
       ★ So the covenant BUILDS them, from its own payee fields and its own royalty, and `hashOutputs`
       then makes them unavoidable. THAT is what "permissionless royalties enforced by proof of work"
       has to mean: the script has no branch that leaves them out. */
    ...royaltyOps(d, p.levels, p.creator),

    PN(d('spenderOutputs')), op(OP.OP_PICK), op(OP.OP_CAT),
    op(OP.OP_HASH256), op(OP.OP_FROMALTSTACK), op(OP.OP_EQUAL),
  )
  return { ops, state: probe, layout: probe.layout }
}


/**
 * ★★★ THE CHILD OUTPUT, on a fork only.
 *
 * ⚠⚠ IT IS NOT REBUILT FROM FIELDS — it is the parent's own scriptCode with two slices replaced.
 * Copying is what makes `forkable`, `genesis` and the covenant's code impossible to alter in a fork:
 * they are never reconstructed, so there is nothing to reconstruct them wrongly.
 *
 * ⚠ Offsets are DERIVED FROM THE COMPILER'S LAYOUT, never counted by hand. Each field occupies
 *   `1 + width` bytes (its push opcode, then its data).
 *
 * ⚠ The altstack is used for two of my own slices and nothing else. `hashOutputs` is already down
 *   there; these are pushed and popped in strict pairs above it, and no attacker-supplied byte
 *   crosses them. That is the condition the runbook sets, met deliberately rather than by luck.
 */
function childOps(d: (n: string) => number, layout: any[], fieldOffset: number, levels: number,
                  owners: number): any[] {
  const w = (n: string) => layout.find((f: any) => f.name === n).width
  const HEAD = fieldOffset + w('genesis') + 1            // …through BRANCH's own push opcode
  /* ⚠ Everything between depth and the payees is copied VERBATIM — tree size, royalty, the fork rule
     and the immutable settings. ⇒ Derived from the layout, so adding a field here cannot desync it. */
  const MID = ['treesize', 'royalty', 'forkable', 'leafcovers'].reduce((a, n) => a + 1 + w(n), 0)
  /* ⚠ owner sits immediately before the register and is substituted with it — the FORKER becomes the
     child's owner, which is what makes a replica usable by the person who made it. */
  const PAY = owners * (1 + w('ownera')) + levels * (1 + w('pa'))
  const slots = [...Array.from({ length: owners }, (_, i) => `childowner${i}`),
                 ...Array.from({ length: levels }, (_, i) => 'child' + 'p' + 'abcdefgh'[i])]

  const body: any[] = [
    /* ★★★ THE CHILD'S BRANCH ID = HASH256(the parent outpoint this fork consumed).
       ⚠⚠ The outpoint sits at a FIXED offset 68 — nVersion(4) ‖ hashPrevouts(32) ‖ hashSequence(32) —
       and MEASURED 25 Aug: it survives ANYONECANPAY intact. Only hashPrevouts and hashSequence are
       zeroed there. ⇒ `betaFrame`'s warning that such a covenant "cannot see which outpoint it is
       spending" describes a consequence of not LOOKING, not an inability to look.
       ★ An outpoint is spendable once, and a parent's tip moves with every fork, so no two forks ever
       see the same one. **Two children can never be byte-identical.** */
    PN(d('preimageCopy')), op(OP.OP_PICK),               // +1
    PN(68), op(OP.OP_SPLIT), op(OP.OP_NIP),              // +1  drop version‖hashPrevouts‖hashSequence
    PN(36), op(OP.OP_SPLIT), op(OP.OP_DROP),             // +1  the 36-byte outpoint
    op(OP.OP_HASH256),                                   // +1  ★ the branch id

    PN(d('preimageCopy') + 1), op(OP.OP_PICK),           // +2  ⚠ +1: the branch id is being held
    ...extractScriptCodeFieldOps(),                      // +2  the parent's scriptCode, again
    PN(HEAD), op(OP.OP_SPLIT),                           // +3  head ‖ rest (through branch's push op)
    PN(w('branch')), op(OP.OP_SPLIT), op(OP.OP_NIP),     // +3  ⚠ the OLD branch id dropped
    PN(1 + w('depth')), op(OP.OP_SPLIT), op(OP.OP_NIP),  // +3  ⚠ the OLD depth AND its push op dropped
    PN(MID), op(OP.OP_SPLIT),                            // +4  head, mid, rest
    PN(PAY), op(OP.OP_SPLIT), op(OP.OP_NIP),             // +4  ⚠ the OLD payees dropped
    op(OP.OP_TOALTSTACK), op(OP.OP_TOALTSTACK),          // +2  alt: [.., suf, mid]
    /* [branchId, head] ⇒ head ‖ branchId */
    op(OP.OP_SWAP), op(OP.OP_CAT),                       // +1
    /* ‖ depth's own push opcode, then depth + 1 */
    pushData([w('depth')]), op(OP.OP_CAT),               // +1
    PN(d('childdepth') + 1), op(OP.OP_PICK),
    PN(w('depth')), op(OP.OP_NUM2BIN), op(OP.OP_CAT),    // +1
    op(OP.OP_FROMALTSTACK), op(OP.OP_CAT),               // +1  ‖ mid, verbatim
  ]
  for (const slot of slots) {
    body.push(
      pushData([w('pa')]), op(OP.OP_CAT),                // the push opcode — owner and payees are both 20
      PN(d(slot) + 1), op(OP.OP_PICK), op(OP.OP_CAT),    // ⚠ +1 for the child being held
    )
  }
  body.push(
    op(OP.OP_FROMALTSTACK), op(OP.OP_CAT),               // ‖ suffix, verbatim
    /* ⚠ The child carries ONE satoshi. A covenant value is never 0 — a 0-value output is refused as
       dust before the script is evaluated at all — and the floor is a floor, so any later anchor may
       top it up. The forker pays it. */
    pushData([...Buffer.from('0100000000000000', 'hex')]), op(OP.OP_SWAP), op(OP.OP_CAT),
    op(OP.OP_CAT),                                       //  0  onto the accumulator
  )
  /* ⚠ BALANCED BY CONSTRUCTION: the true arm nets zero — it builds the child and concatenates it
     away — and the false arm does nothing at all. */
  return [
    PN(d('children')), op(OP.OP_PICK), op(OP.OP_1), op(OP.OP_SUB),
    op(OP.OP_IF), ...body, op(OP.OP_ENDIF),
  ]
}

/**
 * ★★ Build the N royalty outputs from the covenant's OWN state, and concatenate them onto the
 * accumulator already holding out0.
 *
 * Each is a standard P2PKH output: `value(8) ‖ 0x19 ‖ OP_DUP OP_HASH160 <20> ‖ 0x88 0xac`.
 * ⚠ The value is `paid` — the royalty in force for THIS anchor, not the one being set — converted at
 *   runtime with OP_NUM2BIN, because a trunk may change it and a literal would freeze it.
 * ⚠⚠ Depths come from the compiler's model BY NAME, adjusted by exactly the number of items this code
 *   has itself pushed. Every CAT returns to the accumulator depth, so the adjustment stays local.
 */
function royaltyOps(d: (n: string) => number, levels: number, creator: number[]): any[] {
  const out: any[] = []
  /* ★★★ THE CREATOR FIRST, AND FROM A LITERAL. Everything after the value is immutable — the varint,
     the P2PKH template and the creator's own hash — so it is ONE push, not a reconstruction.
     ⚠ The VALUE cannot be a literal: the trunk may change the royalty, and baking it would freeze the
     price at mint. So the amount is computed and the payee is not. */
  out.push(
    PN(d('paid')), op(OP.OP_PICK),
    op(OP.OP_8), op(OP.OP_NUM2BIN),
    pushData([0x19, 0x76, 0xa9, 0x14, ...creator, 0x88, 0xac]),
    op(OP.OP_CAT),
    op(OP.OP_CAT),
  )
  for (let i = 0; i < levels; i++) {
    const slot = 'pay' + 'p' + 'abcdefgh'[i]
    out.push(
      PN(d('paid')), op(OP.OP_PICK),                       // +1: the royalty in force
      op(OP.OP_8), op(OP.OP_NUM2BIN),                      // +1: as 8 little-endian bytes
      pushData([0x19, 0x76, 0xa9, 0x14]),                  // +2: varint(25) ‖ DUP HASH160 PUSH20
      op(OP.OP_CAT),                                       // +1
      PN(d(slot) + 1), op(OP.OP_PICK),                     // +2: ⚠ +1 for the item being held
      op(OP.OP_CAT),                                       // +1
      pushData([0x88, 0xac]),                              // +2: EQUALVERIFY CHECKSIG
      op(OP.OP_CAT),                                       // +1: the finished output
      op(OP.OP_CAT),                                       // +0: onto the accumulator
    )
  }
  return out
}

/**
 * Depth of a name BEFORE the program runs — measured against the one contract above, plus the preimage
 * the unlocking script pushes last. ⚠ Never a hand-written number.
 */
function depthOf(_probe: any, name: string): number {
  const pre: string[] = [...ANCHOR_UNLOCK, 'preimage']
  const i = pre.lastIndexOf(name)
  if (i < 0) throw new Error(`anchorFrame: no '${name}' in the unlocking contract`)
  return pre.length - 1 - i
}

/**
 * ⚠⚠ THE CIRCULAR OFFSET, resolved the only way it can be.
 *
 * `fieldOffset` is where field zero's DATA begins inside the scriptCode — and BIP143 puts the
 * scriptCode's own varint LENGTH in front of it, so the offset depends on how long the finished script
 * is, and the script is not finished while you are computing it. ⇒ Build once with a probe, measure,
 * build again. `buildBasicLock` and `buildShellLock` do the same, for the same reason.
 */
export function buildAnchorLock(p: AnchorFrameParams): any {
  const probeLen = new LockingScript(anchorLockOps({ ...p, fieldOffset: 1 }).ops).toBinary().length
  const varInt = scriptCodeVarIntSize(probeLen)
  return new LockingScript(anchorLockOps({ ...p, fieldOffset: varInt + 1 }).ops)
}
