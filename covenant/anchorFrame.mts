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
export const ANCHOR_UNLOCK = [
  'sig', 'pub', ...ANCHOR_STACK, 'spenderOutputs', 'newValue',
] as const

/**
 * ⚠ SIGHASH_ALL | FORKID. NOT ANYONECANPAY.
 *
 * The anchor path binds every input, deliberately. ⚠ Under ANYONECANPAY `hashPrevouts` is zeroes, so a
 * signature would be replayable against a different funding set — and this signature is the ONLY thing
 * standing between the log and anyone anchoring anything.
 * ⏭ The FORK path will want ANYONECANPAY, because a forker must be able to add their own funding to
 *   somebody else's tip without invalidating anything. ⇒ Two paths, two scopes, and that is a real
 *   design consequence rather than an oversight.
 */
export const ANCHOR_SCOPE = 0x41

export interface AnchorFrameParams {
  /** One entry per DIM, by name: genesis, depth, treesize, royalty, forkable, and the N payees. */
  state: Record<string, number | number[]>
  /** N — lineage levels. ⚠ Fixed at genesis; it changes the script's SHAPE, not just its contents. */
  levels: number
  /** hash160 of the key that may anchor this branch. */
  owner: number[]
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
  /** ⚠ The most an anchor may pay a miner. NO DEFAULT — the covenant's whole drain surface. */
  maxFee: number
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
  if (p.owner.length !== 20) throw new Error(`the owner must be a 20-byte hash160, got ${p.owner.length}`)
  if (p.creator.length !== 20) throw new Error(`the creator must be a 20-byte hash160, got ${p.creator.length}`)

  /* ⚠ The BASIC program's own stack contract, plus the two the frame's value rule and output binding
     reach for. Depths are read from the compiler's model BY NAME below — never counted by hand, which
     is what this project's predecessors did and it cost three bugs in one sitting. */
  /* ⚠⚠ 'preimageCopy' IS NAMED IN THE COMPILER'S MODEL, not left as an anonymous extra item.
     `extractScriptCodeFieldOps` CONSUMES the preimage, and the fork path needs it a second time to
     copy the parent's own script. ⇒ So a copy is kept — and because the compiler is told about it,
     every depth after this point is still measured BY NAME rather than adjusted by hand.
     ★ Naming it is the difference between a stack the model describes and one it merely tolerates. */
  const probe: any = compileState(anchorSrc(p.levels), {
    fieldOffset, stack: [...ANCHOR_UNLOCK, 'preimageCopy'],
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

    /* ── ★★ AUTHORISE THE ANCHORER — BUT ONLY ON THE ANCHOR PATH ────────────────────────────────
       ⚠⚠ FIRST, and adjacent to nothing else. *"Security state must not cross bytes you do not
       control"* — the check happens before any attacker-supplied byte has been touched and its
       result is consumed immediately rather than stashed.

       ★★★ AND IT IS CONDITIONAL, WHICH IS THE WHOLE POINT OF THE DESIGN.
         ANCHOR  needs the owner's key, because SCRIPT CANNOT VALIDATE A ROOT — a root is asserted,
                 not determined, so the covenant authorises the anchorer instead.
         FORK    needs NOTHING. A buyer replicates to themselves, permissionlessly, and the holder
                 plays no part because out0 comes back untouched.

       ⚠ Expressed as ARITHMETIC, not a branch: `authOk OR forking`. Both paths leave one item, so
         there is nothing to balance — the same trick the BASIC uses for its own selectors. */
    PN(depthOf(probe, 'pub')), op(OP.OP_PICK),
    op(OP.OP_HASH160), pushData(p.owner), op(OP.OP_EQUAL),         // +1  ownerOk
    PN(depthOf(probe, 'sig') + 1), op(OP.OP_PICK),                 // +2  sig
    PN(depthOf(probe, 'pub') + 2), op(OP.OP_PICK),                 // +3  pub
    op(OP.OP_CHECKSIG),                                            // +2  sigOk
    op(OP.OP_BOOLAND),                                             // +1  authOk
    PN(depthOf(probe, 'children') + 1), op(OP.OP_PICK),            // +2
    op(OP.OP_1), op(OP.OP_SUB),                                    // +2  forking = children − 1
    op(OP.OP_BOOLOR), op(OP.OP_VERIFY),                            //  0

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
    /* ⚠ THE ANCHOR PATH pays its own fee out of the covenant, so the floor is V − maxFee.
       ⏭ THE FORK PATH WILL NEED `>= V` INSTEAD: a forker must leave the parent WHOLE, because every
         satoshi a fork costs comes from the buyer and none from the holder. ⇒ Two paths, two floors,
         and this is the line that will branch when the fork path lands. */
    PN(d('newValue')), op(OP.OP_PICK), op(OP.OP_BIN2NUM),    // +1  what the spender claims
    op(OP.OP_FROMALTSTACK),                                  // +2  V, from the preimage
    /* ★★★ THE FORKER PAYS, THE HOLDER NEVER DOES. On a fork the allowance is ZERO — the parent must
       come out WHOLE — and on an anchor it is maxFee, which the covenant spends on its own miner fee.
       ⇒ `maxFee × (1 − forking)`, written branch-free as `maxFee × (2 − children)`.
       ⚠ Without this a forker could fund their own replication out of the holder's value, which would
       make "the holder plays no active role" a description of a theft. */
    PN(p.maxFee),                                            // +3
    PN(d('children') + 3), op(OP.OP_PICK),                   // +4
    op(OP.OP_2), op(OP.OP_SWAP), op(OP.OP_SUB),              // +4  (2 − children)
    op(OP.OP_MUL), op(OP.OP_SUB),                            // +2  V − allowance
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
    ...childOps(d, probe.layout, fieldOffset, p.levels),

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
function childOps(d: (n: string) => number, layout: any[], fieldOffset: number, levels: number): any[] {
  const w = (n: string) => layout.find((f: any) => f.name === n).width
  const HEAD = fieldOffset + w('genesis') + 1            // …through depth's own push opcode
  const MID = ['treesize', 'royalty', 'forkable'].reduce((a, n) => a + 1 + w(n), 0)
  const PAY = levels * (1 + w('pa'))
  const slots = Array.from({ length: levels }, (_, i) => 'child' + 'p' + 'abcdefgh'[i])

  const body: any[] = [
    PN(d('preimageCopy')), op(OP.OP_PICK),               // +1  ⚠ a COPY — the first extraction ate it
    ...extractScriptCodeFieldOps(),                      // +1  the parent's scriptCode, again
    PN(HEAD), op(OP.OP_SPLIT),                           // +2  head ‖ rest
    PN(w('depth')), op(OP.OP_SPLIT), op(OP.OP_NIP),      // +2  ⚠ the OLD depth dropped here
    PN(MID), op(OP.OP_SPLIT),                            // +3  head, mid, rest
    PN(PAY), op(OP.OP_SPLIT), op(OP.OP_NIP),             // +3  ⚠ the OLD payees dropped here
    op(OP.OP_TOALTSTACK), op(OP.OP_TOALTSTACK),          // +1  alt: [.., suf, mid]
    /* head ‖ depth+1 */
    PN(d('childdepth') + 1), op(OP.OP_PICK),
    PN(w('depth')), op(OP.OP_NUM2BIN), op(OP.OP_CAT),
    op(OP.OP_FROMALTSTACK), op(OP.OP_CAT),               // ‖ mid, verbatim
  ]
  for (const slot of slots) {
    body.push(
      pushData([w('pa')]), op(OP.OP_CAT),                // the payee's push opcode
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
