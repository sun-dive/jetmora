// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE ANCHOR COVENANT, WRITTEN IN BITCOIN BASIC.
//
// ⚠ LICENCE BOUNDARY, stated once. An anchor IS a BSV transaction, so building it with the Open BSV v6
//   BASIC compiler is use ON BSV and is within that licence. ⇒ The compiler stays in `grafverse`; this
//   SOURCE is jetmora's under Apache-2.0, and the compiled script is an artifact of it.
//   ⚠⚠ jetmora's OWN entry covenants do NOT run on BSV. The compiler must never be used for those.
//
// ── WHAT THIS SAYS, AND WHAT THE FRAME SAYS ───────────────────────────────────────────────────────
// `racerDepotSrc` is explicit that a frame's job is the part BASIC cannot say — *"the preimage fields,
// the owner burn and the output binding are not things BASIC can say"*. Same split here:
//
//   BASIC (this file)   the STATE and the ARITHMETIC — monotonicity, depth, the royalty carry,
//                       the fork rule, and the trunk/branch asymmetry
//   the frame           OP_PUSH_TX, `hashOutputs`, the owner CHECKSIG, and serializing the payees
//
// ── THE STATE, AND WHY EACH FIELD IS IN THE SCRIPT RATHER THAN A DOCUMENT ──────────────────────────
//
//   depth      0 ⇒ THE TRUNK. Inalienable, and it alone carries the price lever.
//              >0 ⇒ a BRANCH, its royalty frozen at the point it forked.
//              ★ One field, two jobs — it is also the shift register's index.
//              ⚠⚠ THERE IS NO TRANSFER OPERATION ANYWHERE IN THIS COVENANT. A buyer cannot be given
//              a log; they REPLICATE one, themselves, permissionlessly. The holder plays no active
//              role because there is nothing to consent to — out0 comes back untouched.
//   treesize   strictly increasing ⇒ a branch CANNOT REWIND. §4d equivocation, prevented in script
//              rather than detected after the fact.
//   royalty    what THIS branch pays, per anchor, per payee. Quine state ⇒ it replicates forward,
//              so a later change on the trunk can never reach a branch that already exists.
//   forkable   fixed at genesis. ⇒ In a quine THE GENESIS IS THE RULE, because the rule is what
//              replicates. Not a flag anyone can decline to honour.
//
// ⚠ The payee shift register is N slots wide, N fixed at genesis, PRE-FILLED WITH THE CREATOR. That
//   pre-fill is not tidiness: it makes the output count CONSTANT at every depth, so `hashOutputs` pins
//   one fixed shape instead of N of them.

/** ⚠ DIM widths are 1–75. 76 makes OP_PUSHDATA1 shift every offset (BASIC.md). */
export const ANCHOR_LEVELS_DEFAULT = 3

/**
 * ★ A BASIC → BASIC generator, which is the sanctioned way to parameterise: rewrite the PROGRAM and
 * hand it to the untouched faithful compiler. ⚠ NOT an opcode rewriter — *"the script then says what
 * no program says, and the reader shows soup"*.
 *
 * @param levels  N — how many ancestors an anchor pays, besides being fixed forever at genesis.
 */
export function anchorSrc(levels = ANCHOR_LEVELS_DEFAULT) {
  if (!Number.isInteger(levels) || levels < 1 || levels > 8) {
    throw new Error(`levels must be 1..8, got ${levels}`)
  }
  // ⚠ Identifiers take LETTERS ONLY — `p1` is refused, correctly (BASIC.md). Hence pa, pb, pc…
  const slot = i => 'p' + 'abcdefgh'[i]

  const dims = Array.from({ length: levels }, (_, i) => `DIM ${slot(i)}$20`).join('\n')

  // ★★ The CHILD's payees: the forker enters at slot 0 and the oldest falls off the end. ⚠ Not
  //    selector arithmetic any more — this block only ever describes a child, and the frame binds it
  //    to out1 only when a fork is happening. Simpler, and it says exactly one thing.
  const shifts = Array.from({ length: levels }, (_, i) =>
    i === 0 ? `child${slot(0)} = forker` : `child${slot(i)} = ${slot(i - 1)}`,
  ).join('\n')

  return `
REM ═══ THE ANCHOR'S STATE ═════════════════════════════════════════════════
REM  ⚠⚠ depth AND forkable ARE TWO BYTES WIDE, NOT ONE, AND THE REASON IS THE
REM  PUSH ENCODING RATHER THAN THE RANGE. A fixed-width 1-byte field holding
REM  0..16 serialises as a 1-byte push, which MINIMAL-PUSH says must be OP_0
REM  or OP_1..OP_16 instead. @bsv/sdk's interpreter refuses it in a LOCKING
REM  script; whether a real node does is UNTESTED — and this project already
REM  knows that everything it believes about opcodes comes from a JavaScript
REM  reimplementation. ⇒ Two bytes costs ~2 B and removes the dependency on
REM  the answer, which is worth more than being right about a contested rule.
REM  depth is the trunk/branch discriminator AND the shift register's index.
REM  ★★★ genesis — the BRC-113 TOKEN ID of this log:
REM    SHA256(genesisTxId ‖ outputIndex LE ‖ immutableChunkBytes)
REM  ⚠⚠ A $ FIELD, NOT %. A hash is RAW BYTES, not a number — round-tripping
REM  32 bytes through BIN2NUM/NUM2BIN is not identity: Script numbers are
REM  sign-magnitude, so a high bit in the top byte reads NEGATIVE and leading
REM  zeroes normalise away. It would have compiled clean and corrupted the
REM  identity of any log whose token id happened to end in a byte >= 0x80.
REM  ⚠ Same for the payee slots below: a hash160 is not a number either.
REM  ⚠ Replicated unchanged into every branch forever, so a tip is recognisable
REM  from ONE OUTPUT with no walk back to the root. ⇒ And the BRC-113 split is
REM  the quine's split exactly: immutableChunkBytes here, tokenAttributes in
REM  the mutable fields below.
DIM genesis$32
DIM depth%2
DIM treesize%8
DIM royalty%4
DIM forkable%2
${dims}

REM ═══ TWO SPEND PATHS, AND ONLY ONE NEEDS A KEY ═════════════════════════
REM  ANCHOR  extend this branch. ⚠ The frame checks the owner's signature,
REM          because SCRIPT CANNOT VALIDATE A ROOT — a root is asserted, not
REM          determined, so the covenant authorises the anchorer instead.
REM  FORK    ★ replicate to yourself, PERMISSIONLESSLY. No signature. The
REM          parent plays no active role because there is nothing to consent
REM          to: out0 comes back COMPLETELY UNCHANGED.
REM  ⇒ This is BRC-226's structure. Its counter is permissionless because
REM  n → n+1 is determined; forking is permissionless because the covenant
REM  forces the parent out unharmed.
VERIFY children >= 1
VERIFY children <= 1 + forkable
forking = children - 1

REM ═══ NO REWIND — ON AN ANCHOR ═══════════════════════════════════════════
REM  A tree only grows. ⚠ But a FORK does not grow it: out0 is returned
REM  identical, so treesize must be UNCHANGED there, not greater.
REM  ⇒ Both said as assertions rather than branches, so a spend that tries to
REM  shrink the log produces NO ANCHOR rather than a wrong one.
grew = newtreesize - treesize
VERIFY grew >= 0
VERIFY grew * forking = 0
VERIFY grew + forking >= 1

REM ═══ THE TRUNK IS INALIENABLE ═══════════════════════════════════════════
REM  ⚠ A buyer can NEVER hold the trunk. They replicate it as a branch, and
REM  they do it themselves — so a sale IS a fork, performed by the BUYER.
REM  There is no transfer operation anywhere in this covenant.
trunk = 0
IF depth = 0 THEN trunk = 1

REM  ⇒ Only the trunk may move the price, and only for anchors and branches
REM  that come AFTER. An existing branch carries its own royalty forward in
REM  its own script, so a change here can never reach it. THAT is what makes
REM  an updatable price safe where a global fee floor was not: the quine
REM  makes the amendment non-retrospective.
REM  ★ And the price is the SPAM CONTROL — a permissionless fork costs real
REM  sats, so abuse prices itself out. One lever, two jobs.
newroyalty = royalty
IF trunk = 1 THEN newroyalty = wantroyalty
VERIFY newroyalty >= 1
VERIFY forking * (newroyalty - royalty) = 0

REM ═══ ⚠ THE FORKER PAYS — BUT NOT IN THIS FILE ═════════════════════════
REM  A fork costs real satoshis and every one comes from the BUYER, so the
REM  parent must come out WHOLE. ⚠⚠ THAT RULE LIVES IN THE FRAME, NOT HERE:
REM  V is read out of the PREIMAGE, which BASIC cannot see. Declaring V and
REM  newv on this program's stack made the compiler measure depths for two
REM  values the frame never pushes, and every OP_PICK after them was wrong.
REM  ⇒ Same split the depot uses. See anchorFrame.mts.

REM ═══ DEPTH ══════════════════════════════════════════════════════════════
REM  ⚠ The PARENT keeps its depth — out0 is unchanged. It is the CHILD that
REM  descends, and the child's state is what the shift below builds.
childdepth = depth + 1

REM ═══ THE LINEAGE SHIFT REGISTER ═════════════════════════════════════════
REM  N slots, pre-filled with the creator at genesis, so the payee count is
REM  CONSTANT at every depth and hashOutputs pins one shape.
REM  ⚠ These are the CHILD's payees. The parent's are untouched.
${shifts}

REM ═══ ⚠⚠ WHAT THE SUCCESSOR ACTUALLY CARRIES ════════════════════════════
REM  ⚠⚠⚠ THE REBUILD GATHERS THE DIMMED NAMES **BY NAME**. A value computed
REM  into a fresh variable is a value the successor never sees — the script
REM  compiles clean and rebuilds the state UNCHANGED, so the log can never
REM  grow. Caught by reading the script back, not by any test.
REM  ⇒ So the last thing this program does is ASSIGN TO THE FIELDS.
REM
REM  ★ And one assignment covers both paths: on a fork the VERIFY above has
REM  already forced newtreesize = treesize, so this is a no-op there and an
REM  advance on an anchor. No branch, no second program.
treesize = newtreesize
royalty  = newroyalty

REM  ⚠ depth is NOT reassigned — out0 is the PARENT and keeps its depth. The
REM  child descends, and childdepth above is what the frame binds to out1.
REM  ⚠ forkable is never recomputed at all. It replicates unchanged into BOTH
REM  outputs, which is the entire point: a fork cannot relax its own rules.
REM  ⚠⚠ Nor is genesis. A covenant that could rewrite its own token id could
REM  claim to be a different log — which is the one thing identity must refuse.
`.trim()
}

/**
 * The names the frame must leave on the stack, bottom first.
 * ⚠⚠ ORDER IS THE INTERFACE — the compiler measures every depth against this list, so a name in the
 *    wrong place builds, runs, and compares the wrong bytes hundreds of opcodes later.
 */
export const ANCHOR_STACK = [
  'forker',       // ★ hash160 of whoever is replicating. Enters the child's register at slot 0.
                  //   ⚠ On a plain anchor nothing reads it — but the model must know it is there.
  'wantroyalty',  // what the spender asks the royalty to become. ⚠ ignored unless this is the trunk
  'children',     // how many covenant outputs this spend creates — the frame counts them
  'newtreesize',  // the tree size being anchored (⚠ equal to treesize on a fork)
]
