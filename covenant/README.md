# The anchor covenant

**Written in Bitcoin BASIC, compiled by the untouched live compiler, and read back through `unbasic`.**

⚠ **Licence boundary.** An anchor IS a BSV transaction, so building it with the Open BSV v6 BASIC
compiler is use *on* BSV. The compiler stays in `grafverse` and is never edited or rebuilt from here;
this source is jetmora's under Apache-2.0. ⚠⚠ jetmora's own entry covenants do **not** run on BSV — the
compiler must never be used for those.

## What it enforces

| ★ **the trunk is inalienable** | there is **no transfer operation**. A buyer cannot be *given* a log; they **replicate** one themselves |
| ★★ **forking is permissionless** | no signature. out0 comes back **completely unchanged**, so the holder plays no role — there is nothing to consent to |
| ⚠ **the forker pays** | the royalties, the child's value and the fee. `newv >= V` ⇒ the parent comes out **whole** |
| **anchoring is not** | ⚠ it needs the owner's key, because **script cannot validate a root** — a root is *asserted*, not determined |
| **no rewind** | `treesize` only grows, and a fork must leave it **unchanged** |
| **the fork rule replicates** | `forkable` is never recomputed ⇒ **a fork cannot relax its own rules** |
| **lineage** | N payees, N fixed at genesis, **pre-filled with the creator** so the output count is constant at every depth |

## Size — measured, not estimated

| N | total | ops |
|---|---|---|
| 1 | 261 B | 209 |
| 2 | 279 B | 223 |
| 3 | **297 B** | 237 |
| 5 | 333 B | 265 |

⇒ **18 B per lineage level.** ⚠ This is the state machine only; the `OP_PUSH_TX` frame is separate and
is the larger half.

## Identity — BRC-113's model, not its encoding

★★★ The `genesis` field is the **BRC-113 Token ID**: `SHA256(genesisTxId ‖ outputIndex LE ‖
immutableChunkBytes)`. ⇒ A log's identity is derived exactly as an MPT's is.

★★ And BRC-113's *"Why Only the Genesis Transaction"* is this design's §6.1a arriving independently:
prove the genesis with a merkle proof and **one** block header, and every later spend is implicitly
valid because miners enforced the UTXO chain. ⇒ **One block header, ever.**

⚠ Where it differs: BRC-113 uses P2PKH + OP_RETURN. Ownership here is a covenant, which is what adds
the royalties and the fork rule — enforcement BRC-113 does not require. ★ But its immutable /
`tokenAttributes` split **is** the quine's split: `genesis` and `forkable` replicate untouched;
`treesize` and `royalty` are the mutable half.

⚠⚠ **The genesis is not a separate format.** In a quine the genesis IS the covenant at its initial
state — depth 0, treesize 0. A first instance of a different shape would leave the replication rule
with nothing to replicate.

## ⚠ What reading it back caught — TWICE

**1 · The wrong successor.** The compile was green at 295 B and built the **wrong successor**: `newtreesize` never reached the state,
because the rebuild gathers the DIMmed names **by name** and every value had been computed into fresh
variables it had never heard of. ⇒ **The parent would have come out unchanged on every anchor — the log
could never have grown.** No test would have said so. The listing did.

★ Hence the last thing the program does is assign to the fields, and one assignment covers both paths:
a fork has already been forced to `newtreesize = treesize`, so it is a no-op there and an advance on an
anchor. **No branch, no second program.**

**2 · ⚠⚠ `%` where `$` was needed.** The token id and the payee hashes were DIMmed as NUMERIC fields, so
the rebuild emitted `NUM2BIN(BIN2NUM(x), 32)`. **Round-tripping a hash through a Script number is not
identity** — numbers are sign-magnitude, so a high bit in the top byte reads NEGATIVE and leading zeroes
normalise away. ⇒ It compiled clean and would have corrupted the identity of any log whose token id
ended in a byte ≥ 0x80. ★ The fix is also **24 B smaller**: the bug was spending bytes to corrupt data.

## Running it

```
npx tsx covenant/compile.mts      # sizes
npx tsx covenant/read-back.mts    # ⚠ the listing — read this before minting anything
```

---

## ✅ THE FRAME — WORKING, 11/11 through the script interpreter

**`covenant/anchorFrame.mts` · `covenant/anchor-spend-test.mts` · 1,072 B at N=3. ⚠ Nothing minted.**

| ★★★ anchor 1 spends the genesis · anchor 2 spends anchor 1 | the chain runs |
| ⚠ a **stranger** cannot anchor | not just anyone may assert a root |
| ⚠ the tree cannot **stand still** on an anchor | no no-op spends |
| ★★ royalties cannot be **omitted** | |
| ★★★ the royalty cannot be **REDIRECTED** | ⇒ the attack someone would actually try |
| ★★★ the royalty cannot be **SHORT-PAID** | |
| ⚠ the covenant cannot be **drained** past its floor | |
| ★★ a **non-forkable** log refuses a second covenant output | |

### ⚠⚠ Two bugs the working acceptance case exposed

**1 · `fieldOffset` was `varInt`, not `varInt + 1`.** I copied `buildBasicLock`'s first two lines **and
its comment** but not its answer — the field's own one-byte push opcode. ⇒ Costs nothing at build time
and everything at the LAST opcode: the peel reads a byte early, every field shifts, and the only symptom
is the final `OP_EQUAL` returning false. ★ The depot's hardcoded `fieldOffset: 4` is exactly
`varint(3) + 1`, which is how it was found.

**2 · ★★★ BINDING IS NOT ENFORCING.** The first version took the serialized royalty outputs from the
UNLOCKING SCRIPT and folded them into the hash. They could not be *altered* — and nothing required them
to be *present*. A spender pushing nothing, with no royalty outputs, satisfied it perfectly.
⇒ **The covenant now BUILDS them** from its own payee fields and its own royalty.
⚠⚠ **It was invisible until the acceptance case passed**, because the refusal had been "passing" for
the wrong reason all along — the unlocking script never parsed. ⇒ Bootcamp rule 2, from the inside.

★ `paid` and `paypa…` exist because of the compiler's coalescing: the shift consumes the names it
reads, so after `childpb = pa` the name `pa` is gone and `pc` falls off the end. **The frame pays the
PARENT's payees, so it needs aliases taken before the shift.**

★★ The output shape follows Phar Lap's proven `replicateTailV2Ops` — `value8 ‖ 0x19 76 a9 14 ‖ hash160
‖ 88 ac`, with `OP_8 OP_NUM2BIN` for the value — rather than a fresh invention. His call: *"we already
have this function working in Phar Lap."*

---

### ⚠ What the frame work turned up

★★★ **@bsv/sdk's `Spend` is STRICTER THAN THE NETWORK on minimal push.** `compileState` and `PN` emit
`{op:1,data:[n]}` for small numbers rather than `OP_1..OP_16`. ⇒ **Checked against the chain: the live
battery genesis `18e31936…` carries 145 such pushes, values 0–16, mined 1,600+ blocks deep.**
⚠ So the test sets `verifyFlags: ['UTXO_AFTER_CHRONICLE']` — matching consensus, not relaxing a real
rule. The alternative was rewriting compiler output, which BASIC.md forbids outright.

★ **`depth` and `forkable` are 2 bytes, not 1** — a fixed-width 1-byte field holding 0–16 serialises as
a non-minimal push. Two bytes costs ~2 B and removes the dependency on a contested rule.

⚠ **The value rule belongs to the FRAME, not to BASIC.** `V` is read from the preimage, which BASIC
cannot see. Declaring `V`/`newv` on the program's stack made the compiler measure depths for two values
the frame never pushes, and **every `OP_PICK` after them was wrong.**

⚠ **Three of my own errors on the way in, all the same shape** — a hand-rolled `{op: len, data}` where
102 means `OP_IF`; `PN` where an unlocking script needs a truly minimal push; a **double** sha256 handed
to `sign()` where one was wanted. ⇒ Each fails silently and far from its cause.
