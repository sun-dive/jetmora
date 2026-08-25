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

---

## 👁 READ BACK — what the decompiler confirmed, and what it exposed

`npx tsx covenant/read-back.mts` ⇒ **the whole lock, frame included**, 640 chunks in ~49 lines.

**Verified by reading, not by assertion:**

| the signature gate | `VERIFY SAMEBYTES(HASH160(pub), &H7777…)` then `VERIFY CHECKSIG(sig, pub)` — ★ first, before any attacker byte is touched |
| `OP_PUSH_TX` | `VERIFY PUSHTX(preimage)` |
| ★ **the value floor** | `VERIFY BIN2NUM(newValue) >= BIN2NUM(t3) - 400` ⇒ `t3` is `V`, read 52 bytes from the end |
| ★★★ **the successor** | `genesis` raw · **old** depth · **new** treesize · **new** royalty · **old** forkable · the **parent's** payees |
| ★★★ **each royalty** | `NUM2BIN(paid,8) ‖ P2PKH_HEAD ‖ payee ‖ P2PKH_TAIL` — ⇒ Phar Lap's exact shape |
| **`fieldOffset`** | `SPLIT(SCRIPTCODE(preimage), 4)` ⇒ **4**, visibly correct now |

### ⚠⚠ And a finding about the READER, not the covenant

The P2PKH template rendered as **`346650137`** and **`-11400`**. Both correct — `19 76 a9 14` and
`88 ac` — and both **illegible**. ⇒ Nobody reads a royalty payment out of a decimal.

★ **A correct rendering that cannot be read defeats the thing the reader was built to serve.** Same
failure the runbook records for shape-matched idioms, from the other direction: there a **wrong name**,
here **no name at all**.

⇒ Fixed in `covenant/anchorIdioms.mts`. `unbasicListing` takes `idioms` as a PARAMETER, so this lives
in jetmora — ⚠ **grafverse is not touched and no bundle is rebuilt.** Both are `exact`, never
shape-matched, because a four-byte push of anything else must not be announced as a P2PKH template.

### ⏭ Loose ends, recorded rather than smoothed over

⚠ **`childdepth` is DEAD on the anchor path** — computed, left on the stack, never read. Costs a few
bytes per anchor and becomes live on the fork path.

⚠ **The listing renders the value rule (470) before `childdepth` (480)**, though the frame appends it
after the compiled program. Both are independent, the spend test is 11/11, and nothing depends on the
order — but **it is not yet explained**, and "it passes and I do not understand the listing" is exactly
where a bug hides.

---

## ⚠⚠ THE CREATOR WAS BEING EVICTED — found 25 Aug, by his Phar Lap remark

**A shift register drops its oldest entry. Mine was dropping the creator.**

```
genesis  [C, C, C]        C = the log's creator
fork 1   [f1, C, C]
fork 2   [f2, f1, C]
fork 3   [f3, f2, f1]     ⚠⚠ THE CREATOR IS GONE, PERMANENTLY
```

⇒ **After N forks the original creator stopped being paid, forever** — silently contradicting the one
rule the whole design rests on. The tests were 11/11 at the time, because none of them forked.

★★★ **The fix is structural rather than logical: the creator's payee is a BAKED LITERAL.** It cannot
be shifted out because it is not in the register. ⚠ The VALUE is still computed — the trunk may change
the royalty, and baking that would freeze the price at mint — so **the amount is computed and the payee
is not.**

★ His pattern, from Phar Lap: **convert what cannot change into an absolute at the edge, and let the
covenant stay simple.** ⇒ One push instead of a reconstruction, and it reads better too:

```
CAT(NUM2BIN(paid, 8), &H1976a914 c1c1…c1c1 88ac)      ← the whole payee, visible
```

### ⚠ Correcting the record on Phar Lap's two covenants

`replicateTailV2Ops` computes `⌊P × pBps / 10000⌋` in script with `OP_MUL`/`OP_DIV` and notes that the
*"reseller absorbs integer-division dust."* ⇒ **v2 NEVER WENT INTO PRODUCTION — v1's approach made it
obsolete** (his words). So it is dead code, not a newer generation, and must not be used as a reference.

★★ **This covenant reached the same answer independently: `OP_DIV` count is ZERO.** No division, so no
rounding and no dust. The three `OP_MUL`s are 0/1 selector multiplications, which are exact.

**13/13** through the interpreter, now including: ★★★ *the creator cannot be left unpaid* and ★★★ *the
creator's royalty cannot be redirected*.

---

## ✅ THE FORK PATH — 21/21, and the eviction is proved fixed

**1,202 B at N=3. ⚠ Nothing minted.**

★★★ **A stranger forks the log with no owner signature anywhere.** That is the claim the whole design
rests on, now executing.

| ★★★ a **stranger** forks — permissionless | no owner key involved at any point |
| ★★★ a fork cannot take **one satoshi** from the holder | ⇒ *the forker pays, the holder never does* |
| ★★★ a fork **cannot relax its own rules** | `forkable` flipped in the child ⇒ refused |
| ⚠ claiming two children while creating one | refused |
| ⚠ the child must carry the lineage the covenant computed | |
| ★★★ **forked 5 deep with a register of 3** | ⇒ the creator is out of **every** slot and was still paid on all five |

**Both rules read back in one line each:**

```
 10 VERIFY SAMEBYTES(HASH160(pub), &H7777…) AND CHECKSIG(sig, pub) OR children - 1
460 VERIFY BIN2NUM(newValue) >= BIN2NUM(t3) - 400 * (2 - children)
```

⇒ Line 460 *is* the rule: on an anchor the allowance is `maxFee`; on a fork `2 − children = 0`, so the
parent comes out **whole**. ★ Both written as ARITHMETIC rather than branches — the same selector trick
the BASIC uses, so there is nothing to balance.

★★ **The child is COPIED, not rebuilt.** Four `SPLIT`s at offsets **derived from the compiler's layout**
carve the parent's own scriptCode into head · depth · middle · payees · tail; only depth and the payees
are replaced. ⇒ **`genesis`, `forkable` and the covenant code itself are never reconstructed, so there
is nothing to reconstruct them wrongly.** That is why a fork cannot relax its own rules.

### ⚠ Three bugs this path cost, all of them mine

**1 · `extractScriptCodeFieldOps` CONSUMES the preimage.** The second call read the accumulator instead
and produced garbage. ⇒ Fixed by keeping a copy the compiler is TOLD about — `'preimageCopy'` is in its
stack model, so every depth after it is still measured **by name** rather than adjusted by hand.

**2 · The funding input was never signed.** Invisible until a fork was forked, because `Spend` never
serializes the whole transaction — only `prevTx.id()` does.

**3 · The test hardcoded `depth: 1`** in the child, which is right exactly once.

⚠⚠ **And for the second time, four refusals "passed" while the acceptance was broken.** They cannot
count until the matching acceptance is green. That is now twice in one build.

### ⏭ Still open

⚠ `childdepth` is computed by the BASIC unconditionally and only used inside the fork branch — a few
dead bytes on every anchor. Fixing it means touching the program, not the frame.

---

## ✂ `maxFee` REMOVED — his call, 25 Aug

**There is no drain surface, so there is nothing to bound.**

⇒ `maxFee` existed to cap how much of the covenant's OWN value a spend could hand a miner. ★ **That
surface only exists if the covenant pays its own fee — and it never has to.** An anchorer and a forker
both bring a funding input. ⚠ *"If the fee paid is too low the transaction can be rejected"* — the
network already owns that rule, and the covenant was duplicating it **with a constant frozen at mint.**
Same shape as the fee floor and `MAX_MEMORY`, and this project has now met it three times.

| before | `newValue >= V - maxFee * (2 - children)` |
| ★ after | **`VERIFY BIN2NUM(newValue) >= BIN2NUM(t3)`** |

⇒ **The parent always comes out whole**, so *"the forker pays, the holder never does"* stops being a
fork rule and becomes the only rule there is. **11 bytes smaller** — simpler and cheaper at once.

### ⏸ ANYONECANPAY DEFERRED — and the reason is a real hazard

The natural companion is scope `0xc1`, so any funder may add an input. ⚠⚠ But `betaFrame.ts` carries the
warning that matters here:

> *"Under ANYONECANPAY `hashPrevouts` is ZEROES, so a covenant signing that way cannot see which
> outpoint it is spending. **Two instances identical in script AND value AND state would be
> interchangeable.**"*

★★★ **Jetmora can produce exactly those twins.** One forker forking the same parent twice yields two
children with the same `genesis`, `depth`, register and 1 satoshi — **byte-identical covenants.** Under
ANYONECANPAY one preimage satisfies both, so both could be spent in a single transaction against a
single successor output.

⇒ ⚠ **The two changes are INDEPENDENT**, which is why one shipped and one did not: removing `maxFee`
needs only a funding input, not a scope change. **Scope stays `0x41` until a branch has an identity of
its own** — which §4bis.4 already asks for and the covenant still lacks.

**21/21.** 1,191 B at N=3. Nothing minted.

---

## 🆔 BRANCH IDENTITY — 26/26, and ANYONECANPAY unblocked

**`branch` = HASH256 of the parent outpoint a fork consumed.** 1,261 B at N=3. ⚠ Nothing minted.

★★★ **Twins are now impossible by construction.** An outpoint is spendable ONCE, and a parent's tip
moves with every fork, so no two forks ever consume the same one. ⇒ Two children can never be
byte-identical — **proved by forking the same parent state twice with the same forker and comparing
the scripts.**

| ★★★ the child's branch id **cannot be chosen** | it is derived; a supplied one is refused |
| ★★★ two forks of one parent ⇒ **different bytes** | different branch ids, same length |
| ★ the trunk's branch is **zeroes** | depth 0 has no parent outpoint to name |

### ⚠⚠ A MEASURED CORRECTION TO `betaFrame.ts`

> *"Under ANYONECANPAY `hashPrevouts` is ZEROES, so a covenant signing that way **cannot see which
> outpoint it is spending**."*

★★★ **Measured 25 Aug: the BIP143 `outpoint` field at offset 68 SURVIVES ANYONECANPAY INTACT.** Only
`hashPrevouts` and `hashSequence` are zeroed:

```
0x41  hashPrevouts 0bbfaec4…   outpoint 77b0cc44…f7 01000000
0xc1  hashPrevouts 00000000…   outpoint 77b0cc44…f7 01000000   ← unchanged
```

⇒ The warning describes a consequence of **not looking**, not an inability to look. ⚠ It is still right
about the *hazard* — a covenant that ignores its outpoint has interchangeable twins — but the remedy is
available, and this covenant takes it. **grafverse is not edited from here; that comment is his to
amend.**

### ★★ SCOPE IS NOW `0xc1`, AND THE COUPLING IS LOAD-BEARING

⚠⚠⚠ **Safe ONLY because twins are impossible. If the `branch` field is ever removed, the scope must go
back to `0x41` in the same commit.**

⇒ And it is **proved rather than assumed**: the suite adds a **late funder** after the covenant's
unlocking data is fixed, and requires it to be **accepted under `0xc1`** and **refused under `0x41`**.
★ A suite that passes under both scopes says nothing about either — which is what it did an hour ago.

---

## ⚖ BRC-113 OR BRC-226 FOR IDENTITY? — investigated 25 Aug, on his challenge

**Neither is inferior. They answer DIFFERENT HALVES, and the design needs both.**

### ★★★ Why BRC-226 cannot supply identity here

In a quine **the script IS the identity** — and that works because **BRC-226's counter never forks.**
⇒ Two branches of one jetmora log have DIFFERENT scripts: different depth, different register,
different branch id. **"The script is the identity" names a BRANCH, not a LOG.**
⇒ BRC-226 has no answer because the question does not arise on a single line. **BRC-113 does**: a
stable name every branch shares.

### ⚠⚠ CORRECTION — the OP_RETURN comparison was a STRAWMAN (his, same day)

*"If we use BRC-113 we're replacing the OP_RETURN with PushDrop."*

⇒ BRC-113 as written uses OP_RETURN for metadata. **He never would**, and this covenant already does
not — **it is a PushDrop already**: nine pushes then `OP_2DROP` × 4, the state readable by anyone from
the output alone.

★★★ So *"fetching a transaction to learn one bit is absurd"* was aimed at something nobody proposed.
**With PushDrop there is no fetch either way**, and the whole in-the-script-versus-behind-a-hash framing
collapses. ⇒ **The real question is not WHERE the data lives. It is whether the script ENFORCES it:**

| **PushDrop alone** | pushed, dropped, never read ⇒ readable by anyone, ⚠ **but a successor may carry something different and nothing notices** |
| ★ **PushDrop + quine** | the same bytes, PLUS peeled from the preimage and rebuilt into the successor ⇒ **cannot drift** |

**Measured:** `leafcovers` cost **24 B**, of which the push itself is **3 B**.
⇒ **Enforcement costs ~21 bytes per field**, and for an immutable rule it is not optional — *"a fork
cannot relax its own rules"* holds **only because `forkable` is rebuilt**, not merely present.

★ ⇒ **The anchor is three standards, each doing the part it is good at:** BRC-113's identity model ·
PushDrop carriage · BRC-226 enforcement.

### ★★ Why BRC-113 should NOT carry the settings

⚠ The immutable set is about **two bits** — `leaf_hash_covers` and encryption. `N` and `forkable` are
already in the script's shape and fields; the key scheme is derived from key length.

⚠⚠ **AND A CORRECTION: "massively over-engineered" was WRONG on bytes, and the measurement said so.**
A Token ID is **32 bytes whether or not it commits to metadata** — folding `immutableChunkBytes` into
the hash costs ZERO extra script bytes.

| **BRC-113** | 0 extra script bytes · one OP_RETURN at genesis (~40 B once) · ⚠ **a transaction fetch + merkle proof to read one bit** |
| ★ **BRC-226** (taken) | **+24 B on every anchor of every branch** · ✅ **no lookup, ever** |

⚠⚠ **BOTH OF THESE ROWS ARE SUPERSEDED BY THE CORRECTION ABOVE** — they assume an OP_RETURN, and this
design uses PushDrop, so the metadata sits in the locking script under either standard. Kept because
the wrong reasoning is worth seeing next to the right.

⇒ **The rule that actually generalises:** an immutable setting must be **ENFORCED**, not merely
**CARRIED**. Where it lives is settled by PushDrop; whether it can drift is settled by the quine.

### ★★★ And the hybrid dissolves the genesis record

`immutableChunkBytes` exists so that tampering with the metadata breaks the Token ID. ⇒ **The quine
already makes tampering impossible**, so the term is redundant:

```
genesis = SHA256(genesisTxId ‖ outputIndex LE)        ← identity, and nothing else
leafcovers                                            ← a field, replicated unchanged
```

⇒ **§4bis's separate genesis record disappears.** There is no OP_RETURN to publish, nothing to fetch,
and nothing that can be lost or disagreed with.

**26/26.** 1,285 B at N=3. Nothing minted.

---

## ⚠⚠⚠ THE SALE MODEL WAS BROKEN — found 25 Aug, by his question about a compromised owner key

**A fork COPIED the parent's suffix verbatim, and the owner literal lived there.**
⇒ Measured: byte **162**, with the state region ending at ~156. **The child inherited the seller's
ADDRESS**, so:

⚠ **"Inherited the key" was my wording and it was wrong — corrected on his challenge.** What a script
holds is a **hash160: a wallet address.** ★ **A PRIVATE KEY NEVER APPEARS IN ANY SCRIPT**, locking or
unlocking. The spender supplies a public key and a signature at SPEND time, and the covenant checks
`HASH160(pub) == owner` before `CHECKSIG`.

⇒ **Audited, not asserted** — every data push in the lock: `20 B × 4` hash160 **addresses** ·
`32 B × 3` hashes · `33 B × 4` which are **`OP_PUSH_TX`'s own public constants** (`Q = a·G`), all four
matched against `pushTxConstants` and none of them anyone's key. **Public keys belonging to a person:
zero. Private keys: zero.**

⇒ The consequence was still real — only the holder of the private key behind that address could anchor
the child, and that was the seller — but **nothing secret was ever exposed.**

| ★★★ **a buyer could not anchor the branch they replicated** | the seller still owned it ⇒ *"a buyer replicates the log to themselves"* was false |
| ⚠⚠ **a compromised owner could not be escaped by forking** | the child inherits the compromise ⇒ **there was NO recovery path at all** |

⚠ Nothing in 26 tests caught it, because **nothing had ever tried to anchor a child.**

### ★ And his warning about rotation REVERSED my recommendation

I proposed making the owner rotatable. ⇒ **He was right that it opens a vector:** with a rotation path,
an attacker who steals the key **rotates first** and locks the owner out permanently. Without one, both
can anchor — bad, but survivable.

**⇒ The fix gives the buyer control WITHOUT giving anyone a rotation path:**

| **FORK** | the child's owner = **the forker**, substituted with the register ⇒ the buyer owns their replica |
| **ANCHOR** | the owner is carried **VERBATIM** ⇒ ⚠⚠⚠ **there is no rotation path, on purpose** |

★★★ So *"sale = fork"* is now literally true — **forking is the ONLY way an owner ever changes** — and
**forking is the recovery** for a compromised key: abandon the branch, keep the history, and the
attacker's branch still pays the creator.

⇒ **30/30**, including: the forker CAN anchor · the seller CANNOT · the owner cannot be rotated · the
child's owner cannot be chosen freely. 1,314 B at N=3.

### ✅ THE SLIDING WINDOW IS CORRECT — his call, and it closes my "laundering" concern

I called this a weakening. ⇒ **It is the design**: *"the N list of ancestors gets shuffled along on
every fork."*

```
forked 5 deep, register: 532643 532643 532643      ← the window slid, as it should
```

★★ **The register is a WINDOW, not a debt ledger.** A depth-10 branch genuinely has different recent
ancestors than a depth-3 one, so nothing is escaped — and a self-forker pays real satoshis **and buries
their own depth permanently** to move the window. ⇒ Self-moderating, the same shape as BRC-226's crumb.

★★★ **And the property that makes it plainly right:**

> **PAYMENT is a window. PROVENANCE is the whole chain.**

⇒ The anchor chain records **every fork, forever**, so a branch at any depth still walks back to the
creator through every intermediate. **Bounded cost, unbounded provenance.**

⚠ ⇒ So `N` is a **POLICY** choice — how far back payment reaches — **not a security parameter.** That
makes freezing it at genesis far less fraught than I had it.

★ And the creator being a baked literal is what anchors the whole thing: the window may slide off every
intermediate, but **it can never slide off the origin.**

### ⏭ STILL OPEN BEFORE A MINT

· **Split keys / multisig for `owner`** — ⚠ his suggestion, and it needs **NO covenant change at all**:
  the field holds a hash160, so it may as well be the hash of a multisig script as a P2PKH address.
  ⇒ *"Making the attack much more difficult"* is free here.
· **A dry-run genesis mint** — build the real transaction locally, read it back, and look at every
  value that is about to become permanent. ⚠ No key needed, nothing broadcast.

---

## 🔑 SPLIT KEYS — n-of-n owners, 35/35

**His call: *"split keys or multikeys, making the attack much more difficult."*** ⇒ Harden the key
rather than make it easier to REPLACE, because a rotation path is itself an attack vector.

⚠ **A correction first — I had conflated two things:**

| **split keys** (threshold / aggregated signing) | the chain sees ONE pubkey and one signature ⇒ genuinely **zero covenant change** ⚠ but needs MuSig/FROST-style signing, absent from `@bsv/sdk` |
| ★ **multisig** (n distinct keys) | **DOES** need a covenant change — the auth path did exactly one `HASH160` and one `CHECKSIG`. ⇒ And it is the one **testable today**, so it is what was built |

**n-of-n, all required.** `owners: 1` is the plain case and compiles to what a single owner always did.

| 1-of-1 | **1,314 B** |
| ★ 2-of-2 | **1,377 B** ⇒ a second key costs **63 bytes** |

⇒ **Tested through the interpreter, not merely assembled** — ⚠⚠ *"it assembles"* is the exact trap that
bit twice today, and this is the AUTH path:

| ★★★ both keys sign | the anchor stands |
| ★★★ the **cold** key missing | **REFUSED** |
| ★★★ the **hot** key missing | **REFUSED** — stealing one is not enough |

⚠ `n` is frozen at genesis: it changes the script's SHAPE, not its values.

### ★ And a property that fell out: CONTROL and PAYMENT are separable

The forker now supplies the child's owner hashes **explicitly**, rather than the covenant substituting
their royalty address. ⇒ **A buyer may put a COLD key in charge of the branch while royalties flow to a
hot one.** The covenant does not check it — the forker is the one spending, and nobody else has an
interest in who controls their own replica.

### 👁 And it reads back as one line

```
530 VERIFY SAMEBYTES(HASH160(pub0), t35) AND CHECKSIG(sig0, pub0)
       AND (SAMEBYTES(HASH160(pub1), t39) AND CHECKSIG(sig1, pub1))
       OR children - 1
```

⇒ **Both owners must match and sign — unless this is a fork, which needs nobody.**

⚠ Two reader-stack corrections on the way, both mine: the listing's stack is **what the UNLOCKING
SCRIPT PUSHES, and nothing else.** ⇒ NOT the compiler's model, which also carries `preimageCopy` and
`scriptCode` — the lock creates those itself and the reader watches it happen. Feeding it either extra
name relabels every line, and it printed `CHECKSIG(pub0, childowner0)` with total confidence.
★ **A listing with confident wrong names is worse than one that stops**, which is the runbook's own
lesson arriving for the second time.

⏭ **UNTESTED, and honestly so:** the OPERATIONAL side — splitting keys across devices, and the signing
ceremony. Only the script half is proved here.
