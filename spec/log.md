# jetmora log — specification

**Status: DRAFT, 24 August 2026.** Normative keywords MUST / MUST NOT / SHOULD / MAY are used in the
usual sense. ⏭ marks a decision not yet made; those are the only parts an implementer may not rely on.

This document says **what**. The reasoning lives elsewhere and is not normative.

⚠⚠ **SECTION NUMBERS IN THIS DOCUMENT AND IN THE DESIGN NOTES DO NOT MATCH, AND THEY COLLIDE.** This
specification's §4b is *signature checking*; the design notes' §4b is *portable state*, which is §8
here. ⇒ **Always cite the document as well as the number.** This bit its own authors within a day.

---

## 1. What a log is

A **log** is an append-only merkle tree of **entries**, published by one **operator**, whose tree head is
periodically **anchored** into a proof-of-work chain.

A log MUST NOT be understood as a chain, a consensus system, or a settlement layer. **It is a witness.**
It records what it was given. It does not adjudicate.

⇒ Three consequences, each normative and each easy to get wrong:

- a log MUST NOT reject an entry because the entry's state transition is invalid (§4.3)
- a log MUST NOT choose between conflicting entries (§4.4)
- a log MUST NOT be required to execute Bitcoin Script at all (§4.1)

## 2. Covenant identity

A **covenant** is identified by its **genesis**, never by the log that carries it.
A covenant is *"the thing descended from genesis G"*; a log merely witnessed some of its history.

A genesis commitment MUST contain:

| `source_hash` | the hash of the covenant's **BASIC source**, canonicalised per §7 |
| `script` | the compiled locking script |
| `state` | the initial state |
| `authorised` | the key, key set, or the literal `open`, that may append (§4.2) |

The genesis commitment SHOULD be timestamped in its own proof-of-work transaction, independent of any
log. A covenant whose genesis is only witnessed by a log inherits that log's honesty for its identity,
which the rest of this specification does not otherwise require.

⏭ **OPEN: the genesis commitment's serialization and its on-chain envelope.**

## 3. The entry

**An entry IS a transaction.** It MUST serialize such that the sighash preimage computed over it has the
BIP143 layout, so that `OP_PUSH_TX` reads identical bytes to those it reads on a proof-of-work chain.

| field | jetmora meaning |
|---|---|
| `nVersion` | **the protocol version in force when the entry was appended.** This is the value `OP_VER` pushes (§6.2) |
| `hashPrevouts` | hash of the previous-entry references consumed |
| `hashSequence` | hash of the `nSequence` values |
| `outpoint` | (previous entry hash, output index) |
| `scriptCode` | the covenant's locking script |
| `value` | 8 bytes. An **application-defined quantity**. It MUST NOT be interpreted as money, and MAY be zero |
| `nSequence` | **the tick index.** Time in a covenant MUST derive from this and MUST NOT derive from any clock (§6.3) |
| `hashOutputs` | hash of the successor states. An entry MUST support **more than one** output |
| `nLocktime` | MUST be 0 in version 1 |
| sighash type | MUST be `0x01` (`SIGHASH_ALL`). `FORKID` MUST NOT be set (§6.4) |

### 3.0a ⚠⚠ The sighash type byte does NOT mean what it means on BSV

**Jetmora has exactly ONE sighash algorithm: the BIP143 layout.** The type byte describes **scope only**
and never selects an algorithm.

⚠⚠ **This differs from BSV and the difference is silent.** There, BIP143 is *selected by* `FORKID`
(`0x40`). Ask a BSV implementation for `0x01` and it returns the **legacy pre-BIP143 sighash** — the
whole transaction serialized with the scriptCode substituted, no `hashPrevouts`, no `hashOutputs`, O(n²).

| byte | on BSV | on jetmora |
|---|---|---|
| `0x01` | **legacy sighash** | ★ **BIP143 layout** |
| `0x41` | BIP143 (`ALL｜FORKID`) | ⚠ **refused** — `FORKID` MUST NOT be set (§5.0c) |

⇒ A covenant compiled for both rails therefore carries a **different constant on each**. That is the
compiler's job and is invisible to the author, but an author reading *"SIGHASH_ALL is 0x01"* in both
places would be wrong about what it selects.

★ **Verified 24 Aug:** a jetmora entry's preimage is **byte-identical** to a transaction preimage built
from the same field values — across one output, several outputs, a zero-value output and a
varint-sized script — differing **only** in the trailing type byte. ⇒ *An entry is a transaction* is
demonstrated, not asserted. See `tools/preimage-check.mjs`.

### 3.0b ⚠⚠ ON CHAIN IS PACKED BYTES. OFF CHAIN IS JSON.

**Anything that reaches a chain, is hashed into a commitment, or is signed MUST be packed bytes.** JSON
is for HTTP, tooling and local files, and MUST NOT appear anywhere a hash or a signature is taken.

⚠ **The reason is not taste. `JSON.stringify` is not canonical** — reorder the keys or add a space and
the same object hashes differently. ⇒ A commitment computed over JSON gives one thing two identities,
which is precisely what §3.1 exists to forbid.

★ It is also a rule that catches mistakes cheaply, because it can be checked by reading rather than by
reasoning: **find the hash, look at what goes into it.**

### 3.1 Canonical serialization

There MUST be exactly one byte string per entry.

An implementation MUST NOT accept two encodings of the same entry, MUST NOT define optional fields, and
MUST NOT permit any integer encoding that admits more than one form.

⚠ This is not tidiness. `OP_PUSH_TX` is secure only because the verifier recomputes the preimage and
compares; **two encodings would let a signer push a preimage that does not describe what they did.**

### 3.1a ★★★ TESTED 25 Aug — the canonical invariant holds under fuzzing

**The invariant, stated as something attackable:**

> for every byte string *b* — either `parse(b)` **fails**, or `serialize(parse(b))` **is exactly *b***

⚠ Anything else means the format admits two encodings of one entry, and then a signer can push a
preimage that does not describe what they did.

**80,000 cases, four seeds. Zero violations.**

| pure noise | 5,000 refused, 0 parsed |
| valid entries, untouched | 5,000 round-trip |
| ★ **one bit flipped** | 415 refused, **4,585 round-trip** — ⇒ correct: a bit inside `prevEntry` or script data gives a *different but valid* entry |
| truncated · extended | refused, always |

★ Hand-built attacks all refused: a trailing zero byte · a non-minimal varint · truncation by one byte
· **an input count claiming `0xffffffff`** (refused as truncated — ⚠ it does not attempt to allocate) ·
a non-zero `nLocktime`.

★ Payload sizes across every pushdata boundary — 0, 1, 74, 75, 76, 77, 254–257, 65535, 65536 — all
round-trip.

### 3.1b ⚠★ TESTED 25 Aug — concurrent appends, and the bug it found

**⚠ An implementation MUST take the write lock BEFORE reading the log's size.**

A sequence number is chosen by reading `size()` and then writing at that index. In SQLite, `BEGIN`
is *deferred*: the write lock is not acquired until the first write, so two appenders can both read
`size() = n`. Under WAL, the loser gets `SQLITE_BUSY_SNAPSHOT` — and ⚠ **`busy_timeout` cannot retry
that one**, because retrying against a stale snapshot cannot help. The append is simply lost.

★ Measured, 8 concurrent appenders: **183 of 200 appends lost.** With `BEGIN IMMEDIATE`: **0 lost.**

| workers | appends | lost |
| 4 · 16 · 24 · 32 | 100 · 400 · 600 · 800 | **0** |
| 16, deeper | **1,600** | **0** |

⇒ Every run: sequence numbers dense with no gaps and no duplicates · the stored tree's root equal to
a from-scratch root over the bodies alone · **every** inclusion proof verifying.

★★ **The integrity was never at risk, only the availability.** `seq` is a PRIMARY KEY, so a lost race
could only ever *refuse* — never write a second entry at one index, and never fold a torn sibling set
into an interior node. That is the property worth stating: **under contention this log fails closed.**
The fix bought throughput, not correctness.

⚠ A verifier's trap, found by the same test: `mt_verify_inclusion` takes the **entry body**, not its
leaf hash — it hashes for you. Passing a hash double-hashes, and then *every* proof fails while the
root still matches, which reads precisely like a corrupt tree. Same class as the ECDSA hash-contract
bug. ⇒ The parameter is now named for what it holds.

### 3.2 Self-containment

An entry MUST contain everything needed to replay it: the unlocking data, every input, and any value the
script reads. An entry that cannot be replayed from its own contents is malformed, **even if every party
present at the time could have replayed it.**

## 4. Appending

### 4.0a ⚠⚠ TWO SIGNATURES EXIST, AND THEY ARE NOT THE SAME THING

An entry carries signatures serving two unrelated purposes. **Conflating them puts an interpreter in
the log, which §4.1 forbids.**

| **the covenant's internal `CHECKSIG`** | via `OP_PUSH_TX`, over the entry's **preimage** ⇒ proves the STATE TRANSITION is what the program permits. **A verifier's concern. The log MUST NOT evaluate it** |
| **the append authorisation** | over the **entry bytes** ⇒ proves WHO SUBMITTED this. **The log's only concern** |

⇒ An operator checks the second and MUST NOT check the first. ★ That is the whole reason a log needs
no Script interpreter, and therefore why it can be a few hundred lines of PHP.

### 4.1 What an operator checks

On receiving an entry an operator MUST check, and MUST check only:

1. the entry is well-formed and canonically serialized (§3.1)
2. the entry is signed by a key permitted by the covenant's genesis `authorised` field

An operator MUST NOT execute the covenant's script as a condition of appending.

⚠ Checking **who signed** is not checking **whether it is valid**. Only the second requires an
interpreter, and this specification does not require one in a log.

### 4.2 Who may append

The genesis `authorised` field governs. A covenant MAY declare `open`, in which case any signature is
permitted and the operator's own policy (§4.5) is the only limit.

### 4.3 Invalid transitions — recorded, and NOT honoured

An operator MUST NOT reject an entry because its state transition would fail the covenant's script.

**An invalid transition MUST NOT advance the covenant's tip.** The tip is the last state the covenant's
script actually permitted.

⚠⚠ **RECORDING IS NOT HONOURING, and the two must not be conflated.** The entry is in the log
permanently, as a signed claim that someone asserted otherwise. It is evidence. It is not history.

⇒ The log still has no opinion: it records everything, and **a reader determines the tip by replaying.**
Validity is a reader's determination and MUST NOT be an operator's.

★ Every property this preserves:
· evidence of a false claim survives permanently, attributable to the key that signed it
· **the tip is always a state the program could have produced**
· verifiers that disagree can examine the entry, because it exists
· ★★ **a later protocol version MAY find the transition valid and compute a different tip** (§6b) —
  which is the reason the entry must be recorded rather than refused

⚠ **DO NOT CONFUSE THIS WITH §9.** An error state and an invalid transition are **opposites, not
variants:**

| **error state** (§9) | the script RAN and PERMITTED it, producing `err≠0` ⇒ **valid. It advances the tip.** |
| **invalid transition** (§4.3) | the script would REFUSE ⇒ recorded as a claim, **does not advance** |

⇒ §9 exists so that a covenant has a **legitimate** way to record a failure, and therefore never needs
an invalid transition to express one.

### 4.4 Conflicting entries

An operator MUST NOT reject an entry because another entry already exists at the same
`(covenant, sequence)`, and MUST NOT mark, rank, or otherwise adjudicate between them.

⚠ Rejecting a duplicate would make the operator decide first-seen, which is consensus in miniature.
Both are recorded; two conflicting entries at one sequence are **a fact about the signer**, faithfully
witnessed. Resolving them is a reader's concern.

### 4.5 Operator policy

An operator MAY impose any admission policy that is not a check on validity: a price, an account, a rate
limit, a proof of work, an allow-list. An operator SHOULD publish its policy.

A log's limits — memory, execution time, entry size — are **operator policy and MUST NOT be protocol
constants.** ⚠ A limit written into the protocol becomes a number nobody can promise to hold.

## 4bis. THE LOG GENESIS — ✅ BUILT 25 Aug, and SMALLER than it was proposed

⚠⚠ **THIS SECTION SHRANK WHEN IT WAS IMPLEMENTED. The separate genesis RECORD does not exist.**
⇒ It was proposed as a document committed by hash, and building it showed there is nothing left for
that document to hold: identity is one derived field, and every immutable setting is a field in the
covenant. **See §4bis.0.**

⚠⚠ **A COVENANT HAS A GENESIS. A LOG DOES NOT, AND THREE SEPARATE REQUIREMENTS ALL NEED ONE.** Until it
exists, a log is identified by its operator's key and its URL — both mutable, neither provable.

### 4bis.0 ★★★ WHAT A GENESIS ACTUALLY IS — one field, and no document

```
genesis = SHA256(genesisTxId ‖ outputIndex LE)
```

**That is all of it.** BRC-113's derivation, minus its `immutableChunkBytes` term.

★★ **The term is redundant HERE and only here.** It exists so that tampering with a token's immutable
metadata breaks its id. ⇒ In a self-replicating covenant the metadata is a FIELD, peeled from the
spending transaction's own `scriptCode` and rebuilt into the successor — **tampering is already
impossible, so there is nothing left for the hash to protect.**

⇒ ⚠ **No OP_RETURN. No published record. Nothing to fetch, lose, or disagree with.**

### 4bis.0a ⚠⚠ CARRIED IS NOT ENFORCED — the distinction the whole section turns on

The state travels as a **PushDrop**: literals pushed at the head of the locking script and dropped
before anything runs. ⇒ **Anyone can READ it from a single output, with no lookup.** That much is free.

⚠ But a PushDrop payload is inert. **Nothing stops a successor carrying something different**, because
the script never looks at it.

| **carried** | in the script, readable ⇒ ~3 bytes ⚠ **may drift** |
| ★ **enforced** | ALSO peeled from the preimage and rebuilt ⇒ **~21 bytes more**, and it **cannot drift** |

★★★ **An immutable setting MUST be enforced, not merely carried.** ⇒ *"A fork cannot relax its own
rules"* is true only because `forkable` is REBUILT. Were it merely present, a fork could set it to
anything and the covenant would not notice.

⇒ **Three standards, each doing the part it is good at:** BRC-113 for identity across branches ·
PushDrop for carriage · BRC-226 for enforcement.

### 4bis.1 Why it is needed — three arguments arriving independently

1. ★ **Identity that cannot be forged.** If a log's first anchor is its genesis in the BRC-113 sense,
   the log is a token whose identity is anchored in a **block header** (§6.0c). ⇒ Forging it costs
   proof of work.
   ⚠ **And it closes a hole in §8**: a port names its source log by PUBLIC KEY, so a hostile source can
   **rotate keys and deny the port came from it.** An identity anchored at genesis cannot be rotated
   away from.
2. ★★ **Private logs.** Not every log should be publicly readable — proprietary data, formulas,
   commercial terms. ⇒ See §4bis.3: the encryption question is answered at genesis and nowhere else.
3. ★★★ **Forking.** A second operator continues a log from a common point (§4bis.4). Without a shared
   genesis there is nothing for both branches to trace back to, and no way to tell a fork from a lie.

### 4bis.2 ⚠ What goes in a genesis, and what does not

**The rule this design has been using without stating it:**

| **what may change over a log's life** | goes in the **HEAD** — `prune_level` is there for exactly this |
| ★ **what must NEVER change** | goes in the **COVENANT, AS AN ENFORCED FIELD** (§4bis.0a) |

⚠ *"Goes in the genesis"* was the original wording and it is now wrong — there is no genesis document
to put anything in. **An immutable setting is a field the quine rebuilds**, which is what makes it
immutable rather than merely stated.

⇒ `prune_level` changing is harmless: old heads record the old value. **A leaf-hash rule changing is
not harmless — it invalidates every proof already issued** rather than describing it.

⚠ Operator limits (§4.5) MUST NOT be in the genesis. They are policy, and policy changes.

### 4bis.3 ★★ Private logs — encryption costs the design nothing

**Everything that makes a log trustworthy runs on hashes.** Inclusion, consistency, anchoring and
equivocation detection all work without reading a single entry. ⇒ **Only replay — "was the computation
correct" — needs plaintext.**

★★★ **So a log can prove it has not cheated without revealing what it holds.** And §4.1 already says a
log does not validate; **an encrypted entry is bytes it understands slightly less.**

★★ **And the property that falls out is better than privacy: SELECTIVE DISCLOSURE.** An inclusion proof
runs on hashes, so one entry may be revealed with its proof — proving it was in the log at a given root
— **without opening the log.** ⇒ A manufacturer proves *this test passed* without publishing the suite;
a laboratory proves *this analysis ran as pre-registered* without publishing the data.

⇒ **✅ BUILT as the enforced field `leafcovers` (§4bis.0a). BOTH are permitted:**

| **plaintext** | ★ a decrypting verifier checks inclusion **end to end**, nothing taken on trust ⚠ the log cannot compute its own leaves; the appender supplies them |
| **stored bytes** | ★ the log computes leaves itself, everything works unchanged ⚠ a verifier must trust that the ciphertext decrypts to what is claimed |

★ For a public log the two are identical, so the field only bites where encryption is used.

⚠ **The honest cost:** `OP_PUSH_TX` operates on the entry, so **only key-holders can verify a private
log's COMPUTATION.** Its INTEGRITY stays publicly checkable. That is inherent, not a defect — but a
private log's computational claims are checkable only by its own circle.

### 4bis.4 ★★★ Forking — branches of one genesis, not new logs

**A fork is a continuation on a new branch, sharing a common root.** ⇒ Not a new log.

| **the genesis** | ★ **shared by every branch.** One origin, one identity |
| **the common prefix** | **not copied — the same tree.** Both branches prove against it |
| ★ **a branch** | **`(genesis, branch)`** ⇒ what a reader names to say WHICH history |

★★★ **`branch` = HASH256 of the PARENT OUTPOINT the fork consumed** — ✅ built 25 Aug, and it is
DERIVED, never chosen. ⚠⚠ **An outpoint is spendable ONCE and a parent's tip moves with every fork, so
no two forks ever consume the same one.** ⇒ **Two children can never be byte-identical.** The trunk's
`branch` is zeroes: depth 0 has no parent outpoint to name.

⚠ **That is a security property, not bookkeeping.** Under `SIGHASH_ANYONECANPAY` — which the anchor uses,
so that any funder may join — `hashPrevouts` is zeroed, and two covenants identical in `scriptCode` and
value would be **interchangeable**: one preimage would satisfy both, letting a single successor output
discharge two inputs. **`branch` is what makes those twins impossible.**
⇒ ⚠⚠⚠ **If `branch` is ever removed, the scope MUST return to `0x41` in the same change.**

★ This is git exactly: the repository is shared, a branch labels a divergence, every commit still
traces to one root.

⚠⚠ **AND IT SHARPENS §4d RATHER THAN MUDDYING IT.** Two heads are a **lie** if they are the same branch
and incompatible. Two heads from **different branches of one genesis** are a **fork**.
⇒ The detector therefore needs one input it does not have: **which branch.** It currently takes a
public key and assumes that identifies the history. **It must take `(genesis, branch, key)`** — and
`branch` now exists (above), so this is no longer blocked on a design decision. ⏭ It remains unbuilt.

⚠⚠⚠ **A FORK MUST BE DECLARED AT OR BEFORE THE DIVERGENCE, NEVER CLAIMED AFTERWARDS.** Otherwise an
operator signs two incompatible histories, is caught, and says *"that was a fork."*
⇒ **The declaration SHOULD live in an anchor**, so the claim costs proof of work and cannot be
backdated. ★ Same shape as everything else here: the escape hatch is real, and it is safe only because
it cannot be applied retrospectively.

### 4bis.4a ★★★ A BRANCH MAY GROW ON ANY HOST — the chain holds identity, not location

**The genesis and the anchors live on BSV. The tree may grow anywhere.**

⇒ §8 already states the principle for covenants — *"a covenant's script MUST NOT reference the log it
runs in"*. ⚠ **It extends by one word: an ANCHOR's script MUST NOT reference the HOST.** A covenant that
named its host would hand whoever runs that host a veto, which is the same freeze §8 exists to prevent.

★★ **Three things already in this spec compose into cross-host forking. None of them is new:**

| ★ **the tree is not the history** (§5c) | a fork carries the **TREE**, not the bodies ⇒ a year at 1,000 players/day is 51 GB of bodies but **3.87 MB of tree**. The retention design made this cheap before anyone asked for it |
| ★★ **a pruned entry answers 410** (§5c.2) | a new host holds the tree, so it can still **prove**; it may not hold the body. ⇒ *"It existed and is still provable; it is simply no longer held here."* **That is the cross-host case exactly** |
| ★★★ **port** (§8.1) | already tested against a hostile operator. A fork onto a new host is the same move made **voluntarily** — and ⚠ *a port from an ANCHORED root is FINAL*, so an anchored fork is too |

⇒ ⚠ **So a branch on another host is not a new mechanism.** It is a port whose source did not object.

### 4bis.4b ⚠ Where a host hint may live — and where it MUST NOT

A reader must still find the branch. §4bis.2's own rule settles it without a new argument:

| **what may change** | ⇒ the **HEAD**, where `prune_level` already lives |
| ★ **what must never change** | ⇒ the **GENESIS** |

**A host is the most mutable thing in the system.** ⇒ A host hint MAY appear in a signed head. It MUST
NOT appear in the genesis, and MUST NOT appear in an anchor's script.

⚠ **And a hint is a convenience, never an authority.** A branch is named by `(genesis, branch)` — both
anchored by proof of work — so a wrong or stale hint costs a lookup, never an identity. ★ Discovery is a
git remote: **someone hands it to you.**

⚠⚠ **The honest gap.** If a branch's host disappears, its anchors still prove **what its roots were** —
they cannot prove **what its entries said**. ⇒ That is the last-copy problem, not a defect in forking,
and it is open.

### 4bis.4c ⚠★★ WHEN A HOST VANISHES — what the anchors still do

**Hosts will vanish. This section is not a mitigation plan; it is a description of the remainder.**

⚠ **Stated plainly first: a hash does not reconstruct anything.** If no copy of the bodies survives
anywhere, the content is gone, and no part of this design pretends otherwise.

★★★ **What the anchors preserve is not the data. It is the ability to AUTHENTICATE the data if it ever
comes back.** ⇒ Ordinarily a copy surfacing years after a host dies is worthless — nothing distinguishes
a genuine archive from a fabrication, and the finder is trusting whoever handed it over. Against an
anchored root, **any copy found anywhere can be proved to be the original, bit for bit**, and the proof
is dated by a block rather than by a claim.

⇒ ⚠ This is a **structural** claim about the anchor chain and cannot rot: no branch of it omits the
root. Whether a copy exists somewhere is an **empirical** question, and a different one.

★★ **And the loss is legible, which silence is not.** The anchors still say what existed, what its
fingerprint was, how large it grew, when it was last seen, and **the whole branch structure — who forked
from whom.** A gap you can describe exactly is a different thing from a gap you cannot see.

### 4bis.4d ★★★ EVERY FORK IS A BACKUP THAT PAYS THE ORIGINAL CREATOR

**A branch holds the common prefix (§4bis.4) — not a copy of it, the same tree.** ⇒ If B forked from A
at height 1,000 and A's host disappears, **B still holds the tree for 0…1,000.**

★★ So the royalty design and the survival design are one mechanism seen from two sides:

| the royalty makes forking **worth doing** | ⇒ a permissionless fork, paid for by the forker |
| forking makes the data **survive** | ⇒ each branch is an independent custodian of the shared prefix |

⇒ **Replication is not a leak to be tolerated. It is the archive.** ★ Which is why *"duplication is not a
problem, it is resilience — antifragile"* is an engineering statement here rather than a philosophical
one: without anchors, finding a thing in many places does not tell you which copy is right.

⚠⚠ **The honest limit: this is a mitigation, not a solution.** A log nobody forks has exactly one
custodian, and a **non-forkable** log can never have more than one by construction. ⇒ That is the real
cost of choosing non-forkable, and it should be weighed at genesis against the cleanliness that choice
buys — because it is the one decision that can never be revisited.

### 4bis.4e ★★ THE LINEAGE REGISTER IS A WINDOW, NOT A LEDGER

**The N ancestor slots shuffle along on every fork.** ⇒ A branch pays the creator and its **N most
recent** ancestors, and an older ancestor slides out.

⚠ **That is correct, not a leak.** A branch at depth 10 genuinely has different recent ancestors than
one at depth 3. ★ And moving the window costs real satoshis **and buries the forker's own depth
permanently**, so it is self-moderating in the same way BRC-226's crumb is.

★★★ **The property that makes it right:**

| **PAYMENT** | a **WINDOW** — bounded, N wide, fixed at genesis |
| **PROVENANCE** | the **WHOLE CHAIN** — every fork, anchored forever |

⇒ **Bounded cost, unbounded provenance.** A branch at any depth still walks back to the creator through
every intermediate; only the payment list is capped.

⚠ ⇒ Therefore **`N` is POLICY, not security.** ★ And the creator is a baked literal precisely so that
the window **can never slide off the origin.**

### 4bis.4f ★★★ IDENTITY, CONTROL AND PAYMENT ARE THREE DIFFERENT THINGS

⚠⚠ **They were conflated, including by me, and separating them is what makes a branch sellable.**

| ★ **IDENTITY** | `branch` = HASH256(parent outpoint) ⇒ **DERIVED, and cannot be chosen** |
| **CONTROL** | the owner slots, n-of-n ⇒ **chosen by the forker**, read only by the auth check |
| **PAYMENT** | the payee register ⇒ **chosen by the forker**, read only when building royalty outputs |

⇒ **A buyer may put a COLD key in charge of a branch while royalties flow to a HOT one** — or to a
collaborator, a treasury, or nobody they control at all. **The covenant does not check either**, and
should not: the forker is the one spending, and nobody else has an interest in who runs or is paid by
their own replica.

⚠⚠⚠ **THE MISREADING TO GUARD AGAINST.** The payee register is **NOT** a record of who forked. The
stack field was called `forker` and that name invited exactly that inference; it is now `childpayee`.
⇒ **Provenance is the BRANCH ID and the anchor chain — both unchooseable.** Anyone reading a fork's
authorship out of the payee register is reading a nomination as a fact.

★ ⇒ With §4bis.4e this completes the picture: **payment is a window, provenance is the chain, and
control is neither.**

### 4bis.5 ⏭ Open

✅ **RESOLVED — "the genesis's serialization, and whether it is committed in the first anchor or in a
transaction the first anchor references."** ⇒ **NEITHER.** There is nothing to serialize: identity is
one derived field and every immutable setting is a field in the covenant (§4bis.0).

· whether `anchor_policy` — which chains a log anchors to — is immutable or mutable. ⚠ Probably mutable,
  ⇒ in which case it belongs in the HEAD and not in the covenant at all
· what else, if anything, is immutable enough to be worth **~21 bytes per anchor** (§4bis.0a). ⚠ That
  price is the whole test now, and it is charged on every anchor of every branch, forever

## 4c. ⚠⚠ Vocabulary — there is no such thing as an unconfirmed entry

**This system has no pending state.** No mempool, no queue, no reorganisation. **An entry is appended or
it is not**, and an append is final at the instant it happens. There is nothing to converge on,
therefore nothing to wait for.

⚠ **"Confirmed" and "unconfirmed" MUST NOT be used of anything in this specification except an anchoring
transaction on the carrying proof-of-work chain (§6).** There, confirmations are real and the word is
borrowed correctly. Used of an entry or a head it is an error, and it invites a reader to expect a
limbo that does not exist.

★ **There IS a gradation, and it is not confirmation. These are different KINDS of assurance, not
degrees of one:**

| **witnessed** | the log holds the entry. **Final immediately** |
| **signed** | the operator has publicly committed to holding it ⇒ as good as their key, and their equivocation becomes provable (§3.4b) |
| **anchored** | that commitment is dated by proof of work ⇒ **it cannot be walked back**, and it is objectively ordered against other logs |

⇒ Confirmation counts are degrees of one thing — one, six, a hundred, all the same guarantee more
firmly. **These add different guarantees**: signing adds ACCOUNTABILITY, anchoring adds OBJECTIVE
ORDERING. Flattening them into a number would misdescribe all three.

★★ **A consequence worth stating for implementers:** an application MUST NOT build a wait-for-N-blocks
flow around an entry. **A lap time is final the moment it is recorded.** Anchoring is about what a third
party can later be made to accept, never about whether the entry happened.

## 4d. Equivocation, and how it is proved

The design's central claim is that a log **cannot cheat invisibly**. That is worth nothing until
something can produce the receipt, so this states what a receipt is.

### 4d.1 ⚠⚠ There are two forms, and the obvious one is the easy one

| **same size, different roots** | two signed heads at one tree size. Trivial to spot |
| ★ **an inconsistent history** | heads at DIFFERENT sizes where the smaller is not a prefix of the larger. **An operator avoiding the first form will do this instead** |

⇒ A verifier that checks only same-size collisions **clears a clever operator completely.** Catching the
second form requires a consistency proof (§5.3), which is what that proof is for.

### 4d.2 ⚠⚠ Absence of a proof is EVIDENCE, NEVER GUILT

A log that will not serve a consistency proof MUST NOT be treated as having equivocated. **You cannot
prove the absence of a proof**, and a log may be offline, slow, or pruned.

⇒ ★ A detector that convicts the unreachable is worse than none, because it makes every accusation
worthless. Report it as suspicion and let a reader act on that as they choose.

★ Likewise, a signature made by someone else in an operator's name proves nothing about the operator. A
verifier MUST check the signature **before** it examines the content.

### 4d.3 An author can convict themselves

Two entries at one `(covenant, sequence)` signed by the same authorised key are **self-equivocation**
— the evidence a rewind leaves (§8). ⚠ It needs no gossip protocol: **whoever was on the other side of
that covenant already holds the later signature.**

### 4d.5 ★★★ TESTED 25 Aug — BRANCHES, and the escape hatch a liar reaches for

**18 cases now: the original eleven, plus seven the detector could not previously EXPRESS.**

⇒ **A fork is no longer convicted.** Two heads at one size with different roots and DIFFERENT `log_id`s
are a fork claim, not a lie. ⚠ And a head with **no** `log_id` is *uncomparable* — not "the same
branch".

★★★ **But the claim itself is where a liar hides**, so it is checked rather than believed:

| declared **at or before** the divergence | ⇒ **a real fork** |
| ★★★ declared **after** | ⇒ **refuted, and convicted** — *"a fork declared after the fact is a rewrite"* |
| **no anchor offered** | ⇒ **unproven, NEVER disproven** ⚠ §4d.2 again: you cannot prove the absence of a proof |
| the `(genesis, branch)` hashes to **neither** head's id | ⇒ refuted — the branch pointed at is not these heads' |

⚠⚠ **This is why §4bis.4 requires the declaration to live in an ANCHOR.** The whole defence is that an
anchor **cannot be backdated** — proof of work is what makes "I declared this fork earlier" checkable
rather than assertable.

### 4d.4 ★★★ TESTED 24 Aug — eleven cases, none fooled it

Convicted: two roots at one size · a history that is not a prefix · **a consistency proof borrowed from
a different, genuine pair of trees** · an author rewinding.
Cleared: an honest log growing normally · the same head twice · **a log offline with no proof offered**
· **a head forged in the operator's name** · an author advancing normally · an author signing the same
entry twice · an entry signed by someone else.

## 5. The tree

### 5.1 Construction — RFC 6962, NOT Bitcoin's tree

Merkle tree hashing MUST follow **RFC 6962 §2**:

```
leaf hash  = SHA-256( 0x00 ‖ entry_bytes )
node hash  = SHA-256( 0x01 ‖ left ‖ right )
empty tree = SHA-256( )
```

For an odd number of nodes the tree MUST be split at the largest power of two less than *n*. **A node
MUST NOT be duplicated and hashed with itself.**

⚠⚠ **Bitcoin's merkle tree MUST NOT be used here.** It duplicates the final node on an odd count
(`i2 = min(i+1, nSize-1)`, 0.1.3 `main.h`), so distinct entry lists can produce identical roots
(CVE-2012-2459); and it applies no domain separation, so an internal node can be presented as a leaf.

⚠ **Two tree types exist in this system and MUST NOT be conflated:** RFC 6962 for jetmora logs, and the
carrying chain's own tree for anchor inclusion proofs (§6.1, and BRC-113 for BSV).

### 5.2 Heads

An operator MUST publish signed tree heads containing at least: tree size, root hash, and a signature by
the operator's key. A head MUST NOT be modified once published.

⏭ **PROPOSED and implemented — 122 bytes, canonical by construction:**

```
version      1 byte
log_id      32 bytes  — ★★★ HASH256(genesis ‖ branch): WHICH HISTORY THIS HEAD IS FOR
tree_size    8 bytes, big-endian
root        32 bytes
timestamp    8 bytes, big-endian, unix seconds
anchor_root 32 bytes  — the last ANCHORED root, or 32 zero bytes if none
anchor_size  8 bytes  — the tree size at that anchored root
prune_level  1 byte   — retention granularity, K = 2^level. 0 = nothing pruned
```

★★★ **`log_id` EXISTS BECAUSE WITHOUT IT THE EQUIVOCATION DETECTOR CANNOT WORK — added 25 Aug.**

⚠⚠ §4bis.4 asked the detector to take `(genesis, branch, key)`. **A caller cannot supply what the heads
do not carry.** One operator key runs many branches, so two heads signed by that key at one tree size
with different roots are either a **LIE** or a **FORK** — and nothing in 90 bytes said which.
⇒ **A detector that convicts on the key alone convicts every legitimate fork**, which is worse than
none: it makes every accusation worthless (§4d.2).

★ A reader checks it against the chain — the branch's anchor covenant carries `genesis` and `branch` in
its PushDrop state (§6.1a-i), so hash them and compare. ⇒ **The head becomes attributable to a specific
ON-CHAIN branch, not merely to a key.**

⚠ **32 zero bytes means the log never declared which history this is.** That is legal, and a detector
MUST treat two such heads as **UNCOMPARABLE** rather than as one branch — an absent fact is not evidence
of a shared history.

⚠ **The timestamp is the operator's clock and is a CLAIM, not a fact.** Nothing depends on it being
honest; anyone may compare it against the anchor. ★ It exists so a reader can see a log that has
stopped anchoring (§6.3), which is the health signal that matters.
★ `anchor_root` and `anchor_size` make §4c's gradation visible in one object: entries above
`anchor_size` are **witnessed and signed but not yet anchored** — a precise state, and never an
"unconfirmed" one.

⚠⚠ **AN IMPLEMENTATION SHOULD MAKE RE-SIGNING A SIZE IMPOSSIBLE, NOT MERELY FORBIDDEN.** Two heads at
one tree size with different roots are the operator's own evidence of equivocation, and that evidence
is the security model. ⇒ The reference implementation uses `tree_size` as a primary key, so a second
head at that size fails in the database rather than relying on discipline.
★ **Signature scheme — PROPOSED and implemented:** the **key length selects the scheme**, so a host
without libsodium can still run a log. **32 bytes ⇒ Ed25519 · 33 or 65 bytes ⇒ secp256k1.**
⚠ A malformed key or signature MUST be a failed check, never an error — a log that throws on bad input
is a log anyone can stop.

### 5.3 Proofs

A log MUST serve, for any entry it holds:

| **inclusion proof** | entry is in the tree with root R |
| **consistency proof** | tree at root R₂ contains everything R₁ did, appended only, nothing rewritten |

⚠ The consistency proof is the property a proof-of-work chain does not provide, and it is what makes an
append-only claim checkable rather than trusted.

## 5c. Retention — a log holds the TREE, not the history

**His observation:** as a log grows it will exceed its host, *"however it should also be possible to
offload the chain history, so the real limit is what happens within a 24 hour period."*

★★ **This works because the log never needs the bodies to do its job.** MEASURED on 424-byte entries:
**the tree is 15% of the stored data and the bodies are the other 85%.** An inclusion proof is built
from tree nodes alone; the body is needed only by someone REPLAYING the entry, who must fetch it anyway.

| one year at 1,000 players/day | bodies **51.3 GB** ⚠ · full tree **7.9 GB** ⚠ · ★ **one node per 1,024 entries: 3.87 MB** |
| one day at that rate | full tree **22 MB** ✓ — comfortable on any host |

### 5c.1 What an operator MAY discard

After a root has been **anchored** (§6.2) and a head covering it published (§5.2), an operator MAY:

- **discard entry bodies** below that point, and
- **prune the tree** below a chosen level, keeping only subtree roots at a granularity *K*

An operator MUST NOT discard anything **above** its last anchored root, and MUST NOT discard a signed
head at any age. ⚠ A head is the evidence of its own commitments; discarding one destroys the
equivocation proof that makes the whole model work.

### 5c.2 What is lost, stated plainly

A pruned log can still **prove** that an entry is included, given the entry. ⚠ **It can no longer
PRODUCE that entry.** Serving an old inclusion proof requires fetching the *K* bodies under the retained
subtree root and recomputing the lower path — roughly 434 KB at *K* = 1,024 with 424-byte entries.

⇒ ★ This is §3.3 applied to the log's own storage, and it is the same promise the system makes about
data generally: **identity is guaranteed forever, availability while someone values it.** A log that has
pruned is not a broken log; it is a log that has stopped being a CDN for its own past.

### 5c.2a ★★★ TESTED 25 Aug — and offloading to an untrusted store is SAFE

4,096 entries pruned to level 10 (K = 1,024) below entry 3,072. **3,072 bodies and 6,138 nodes
discarded; 2,053 nodes remain.**

| ★ **the root is unchanged** | pruning alters nothing the log has committed to |
| proofs for unpruned entries | **1,024 verify, 0 fail** |
| ⚠ a proof for a pruned entry | **refused honestly** — absent, not wrong |
| ★★★ **restore the K bodies, rebuild the proof** | **verifies against the SAME root** |

★★ **A RESTORED BODY IS CHECKED AGAINST ITS STORED LEAF HASH before it is accepted**, so a wrong body
is refused. ⇒ **Bodies may therefore be offloaded to an UNTRUSTED store.** A hostile mirror can withhold
them; it cannot substitute them. That makes §5c.3 safe as well as economical.

⚠ **Two implementation notes earned here:** a pruned body is an EMPTY value, not a missing one — code
checking only for absence returns success with nothing in it, which is worse than either. And SQLite
does not return the space to the filesystem without `VACUUM`; pruning frees logical space immediately
and disk space only when asked.

### 5c.3 Where the bodies go

⚠ **This specification does not say.** A proof-of-work chain gives permanence and addressability; a
cheap disk gives cost; a mirror gives both cheaply and neither permanently. ⇒ Same position as payment
(§3.4-0b): **the protocol has no opinion, and an operator SHOULD publish what it does.**

★ An operator that prunes SHOULD publish, alongside its retention policy, **where the discarded bodies
can be obtained** — otherwise it has not pruned, it has deleted.

★ **DECIDED: *K* is CHOSEN PER LOG** and declared in the head as `prune_level`, where K = 2^level and
0 means nothing is pruned. ⇒ A small operator may prune harder than a large one, which is the point of
a design a website can run.

⚠ **It lives in the HEAD rather than in a policy document for a specific reason:** a client verifying an
OLD proof needs the value that applied at THAT time, not the value today. Heads are immutable and are
never discarded (§5c.1), so the answer is always recoverable. ⇒ A policy document can be edited; a
signed head cannot.

## 6. Anchoring

### 6.0 ★★★ WHY AN ANCHOR EXISTS: THIS SYSTEM HAS NO BLOCK HEADERS

**There are no headers here because there are no blocks, and there are no blocks because there is no
consensus.** A header is where **objectivity** comes from — the point at which a claim stops being
somebody's word and becomes something work was spent on. ⇒ **Jetmora does not invent one. It borrows
one.**

The complete proof chain for a single entry:

```
entry
  → log root           RFC 6962 tree, signed by the operator
                       ⚠ as good as that key and no more
  → anchor transaction PushDrop, spendable ⇒ anchor n+1 consumes anchor n (§6.1a)
  → block merkle root  the carrying chain's own tree
  → block header       ★ where proof of work enters, and the only place it does
```

⇒ **Five hops, and only the last two carry any work.** Everything above the anchor is signatures and
hashes; everything below is somebody else's electricity.

### 6.0a ⇒ Therefore BRC-113 applies at two levels, not one

| **entry → log root** | jetmora's own tree — **the layer MPT never had** |
| **anchor → block root → header** | **MPT's original job, completely unchanged** |

★ A port entry (§8) is an MPT with one extra tree stacked underneath it. That is not an analogy; it is
the same construction, applied twice.

### 6.0b ⚠⚠ Two consequences that follow immediately

**A log that never anchors has no headers at all.** Its entire history is the operator's word, provable
against nothing. ⇒ This is why §6.3 requires that a log which stops anchoring be treated as failing —
not as a health heuristic, but because **anchoring is the only place objectivity enters the system.**

★★ **Multi-anchoring borrows headers from several chains.** A log's objectivity then rests on no single
chain surviving, and on no single chain's fee policy. ⇒ The same escape as portable state (§8), one
level up: **do not depend on a party who can change the terms.**

### 6.0c A log may therefore have an unforgeable identity

If a log's first anchor is taken as its genesis in the BRC-113 sense — identity derived from that
transaction plus the log's immutable parameters — then **the log itself is a token whose identity is
anchored in a block header.**

⇒ Forging a log's identity would mean rewriting proof of work, which is the same difficulty as forging
a transaction. ★ Not *"unforgeable"* by assertion — unforgeable **for a stated reason**.

⚠ **And it closes a gap in §8.** A port entry currently names its source log by **public key**, and a
hostile source could rotate keys and deny the port came from it. **An identity anchored at genesis
cannot be rotated away from.**

⏭ **OPEN: whether a log SHOULD have such an identity, and what its immutable parameters are.**



### 6.1 What an anchor is

An anchor is a transaction on a proof-of-work chain committing to a tree head. Its purpose is to make
**one history** objective — nothing else in this specification provides that.

An anchor MUST commit to:

1. the tree head being anchored
2. **the previous anchor's transaction id**

⚠ Requirement 2 is not redundant. Two anchors may be mined into one block, or out of order; **without
an explicit chain between anchors their order is undefined**, and ordering is the only thing anchoring
buys.

### 6.1a Anchors form a UTXO chain — PushDrop, not OP_RETURN

✅ **BUILT 25 Aug as a COVENANT** (§6.1a-i). A modified BRC-113 carrying its commitment in a
**PushDrop** output rather than `OP_RETURN`.

⚠ A commitment held in `OP_RETURN` data can be forged or omitted, and **two anchors may both CLAIM the
same predecessor.** A PushDrop output is **spendable**, so anchor *n* does not cite anchor *n−1* — it
**SPENDS** it.

| `OP_RETURN` | anchor *n* **claims** to follow *n−1* ⚠ two anchors can both claim it |
| ★★★ **PushDrop** | anchor *n* **spends** *n−1* ⇒ **only one ever can.** Double-spend protection yields anchor uniqueness for free |

⇒ **The anchor sequence becomes ENFORCED rather than ASSERTED**, and a log cannot equivocate about its
anchors at all: conflicting anchored heads would require a double spend, which proof of work prevents.
★ Strictly stronger than §6.1's requirement 2, which it supersedes if adopted.
★ And the output carries value, so it may hold the satoshi funding the next anchor — **a self-funding
anchor chain**, the same pattern as an agent battery.

★ **IMPLEMENTED AND VALIDATED 24 Aug.** Output 88 B: `<pubkey> OP_CHECKSIG <marker> <root> <size>
OP_2DROP OP_DROP`. Unlock **73 B — the signature alone**, because the key is already in the locking
script; strictly smaller than a P2PKH unlock, which pushes a key nothing consumes. **An anchor spending
its predecessor validates through an independent interpreter.** Whole transaction 403 B, **41 sat**.

★★ **This IS a modified BRC-113.** MPT commits in `OP_RETURN`; the anchor commits in a **spendable**
output — and that spendability is the whole difference between a series of commitments and a chain.
⇒ **MPT proves a token's identity; the anchor chain proves a log's order.** Same structure, one field
moved.

⏭ **OPEN: whether the anchor output should itself be a covenant** (e.g. refusing
to advance except under the log's key, or except on a well-formed head).

⏭ **OPEN: the anchor transaction's output format** — see 6.1a.

### 6.2 Anchored, not merely broadcast

⚠ **This is the ONE place confirmation vocabulary is correct** (§4c), because it describes a
transaction on a chain that has confirmations.

A root is **anchored** only when its anchoring transaction has reached the depth the log publishes as
its threshold. A log MUST publish its **last anchored** root, and MUST NOT present a broadcast-but-not-
yet-deep-enough anchor as an anchored one.

⚠ A failed anchor — underpriced, never mined, reorganised away — otherwise leaves a silent gap: the log
looks anchored to that point and is not.

★ Note what this does NOT affect: **the entries themselves are already final** (§4c). Anchoring changes
what a third party can later be made to accept about their ORDER, not whether they happened.

⏭ **OPEN: recommended depth.**

### 6.1a-i ✅ THE ANCHOR IS A COVENANT — built 25 Aug, 26/26, nothing minted

**The first anchor's 88-byte PushDrop proved the chain. It could not enforce anything.**
⇒ A PushDrop is inert: it CARRIES a commitment, and a spender may write whatever they like into the
successor. The anchor is now a **BRC-226-style quine** — the state is peeled out of the spending
transaction's own `scriptCode` and rebuilt into the successor, so it **cannot drift**. **1,285 bytes.**

**What it enforces, every one of them tested through a script interpreter:**

| ★ **anchoring needs the owner's key** | ⚠ because **SCRIPT CANNOT VALIDATE A ROOT** — a root is *asserted*, not determined. ⇒ The covenant AUTHORISES the anchorer instead, the same shape as §4.1 |
| ★★★ **forking needs nothing at all** | a stranger replicates the log; out0 returns the parent **completely unchanged**, so there is nothing to consent to |
| ★★★ **the forker pays, the holder never does** | `newValue >= V`. ⚠ There is no fee allowance: an anchorer and a forker both bring their own funding, and **an underpaying transaction is refused by the network anyway** — the covenant has no business duplicating a rule it does not own |
| ★★★ **N ancestors + the creator are PAID** | not omittable, not redirectable, not short-payable. ⇒ **Permissionless royalties enforced by proof of work** |
| ★★ **the creator is a BAKED LITERAL** | ⚠ he lived in the shifting register once, and was **evicted after N forks.** A literal cannot be shifted out |
| ★★★ **a fork cannot relax its own rules** | the child is **COPIED** from the parent's own scriptCode with two substitutions ⇒ `genesis`, `forkable` and the covenant code are never *rebuilt*, so nothing can rebuild them wrongly |
| **no rewind** | `treesize` only grows, and a fork must leave it unchanged |

⚠ **Scope is `SIGHASH_ANYONECANPAY｜ALL｜FORKID`**, so any funder may join after the spend is assembled
— proved by adding a late funder and requiring it **accepted** there and **refused** under `0x41`.
⇒ ⚠⚠⚠ Safe **only** because `branch` makes twins impossible (§4bis.4).

### 6.1a-ii ★★★ TESTED 25 Aug — anchor 2 spends anchor 1, proved offline

⚠ **A broadcast is not the test.** That a miner accepted a transaction says a node agreed; it does
not say *why*. Running anchor 2's unlocking script **against anchor 1's locking script** says why,
and needs no key on the network and no satoshi at risk.

**11 of 11.** ★ The two that carry the weight:

| ★★★ anchor 2's unlock **satisfies** anchor 1's lock | full script evaluation |
| ⚠ a **different key's** anchor **refuses** the same unlock | ⇒ not a rubber stamp |

⇒ Also: input 0 *is* anchor 1's output · the unlocking script is **just the signature**, 73 bytes,
one push — smaller than a P2PKH unlock, which pushes a key nothing consumes · the new root and the
advanced tree size decode from the output alone · 102 sat/KB.

★★ **The test found that this had never worked.** The only anchor ever built had no predecessor, so
`pushDropUnlock` — the entire point of §6.1a — had never once executed. `buildAnchor` took
`{ txid, vout, satoshis }` where the signer needs the whole source transaction, and could not sign at
all. Meanwhile `broadcast.mjs` had quietly grown its own working copy of the same logic, so the first
anchor succeeded through code that was not the code anyone would have tested.

⇒ ⚠ Two implementations of one rule, one of them dead and one of them live, is worse than either. The
fix was not to repair the dead copy — that would have been *a green test on a path the change cannot
reach*. Both now go through `buildAnchor`, and the test exercises what actually broadcasts.

### 6.1b ★★★ THE FIRST ANCHOR — ON MAINNET, 24 AUGUST 2026

```
txid    4fc8460d8919400c9eac9584b54b6193fb8da24c57ef96ece6ebf446439ef615
marker  JETMORA1
root    9406cb5ecbea1b97579e385e737e6c7d19ec2c75093dc386527c7e933c5b27d4
size    264
```

289 bytes, **29 satoshis**, 100.3 sat/KB. It commits to a log holding **four drag races — 264
individually provable ticks, roughly 145 kB** — in 32 bytes on a proof-of-work chain.

★ Anyone may now fetch that transaction and check any of those ticks against a root nobody can walk
back, including the operator.

#### ⚠ A note that is not normative, and is recorded because it is true

⚠ **Superseded for future anchors by the covenant (§6.1a-i), which enforces rather than merely
commits.** This records what was actually broadcast, and it remains true of that transaction.

The locking script is **88 bytes exactly**:

```
 1 + 33  push + compressed pubkey   34
 1       OP_CHECKSIG                35
 1 +  8  push + "JETMORA1"          44
 1 + 32  push + root                77
 1 +  8  push + tree size           86
 1       OP_2DROP                   87
 1       OP_DROP                    88
```

⇒ Found while answering an unrelated question about whether the anchor was packed bytes or JSON, by
decomposing the script off the chain. **Nobody was counting.**
⚠ **And the mechanism, in the same breath:** the marker is 8 bytes because eight characters looked
tidy — `JETMORA` gives 87, and an uncompressed key gives 120. **An accident of four choices, nothing
planted, and it constrains nothing in this specification.**
★ It is here because a number that turns up unlooked-for should be written down with its explanation
attached, rather than remembered without one.
⚠ A first anchor spends no predecessor, which is why it is 29 sat rather than ~41. **It is also the one
anchor whose position rests on its own timestamp alone** — every anchor after it is chained.

### 6.1c ★★ The chain is walkable, so an operator keeps no anchor history

Anchor *n+1* is **whatever spent anchor *n*'s output 0**, and the tip is the one still unspent. ⇒ Given
the first anchor's transaction id — the only fact that cannot be derived — the whole chain follows.

⚠ **An implementation SHOULD NOT keep a local record of its anchor history.** It would be a second
source of truth, and a second source of truth is a disagreement waiting to happen. **The chain already
knows where it is.**

★★ **And this is not merely tidier — it is necessary.** An anchor output is a bare public key and
`OP_CHECKSIG`; it maps to no standard address, so an address index does not list it. ⇒ **The anchor is
findable only by walking**, and as a happy consequence the funding logic cannot spend it by accident.

### 6.2a Offloading at the anchor point

★★ **The anchor is the correct trigger for the pruning §5c permits, and for a specific reason: it is
the moment the log's claim stops depending on the log.** Before it, the log's word about a range rests
on its own signature alone; after it, the root is fixed by proof of work.

⚠⚠ **AN OPERATOR MUST NOT OFFLOAD AGAINST AN ANCHOR THAT IS ONLY BROADCAST.** Between broadcast and
depth a reorganisation can remove it, and bodies discarded against a commitment that no longer exists
cannot be recovered. ⇒ **Anchored, in the sense of §6.2. Not sent.**

★★★ **No additional commitment is required.** The anchored root already commits to every entry through
its leaf hash, so offloaded bodies can be checked against it by anyone who fetches them. ⇒ **The anchor
does not need a field pointing at the bundle — it already proves what the bundle must contain.**

**⇒ The operational cycle:**

```
append … append … ANCHOR … wait for depth … publish head … offload bodies … prune tree
```

#### ⚠ Where the bodies go — and why it is almost never a chain

MEASURED at 100 sat/KB with 424-byte entries:

| **anchoring the root** | one transaction a day ⇒ **44 sat**, at any volume |
| writing the bodies to a chain | 1,000 players/day ⇒ 145.6 MB ⇒ **15,264,000 sat** |

⇒ **Writing bodies to a chain costs roughly 350,000× what anchoring them does.**

⚠ **This does not contradict putting user data on a chain.** A published work is written once and is
valuable per byte. **A log's operational history is high-volume and low-value-per-byte** — the opposite
economics, and therefore the opposite answer. ⇒ Anchor the root; put the bodies wherever is cheapest.

★ §5c.3 still applies: an operator that prunes SHOULD publish **where the discarded bodies can be
obtained**, or it has not pruned, it has deleted.

### 6.3 Cadence

Anchor cadence is operator policy and SHOULD be published. It bounds, simultaneously:

- how far a signed head may be backdated
- how long two conflicting heads may both appear current
- **how much history is stranded if the operator turns hostile** (§8)

⇒ A log that stops anchoring SHOULD be treated as failing, whatever else it continues to serve.

## 4b. Signature checking

`OP_CHECKSIG` verifies a signature against the preimage of **the entry that actually happened** (§3),
never against anything the script supplies. ⇒ That recomputation is the entire security property: a
script is not trusted about its own inputs.

A signature is DER followed by **one appended sighash-type byte**. That byte is not part of the
signature; it selects which preimage to build. ★ The same value also occupies the preimage's final four
bytes, so altering the appended byte changes the preimage and the signature ceases to match.

⚠ **NO LOW_S RULE.** Bitcoin 0.1.3 has none, and an implementation MUST NOT impose one. Signature
malleability is not a threat here: an entry is identified by the hash of its own canonical bytes, and
nothing in this specification depends on a signature being unique.

⏭ **OPEN: `OP_CHECKMULTISIG`.** Covenants here are keyless, so it has no use yet. It is deliberately
unimplemented rather than written untested — **a wrong signature check is worse than an absent one.**

⏭ **OPEN: `OP_CODESEPARATOR`'s effect on `scriptCode`.** Currently the whole script is used.

## 5b. Opcode assignment

### 5b.1 ★ The governing rule

**Bitcoin 0.1.3's assignments are authoritative in the single-byte space.** Where a later
implementation reused one of those numbers for a different instruction, **the later meaning is
REMAPPED and 0.1.3 keeps the position.**

An implementation MUST NOT change a 0.1.3 assignment to accommodate a later one.

⇒ Today this affects exactly three, all introduced by Bitcoin Cash in 2018 and inherited by BSV:

| number | 0.1.3 — **kept** | later meaning — **remapped to** |
|---|---|---|
| `0x7f` | `OP_SUBSTR` | `OP_SPLIT` → `0xb0` |
| `0x80` | `OP_LEFT` | `OP_NUM2BIN` → `0xb1` |
| `0x81` | `OP_RIGHT` | `OP_BIN2NUM` → `0xb2` |

★ The rule is general, not a list. Any future collision resolves the same way, and the map is the
permanent expression of it rather than a one-off patch.

### 5b.1a ★★ Why fidelity, and not for its own sake

**So that historical script remains executable.**

`OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_MUL` and the rest were live until mid-2010. Anything
mined in that window using them exists in the early chain today, and:

| **BTC** | disabled them ⇒ cannot execute such a script at all |
| **BSV** | re-enabled, but **renumbered `0x7f`–`0x81`** ⇒ a 2009 `OP_SUBSTR` executes as `OP_SPLIT`. ⚠ **Not an error — a different answer** |
| ★ **jetmora** | 0.1.3 positions intact ⇒ **executes it as written** |

⇒ ★★★ **An implementation following this rule may be the only environment able to correctly execute
early Bitcoin script.** That does not rest on any claim about Script's origins; it follows from the
numbering alone, and it is checkable — find such an output and run it.

★ It also completes the archival case: a record that can no longer be **executed** is only half
preserved.

⚠ Note, without weight: 0.1.3 ships an extension mechanism it never uses — `OP_SINGLEBYTE_END` and a
whole two-byte address space, implemented and empty. Suggestive of a longer history than Bitcoin's, but
suggestion is not evidence and this specification claims nothing about it. It is simply the reason the
space exists for §5b.3 to use.

### 5b.2 ⚠⚠ Both sets are kept, and they are not redundant

`OP_SUBSTR`/`LEFT`/`RIGHT` and `OP_SPLIT` are equivalent in power and **not in cost**. They optimise
different access patterns and a covenant uses both:

| `OP_SPLIT` | **sequential parsing** — walk a structure front to back, keeping each piece. What state peeling does |
| `OP_SUBSTR` | **random access** — extract one field from the middle and ignore the rest |

⇒ A covenant needing only field 3 of 8 does **one `OP_SUBSTR`**, where `OP_SPLIT` must walk three
fields and discard both ends. Expressed in the other's terms, each costs five to seven opcodes.

⚠ The price of keeping both is real and is not bytes: **every implementation must get both right, and
the vectors must cover both.**
★ A covenant author SHOULD NOT choose between them. The compiler SHOULD.

### 5b.3 The ranges

| `0x00`–`0xaf` | **Bitcoin 0.1.3, unaltered** |
| `0xb0`–`0xef` | **jetmora's own single-byte opcodes.** 0.1.3 leaves this empty ⚠ but BTC reused `0xb1`/`0xb2` for `CHECKLOCKTIMEVERIFY`/`CHECKSEQUENCEVERIFY`, which cannot exist here — there is no block height and no clock — so these numbers are NOT interchangeable with BTC's |
| `0xf0` + one byte | the **two-byte space**. 0.1.3 declares `OP_SINGLEBYTE_END = 0xf0`; bounded loops and archive opcodes live here |

⚠ Scripts carrying opcodes at `0xb0` or above cannot be executed on a proof-of-work chain and therefore
cannot be appealed there (§10). An implementation SHOULD be able to report which opcodes make a given
script jetmora-only.

## 6b. Protocol versioning — no activation height

The protocol version in force for an entry is carried **in the entry** (`nVersion`, §3), and is the value
`OP_VER` pushes.

A verifier replaying an entry MUST apply the semantics of the version named **in that entry**, and MUST
NOT apply its own. ⇒ A log therefore remains fully replayable across arbitrary protocol evolution.

There MUST NOT be an activation height, a flag day, or a coordinated upgrade schedule.

⇒ Two consequences follow, and both are intended:

- **two logs MAY run different protocol versions simultaneously**, and both remain verifiable
- a covenant MAY branch on protocol version with `OP_VERIF`, giving a **forward upgrade path** without
  the covenant being reissued

⚠ This is the reason §4.3 requires invalid transitions to be **recorded**. If they were rejected at
append time, a log running version *n* could never accept an entry that only becomes valid at version
*n+k* — **and the rejection would be permanent, because the entry would not exist to re-examine.**
Recording it preserves the option; rejecting it destroys one. ★ Recording it does not honour it: an
invalid transition never advances the tip (§4.3).

★ Three requirements lock together: **entry-bound version · record-don't-reject · `OP_VERIF`**
⇒ flexibility forward, compatibility backward, and no flag day.

## 7. Source canonicalisation

`source_hash` (§2) MUST be computed over the **parsed abstract syntax tree**, not the source text.

⚠ Hashing text makes whitespace, comments and capitalisation significant, so a reformatted program
becomes a different program. Hashing the tree makes formatting irrelevant and meaning significant.

The AST serialization MUST itself be canonical, per the requirements of §3.1.

⏭ **OPEN: the AST node encoding.**

## 8. Portability

A covenant MUST be continuable in another log. **A log MUST NOT be able to claim exclusivity over a
covenant, and a covenant's script MUST NOT reference the log it runs in.**

⚠ Without this, an operator who refuses to append can freeze a covenant permanently.

A **port entry** MUST contain: `genesis`, `state`, `script`, `sequence`, the source log's public key,
the source root, an inclusion proof, the source log's signature over that root, the anchor if one
exists, and a signature by an authorised key (§4.2).

A receiving log MUST verify only: the inclusion proof against the source root; the source operator's
signature; the anchor, if presented; and the authorising signature. **It MUST NOT replay the covenant's
history.**

★ A port from an **anchored** root is final. A port from a signed-but-unanchored head is portable but
contestable — the source operator cannot un-sign it, but nothing has yet collapsed the possibility that
they signed two.

### 8.1 ★★★ TESTED 24 Aug — a covenant survives a hostile operator

⚠ Until this ran, this section was a paragraph and nothing more: the endpoint did not exist.

A covenant took three entries on log A; A published a signed head and then **refused everything
further** — the freeze described above. The covenant **ported to log B and continued there.**

★ And B refused all four things it must: a **stranger** porting someone else's covenant, a **forged**
source-head signature, an inclusion proof **for a different leaf**, and an entry **that was never in
log A**.

⇒ **A hostile operator cannot freeze a covenant.** Without that, an operator's refusal is the same
lever this whole design exists to remove, wearing different clothes.

⏭ **Not yet tested: porting from an ANCHORED root** — the *final* case above, as against the
*contestable* one exercised here.

## 9. Error states

A covenant SHOULD branch to a recorded error state rather than aborting, so that a refusal carries a
reason. ⚠ A covenant can only explain failures it anticipated; unanticipated ones are reported by
whoever replays the entry.

### 9.1 What is standardised: the discriminator, and nothing else

⚠ **Errors are unbounded.** A deslot, an empty depot, a patient outside protocol — no enumeration can
span applications, and a maintained registry would be exactly the protocol constant §4.5 forbids.

⇒ Two questions, and only the first is universal:

| **that something failed** | ★ all generic tooling needs |
| **what failed** | application-specific, unbounded, **the covenant's business** |

A covenant that reports errors MUST declare a single-byte state field named **`err`**. Zero means
success; any non-zero value is a failure code assigned by the covenant itself.

A covenant that cannot fail MUST NOT be required to declare it. Tooling determines the field's presence
and position from the covenant's source, which is committed in the genesis (§2).

⚠ This is a reserved **field name**, not a protocol field. It adds nothing to §3's entry layout.

### 9.2 Codes name themselves

Error codes MUST be declared in the covenant's source, so that a decompiler can render the name and not
merely the number:

```basic
ERROR 3 "deslot: v² > K·r"
```

⇒ There is no registry, no allocation authority and no reserved range. **The covenant carries its own
dictionary**, and because the source hash is the covenant's identity (§2, §7), **the meaning of a code is
fixed at genesis and cannot drift.**

⏭ **OPEN: the `ERROR` statement's surface syntax in BASIC.** The encoding is settled; the spelling
is not.

## 10. Conformance

An implementation is conformant if it reproduces `vectors/core.json`. Vectors carry a result hash so
comparison is O(1):

```
H(result) = SHA-256( for each stack item: varint(len) ‖ bytes )
```

⚠ Vectors marked `013` describe behaviour where **Bitcoin 0.1.3 and BSV differ**; a BSV interpreter is
not an oracle for them. Vectors marked `jetmora` have no external oracle at all.

## 11. Version 1 summary of open items

| ~~§2~~ | ~~genesis commitment serialization and on-chain envelope~~ ⇒ ✅ **CLOSED 25 Aug: there is none.** Identity is one derived field and every immutable setting is an enforced field in the covenant (§4bis.0) |
| ~~§6.1~~ | ~~anchor transaction output format~~ ⇒ ✅ **CLOSED 25 Aug**: a PushDrop covenant, 1,285 B, 26/26 (§6.1a-i) |
| §6.2 | recommended anchor depth |
| §7 | AST node encoding |
| §9 | the `ERROR` statement's spelling in BASIC — the encoding is settled (§9.1–9.2) |
| §4b | `OP_CHECKMULTISIG`, and `OP_CODESEPARATOR`'s effect on `scriptCode` |
| ~~§4d~~ | ~~the equivocation detector takes a key where it needs `(genesis, branch, key)`~~ ⇒ ✅ **CLOSED 25 Aug**: `log_id` added to the head, detector is branch-aware, 18/18 (§4d.5) |

An implementation MUST NOT claim conformance to version 1 while any of these remain open.
