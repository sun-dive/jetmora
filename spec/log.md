# jetmora log — specification

**Status: DRAFT, 24 August 2026.** Normative keywords MUST / MUST NOT / SHOULD / MAY are used in the
usual sense. ⏭ marks a decision not yet made; those are the only parts an implementer may not rely on.

This document says **what**. The reasoning lives elsewhere and is not normative.

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

### 3.1 Canonical serialization

There MUST be exactly one byte string per entry.

An implementation MUST NOT accept two encodings of the same entry, MUST NOT define optional fields, and
MUST NOT permit any integer encoding that admits more than one form.

⚠ This is not tidiness. `OP_PUSH_TX` is secure only because the verifier recomputes the preimage and
compares; **two encodings would let a signer push a preimage that does not describe what they did.**

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

⏭ **PROPOSED and implemented — 89 bytes, canonical by construction:**

```
version      1 byte
tree_size    8 bytes, big-endian
root        32 bytes
timestamp    8 bytes, big-endian, unix seconds
anchor_root 32 bytes  — the last ANCHORED root, or 32 zero bytes if none
anchor_size  8 bytes  — the tree size at that anchored root
```

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

### 5c.3 Where the bodies go

⚠ **This specification does not say.** A proof-of-work chain gives permanence and addressability; a
cheap disk gives cost; a mirror gives both cheaply and neither permanently. ⇒ Same position as payment
(§3.4-0b): **the protocol has no opinion, and an operator SHOULD publish what it does.**

★ An operator that prunes SHOULD publish, alongside its retention policy, **where the discarded bodies
can be obtained** — otherwise it has not pruned, it has deleted.

⏭ **OPEN: whether *K* should be fixed by the specification or chosen per log.** Fixed makes a pruned
proof's shape predictable to any client; per-log lets a small operator prune harder. ⇒ Leaning per-log,
declared in the head, but nothing depends on it yet.

## 6. Anchoring

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

⏭ **PROPOSED 24 Aug, not yet normative.** A modified BRC-113 carrying its commitment in a **PushDrop**
output rather than `OP_RETURN`.

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

⏭ **OPEN: the PushDrop field layout, and whether the anchor output is itself a covenant** (e.g. refusing
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

| §2 | genesis commitment serialization and on-chain envelope |

| §6.1 | anchor transaction output format |
| §6.2 | recommended anchor depth |
| §7 | AST node encoding |
| §9 | the `ERROR` statement's spelling in BASIC — the encoding is settled (§9.1–9.2) |
| §4b | `OP_CHECKMULTISIG`, and `OP_CODESEPARATOR`'s effect on `scriptCode` |

An implementation MUST NOT claim conformance to version 1 while any of these remain open.
