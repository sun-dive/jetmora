# jetmora — conformance vectors

**The specification is a file of test vectors, not a document.** An implementation that reproduces
`vectors/core.json` is conformant; one that does not is provably wrong at a named opcode.

⚠ This directory is **not** part of grafverse and must never be bundled into one of its pages.

## Why vectors instead of prose

Prose about what `OP_MUL` does cannot be executed. Two honest implementations will still diverge on
overflow, negative zero and minimal encoding — silently. A vector names the divergence and fails.

Each vector carries a **result hash**, so comparison is O(1) regardless of the work done:

```
H(result) = sha256( for each stack item: varint(len) ‖ bytes )
```

## The three oracle classes

| `bsv` | 0.1.3 and BSV agree ⇒ an independent BSV interpreter can confirm it. **49 of these, all confirmed.** |
| `013` | ⚠ **0.1.3 ONLY — BSV differs.** No external oracle exists. Hand-derived from the MIT source. |
| `jetmora` | our own decision (entry-bound `OP_VER`, the extensions). No oracle can exist. |

## ⚠⚠ Divergences found so far — the reason this exists

**`OP_LSHIFT` / `OP_RSHIFT` are NUMERIC in 0.1.3, BYTEWISE in BSV.**
`bn = bn1 << bn2.getulong()` (script.cpp) shifts an arbitrary-precision bignum by N bits. BSV's
post-Genesis version shifts a byte array. **Same opcode number, different meaning, no error raised.**
⇒ Also the canonical case of the output-size hazard: shift size depends on a **value**, not a size.

**0.1.3 has NO numeric size limit.** `CBigNum bn1(stacktop(-2))` — no 4-byte cap, no minimal-encoding
rule. ★ BSV agrees (it removed the limit at Genesis); BTC does not.

**`OP_RETURN` does not fail.** `case OP_RETURN: { pc = pend; } break;` — it jumps to the end and
continues; the stack survives. ⚠ BTC made it an unconditional failure in 2010. **BSV kept 0.1.3's.**
★ This one was found by the cross-check on its first run, correcting a vector written from familiarity
rather than from the source.

## The specification

`spec/log.md` — what a log is, the entry format, appending, the tree, anchoring, portability.
⚠ It says **what**; the reasoning lives elsewhere and is not normative. Seven items are marked ⏭ OPEN
and an implementation must not claim conformance while any remain.

## ⚠ Why fuzzing, when the vectors already pass

The vectors were hand-written and the interpreter was written to satisfy them. **On its own that is
circular.** The cross-check breaks the circle for the `bsv` subset; differential fuzzing breaks it far
harder, by generating scripts nobody curated and comparing two independent implementations.

It found two real defects on its first run, neither of which any curated vector reached:

- **`OP_AND`/`OP_OR`/`OP_XOR` on unequal lengths.** 0.1.3 calls `MakeSameSize()` and **zero-pads the
  shorter to the longer**; the result takes the longer length. BSV *refuses* unequal sizes. Our first
  implementation *truncated to the shorter* — a third behaviour, matching neither.
- **Unbalanced `OP_IF`.** 0.1.3 has no end-of-script balance check at all; it simply returns
  `CastToBool(stack.back())`. Ours failed, having imported a modern rule by habit.

⇒ **16,000 generated scripts across four seeds now diverge zero times** on the shared subset.

## ⚠⚠ Why transcoding is not optional

BSV places `SPLIT`/`NUM2BIN`/`BIN2NUM` at `0x7f`–`0x81`, overwriting 0.1.3's `SUBSTR`/`LEFT`/`RIGHT`.
Jetmora keeps 0.1.3's range intact and puts its own at `0xb0`–`0xb2`. So the same byte is a different
instruction on each rail:

```
0x7f    BSV: OP_SPLIT       jetmora: OP_SUBSTR
0x80    BSV: OP_NUM2BIN     jetmora: OP_LEFT
0x81    BSV: OP_BIN2NUM     jetmora: OP_RIGHT
```

⇒ Run BSV bytes on jetmora without transcoding and **they will not error. They will quietly compute
something else.** The mapping is therefore explicit, total, and refuses anything it does not recognise.

★ Measured: a state-peeling program renumbers 8 opcodes and **the byte length does not change** —
putting these in the free single-byte range rather than the two-byte space costs nothing.

## ★★★ The acid test

`node --experimental-strip-types tools/acid.mjs`

A real covenant — 212 lines of BASIC, the physics of a slot car, **3,669 bytes and 2,179 opcodes** —
compiled once and executed on **three independent implementations**:

| an independent BSV Script interpreter | on BSV-numbered bytes |
| ours | the same program transcoded to jetmora numbering, 44 opcodes renumbered |
| ★ the JavaScript reference | **not a Script interpreter at all** |

**15 of 15 agree. The reference agrees on all 10 that produced output.**

★ The other five are lifted-throttle cases, where the covenant refuses — and **both interpreters refuse
identically.** Agreement on a refusal is still agreement, and it is what identified a harness bug
earlier rather than letting it look like a divergence between implementations.

⇒ This is the claim executed against real work rather than a toy: **H(source) · H(input) → H(output)**,
run anywhere, same answer. The three paths share nothing — different opcode numbers, different
serializers, different interpreters, written years apart by different hands.

## Files

| `tools/ops.mjs` | the 0.1.3 opcode table. ⚠ `0x7f`–`0x81` are `SUBSTR`/`LEFT`/`RIGHT`, **not** `SPLIT`/`NUM2BIN`/`BIN2NUM` |
| `tools/scriptnum.mjs` | script-number codec — little-endian sign-magnitude, no size limit |
| `tools/vectors.mjs` | the vectors, hand-derived from the MIT source |
| `tools/hash.mjs` | the O(1) comparison hash |
| `tools/interpreter.mjs` | **the interpreter.** 0.1.3 semantics, arbitrary-precision integers, no build step |
| `tools/verify.mjs` | `node tools/verify.mjs` → runs the vectors against our interpreter |
| `tools/fuzz.mjs` | `node tools/fuzz.mjs` → **differential fuzzing** against an independent BSV interpreter |
| `tools/serialize.mjs` | chunks ⇄ bytes, including the two-byte space. ⚠ `@bsv/sdk`'s `LockingScript` cannot represent a two-byte opcode, so this had to exist regardless of any licence question |
| `tools/transcode.mjs` | **BSV numbering → jetmora numbering.** ⚠ Not optional — see below |
| `tools/acid.mjs` | **the acid test** — a real covenant on three implementations |
| `tools/crosscompile.mjs` | `node --experimental-strip-types tools/crosscompile.mjs` → compiles BASIC once, runs it both ways, requires one answer |
| `tools/ecdsa.mjs` | secp256k1 verification, no dependencies. ⚠ Takes the **raw preimage** — see the contract note in the file |
| `tools/entry.mjs` | the entry — canonical serialization, ⚠ refuses non-minimal varints and trailing bytes |
| `tools/preimage.mjs` | the BIP143 preimage **over an entry** — what lets `OP_PUSH_TX` exist with no transaction |
| `tools/preimage-check.mjs` | proves an entry's preimage is byte-identical to a transaction's |
| `tools/emit.mjs` | `node tools/emit.mjs` → writes `vectors/core.json` |
| `tools/crosscheck.mjs` | `node tools/crosscheck.mjs` → differential check of the `bsv` subset. ⚠ Needs `@bsv/sdk` resolvable; set `BSV_SDK=/abs/path/to/@bsv/sdk/dist/esm/mod.js` if it is not installed alongside |

⚠ **Licence position.** Expected results are derived from **Bitcoin 0.1.3, which is MIT/X11**.
`crosscheck.mjs` uses `@bsv/sdk` (Open BSV Licence) **solely to establish BSV compatibility** — that is
use on BSV. It is not a jetmora interpreter and emits no jetmora code. Nothing in `vectors/core.json`
is derived from BSV-licensed software.

## Licence

**Apache License 2.0** — see `LICENSE`. © 2026 sun-dive.
**`vectors/core.json` is CC0 / public domain** (`vectors/LICENSE`): the vectors ARE the specification,
so reproducing them must not make an implementation a derivative work of it.

### ⚠⚠ Why not Open BSV, when the rest of the author's work is

> **Licensing jetmora under Open BSV would forbid running it on jetmora.**

Open BSV clause 2 restricts use to the BSV blockchains. Jetmora is not one. The same split already
applies elsewhere in this author's work — portable components MIT/Apache, BSV-specific components
Open BSV — and jetmora is entirely the portable half.

### Why Apache rather than MIT

Both say *do what you like*. Apache also says **you cannot turn a patent on the project afterwards**:
an explicit patent grant, with the licence terminating for anyone who brings a patent claim. For a
protocol intended for institutional implementers, that clause is what their counsel looks for — and it
protects the author as much as the adopter.
