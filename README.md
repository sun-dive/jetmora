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

## Files

| `tools/ops.mjs` | the 0.1.3 opcode table. ⚠ `0x7f`–`0x81` are `SUBSTR`/`LEFT`/`RIGHT`, **not** `SPLIT`/`NUM2BIN`/`BIN2NUM` |
| `tools/scriptnum.mjs` | script-number codec — little-endian sign-magnitude, no size limit |
| `tools/vectors.mjs` | the vectors, hand-derived from the MIT source |
| `tools/hash.mjs` | the O(1) comparison hash |
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
