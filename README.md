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

`spec/log.md` — the thread service, the entry format, appending, the tree, anchoring, portability.
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

## The server

`server/merkle.php` is the tree; `server/probe.php` answers what a host can actually do before anything
is built on an assumption about it.

⚠ **The probe is token-gated and meant to be deleted.** Set `PROBE_KEY`, upload it alongside
`merkle.php`, call it as `?k=<key>`, read the verdict, remove both. It 404s rather than 403s so it does
not confirm its own existence.

★ It **runs the real merkle implementation on the host** rather than checking a proxy for it. An earlier
draft compared against a hash written from memory, the hash was wrong, and the probe reported the *host*
as broken — a capability probe producing false negatives is worse than none, because you redesign around
a limitation that isn't there.

## ★★★ Bitcoin Racers on a test chain

`node --experimental-strip-types tools/dragchain.mjs` (with a thread service running)

The quarter mile, one tick per entry. Four races, four endings, **264 individually provable ticks**:

| **finishes** | eng 8 tyr 4 | 78 entries · 410.0 m at 8.79 m/s |
| **goes off** | tyr 2, grippy strip | 90 entries · 13.8 m — lost grip at speed |
| **grenades** | tyr 2, throttle 14, greasy | **1 entry** — the motor ran away with itself off the line |
| **runs dry** | tyr 2, greasy | 95 entries · 6.2 m — coasted to a stop |

**264/264 inclusion proofs verified.**

### ⚠ What this actually demonstrates, which is not what you'd guess

**It is not that ticks are free.** On a proof-of-work chain a car is compiled *for one run and no other*:
the race is simulated to its last tick **before anything is minted**, the whole run is unrolled into a
single locking script, and the covenant refuses the car if its physics disagree.

⇒ **So the race is PREDICTED at mint. The driver cannot change their mind at tick 40.**

★ Here the throttle is a **decision per tick, not a plan**. The grenade above is one entry: the driver
pressed the pedal, the engine let go, and the thread recorded exactly that. On a chain that race would have
had to be foreseen and committed to before it existed.

## Anchoring

`tools/anchor.mjs` builds the anchor; `tools/broadcast.mjs` sends it.

⚠⚠ **The key is never asked for, never stored, and never passed as an argument** — arguments appear in
`ps`, the environment does not:

```
read -s JETMORA_WIF && export JETMORA_WIF
node tools/broadcast.mjs address            # the address to fund
node tools/broadcast.mjs status             # what it holds
node tools/broadcast.mjs anchor <root> <n>  # build and show — add --send to broadcast
```

★ **Use a dedicated key.** The anchor chain's key becomes the thread service's identity: it signs every anchor,
forever. Mixing that with a spending wallet is poor hygiene.

⚠ **Dry run by default.** Nothing broadcasts without `--send`, and even then it refuses a fee below the
100 sat/KB floor (it would not relay) or more than 3× above it (money thrown away). The fee is measured
by serializing the **signed** transaction — never hand-counted, and never taken from the figure computed
before signing.

## The thread service

`server/` is a complete thread service: signature-gated append, an incremental merkle tree held on disk, immutable
signed heads, and inclusion and consistency proofs over HTTP.

| `merkle.php` | RFC 6962 |
| `store.php` | the tree is **stored, never rebuilt** — appends touch log(n) nodes, proofs are read |
| `genesis.php` | answers the one question the append rule asks: which key may advance covenant G |
| `append.php` | ⚠ the whole rule: canonical, signed by an authorised key, names the tip, and the script of the output it spends accepts it. **Nothing else** |
| `wallet/jetmora/thread.php` | `CovenantThread::judge`: builds the preimage from the tick and runs the interpreter its nVersion names |
| `dispatch.php` | the nVersion → interpreter registry (§6b) |
| `preimage.php` | the BIP143 preimage over an entry |
| `interpreter-jf.php`, `ops-jf.php` | the JF interpreter that judges a tick (spec §3.3), and its opcode table. 0xD0, 0xD2 and 0xD3 hold no word |
| `ed25519.php` | Ed25519 verification by libsodium 1.0.22's rules, on every host: ED25519-CHECKSIG and 32-byte append keys never depend on the host's sodium |
| `ed25519-sign.php` | Ed25519 keys and signatures for the signed heads and the jetmora wallet: byte for byte libsodium 1.0.22's, with no PHP extension. The secret path has the shape of ref10's constant-time code; the file says what PHP can and cannot promise |
| `head.php` | 90-byte signed head. ⚠ Re-signing a size is impossible, not merely forbidden |
| `threads.php` | the HTTP endpoints of the thread service |
| `probe.php` | ⚠ host capability probe. Token-gated, delete after use |

★ **Verified end to end by an independent implementation:** a JS client checked 200 inclusion proofs and
8 consistency proofs served by the PHP service, and rejected a tampered proof and a false entry claim.

★ **It judges a tick as a node judges a spend:** the output the tick spends must exist, and that output's script, run
against the tick, decides. A tick the script refuses is not recorded (422); a tick this host cannot judge is not recorded either (501).

⚠ **What it deliberately does not do:** adjudicate. A second entry naming a tip that is already ticked is refused as
invalid (§4.4), never weighed against the first. A thread service is a witness. The parties to a thread reach consensus by running its script, without trusting each
other or the host; it is not a global consensus among strangers who care nothing for the tick.

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
| `tools/ecdsa.mjs` | secp256k1 verification through node's own crypto (`node:crypto`), so for node only: a page loads `tools/secp256k1.mjs`. ⚠ Takes the **raw preimage**: see the contract note in the file |
| `tools/ed25519.mjs`, `tools/sha512.mjs` | Ed25519 verification by libsodium 1.0.22's rules, as `server/ed25519.php`'s, and the SHA-512 it hashes with. No dependencies, synchronous: the same code in a page and in node. `node tools/verify-ed25519.mjs` holds it to the PHP, case by case |
| `tools/entry.mjs` | the entry — canonical serialization, ⚠ refuses non-minimal varints and trailing bytes |
| `tools/preimage.mjs` | the BIP143 preimage **over an entry**: what lets `OP_PUSH_TX` exist with no transaction. Our own SHA-256, so it runs in a page unchanged, byte for byte `Preimage::build`'s |
| `tools/thread.mjs` | **`CovenantThread`, in JavaScript**: `tick()` builds a tick from the tip (the preimage first, then the caller's unlocking script), `judge(entry, inputIndex, prevLocking, prevValue)` runs the script as the service does, and `create()` and `authorisedHashes()` make a genesis. Ports of the PHP. ⚠ `judge` **throws** when it cannot judge (`VersionError`, `JfHostError`), and on what `CovenantEntry::decode` refuses (`CovenantEntryError`: an input with no unlocking script, an output with no locking script): no verdict, never a refusal |
| `tools/thread-writer.mjs` | **the writer, for a page**: `ThreadWriter` builds a tick from the tip, runs its script before it signs the append (a tick the script refuses is never sent), signs, sends, and handles each answer (201, 409, 422, 501). ⚠ **Strict writing**: its tick ledger records each successor before it is signed, keyed by the output it spends and shared by every thread a page writes, so it never signs two successors of one spent output, across a reload (IndexedDB by default in a page) and whatever thread a host files the output under. It extends only a tip it can stand behind (its own tick, or every tick after its newest one linked and accepted), refuses before signing what the service cannot store (over 100,000 bytes, a genesis needing several signatures), and keeps the bytes of every tick it sent, so `resend()` can put a rolled-back thread back, in order |
| `tools/thread-reader.mjs` | **the reader**: `readThread()` reads a thread from the genesis and checks every tick (the link, the canonical form, the judge against the output it spends), reporting each gap, broken link and refusal by position, never skipping one. It checks it read all the service holds (the last page's tip, `op=tip`'s count) and that its pages move forward, within a bound: a shortfall or a page that repeats is a problem, never a loop. Returns the tip and its outputs |
| `tools/thread-service.mjs` | the thread service's HTTP endpoint, from a page or node: genesis (its id checked), tip, entries, register and append, in JSON or packed. fetch only |
| `tools/verify-writer.mjs` | `node tools/verify-writer.mjs [--no-browser]` → the writer and the reader end to end, against the service staged as `.cpanel.yml` deploys it and served by `php -S`: ticks land, a refused tick is never sent, 409s, lost answers, a reload, two tabs on one ledger, a rolled-back host put back by `resend()`, one key on two threads with a host that mixes them up, a forged tick, the service's size and signature limits, hosts whose pages stop short, repeat or never end, 260 ticks paged, a corrupt store, pruned bodies, a lying genesis; the limits pinned to `server/append.php`; each guard of the cross-thread attack alone; mutants that must be caught; and one headless Chromium run with a WebCrypto key and the default ledger, IndexedDB |
| `tools/run-folder.mjs` | a test run's temp folder and the processes it starts, gone however the run ends; a run killed outright is cleared by the next run of the same test |
| `tools/dispatch.mjs` | the nVersion → interpreter registry, a port of `dispatch.php`, its errors in the same words |
| `tools/jf-crypto.mjs` | the crypto a JF tick is judged with, the same in a page and in node: SHA-256, SHA-1, RIPEMD-160, Ed25519 by libsodium 1.0.22's rules, and secp256k1. All ours, synchronous, and never a browser's own |
| `tools/sha1.mjs`, `tools/ripemd160.mjs` | SHA-1 and RIPEMD-160, no dependencies, synchronous |
| `tools/secp256k1.mjs` | secp256k1 verification over a digest by `server/secp256k1.php`'s rules, no dependencies: the curve a page can load (`tools/ecdsa.mjs` goes through node:crypto) |
| `tools/verify-judge.mjs` | `node tools/verify-judge.mjs [--browser]` → the judge, its preimage and its crypto held to the PHP tick for tick: `verify-tip.php`'s ticks, `verify-wired.php`'s counter, random ticks, bytes `CovenantEntry::decode` refuses (no verdict on either side), and mutants that must be caught. `--browser` runs the judge in headless Chromium too. Its PHP side is `tools/judge-run.php` |
| `tools/preimage-check.mjs` | proves an entry's preimage is byte-identical to a transaction's |
| `tools/emit.mjs` | `node tools/emit.mjs` → writes `vectors/core.json` |
| `tools/crosscheck.mjs` | `node tools/crosscheck.mjs` → differential check of the `bsv` subset. ⚠ Needs `@bsv/sdk` resolvable; set `BSV_SDK=/abs/path/to/@bsv/sdk/dist/esm/mod.js` if it is not installed alongside |

⚠ **Licence position.** Expected results are derived from **Bitcoin 0.1.3, which is MIT/X11**.
`crosscheck.mjs` uses `@bsv/sdk` (Open BSV Licence) **solely to establish BSV compatibility** — that is
use on BSV. It is not a jetmora interpreter and emits no jetmora code. Nothing in `vectors/core.json`
is derived from BSV-licensed software.

## Licence

**The code: Business Source License 1.1** — see `LICENSE`. © 2026 sun-dive. Source-available now;
the Additional Use Grant permits running it as a host, witness or mirror for anyone, free or paid, and
building and operating applications on it. What it holds back until the Change Date, **2030-09-14**, is
offering the code itself as a competing hosted product. On that date it becomes Apache 2.0.

**The specification and the papers: Apache License 2.0**, as first published. A specification that could
not be implemented freely would not be one.

**`vectors/core.json` is CC0 / public domain** (`vectors/LICENSE`): the vectors ARE the specification,
so reproducing them must not make an implementation a derivative work of it.

### ⚠⚠ Why not Open BSV, when the rest of the author's work is

> **Licensing jetmora under Open BSV would forbid running it on jetmora.**

Open BSV clause 2 restricts use to the BSV blockchains. Jetmora is not one. The same split already
applies elsewhere in this author's work — portable components under permissive or source-available
terms, BSV-specific components Open BSV — and jetmora is entirely the portable half.

### Why BSL, and why it converts to Apache

Two things at once. Nobody may close a fork before the Change Date, because every copy carries the same
terms; so the author cannot be locked out of improvements to his own design. And nobody is stopped from
building on it, because the grant names the uses the design depends on. Apache follows, with its patent
grant and its termination for anyone who brings a patent claim; contributions are accepted under Apache
2.0 from the start (see `CONTRIBUTING.md`), so nothing added later can bind the author either.
