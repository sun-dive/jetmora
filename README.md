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
| `append.php` | ⚠ the whole rule: canonical, signed by an authorised key, names the tip, names the version the lock of the output it spends declares, and that lock's script accepts it. **Nothing else** |
| `wallet/jetmora/thread.php` | `CovenantThread::judge`: runs the interpreter the spent lock declares (its first five bytes, `VER` and a version), refuses a tick that names another version, and builds the preimage from the tick |
| `dispatch.php` | the nVersion → interpreter registry (§6b) |
| `preimage.php` | the BIP143 preimage over an entry |
| `interpreter-jf.php`, `ops-jf.php` | the JF interpreter that judges a tick (spec §3.3), and its opcode table. A jump lands only on the start of an instruction, as `GOTO` lands on a line, never inside another instruction's bytes. `VER` is the lock's declaration, its first instruction: `VER` and the four bytes of the version its code is written for. The preimage's fields: `TXVALUE`, `NSEQUENCE` and `LOCKTIME` push a number; `PREVOUTS-HASH`, `SEQUENCES-HASH`, `OUTPOINT`, `SCRIPTCODE` and `OUTPUTS-HASH` write their bytes to a destination you give. 0xD0, 0xD2 and 0xD3 hold no word |
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

## Releases

`tools/release.mjs` writes a release of this code base to a thread service, as a thread of its own: the genesis
is the code thread's covenant, `basic/code-thread.bas`, owned by the release key, and each tick carries one part of
the archive, in order. Joined, the parts are the archive. Its SHA-256 is what is timestamped.

The archive is every file `git ls-files` lists at the commit, read from git's objects, never the working tree. It
is one tar as GNU tar writes it (owner and group root, mode 0644 or 0755 for an executable, mtime 00:00 of the
commit's date in its own timezone), gzipped as GNU gzip does at level 6, with no name and no time.
`tools/gzip.mjs` is our own port of gzip's deflate, so node alone rebuilds the same bytes on any machine. It is how
the 14 Sept archive was made: 448b796 rebuilds to `8f3884e2…`, 624,949 bytes, the hash in `PROVENANCE.md`.

```
node tools/release.mjs keygen FILE                                         # a new seed, mode 0600, outside any git work tree
node tools/release.mjs archive <commit> [--out FILE]                       # the archive, its hash, its parts
node tools/release.mjs publish <commit> --service URL                      # the plan; add --send to write it
node tools/release.mjs verify <genesis-id> --service URL --owner HASH160   # read back and check every part
```

⚠⚠ **The release key is never asked for, never passed as an argument, and never printed.** `publish` reads it
from the environment, a 32-byte Ed25519 seed in hex. Set it for that one run, so nothing started from the shell
afterwards inherits it:

```
# fish: typed (not shown), or read from the seed file
begin; read -l -x -s JETMORA_RELEASE_SEED; node tools/release.mjs publish <commit> --service URL; end
begin; read -l -x JETMORA_RELEASE_SEED < FILE; node tools/release.mjs publish <commit> --service URL; end
# bash: the same, in a subshell
( read -rs JETMORA_RELEASE_SEED && export JETMORA_RELEASE_SEED && node tools/release.mjs publish <commit> --service URL )
```

The tool takes the variable out of its own environment before git runs, and refuses an argument that holds the
seed.

★ **Use a key for releases only.** Should it leak, only releases are exposed.

⚠ **Dry run by default.** Nothing is written without `--send`, and there is no default service. Publishing again
carries on after the ticks already there.

The tool holds no blockchain key. BTC is stamped with OpenTimestamps (`ots stamp`, as `PROVENANCE.md` describes);
WAX and BSV are stamped from foenjam, which holds those keys. `verify` prints draft rows for
`PROVENANCE.md`.

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
| `tools/thread-writer.mjs` | **the writer, for a page**: `ThreadWriter` builds a tick from the tip, naming the version the lock it spends declares, runs its script before it signs the append (a tick the script refuses is never sent), signs, sends, and handles each answer (201, 409, 422, 501). ⚠ **Strict writing**: its tick ledger records each successor before it is signed, keyed by the output it spends and shared by every thread a page writes, so it never signs two successors of one spent output, across a reload (IndexedDB by default in a page) and whatever thread a host files the output under. It extends only a tip it can stand behind (its own tick, or every tick after its newest one linked and accepted), refuses before signing what the service cannot store (over 100,000 bytes, a genesis needing several signatures), and keeps the bytes of every tick it sent, so `resend()` can put a rolled-back thread back, in order |
| `tools/thread-reader.mjs` | **the reader**: `readThread()` reads a thread from the genesis and checks every tick (the link, the canonical form, the judge against the output it spends), reporting each gap, broken link and refusal by position, never skipping one. It checks it read all the service holds (the last page's tip, `op=tip`'s count) and that its pages move forward, within a bound: a shortfall or a page that repeats is a problem, never a loop. Returns the tip and its outputs |
| `tools/thread-service.mjs` | the thread service's HTTP endpoint, from a page or node: genesis (its id checked), tip, entries, register and append, in JSON or packed. fetch only |
| `tools/verify-writer.mjs` | `node tools/verify-writer.mjs [--no-browser]` → the writer and the reader end to end, against the service staged as `.cpanel.yml` deploys it and served by `php -S`: ticks land, a refused tick is never sent, 409s, lost answers, a reload, two tabs on one ledger, a rolled-back host put back by `resend()`, one key on two threads with a host that mixes them up, a forged tick, the service's size and signature limits, hosts whose pages stop short, repeat or never end, 260 ticks paged, a corrupt store, pruned bodies, a lying genesis; the limits pinned to `server/append.php`; each guard of the cross-thread attack alone; mutants that must be caught; and one headless Chromium run with a WebCrypto key and the default ledger, IndexedDB |
| `tools/release.mjs` | **a release of the code base**: the archive of a commit, rebuilt the same anywhere, written as a thread of ticks, read back and verified. See *Releases* |
| `tools/gzip.mjs` | gzip as GNU gzip writes it at level 6, with no name and no time: a port of its deflate, no dependencies, synchronous |
| `tools/verify-release.mjs` | `node tools/verify-release.mjs` → the release tool end to end, against the staged thread service and a lying host in front of it: 448b796 rebuilt to the 14 Sept archive, the gzip port held to GNU gzip and the tar to GNU tar, a local `git replace` and `GIT_DIR` ignored, `keygen` (never in a git work tree; the shell lines it prints leave nothing behind), `publish` (refused without the key, with the seed in an argument, without a service, and for a commit that holds no covenant or whose compiler cannot compile it; a dry run, in full, again, and carried on after a stop), the covenant always the release's commit's (a release still verifies once the working tree, or a later commit, changes the covenant and bumps the compiler), the draft rows in `PROVENANCE.md`'s columns, `verify` refusing a part missing, out of order, changed, empty or cut to another size, another key's thread, the wrong commit, each wrong genesis field and a lying host, a host's control characters kept off the terminal, Ctrl-\ without a core dump, and no seed in anything printed |
| `tools/run-folder.mjs` | a test run's temp folder and the processes it starts, gone however the run ends; a run killed outright is cleared by the next run of the same test |
| `tools/dispatch.mjs` | the nVersion → interpreter registry, a port of `dispatch.php`, its errors in the same words |
| `tools/jf-crypto.mjs` | the crypto a JF tick is judged with, the same in a page and in node: SHA-256, SHA-1, RIPEMD-160, Ed25519 by libsodium 1.0.22's rules, and secp256k1. All ours, synchronous, and never a browser's own |
| `tools/sha1.mjs`, `tools/ripemd160.mjs` | SHA-1 and RIPEMD-160, no dependencies, synchronous |
| `tools/secp256k1.mjs` | secp256k1 verification over a digest by `server/secp256k1.php`'s rules, no dependencies: the curve a page can load (`tools/ecdsa.mjs` goes through node:crypto) |
| `tools/verify-judge.mjs` | `node tools/verify-judge.mjs [--browser]` → the judge, its preimage and its crypto held to the PHP tick for tick: `verify-tip.php`'s ticks, `verify-wired.php`'s counter, random ticks, the lock's declaration (another version, none, one not served), the preimage's field words on real ticks, bytes `CovenantEntry::decode` refuses (no verdict on either side), and mutants that must be caught. `--browser` runs the judge in headless Chromium too. Its PHP side is `tools/judge-run.php` |
| `tools/preimage-check.mjs` | proves an entry's preimage is byte-identical to a transaction's |
| `tools/emit.mjs` | `node tools/emit.mjs` → writes `vectors/core.json` |
| `tools/crosscheck.mjs` | `node tools/crosscheck.mjs` → differential check of the `bsv` subset. ⚠ Needs `@bsv/sdk` resolvable; set `BSV_SDK=/abs/path/to/@bsv/sdk/dist/esm/mod.js` if it is not installed alongside |
| `basic/basic-jf.mjs` | **the jetForth BASIC compiler**, 0.5: BASIC to jetForth, served at `/basic.html`. `VERSION JF 3` compiles to the lock's declaration, `VER JF 3`, the script's first five bytes. `compileCovenant` lays a thread's covenant down: its DIM state at its head, rules 1 to 4 written for it, the declaration carried into every successor. `INPUT` names what each tick carries, pushed after the owner's signature and key, each checked for the size it says |
| `basic/unbasic-jf.mjs` | the reader: jetForth back to BASIC, the declaration read back as the `VERSION` line and a covenant's inputs as its `INPUT` line. A script that declares no version, or another one, is not read |
| `basic/code-thread.bas` | **the covenant of jetmora's own code thread**. A release is a thread of its own: each tick, signed by the release key, carries one part of the code archive and the engine revision; the successor keeps that part's SHA-256 and the revision. It holds no key: the genesis state is given when the thread is made |
| `basic/test/basic-jf.mjs` | `node basic/test/basic-jf.mjs` → every program in both interpreters, each read back to the same bytes, `INPUT` compiled, refused and read back, and the compiler proved against 0.4 and 0.3 as released, read from git: without `INPUT`, a program or a covenant is 0.4's bytes exactly; against 0.3, a program is `VER JF 3` and then 0.3's bytes, and a covenant is `VER JF 3` and then 0.3's covenant laid down for its length, the same but for one number when it writes a field |
| `basic/test/thread.mjs` | `node basic/test/thread.mjs` → a covenant thread in BASIC, ticked and judged by both interpreters and both judges, every `VERIFY` in it disabled in turn |
| `basic/test/code-thread.mjs` | `node basic/test/code-thread.mjs` → the code thread end to end, with a throwaway key: ticks carrying the engine's code, judged by both judges; another signer, another hash, another revision and the wrong pushes refused; the largest bundle one tick can carry; and two ticks through the staged thread service, read back |

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
