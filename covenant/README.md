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
| 1 | 252 B | 202 |
| 2 | 276 B | 221 |
| 3 | **300 B** | 240 |
| 5 | 348 B | 278 |

⇒ **Exactly 24 B per lineage level.** ⚠ This is the state machine only; the `OP_PUSH_TX` frame is
separate and is the larger half.

## ⚠ What reading it back caught

The compile was green at 295 B and built the **wrong successor**: `newtreesize` never reached the state,
because the rebuild gathers the DIMmed names **by name** and every value had been computed into fresh
variables it had never heard of. ⇒ **The parent would have come out unchanged on every anchor — the log
could never have grown.** No test would have said so. The listing did.

★ Hence the last thing the program does is assign to the fields, and one assignment covers both paths:
a fork has already been forced to `newtreesize = treesize`, so it is a no-op there and an advance on an
anchor. **No branch, no second program.**

## Running it

```
npx tsx covenant/compile.mts      # sizes
npx tsx covenant/read-back.mts    # ⚠ the listing — read this before minting anything
```
