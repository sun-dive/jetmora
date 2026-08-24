# A live mainnet covenant, kept as a vector

`6cb71ef6a2444da647d7fd3cf878f627d6cc09ef3faaf5d0c8f7f8deb3e40767` — Bitcoin Racers, block **962,950**,
19 August 2026. A car covenant of **1,730 bytes**, minted and spent in the same block.

| `car-lock.hex` | the covenant, from `cad9e46c…` output 0 (199 sat) |
| `race-unlock.hex` | the unlocking script that spent it, 1,892 bytes |

⇒ Transcoded from BSV to jetmora numbering (**74 bytes differ**) and executed: **966 operations, result
TRUE** — the same verdict the network reached when it mined the transaction.

⚠ **Executed in REPLAY MODE**, with the preimage supplied from the unlocking script rather than
recomputed. That answers *"did this script accept these inputs"*, which is weaker than *"is this a
valid jetmora entry"*. **A log must never do this** — there, the verifier recomputes the preimage from
the entry that actually happened, and that recomputation is the security of `OP_PUSH_TX`.

★ What it demonstrates: the interpreter and the transcoder handle a real covenant, not a curated
vector — and two independent implementations, one of them a live public network, agree about the same
3,622 bytes.
