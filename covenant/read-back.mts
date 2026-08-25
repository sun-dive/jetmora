// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ READ THE WHOLE COVENANT BACK — frame and all, not just the BASIC half.
//
// ⚠ Nothing gets minted until this has been read. *"A hand-written one can only be re-derived, which
//   is the opposite of why the reader was built."*
import { unbasicListing } from '../../grafverse/mint/src/unbasic.ts'
import { buildAnchorLock, ANCHOR_UNLOCK } from './anchorFrame.mts'
import { ANCHOR_IDIOMS } from './anchorIdioms.mts'

const LEVELS = Number(process.env.N ?? 3)
const creator = Array(20).fill(0xc1)
const payees = Object.fromEntries(
  Array.from({ length: LEVELS }, (_, i) => ['p' + 'abcdefgh'[i], creator]))

const lock: any = buildAnchorLock({
  levels: LEVELS, owner: Array(20).fill(0x77), maxFee: 400,
  state: { genesis: Array(32).fill(0x9a), depth: 0, treesize: 0, royalty: 1, forkable: 1, ...payees },
})
console.log(`  ── the anchor covenant · N=${LEVELS} · ${lock.toBinary().length} B · ${lock.chunks.length} chunks ──\n`)
/* ⚠ THE READER'S STACK IS THE UNLOCKING CONTRACT, not the compiler's model — they are different
   lists, and feeding it the wrong one shifts every name by the difference. */
console.log(unbasicListing(lock.chunks, {
  stack: [...ANCHOR_UNLOCK, 'preimage'], idioms: ANCHOR_IDIOMS,
}))
