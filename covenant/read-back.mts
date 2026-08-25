// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ READ THE WHOLE COVENANT BACK — frame and all, not just the BASIC half.
//
// ⚠ Nothing gets minted until this has been read. *"A hand-written one can only be re-derived, which
//   is the opposite of why the reader was built."*
import { unbasicListing } from '../../grafverse/mint/src/unbasic.ts'
import { buildAnchorLock, anchorUnlock } from './anchorFrame.mts'
import { ANCHOR_IDIOMS } from './anchorIdioms.mts'

const LEVELS = Number(process.env.N ?? 3)
const OWNERS = Number(process.env.OWNERS ?? 1)
const creator = Array(20).fill(0xc1)
const payees = Object.fromEntries(
  Array.from({ length: LEVELS }, (_, i) => ['p' + 'abcdefgh'[i], creator]))
/* ⚠ one hash per owner slot — n-of-n, and n changes the script's SHAPE. */
const owners = Object.fromEntries(
  Array.from({ length: OWNERS }, (_, i) => ['owner' + 'abcd'[i], Array(20).fill(0x77 + i)]))

const lock: any = buildAnchorLock({
  levels: LEVELS, owners: OWNERS, creator,
  state: { genesis: Array(32).fill(0x9a), branch: Array(32).fill(0), depth: 0, treesize: 0, royalty: 1, forkable: 1, leafcovers: 1, ...owners, ...payees },
})
console.log(`  ── the anchor covenant · N=${LEVELS} · ${lock.toBinary().length} B · ${lock.chunks.length} chunks ──\n`)
/* ⚠⚠ THE READER'S STACK IS WHAT THE UNLOCKING SCRIPT PUSHES — and nothing else.
   ⇒ NOT the compiler's model, which also carries `preimageCopy` and `scriptCode`: the lock creates
   those itself, and the reader watches it happen. Feeding it either extra name shifts every label,
   and a listing with confident wrong names is worse than one that stops. */
console.log(unbasicListing(lock.chunks, {
  stack: [...anchorUnlock(OWNERS), 'preimage'], idioms: ANCHOR_IDIOMS,
}))
