// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ READ A COVENANT'S STATE BACK OFF THE CHAIN — and PROVE the reading is right.
//
// ⚠⚠ A decoder that guesses wrong QUIETLY is worse than no decoder, because everything downstream
//    inherits the mistake. So this does not trust its own parse: it REBUILDS the locking script from
//    what it decoded and requires the result to be BYTE-IDENTICAL to the script it was handed.
//    ⇒ If the bytes match, the reading is correct by construction. If they do not, it returns null.
//
// ★ That also solves the layout ambiguity for free. Owner slots and payee slots are both 20 bytes, so
//   the header alone cannot say how many of each there are — but only ONE combination rebuilds.
import { Script } from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { buildAnchorLock } from './anchorFrame.mts'

export interface CovenantState {
  genesis: number[]; branch: number[]; depth: number; treesize: number; royalty: number
  forkable: number; leafcovers: number
  owners: number[][]; payees: number[][]; creator: number[]
}

/**
 * ⚠⚠ LITTLE-ENDIAN, SIGN-MAGNITUDE — matching `fixedField`, which is what wrote these bytes.
 * ⇒ Reading them big-endian decodes a depth of 7 as 1,792 and rebuilds a different script. The
 *   rebuild check caught it immediately; a decoder that merely "looked plausible" would not have.
 */
const num = (b: number[]) => {
  const neg = (b[b.length - 1] & 0x80) !== 0
  let v = 0
  for (let i = b.length - 1; i >= 0; i--) v = v * 256 + (i === b.length - 1 ? b[i] & 0x7f : b[i])
  return neg ? -v : v
}
const eq = (a: number[], b: number[]) => a.length === b.length && a.every((v, i) => v === b[i])

/**
 * @param lockBytes the raw locking script
 * @returns the state, or **null** if it does not rebuild — never a guess
 */
export function decodeState(lockBytes: number[]): CovenantState | null {
  let chunks: any[]
  try { chunks = Script.fromBinary(lockBytes).chunks } catch { return null }

  /* the PushDrop header: every data push before the first OP_2DROP */
  const head: number[][] = []
  for (const c of chunks) {
    if (!c.data?.length) break
    head.push([...c.data])
  }
  /* genesis, branch, depth, treesize, royalty, forkable, leafcovers, then 20-byte slots */
  if (head.length < 8) return null
  const [genesis, branch, depth, treesize, royalty, forkable, leafcovers] = head
  if (genesis.length !== 32 || branch.length !== 32) return null
  const slots = head.slice(7)
  if (!slots.length || slots.some(s => s.length !== 20)) return null

  /* ⚠ THE CREATOR is a literal in the royalty output, not in the header: the 26-byte push
     0x19 76 a9 14 <hash20> 88 ac. Distinctive enough to find without guessing. */
  const cre = chunks.find((c: any) => c.data?.length === 26 && c.data[0] === 0x19 &&
    c.data[1] === 0x76 && c.data[2] === 0xa9 && c.data[3] === 0x14 &&
    c.data[24] === 0x88 && c.data[25] === 0xac)
  if (!cre) return null
  const creator = [...cre.data].slice(4, 24)

  /* ★★ Try each split of the 20-byte slots into owners and payees, and REBUILD. Only the true one
     reproduces the script byte for byte — so the answer is verified rather than inferred. */
  for (let nOwners = 1; nOwners <= Math.min(4, slots.length - 1); nOwners++) {
    const levels = slots.length - nOwners
    if (levels < 1 || levels > 8) continue
    const owners = slots.slice(0, nOwners), payees = slots.slice(nOwners)
    const state: any = {
      genesis, branch, depth: num(depth), treesize: num(treesize), royalty: num(royalty),
      forkable: num(forkable), leafcovers: num(leafcovers),
      ...Object.fromEntries(owners.map((h, i) => ['owner' + 'abcd'[i], h])),
      ...Object.fromEntries(payees.map((h, i) => ['p' + 'abcdefgh'[i], h])),
    }
    let rebuilt: number[]
    try { rebuilt = buildAnchorLock({ levels, owners: nOwners, creator, state }).toBinary() }
    catch { continue }
    if (eq(rebuilt, lockBytes)) {
      return { genesis, branch, depth: num(depth), treesize: num(treesize), royalty: num(royalty),
               forkable: num(forkable), leafcovers: num(leafcovers), owners, payees, creator }
    }
  }
  return null
}
