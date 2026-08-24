// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// RFC 6962 MERKLE TREE — spec §5.1.  ⚠⚠ NOT Bitcoin's tree, and the difference is not cosmetic:
//   · Bitcoin duplicates the last node on an odd count (`i2 = min(i+1, nSize-1)`, 0.1.3 main.h:878),
//     so two different entry lists can produce the SAME root — CVE-2012-2459.
//   · Bitcoin hashes leaves and internal nodes identically, so an internal node can be presented as
//     a leaf. RFC 6962 prefixes 0x00 for leaves and 0x01 for nodes, which forecloses that.
//   · And RFC 6962 gives CONSISTENCY proofs, which no proof-of-work chain provides: proof that one
//     tree is an append-only extension of another. That is what makes "append-only" checkable
//     rather than trusted.
import { createHash } from 'node:crypto'

const sha = (...parts) => [...createHash('sha256').update(Buffer.concat(parts.map(Buffer.from))).digest()]
export const leafHash = d => sha([0x00], d)
export const nodeHash = (l, r) => sha([0x01], l, r)
const EMPTY = () => [...createHash('sha256').update(Buffer.alloc(0)).digest()]

/** ⚠ k = the largest power of two STRICTLY LESS than n. This is the whole shape of the tree. */
export function splitPoint(n) {
  if (n < 2) throw new Error('splitPoint needs n >= 2')
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** MTH(D[n]) — the Merkle Tree Hash. */
export function root(entries) {
  const n = entries.length
  if (n === 0) return EMPTY()
  if (n === 1) return leafHash(entries[0])
  const k = splitPoint(n)
  return nodeHash(root(entries.slice(0, k)), root(entries.slice(k)))
}

/** PATH(m, D[n]) — the inclusion proof for entry m. */
export function inclusionProof(m, entries) {
  const n = entries.length
  if (m < 0 || m >= n) throw new Error(`index ${m} outside 0..${n - 1}`)
  if (n === 1) return []
  const k = splitPoint(n)
  return m < k
    ? [...inclusionProof(m, entries.slice(0, k)), root(entries.slice(k))]
    : [...inclusionProof(m - k, entries.slice(k)), root(entries.slice(0, k))]
}

/**
 * Recompute a root from a leaf and its path. A verifier needs only this and the entry.
 * ⚠⚠ THE PATH IS BUILT BOTTOM-UP by the recursion in `inclusionProof`, so it must be CONSUMED
 *    bottom-up. Walking it top-down agrees only for particular sizes — it passed 203 of 820 cases,
 *    which is exactly the kind of partial green that looks like a working implementation.
 *    ⇒ This mirrors the construction rather than reasoning about the order, which is why it is right.
 */
export function verifyInclusion(m, n, leaf, path, expectedRoot) {
  if (m < 0 || m >= n || n < 1) return false
  const walk = (m, size, pos) => {
    if (size === 1) return { h: leafHash(leaf), pos }
    const k = splitPoint(size)
    const r = m < k ? walk(m, k, pos) : walk(m - k, size - k, pos)
    if (r.pos >= path.length) return { h: null, pos: r.pos + 1 }
    if (r.h === null) return { h: null, pos: r.pos + 1 }
    return { h: m < k ? nodeHash(r.h, path[r.pos]) : nodeHash(path[r.pos], r.h), pos: r.pos + 1 }
  }
  const { h, pos } = walk(m, n, 0)
  return h !== null && pos === path.length
    && h.length === expectedRoot.length && h.every((b, j) => b === expectedRoot[j])
}

/** PROOF(m, D[n]) — proof that the tree of size m is a prefix of the tree of size n. */
export function consistencyProof(m, entries) {
  const n = entries.length
  if (m < 1 || m > n) throw new Error(`m must be 1..${n}`)
  if (m === n) return []
  return subProof(m, entries, true)
}
function subProof(m, entries, b) {
  const n = entries.length
  if (m === n) return b ? [] : [root(entries)]
  const k = splitPoint(n)
  return m <= k
    ? [...subProof(m, entries.slice(0, k), b), root(entries.slice(k))]
    : [...subProof(m - k, entries.slice(k), false), root(entries.slice(0, k))]
}

/** ⚠ Verify that `oldRoot` (size m) really is a prefix of `newRoot` (size n). */
export function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])
  if (m === n) return proof.length === 0 && eq(oldRoot, newRoot)
  if (m < 1 || m > n) return false
  let p = [...proof]
  // when m is an exact power of two the old root is not carried in the proof — it is the old root
  let fn = m - 1, sn = n - 1
  while (fn & 1) { fn >>= 1; sn >>= 1 }
  let fr, sr
  if (fn !== 0) { if (!p.length) return false; fr = sr = p.shift() }
  else { fr = sr = oldRoot }
  while (sn !== 0) {
    if (fn & 1 || fn === sn) {
      if (!p.length) return false
      const s = p.shift()
      fr = nodeHash(s, fr); sr = nodeHash(s, sr)
      while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1 }
    } else {
      if (!p.length) return false
      sr = nodeHash(sr, p.shift())
    }
    fn >>= 1; sn >>= 1
  }
  return p.length === 0 && eq(fr, oldRoot) && eq(sr, newRoot)
}
