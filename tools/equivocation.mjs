// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE EQUIVOCATION DETECTOR — the security model, made checkable.
//
// The whole design rests on one claim: **a log cannot cheat without leaving a receipt.** It is not
// prevented from cheating; it is prevented from cheating INVISIBLY. That claim is worth nothing until
// something can actually produce the receipt, which is what this does.
//
// ⚠⚠ THERE ARE TWO WAYS TO EQUIVOCATE AND THE OBVIOUS ONE IS THE EASY ONE:
//
//   1. SAME SIZE, DIFFERENT ROOTS — two signed heads at one tree size. Trivial to spot.
//   2. ★ AN INCONSISTENT HISTORY — heads at DIFFERENT sizes where the smaller is not a prefix of the
//      larger. An operator avoiding (1) will do this instead, and a detector that only checks (1)
//      misses it entirely.
//
// ⚠ And a third thing that is EVIDENCE BUT NOT PROOF: refusing to serve a consistency proof. You
//   cannot prove the absence of a proof. Reported as suspicion, never as guilt — a detector that
//   conflates the two is worse than none, because it convicts the merely unreachable.
import { createHash, verify as nodeVerify, createPublicKey } from 'node:crypto'
import * as M from './merkle.mjs'

const hex = b => Buffer.from(b).toString('hex')
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

/** ⚠ Key length selects the scheme, matching the append rule: 32 ⇒ Ed25519, 33/65 ⇒ secp256k1. */
export function verifySig(msg, pubkey, sig) {
  try {
    if (pubkey.length === 32) {
      const key = createPublicKey({ key: Buffer.concat([
        Buffer.from([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]),
        Buffer.from(pubkey)]), format: 'der', type: 'spki' })
      return nodeVerify(null, Buffer.from(msg), key, Buffer.from(sig))
    }
    const prefix = pubkey.length === 33
      ? [0x30,0x36,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x0a,0x03,0x22,0x00]
      : [0x30,0x56,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,0x81,0x04,0x00,0x0a,0x03,0x42,0x00]
    const key = createPublicKey({ key: Buffer.from([...prefix, ...pubkey]), format: 'der', type: 'spki' })
    return nodeVerify('sha256', Buffer.from(msg), key, Buffer.from(sig))
  } catch { return false }
}

/** A signed head, 90 bytes — spec §5.2. */
export function parseHead(b) {
  if (b.length !== 90) throw new Error(`a head is 90 bytes, got ${b.length}`)
  const rd = (o, n) => { let v = 0n; for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[o+i]); return Number(v) }
  const anchorRoot = b.slice(49, 81)
  return { version: b[0], treeSize: rd(1, 8), root: b.slice(9, 41), timestamp: rd(41, 8),
           anchorRoot: anchorRoot.every(x => x === 0) ? null : anchorRoot,
           anchorSize: rd(81, 8), pruneLevel: b[89] }
}

/**
 * ★ FORM 1 — two heads at ONE tree size with different roots.
 * @returns a proof object anyone can re-check, or a reason it is not proof
 */
export function checkSameSize(headA, sigA, headB, sigB, pubkey) {
  const a = parseHead(headA), b = parseHead(headB)
  if (!verifySig(headA, pubkey, sigA)) return { equivocated: false, reason: 'first head is not signed by that key' }
  if (!verifySig(headB, pubkey, sigB)) return { equivocated: false, reason: 'second head is not signed by that key' }
  if (a.treeSize !== b.treeSize) return { equivocated: false, reason: 'different tree sizes — see checkConsistency' }
  if (eq(a.root, b.root)) return { equivocated: false, reason: 'same size, same root — this is one head twice' }
  return { equivocated: true, form: 'same-size', treeSize: a.treeSize,
           rootA: hex(a.root), rootB: hex(b.root),
           proof: { headA: hex(headA), sigA: hex(sigA), headB: hex(headB), sigB: hex(sigB), pubkey: hex(pubkey) },
           statement: `signed two different roots at tree size ${a.treeSize}` }
}

/**
 * ★★ FORM 2 — an INCONSISTENT HISTORY. Two heads at different sizes where the smaller is not a
 * prefix of the larger. ⚠ An operator avoiding form 1 does this instead.
 * @param proof the operator's own consistency proof, or null if it refused / cannot produce one
 */
export function checkConsistency(headSmall, sigSmall, headLarge, sigLarge, pubkey, proof) {
  const s = parseHead(headSmall), l = parseHead(headLarge)
  if (!verifySig(headSmall, pubkey, sigSmall) || !verifySig(headLarge, pubkey, sigLarge))
    return { equivocated: false, reason: 'a head is not signed by that key' }
  if (s.treeSize > l.treeSize) return checkConsistency(headLarge, sigLarge, headSmall, sigSmall, pubkey, proof)
  if (s.treeSize === l.treeSize) return checkSameSize(headSmall, sigSmall, headLarge, sigLarge, pubkey)
  if (proof === null || proof === undefined)
    // ⚠⚠ NOT PROOF. You cannot prove the absence of a proof, and an unreachable log is not a liar.
    return { equivocated: false, suspicious: true,
             reason: 'no consistency proof supplied — evidence, never guilt: a log may be offline, slow, or pruned' }
  const ok = M.verifyConsistency(s.treeSize, l.treeSize, [...s.root], [...l.root], proof)
  if (ok) return { equivocated: false, reason: `size ${s.treeSize} is a genuine prefix of size ${l.treeSize}` }
  return { equivocated: true, form: 'inconsistent-history', from: s.treeSize, to: l.treeSize,
           rootSmall: hex(s.root), rootLarge: hex(l.root),
           proof: { headSmall: hex(headSmall), sigSmall: hex(sigSmall),
                    headLarge: hex(headLarge), sigLarge: hex(sigLarge),
                    pubkey: hex(pubkey), offered: proof.map(hex) },
           statement: `signed size ${s.treeSize} and size ${l.treeSize}, and the first is not a prefix of the second` }
}

/**
 * ★★★ FORM 3 — AN AUTHOR convicting themselves. Spec §4b.5: rewinding is self-equivocation, because
 * the author signs the port and cannot un-sign the sequence they already signed.
 * ⚠ The evidence lands where it is needed with no gossip protocol: whoever you raced against already
 *   holds your later signature.
 */
export function checkAuthor(entryA, sigA, entryB, sigB, authorKey, sequenceOf) {
  if (!verifySig(entryA, authorKey, sigA)) return { equivocated: false, reason: 'first entry is not signed by that key' }
  if (!verifySig(entryB, authorKey, sigB)) return { equivocated: false, reason: 'second entry is not signed by that key' }
  if (eq(entryA, entryB)) return { equivocated: false, reason: 'the same entry twice' }
  const sa = sequenceOf(entryA), sb = sequenceOf(entryB)
  if (sa !== sb) return { equivocated: false, reason: `different sequences (${sa}, ${sb}) — a covenant advancing, not equivocating` }
  return { equivocated: true, form: 'author-self-equivocation', sequence: sa,
           proof: { entryA: hex(entryA), sigA: hex(sigA), entryB: hex(entryB), sigB: hex(sigB), key: hex(authorKey) },
           statement: `signed two different entries at sequence ${sa}` }
}
