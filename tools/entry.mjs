// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE ENTRY.  spec §3.
//
// ★★ An entry IS a transaction. Same serialization, so the sighash preimage computed over it has the
// BIP143 layout and OP_PUSH_TX reads identical bytes to those it reads on a proof-of-work chain.
// The chain is gone; the transaction FORMAT survives. That is why a covenant ports on a recompile.
//
// ⚠⚠ CANONICAL SERIALIZATION IS A HARD REQUIREMENT (spec §3.1). Exactly one byte string per entry.
// OP_PUSH_TX is secure only because a verifier RECOMPUTES the preimage and compares; two encodings
// would let a signer push a preimage that does not describe what they actually did. So: varints are
// minimally encoded, and parsing REFUSES a non-minimal one rather than accepting it charitably.

// ⚠ Our own SHA-256, not node's: this module must run unchanged in a browser so a page verifies
//   with the SAME code the fuzzer exercises. Cross-checked against node's in test/sha256.mjs.
import { sha256 } from './sha256.mjs'

const u32 = n => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]
const u64 = n => { const o = []; let v = BigInt(n); for (let i = 0; i < 8; i++) { o.push(Number(v & 0xffn)); v >>= 8n } return o }

export function varint(n) {
  if (n < 0xfd) return [n]
  if (n <= 0xffff) return [0xfd, n & 0xff, n >> 8]
  if (n <= 0xffffffff) return [0xfe, ...u32(n)]
  return [0xff, ...u64(n)]
}

class Reader {
  constructor(b) { this.b = b; this.p = 0 }
  take(n) { if (this.p + n > this.b.length) throw new Error('entry truncated'); const s = this.b.slice(this.p, this.p + n); this.p += n; return s }
  u32() { const s = this.take(4); return (s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24)) >>> 0 }
  u64() { const s = this.take(8); let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(s[i]); return v }
  /** ⚠ REFUSES a non-minimal varint — accepting one would give an entry two encodings. */
  varint() {
    const f = this.take(1)[0]
    if (f < 0xfd) return f
    if (f === 0xfd) { const v = this.take(2); const n = v[0] | (v[1] << 8); if (n < 0xfd) throw new Error('non-minimal varint'); return n }
    if (f === 0xfe) { const n = this.u32(); if (n <= 0xffff) throw new Error('non-minimal varint'); return n }
    const n = this.u64(); if (n <= 0xffffffffn) throw new Error('non-minimal varint'); return Number(n)
  }
}

/**
 * @typedef {{prevEntry:number[], index:number, unlocking:number[], sequence:number}} Input
 * @typedef {{value:bigint, locking:number[]}} Output
 * @typedef {{version:number, inputs:Input[], outputs:Output[], locktime:number}} Entry
 */

export function serializeEntry(e) {
  if (e.locktime !== 0) throw new Error('spec §3: nLocktime MUST be 0 in version 1')
  if (!e.inputs.length) throw new Error('an entry must consume at least one previous entry')
  if (!e.outputs.length) throw new Error('an entry must produce at least one successor')
  const out = [...u32(e.version), ...varint(e.inputs.length)]
  for (const i of e.inputs) {
    if (i.prevEntry.length !== 32) throw new Error('prevEntry must be 32 bytes')
    out.push(...i.prevEntry, ...u32(i.index), ...varint(i.unlocking.length), ...i.unlocking, ...u32(i.sequence))
  }
  out.push(...varint(e.outputs.length))
  for (const o of e.outputs) out.push(...u64(o.value), ...varint(o.locking.length), ...o.locking)
  out.push(...u32(e.locktime))
  return out
}

export function parseEntry(bytes) {
  const r = new Reader(bytes)
  const version = r.u32()
  const inputs = []
  for (let n = r.varint(), i = 0; i < n; i++) {
    const prevEntry = r.take(32), index = r.u32()
    const unlocking = r.take(r.varint()), sequence = r.u32()
    inputs.push({ prevEntry, index, unlocking, sequence })
  }
  const outputs = []
  for (let n = r.varint(), i = 0; i < n; i++) outputs.push({ value: r.u64(), locking: r.take(r.varint()) })
  const locktime = r.u32()
  if (r.p !== bytes.length) throw new Error(`trailing bytes: ${bytes.length - r.p}`)
  return { version, inputs, outputs, locktime }
}

/** ⚠ Round-tripping is not optional: canonical means parse(serialize(e)) re-serializes identically. */
export function assertCanonical(bytes) {
  const again = serializeEntry(parseEntry(bytes))
  if (again.length !== bytes.length || again.some((b, i) => b !== bytes[i]))
    throw new Error('entry is not canonically serialized')
  return true
}

/** An entry's identity: double SHA-256 of its canonical bytes, as a transaction id is. */
export const entryHash = e => sha256(sha256(serializeEntry(e)))
