// © 2026 sun-dive. Apache License 2.0 — see LICENSE. The §2b comparison hash.
//   H(result) = sha256( for each stack item: varint(len) ‖ bytes )
// ⚠ CANONICAL BY CONSTRUCTION — one byte string per stack, no optional fields (doc §4c.3).
import { createHash } from 'node:crypto'
function varint(n) {
  if (n < 0xfd) return [n]
  if (n <= 0xffff) return [0xfd, n & 0xff, n >> 8]
  return [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]
}
export function stackHash(items) {
  const b = []
  for (const h of items) { const d = Array.from(Buffer.from(h, 'hex')); b.push(...varint(d.length), ...d) }
  return createHash('sha256').update(Buffer.from(b)).digest('hex')
}
