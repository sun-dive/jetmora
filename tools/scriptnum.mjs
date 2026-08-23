// © 2026 sun-dive. Apache License 2.0 — see LICENSE. ⚠ NOT Open BSV: see NOTICE.
// Script number encoding, as Bitcoin 0.1.3 does it: little-endian sign-magnitude,
// sign in the high bit of the LAST byte. ⚠ 0.1.3 applies NO size limit and NO minimal-encoding
// rule — operands are OpenSSL BIGNUMs (`CBigNum bn1(stacktop(-2))`, script.cpp:567).

/** BigInt → script-number bytes (minimal form). */
export function toNum(n) {
  n = BigInt(n)
  if (n === 0n) return []
  const neg = n < 0n
  let v = neg ? -n : n
  const out = []
  while (v > 0n) { out.push(Number(v & 0xffn)); v >>= 8n }
  if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0x00)
  else if (neg) out[out.length - 1] |= 0x80
  return out
}

/** script-number bytes → BigInt. ⚠ Accepts non-minimal forms, as 0.1.3 does. */
export function fromNum(b) {
  if (b.length === 0) return 0n
  let v = 0n
  for (let i = 0; i < b.length; i++) v |= BigInt(b[i]) << BigInt(8 * i)
  const signBit = 1n << BigInt(8 * b.length - 1)
  return (v & signBit) ? -(v & ~signBit) : v
}

export const hex = b => Buffer.from(b).toString('hex')
export const unhex = h => Array.from(Buffer.from(h, 'hex'))
