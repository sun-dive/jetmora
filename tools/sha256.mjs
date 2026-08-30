// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// SHA-256, in plain JavaScript, synchronous, over byte arrays.
//
// ⚠⚠ WHY THIS EXISTS AT ALL, GIVEN node:crypto AND WebCrypto BOTH SHIP ONE.
//   `entry.mjs` and `merkle.mjs` are the reference implementation of this specification's tree, and a
//   browser must be able to verify a proof with the SAME code the fuzzer exercises. But `node:crypto`
//   does not exist in a browser, and WebCrypto's digest is ASYNC while `leafHash`/`nodeHash` are used
//   synchronously everywhere. ⇒ Neither can be the shared one.
//   ★ So the hash is ours, and node and the browser run LITERALLY the same code path — which is a
//   stronger guarantee than "same file, different backend", and it is the whole point: one tree, one
//   implementation, no third answer (see the LSHIFT divergence that motivated this project).
//
// ⚠⚠ AND IT IS CROSS-CHECKED, BECAUSE AN IMPLEMENTATION AGREEING WITH ITSELF PROVES NOTHING.
//   `test/sha256.mjs` runs this against node's native SHA-256 over the NIST vectors and thousands of
//   random inputs, including every length across a block boundary — where padding bugs live.

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

const rotr = (x, n) => (x >>> n) | (x << (32 - n))

/**
 * @param {number[]|Uint8Array} bytes
 * @returns {number[]} 32 bytes
 */
export function sha256(bytes) {
  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

  const len = bytes.length
  // ⚠ Padding: 0x80, then zeros, then the length in BITS as 64-bit big-endian. The reserved 9 bytes
  //   (marker + 8 length) are why a message of length 56..63 mod 64 needs an EXTRA block — the classic
  //   off-by-one, and why the test sweeps every length across a boundary rather than sampling.
  const withPad = Math.ceil((len + 9) / 64) * 64
  const m = new Uint8Array(withPad)
  m.set(bytes)
  m[len] = 0x80
  // ⚠ Length in bits can exceed 2^32, so the high word is computed rather than left zero.
  const bits = len * 8
  const hi = Math.floor(bits / 0x100000000)
  const lo = bits >>> 0
  m[withPad - 8] = (hi >>> 24) & 0xff; m[withPad - 7] = (hi >>> 16) & 0xff
  m[withPad - 6] = (hi >>> 8) & 0xff;  m[withPad - 5] = hi & 0xff
  m[withPad - 4] = (lo >>> 24) & 0xff; m[withPad - 3] = (lo >>> 16) & 0xff
  m[withPad - 2] = (lo >>> 8) & 0xff;  m[withPad - 1] = lo & 0xff

  const w = new Int32Array(64)
  for (let off = 0; off < withPad; off += 64) {
    for (let i = 0; i < 16; i++)
      w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3]
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) | 0
      h = g; g = f; f = e; e = (d + t1) | 0
      d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0
  }

  const out = []
  for (const v of H) out.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff)
  return out
}

/** HASH256 — the double hash this specification uses for entry ids and genesis ids. */
export const sha256d = b => sha256(sha256(b))

export const toHex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
export const fromHex = h => {
  const o = []
  for (let i = 0; i < h.length; i += 2) o.push(parseInt(h.slice(i, i + 2), 16))
  return o
}
