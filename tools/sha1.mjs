// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// SHA-1 (FIPS 180-4), in plain JavaScript, synchronous, over byte arrays.
//
// ⚠⚠ WHY THIS EXISTS, GIVEN node:crypto AND WebCrypto BOTH SHIP ONE.
//   A JF script may hash with SHA1 (and so may a Bitcoin script, with OP_SHA1), and the interpreter takes its hashes
//   from the caller (tools/interpreter-jf.mjs). A page must judge a tick with the same code a test in node runs, as
//   tools/jf-crypto.mjs supplies it. node:crypto does not exist in a browser, and WebCrypto's digest is async. So the
//   hash is ours, as tools/sha256.mjs and tools/sha512.mjs are.
// ⚠ SHA-1 is broken for collisions. It is here because a script may ask for it; nothing in jetmora relies on it.
//
// ⚠⚠ AND IT IS CROSS-CHECKED: tools/verify-judge.mjs runs it against node's SHA-1 on FIPS 180's examples, every length
//   from 0 to 300 (each block boundary, where padding bugs live, among them), long inputs and random data.

const IV = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
const rotl = (x, n) => (x << n) | (x >>> (32 - n))

/** Compress the 64-byte blocks of b from `from` to `to` into H. Words are big-endian. */
function blocks(H, w, b, from, to) {
  let [h0, h1, h2, h3, h4] = H
  for (let off = from; off < to; off += 64) {
    for (let i = 0; i < 16; i++) {
      const p = off + 4 * i
      w[i] = (b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]
    }
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    let a = h0, c1 = h1, c2 = h2, c3 = h3, e = h4
    for (let i = 0; i < 80; i++) {
      let f, k
      if (i < 20) { f = (c1 & c2) | (~c1 & c3); k = 0x5a827999 }               // Ch
      else if (i < 40) { f = c1 ^ c2 ^ c3; k = 0x6ed9eba1 }                   // Parity
      else if (i < 60) { f = (c1 & c2) | (c1 & c3) | (c2 & c3); k = 0x8f1bbcdc } // Maj
      else { f = c1 ^ c2 ^ c3; k = 0xca62c1d6 }                               // Parity
      // five terms of at most 2^32 each: exact as a Number, then wrapped to 32 bits
      const t = (rotl(a, 5) + f + e + k + w[i]) | 0
      e = c3; c3 = c2; c2 = rotl(c1, 30); c1 = a; a = t
    }
    h0 = (h0 + a) | 0; h1 = (h1 + c1) | 0; h2 = (h2 + c2) | 0; h3 = (h3 + c3) | 0; h4 = (h4 + e) | 0
  }
  H[0] = h0; H[1] = h1; H[2] = h2; H[3] = h3; H[4] = h4
}

/**
 * @param {number[]|Uint8Array} bytes
 * @returns {Uint8Array} 20 bytes
 */
export function sha1(bytes) {
  const H = Int32Array.from(IV), w = new Int32Array(80)
  const len = bytes.length, whole = len - (len % 64)
  blocks(H, w, bytes, 0, whole)
  // ⚠ Padding: 0x80, then zeros, then the length in BITS as 64-bit big-endian. The reserved 9 bytes are why a tail of
  //   56 to 63 bytes needs a second block. Only the tail is copied; whole blocks are read in place.
  const tail = new Uint8Array(len - whole + 9 <= 64 ? 64 : 128)
  for (let i = whole; i < len; i++) tail[i - whole] = bytes[i]
  tail[len - whole] = 0x80
  const bits = len * 8, hi = Math.floor(bits / 0x100000000), lo = bits >>> 0, n = tail.length
  tail[n - 8] = hi >>> 24; tail[n - 7] = (hi >>> 16) & 0xff; tail[n - 6] = (hi >>> 8) & 0xff; tail[n - 5] = hi & 0xff
  tail[n - 4] = lo >>> 24; tail[n - 3] = (lo >>> 16) & 0xff; tail[n - 2] = (lo >>> 8) & 0xff; tail[n - 1] = lo & 0xff
  blocks(H, w, tail, 0, n)
  const out = new Uint8Array(20)
  for (let i = 0; i < 5; i++) {
    const v = H[i]
    out[4 * i] = v >>> 24; out[4 * i + 1] = (v >>> 16) & 0xff; out[4 * i + 2] = (v >>> 8) & 0xff; out[4 * i + 3] = v & 0xff
  }
  return out
}
