// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// SHA-512 (FIPS 180-4), in plain JavaScript, synchronous, over byte arrays.
//
// ⚠⚠ WHY THIS EXISTS, GIVEN node:crypto AND WebCrypto BOTH SHIP ONE.
//   Ed25519 hashes R ‖ A ‖ M with SHA-512, and tools/ed25519.mjs must reach its verdict with the same code in a page
//   and in node, synchronously, as the engine's other crypto does. node:crypto does not exist in a browser, and
//   WebCrypto's digest is async. So the hash is ours, as tools/sha256.mjs is.
//
// ⚠ A 64-bit word is two 32-bit halves, high and low. JavaScript's bit operators work on 32 bits, so each rotation is
//   built from both halves, and each addition sums the low halves as plain numbers (exact far past the five 32-bit
//   terms a round adds) and carries what passes 2^32 into the high half. BigInt would be exact too, and many times
//   slower.
//
// ⚠⚠ AND IT IS CROSS-CHECKED: tools/verify-ed25519.mjs runs it against node's SHA-512 on FIPS 180's examples, every
//   length from 0 to 300 (each block boundary, where padding bugs live, among them) and random data.

/** The round constants, high and low half of each: the first 64 bits of the fractional parts of the cube roots of the
 *  first 80 primes. */
const K = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]
/** The initial hash, the same way from the square roots of the first 8 primes. */
const IV = [
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]
const TWO32 = 0x100000000

/** The 128-byte blocks of m from `off` up to `end`, into the state H (16 halves). w holds the 80-word schedule. */
function blocks(H, w, m, off, end) {
  for (; off < end; off += 128) {
    for (let i = 0, o = off; i < 32; i++, o += 4) w[i] = (m[o] << 24) | (m[o + 1] << 16) | (m[o + 2] << 8) | m[o + 3]
    for (let i = 32; i < 160; i += 2) {
      // σ0 = rotr 1 ^ rotr 8 ^ shr 7 of word i − 15; σ1 = rotr 19 ^ rotr 61 ^ shr 6 of word i − 2
      let xh = w[i - 30], xl = w[i - 29]
      const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7)
      const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25))
      xh = w[i - 4]; xl = w[i - 3]
      const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6)
      const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26))
      const lo = (s1l >>> 0) + (w[i - 13] >>> 0) + (s0l >>> 0) + (w[i - 31] >>> 0)
      w[i] = s1h + w[i - 14] + s0h + w[i - 32] + ((lo / TWO32) | 0)
      w[i + 1] = lo
    }
    let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7]
    let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15]
    for (let i = 0; i < 160; i += 2) {
      // T1 = h + Σ1(e) + Ch(e, f, g) + K + w, with Σ1 = rotr 14 ^ rotr 18 ^ rotr 41
      const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23))
      const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23))
      const chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl)
      let lo = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + K[i + 1] + (w[i + 1] >>> 0)
      const t1h = (hh + S1h + chh + K[i] + w[i] + ((lo / TWO32) | 0)) | 0, t1l = lo | 0
      // T2 = Σ0(a) + Maj(a, b, c), with Σ0 = rotr 28 ^ rotr 34 ^ rotr 39
      const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25))
      const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25))
      const mh = (ah & bh) ^ (ah & ch) ^ (bh & ch), ml = (al & bl) ^ (al & cl) ^ (bl & cl)
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el
      lo = (dl >>> 0) + (t1l >>> 0)
      eh = (dh + t1h + ((lo / TWO32) | 0)) | 0; el = lo | 0
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al
      lo = (t1l >>> 0) + (S0l >>> 0) + (ml >>> 0)
      ah = (t1h + S0h + mh + ((lo / TWO32) | 0)) | 0; al = lo | 0
    }
    const v = [ah, al, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl]
    for (let i = 0; i < 16; i += 2) {
      const lo = (H[i + 1] >>> 0) + (v[i + 1] >>> 0)
      H[i] = (H[i] + v[i] + ((lo / TWO32) | 0)) | 0; H[i + 1] = lo | 0
    }
  }
}

/**
 * @param {number[]|Uint8Array} bytes
 * @returns {Uint8Array} 64 bytes
 */
export function sha512(bytes) {
  const H = Int32Array.from(IV), w = new Int32Array(160)
  const len = bytes.length, whole = len - (len % 128)
  blocks(H, w, bytes, 0, whole)
  // ⚠ Padding: 0x80, then zeros, then the length in BITS as a 128-bit big-endian number. The reserved 17 bytes are
  //   why a tail of 112 to 127 bytes needs a second block. Only the tail is copied; whole blocks are read in place.
  const tail = new Uint8Array(len - whole + 17 <= 128 ? 128 : 256)
  for (let i = whole; i < len; i++) tail[i - whole] = bytes[i]
  tail[len - whole] = 0x80
  const bits = len * 8, hi = Math.floor(bits / TWO32), lo = bits >>> 0, n = tail.length
  tail[n - 8] = hi >>> 24; tail[n - 7] = (hi >>> 16) & 0xff; tail[n - 6] = (hi >>> 8) & 0xff; tail[n - 5] = hi & 0xff
  tail[n - 4] = lo >>> 24; tail[n - 3] = (lo >>> 16) & 0xff; tail[n - 2] = (lo >>> 8) & 0xff; tail[n - 1] = lo & 0xff
  blocks(H, w, tail, 0, n)
  const out = new Uint8Array(64)
  for (let i = 0; i < 16; i++) {
    const v = H[i]
    out[4 * i] = v >>> 24; out[4 * i + 1] = (v >>> 16) & 0xff; out[4 * i + 2] = (v >>> 8) & 0xff; out[4 * i + 3] = v & 0xff
  }
  return out
}
