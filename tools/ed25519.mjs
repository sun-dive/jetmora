// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── Ed25519 VERIFICATION BY LIBSODIUM 1.0.22's RULES, IN JAVASCRIPT ─────────────────────────────────
//
// A PORT of server/ed25519.php: the same rules in the same order, refusing by the same names, with the same decoding,
// encoding and double multiply. A page and a test in node reach the verdict the thread service reaches, with no
// library: node:crypto does not exist in a browser, WebCrypto's verify is async, and the browsers' own Ed25519 accept
// signatures libsodium refuses. tools/verify-ed25519.mjs holds this file to ed25519.php on every case of
// server/verify-ed25519.php's corpus, the verdict and the refusing rule both.
//
// A signature is R ‖ S, 64 bytes; a key A is 32 bytes. The signature verifies when
//   1  S < L
//   2  R is none of the small-order encodings
//   3  A is canonical: its y, the sign bit cleared, is below p
//   4  A is none of the small-order encodings
//   5  A is a point of the curve
//   6  [S]B − [h]A, encoded, is R byte for byte, h = SHA-512(R ‖ A ‖ M) mod L
// server/ed25519.php gives each rule's name in libsodium, and says why no signature anyone can build shows rule 3 in a
// verdict. Any other input gives false, a wrong length included. Nothing here throws for bad bytes.
//
// ── THE ARITHMETIC ───────────────────────────────────────────────────────────────────────────────────
// A field element mod p = 2^255 − 19 is a BigInt. A product comes back below 2^256 by folding 2^255 = 19 (mod p) twice;
// sums and differences are left as they are, negative ones included, for the next product to fold. A value is made
// canonical, 0 to p − 1, only where its bytes or its low bit are read. BigInt cannot overflow, so the limb bounds
// ed25519.php keeps have no counterpart here. Scalars mod L are BigInt remainders.
// The points and their formulas are ref10's, as ed25519.php carries them: extended twisted Edwards coordinates and the
// complete addition law (d is not a square), so a double, the identity and a point of small order all go through the
// same formulas.
// Bytes are little-endian, as Ed25519 writes them.
//
// ★ Constant time is not a goal: a signature, a key and a message are public, and there is no secret here to leak by
//   timing. This is a verifier, never a signer.
//
// The point code is ported through server/ed25519.php from sodium_compat (src/Core/Ed25519.php), and the rules and the
// small-order list from libsodium (open.c, crypto_core/ed25519/ref10/ed25519_ref10.c at 1.0.22-RELEASE). Both are ISC,
// and both ask that their notice be kept:
//
//   ISC License
//
//   Copyright (c) 2016-2023, Paragon Initiative Enterprises <security at paragonie dot com>
//   Copyright (c) 2013-2019, Frank Denis <j at pureftpd dot org>
//
//   Permission to use, copy, modify, and/or distribute this software for any
//   purpose with or without fee is hereby granted, provided that the above
//   copyright notice and this permission notice appear in all copies.
//
//   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//   ISC License
//
//   Copyright (c) 2013-2026
//   Frank Denis <j at pureftpd dot org>
//
//   Permission to use, copy, modify, and/or distribute this software for any
//   purpose with or without fee is hereby granted, provided that the above
//   copyright notice and this permission notice appear in all copies.
//
//   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
import { sha512 } from './sha512.mjs'

/** p = 2^255 − 19 and L = 2^252 + 27742317777372353535851937790883648493. */
const P = (1n << 255n) - 19n
const L = (1n << 252n) + 27742317777372353535851937790883648493n
const LOW255 = (1n << 255n) - 1n
/** d = −121665/121666 and 2d, and sqrt(−1) = 2^((p − 1)/4), canonical. */
const D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159n
const D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3n
const SQRTM1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n

/** B, 3B, 5B, ..., 15B as affine [x, y]: the odd multiples a signed window of 5 bits reads. ed25519.php's B_ODD. */
const B_ODD = [
  [0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51an, 0x6666666666666666666666666666666666666666666666666666666666666658n],   // B
  [0x67ae9c4a22928f491ff4ae743edac83a6343981981624886ac62485fd3f8e25cn, 0x1267b1d177ee69aba126a18e60269ef79f16ec176724030402c3684878f5b4d4n],   // 3B
  [0x49fda73eade3587bfcef7cf7d12da5de5c2819f93e1be1a591409cc0322ef233n, 0x5f4825b298feae6fe02c6e148992466631282eca89430b5d10d21f83d676c8edn],   // 5B
  [0x14568685fcf4bd4ee9e3ee194b1d810783e809f3bbf1ce955855981af50e4107n, 0x31c563e32b47d52f87ce6468dd36ad41f0882b46f7abf23d12c4c4b59f4062b8n],   // 7B
  [0x357cc970c80071651bf336e06f9422b886d80e5c2e4e0294d3e023065185715cn, 0x7f3d23c2c2dd0df4b2befce956f2d2fd1f789013236e4430c74e44845522f1c0n],   // 9B
  [0x14e528b1154be417b6cf078dd6712438d381a5b2c593d552ff2fd2c1207cf3cbn, 0x2d9082313f21ab975a6f7ce340ff0fce1258591c3c9c58d4308f2dc36a033713n],   // 11B
  [0x107427e0d5f366ccdb33adf0282d304f8843e3e88d22b7b83780e073b7c05fedn, 0x12dbb00ded538b7478466022d2da89b83740cfb2289a272387efe1aeea401f80n],   // 13B
  [0x4f162deaec2ec435dc5ac6f95d20419ed9631374770189cb90617f3e66a18dc1n, 0x12cbfb2d04ff22f55162f70164d29331ace5af18a19a9aa1946d4cc4ad2e5cdfn],   // 15B
]

/**
 * The seven y values of the small-order points, little-endian with the sign bit cleared, as libsodium lists them:
 * 0 (order 4), 1 (order 1), the two of order 8, p − 1 (order 2), and p and p + 1, which read as 0 and 1.
 */
const SMALL_ORDER = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
])

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'))
/** The little-endian bytes b[from], ..., b[to − 1] as a number. */
function num(b, from, to) {
  let h = '0x'
  for (let i = to - 1; i >= from; i--) h += HEX[b[i]]
  return BigInt(h)
}
const bytesOf = x => x instanceof Uint8Array ? x : Uint8Array.from(x)

// ── the verdict ──────────────────────────────────────────────────────────────────────────────────────

/**
 * RFC 8032 Ed25519 over the message as given, with libsodium 1.0.22's verdict: true when sig is a valid signature of
 * msg under the key pub. False for anything else, and for a signature that is not 64 bytes or a key that is not 32.
 * @param {Uint8Array|number[]} sig  @param {Uint8Array|number[]} msg  @param {Uint8Array|number[]} pub
 * @returns {boolean}
 */
export function verify(sig, msg, pub) {
  return refusal(sig, msg, pub) === null
}

/**
 * The rule that refuses the signature, by the header's numbering and in ed25519.php's words, or null when it
 * verifies. verify() is whether this is null; tools/verify-ed25519.mjs reads the rule, which is how rule 3 is seen.
 * @returns {string|null}
 */
export function refusal(sig, msg, pub) {
  if (sig.length !== 64 || pub.length !== 32) return 'lengths'
  sig = bytesOf(sig); msg = bytesOf(msg); pub = bytesOf(pub)
  if (num(sig, 32, 64) >= L) return '1 S < L'
  if (smallOrder(sig)) return '2 R small order'
  if (!canonical(pub)) return '3 A canonical'
  if (smallOrder(pub)) return '4 A small order'
  const a = decodeNegated(pub)
  if (a === null) return '5 A on the curve'
  const m = new Uint8Array(64 + msg.length)
  m.set(sig.subarray(0, 32)); m.set(pub, 32); m.set(msg, 64)
  const h = num(sha512(m), 0, 64) % L
  if (encode(mulAdd(le32(h), a, sig.subarray(32))) !== num(sig, 0, 32)) return '6 the equation'
  return null
}

/** One of the 14 small-order encodings: its first 32 bytes' y, the sign bit cleared, is one of the seven. */
function smallOrder(b) {
  let h = ''
  for (let i = 0; i < 31; i++) h += HEX[b[i]]
  return SMALL_ORDER.has(h + HEX[b[31] & 0x7f])
}

/** y, the sign bit cleared, is below p. */
const canonical = b => (num(b, 0, 32) & LOW255) < P

// ── the field ────────────────────────────────────────────────────────────────────────────────────────

/** x mod p, loosely: 2^255 = 19 (mod p) folded in twice. Congruent to x, perhaps negative, and below 2^256 in size
 *  for any x below 2^520, which every product here is. */
function fold(x) {
  x = (x & LOW255) + 19n * (x >> 255n)
  return (x & LOW255) + 19n * (x >> 255n)
}
const mul = (f, g) => fold(f * g)
const sq = f => fold(f * f)
/** 2f², fe25519_sq2 */
const sq2 = f => fold(2n * f * f)
/** The canonical value, 0 to p − 1. */
function canon(f) {
  f %= P
  return f < 0n ? f + P : f
}
const isZero = f => canon(f) === 0n
/** The low bit of the canonical value: the sign of x in an encoding. */
const isNegative = f => Number(canon(f) & 1n)

/** f squared n times, then times g. */
function sqMul(f, n, g) {
  for (let i = 0; i < n; i++) f = sq(f)
  return mul(f, g)
}

/**
 * z^(2^250 − 1) and z^11: the squarings fe25519_invert and fe25519_pow22523 share, by the runs of ones
 * 2^5 − 1, 2^10 − 1, 2^20 − 1, 2^40 − 1, 2^50 − 1, 2^100 − 1, 2^200 − 1 and 2^250 − 1.
 */
function pow250(z) {
  const z2 = sq(z)
  const z9 = mul(z, sq(sq(z2)))
  const z11 = mul(z2, z9)
  const t5 = mul(z9, sq(z11))                                   // 2^5 − 1
  const t10 = sqMul(t5, 5, t5)
  const t20 = sqMul(t10, 10, t10)
  const t40 = sqMul(t20, 20, t20)
  const t50 = sqMul(t40, 10, t10)
  const t100 = sqMul(t50, 50, t50)
  const t200 = sqMul(t100, 100, t100)
  const t250 = sqMul(t200, 50, t50)
  return [t250, z11]
}

/** 1/z = z^(p − 2) = z^(2^255 − 21): 2^250 − 1, five squarings, times z^11. */
function invert(z) {
  const [t250, z11] = pow250(z)
  return sqMul(t250, 5, z11)
}

/** z^((p − 5)/8) = z^(2^252 − 3): 2^250 − 1, two squarings, times z. */
function pow22523(z) {
  return sqMul(pow250(z)[0], 2, z)
}

// ── points, extended twisted Edwards: −x² + y² = 1 + d·x²·y² ───────────────────────────────────────
// As ref10 names them:  p2 [X, Y, Z], (X/Z, Y/Z) · p3 [X, Y, Z, T], with T = XY/Z · p1p1 [X, Y, Z, T], (X/Z, Y/T),
// what a sum or a double gives before its last multiply · cached [Y + X, Y − X, Z, 2dT] · precomp [y + x, y − x, 2dxy],
// affine.

/** 2P for a p2 or p3 point, as p1p1: ge25519_p2_dbl. */
function dbl(p) {
  const xx = sq(p[0]), yy = sq(p[1]), zz = sq2(p[2])
  const s = sq(p[0] + p[1])
  const y = yy + xx, z = yy - xx
  return [s - y, y, z, zz - z]
}

/** p1p1 as p2. */
const p2 = p => [mul(p[0], p[3]), mul(p[1], p[2]), mul(p[2], p[3])]

/** p1p1 as p3. */
const p3 = p => [mul(p[0], p[3]), mul(p[1], p[2]), mul(p[2], p[3]), mul(p[0], p[1])]

/** p3 as cached. */
const cached = p => [p[1] + p[0], p[1] - p[0], p[2], mul(p[3], D2)]

/** p + q for a p3 p and a cached q, as p1p1: ge25519_add. q negated, ge25519_sub, when minus. */
function addCached(p, q, minus) {
  const a = mul(p[1] + p[0], minus ? q[1] : q[0])
  const b = mul(p[1] - p[0], minus ? q[0] : q[1])
  const t = mul(q[3], p[3])
  let z = mul(p[2], q[2])
  z = z + z
  return minus ? [a - b, a + b, z - t, z + t] : [a - b, a + b, z + t, z - t]
}

/** p + q for a p3 p and a precomp q, as p1p1: ge25519_madd. q negated, ge25519_msub, when minus. */
function addPrecomp(p, q, minus) {
  const a = mul(p[1] + p[0], minus ? q[1] : q[0])
  const b = mul(p[1] - p[0], minus ? q[0] : q[1])
  const t = mul(q[2], p[3])
  const z = p[2] + p[2]
  return minus ? [a - b, a + b, z - t, z + t] : [a - b, a + b, z + t, z - t]
}

/** B_ODD as precomp points. */
const BI = B_ODD.map(([x, y]) => [y + x, y - x, mul(mul(x, y), D2)])

/**
 * −A as p3 for the encoding of A, or null when its y has no x on the curve: ge25519_frombytes_negate_vartime.
 * x = u·v³·(u·v⁷)^((p − 5)/8) with u = y² − 1 and v = d·y² + 1 is a square root of u/v when v·x² = u, and becomes one
 * times sqrt(−1) when v·x² = −u; otherwise u/v has none. Then the root whose low bit is NOT the sign bit is kept,
 * which negates A. The same root when x = 0 and the sign bit is set: no such A reaches here (rule 4).
 */
function decodeNegated(s) {
  const y = num(s, 0, 32) & LOW255                              // the top bit dropped, as fe25519_frombytes reads it
  let u = sq(y)
  const v = mul(u, D) + 1n
  u = u - 1n
  const v3 = mul(sq(v), v)
  let x = mul(mul(sq(v3), v), u)
  x = mul(mul(pow22523(x), v3), u)
  const vxx = mul(sq(x), v)
  if (!isZero(vxx - u)) {
    if (!isZero(vxx + u)) return null
    x = mul(x, SQRTM1)
  }
  if (isNegative(x) === s[31] >> 7) x = -x
  return [x, y, 1n, mul(x, y)]
}

/** The encoding of a p2 point as a number: y canonical, the sign of x in bit 255. The one inversion. */
function encode(p) {
  const zi = invert(p[2])
  return canon(mul(p[1], zi)) | (BigInt(isNegative(mul(p[0], zi))) << 255n)
}

/** A scalar below 2^256 as 32 little-endian bytes. */
function le32(n) {
  const out = new Uint8Array(32)
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n }
  return out
}

/**
 * [a]A + [b]B as p2, a and b little-endian bytes of the same length and A as p3: ge25519_double_scalarmult_vartime. One
 * doubling a bit shared by both, A's digits read from A, 3A, ..., 15A built here and B's from B_ODD.
 * The group law gives one answer whatever the method.
 */
function mulAdd(a, A, b) {
  const da = digits(a), db = digits(b)
  const ai = [cached(A)]
  const a2 = p3(dbl(A))
  for (let i = 1; i < 8; i++) ai[i] = cached(p3(addCached(a2, ai[i - 1], false)))
  let r = [0n, 1n, 1n]
  let i = da.length - 1
  while (i >= 0 && da[i] === 0 && db[i] === 0) i--
  for (; i >= 0; i--) {
    let t = dbl(r)
    const x = da[i], y = db[i]
    if (x !== 0) t = addCached(p3(t), ai[(x > 0 ? x : -x) >> 1], x < 0)
    if (y !== 0) t = addPrecomp(p3(t), BI[(y > 0 ? y : -y) >> 1], y < 0)
    r = p2(t)
  }
  return r
}

/**
 * The signed-window form of a little-endian scalar, by bit position: each digit odd with |digit| < 16, any two at
 * least 5 positions apart, 0 between them, and Σ digit·2^position equal to the scalar. A carry out of the last window
 * lands at most 5 positions past the last bit.
 */
function digits(k) {
  const len = 8 * k.length, bits = new Uint8Array(len)
  for (let i = 0; i < len; i++) bits[i] = (k[i >> 3] >> (i & 7)) & 1
  const out = new Int8Array(len + 6)
  let carry = 0, i = 0
  while (i < len) {
    if (bits[i] === carry) { i++; continue }                    // this bit plus the carry is even: a zero digit
    let word = carry
    for (let j = 0; j < 5 && i + j < len; j++) word += bits[i + j] << j
    carry = (word >> 4) & 1                                     // past half the window: a negative digit, and carry
    out[i] = word - (carry << 5)
    i += 5
  }
  if (carry) out[i] = 1                                         // never from verify(): S and h are below L < 2^253
  return out
}
