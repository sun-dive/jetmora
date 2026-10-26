// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── secp256k1 ECDSA VERIFICATION BY server/secp256k1.php's RULES, IN JAVASCRIPT ─────────────────────────────────────
//
// A PORT of Secp256k1::verifyDigest and the two decoders it reads with (server/secp256k1.php): SEC1 §4.1.4 with SEC2's
// curve, the same DER rules, the same point rules and range checks, in the same order, and x(R) mod n compared with r
// without an inversion, as the PHP compares it. A page and a test in node reach the verdict the thread service reaches,
// with no library: node:crypto does not exist in a browser, and WebCrypto has no secp256k1. tools/verify-judge.mjs holds
// this file to secp256k1.php case by case, on signatures made by PHP and by node, altered, and on garbage.
//
//   DER       SEQUENCE { INTEGER r, INTEGER s }. Nothing may follow it unless allowTrailing (a Bitcoin sighash byte is
//             the one use). A negative integer is refused; a needlessly padded one is read as its value, as PHP reads
//             it. ⚠ JF's CHECKSIG refuses a padded integer before it gets here: tools/interpreter-jf.mjs's isStrictDer is
//             BIP66, as InterpreterJF::isStrictDer is.
//   ranges    1 <= r < n and 1 <= s < n.
//   key       33-byte compressed (02 or 03) or 65-byte uncompressed (04), x and y below p, on the curve.
//   digest    exactly 32 bytes, taken as given: ECDSA signs a digest, and which hash made it is the caller's choice.
//   ⛔ No LOW_S rule (spec §3.3: "Low-S is not required"). A lock that wants low S checks s itself.
//
// ── THE ARITHMETIC ───────────────────────────────────────────────────────────────────────────────────────────────────
// Field elements and scalars are BigInt, reduced after each product, so the PHP's limbs and their bounds have no
// counterpart here. Points are Jacobian {x, y, z} standing for (x/z², y/z³), null for the point at infinity.
// u1·G + u2·Q is one pass over the bits of both scalars (Shamir's trick), so an inversion is needed only for w = s⁻¹.
// ★ Constant time is not a goal: a signature, a key and a digest are public, and there is no secret here to leak by
//   timing. This is a verifier, never a signer. Nothing here throws for bad bytes: any input that is not a valid
//   signature gives false.

/** SEC2's secp256k1: y² = x³ + 7 over F_p, the base point G of prime order n. */
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G = { x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
            y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n, z: 1n }

const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r }
/** Big-endian bytes b[from, to) as a number. */
const num = (b, from, to) => { let v = 0n; for (let i = from; i < to; i++) v = (v << 8n) | BigInt(b[i] & 0xff); return v }
function pow(b, e, m) {
  let r = 1n
  for (b = mod(b, m); e > 0n; e >>= 1n) { if (e & 1n) r = r * b % m; b = b * b % m }
  return r
}
/** a⁻¹ mod m, m prime, by the extended Euclidean algorithm; 0 for a ≡ 0. */
function inv(a, m) {
  let [r0, r1, t0, t1] = [m, mod(a, m), 0n, 1n]
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [t0, t1] = [t1, t0 - q * t1] }
  return r0 === 1n ? mod(t0, m) : 0n
}
const curveY2 = x => (x * x % P * x + 7n) % P

// ── encodings ────────────────────────────────────────────────────────────────────────────────────────────────────────

/** SEC1 point {x, y}, or null: 33-byte compressed (02/03) or 65-byte uncompressed (04). Secp256k1::point's rules. */
function point(pub) {
  const len = pub.length
  let x, y
  if (len === 65) {
    if (pub[0] !== 0x04) return null
    x = num(pub, 1, 33); y = num(pub, 33, 65)
    if (x >= P || y >= P) return null
  } else if (len === 33) {
    const t = pub[0]
    if (t !== 0x02 && t !== 0x03) return null
    x = num(pub, 1, 33)
    if (x >= P) return null
    // y = v^((p+1)/4), p ≡ 3 (mod 4). ⚠ The exponentiation always returns SOMETHING: when v is not a square the
    //   result is not on the curve, and skipping this check accepts a point that is not on the curve at all.
    const v = curveY2(x)
    y = pow(v, (P + 1n) / 4n, P)
    if (y * y % P !== v) return null
    if (Number(y & 1n) !== (t & 1)) y = mod(-y, P)
  } else {
    return null
  }
  // on the curve: the test for the uncompressed form, and a second look at the compressed one, as the PHP does
  return y * y % P === curveY2(x) ? { x, y, z: 1n } : null
}

/**
 * DER SEQUENCE { INTEGER r, INTEGER s } as [r, s], or null. Strict unless allowTrailing: nothing may follow the
 * sequence. Secp256k1::decodeDer's rules, and its reading of a padded integer (as its value).
 */
function decodeDer(sig, allowTrailing) {
  const n = sig.length
  if (n < 8 || sig[0] !== 0x30) return null
  const len = sig[1], end = 2 + len
  if (end > n) return null                                   // truncated
  if (!allowTrailing && end !== n) return null               // ⛔ trailing bytes: malformed, not lenient
  const at = { i: 2 }
  const r = derInt(sig, at, end); if (r === null) return null
  const s = derInt(sig, at, end); if (s === null) return null
  if (at.i !== end) return null                              // bytes left over INSIDE the sequence
  return [r, s]
}
/** One INTEGER at at.i, before end: its value, or null when it is negative or does not fit. */
function derInt(b, at, end) {
  const i = at.i
  if (i + 2 > end || b[i] !== 0x02) return null
  const l = b[i + 1]
  if (l === 0 || i + 2 + l > end) return null
  if (b[i + 2] & 0x80) return null                           // negative: not a valid ECDSA component
  at.i = i + 2 + l
  return num(b, i + 2, i + 2 + l)
}
/** 1 <= v < n. A value of more than 32 significant bytes is at least 2^256, so above n, as the PHP's length check refuses it. */
const inRange = v => v >= 1n && v < N

// ── the curve ────────────────────────────────────────────────────────────────────────────────────────────────────────

/** 2·p, Jacobian, a = 0 (dbl-2009-l). */
function dbl(p) {
  if (p === null || p.y === 0n) return null
  const a = p.x * p.x % P, b = p.y * p.y % P, c = b * b % P
  const xb = p.x + b
  const d = mod(2n * (xb * xb - a - c), P)
  const e = 3n * a % P, f = e * e % P
  const x = mod(f - 2n * d, P)
  return { x, y: mod(e * (d - x) - 8n * c, P), z: 2n * p.y % P * p.z % P }
}
/** p + q, Jacobian; the same point twice is a double, and a point plus its negation is infinity. */
function add(p, q) {
  if (p === null) return q
  if (q === null) return p
  const z1z1 = p.z * p.z % P, z2z2 = q.z * q.z % P
  const u1 = p.x * z2z2 % P, u2 = q.x * z1z1 % P
  const s1 = p.y * q.z % P * z2z2 % P, s2 = q.y * p.z % P * z1z1 % P
  if (u1 === u2) return s1 === s2 ? dbl(p) : null
  const h = mod(u2 - u1, P), r = mod(s2 - s1, P)
  const hh = h * h % P, hhh = hh * h % P, v = u1 * hh % P
  const x = mod(r * r - hhh - 2n * v, P)
  return { x, y: mod(r * (v - x) - s1 * hhh, P), z: h * p.z % P * q.z % P }
}
/** u1·G + u2·Q in one pass over the bits of both (Shamir's trick). u1 and u2 are public. */
function mulAdd(u1, q, u2) {
  const gq = add(G, q)
  let r = null
  for (let i = 255n; i >= 0n; i--) {
    r = dbl(r)
    const a = (u1 >> i) & 1n, b = (u2 >> i) & 1n
    if (a && b) r = add(r, gq)
    else if (a) r = add(r, G)
    else if (b) r = add(r, q)
  }
  return r
}

// ── verification ─────────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * SEC1 §4.1.4: is sig a signature of the 32-byte digest under the key pub? Secp256k1::verifyDigest's verdict.
 * @param {Uint8Array|number[]} sig       DER, and nothing after it unless allowTrailing
 * @param {Uint8Array|number[]} pub       33- or 65-byte SEC1 point
 * @param {Uint8Array|number[]} digest32  the digest ALREADY COMPUTED by the caller (Bitcoin signs a double SHA-256)
 * @param {boolean} [allowTrailing]       permits bytes after the DER sequence, which is what a Bitcoin signature's
 *                                        appended sighash-type byte looks like. ⛔ Off by default.
 * @returns {boolean}
 */
export function verifyDigest(sig, pub, digest32, allowTrailing = false) {
  if (digest32.length !== 32) return false
  const der = decodeDer(sig, allowTrailing); if (der === null) return false
  const q = point(pub);                      if (q === null) return false
  const [r, s] = der
  if (!inRange(r) || !inRange(s)) return false
  const w = inv(s, N)
  if (w === 0n) return false
  const u1 = num(digest32, 0, 32) * w % N                    // a 256-bit curve: the digest is e, not truncated
  const u2 = r * w % N
  const pt = mulAdd(u1, q, u2)
  if (pt === null) return false
  // x(R) mod n == r without an inversion: x = X/Z², and x < p < 2n, so x mod n == r means x == r, or x == r + n when
  // r + n < p.
  const zz = pt.z * pt.z % P
  if (mod(pt.x - r * zz, P) === 0n) return true
  if (r >= P - N) return false
  return mod(pt.x - (r + N) * zz, P) === 0n
}
