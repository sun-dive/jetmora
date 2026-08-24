// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// secp256k1 ECDSA VERIFICATION — no dependencies. Node's crypto has the curve natively; what it does
// not have is Bitcoin's packaging, which is what this file supplies.
//
// ⚠ TWO PIECES OF PACKAGING, both of which fail SILENTLY rather than loudly if got wrong:
//   1. a Bitcoin signature is DER with the SIGHASH TYPE BYTE APPENDED. That byte is not part of the
//      signature — it tells the verifier which preimage to build — and it must be stripped before DER
//      parsing, or the DER is malformed and verification fails for the wrong reason.
//      ★ The same value also sits in the preimage's last four bytes, so tampering with the appended
//      byte changes the preimage too and the signature stops matching. The hint is protected by the
//      thing it is a hint for.
//   2. public keys are COMPRESSED 33-byte points. Node wants SPKI DER, so we wrap them.
//
// ⚠⚠ NO LOW_S RULE. 0.1.3 has none, and it is a policy that has already cost this project real spends:
//   a conformant covenant spend was refused by a broadcaster enforcing LOW_S after the rule had been
//   removed from the node software. Jetmora does not inherit it. Malleability is not a threat here —
//   an entry is identified by its own hash and nothing depends on a signature being unique.
import { createPublicKey, verify as nodeVerify, createHash } from 'node:crypto'

const sha256 = b => createHash('sha256').update(Buffer.from(b)).digest()

// SPKI DER prefix for id-ecPublicKey + secp256k1. The last byte is the BIT STRING length, which
// depends on the point encoding, so the prefix differs for compressed and uncompressed keys.
const SPKI_COMPRESSED   = [0x30,0x36,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
                           0x06,0x05,0x2b,0x81,0x04,0x00,0x0a,0x03,0x22,0x00]
const SPKI_UNCOMPRESSED = [0x30,0x56,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
                           0x06,0x05,0x2b,0x81,0x04,0x00,0x0a,0x03,0x42,0x00]

/** @param {number[]} pub 33-byte compressed or 65-byte uncompressed secp256k1 point */
export function publicKeyFrom(pub) {
  let prefix
  if (pub.length === 33 && (pub[0] === 0x02 || pub[0] === 0x03)) prefix = SPKI_COMPRESSED
  else if (pub.length === 65 && pub[0] === 0x04) prefix = SPKI_UNCOMPRESSED
  else throw new Error(`not a secp256k1 point: ${pub.length} bytes starting 0x${(pub[0] ?? 0).toString(16)}`)
  return createPublicKey({ key: Buffer.from([...prefix, ...pub]), format: 'der', type: 'spki' })
}

/** Split a Bitcoin signature into its DER part and the appended sighash type byte. */
export function splitSignature(sig) {
  if (sig.length < 9) throw new Error('signature too short')
  return { der: sig.slice(0, -1), sighashType: sig[sig.length - 1] }
}

/**
 * Verify a Bitcoin-packaged signature.
 * @param {number[]} sig       DER ‖ sighash-type byte
 * @param {number[]} pub       33- or 65-byte point
 * @param {number[]} preimage  ⚠ THE RAW PREIMAGE — not a hash of it. See below.
 */
export function verify(sig, pub, preimage) {
  let der, key
  try { ({ der } = splitSignature(sig)); key = publicKeyFrom(pub) }
  catch { return false }                       // malformed inputs are a failed check, never a throw
  // ⚠⚠ THE CONTRACT IS THE RAW PREIMAGE, DELIBERATELY. Bitcoin signs the DOUBLE SHA-256 of it, and
  //    node's verify ALWAYS hashes its input once — so we hash once here and node's 'sha256' supplies
  //    the second. Taking a hash as the argument invites the caller to pass one hash or two, and both
  //    look plausible; only one verifies, and the wrong one fails silently with no clue why.
  //    ⚠ Note `verify(null, x)` does NOT mean "x is already the digest" — it means "use the default
  //    algorithm". There is no way to hand node a finished digest, so the argument must be raw.
  try { return nodeVerify('sha256', sha256(preimage), key, Buffer.from(der)) }
  catch { return false }
}
