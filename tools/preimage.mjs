// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE SIGHASH PREIMAGE, computed over an ENTRY.  spec §3, doc §3.2.
//
// ★★★ This is the piece that lets OP_PUSH_TX exist with no transaction. The technique works because a
// verifier RECOMPUTES the preimage from what actually happened and CHECKSIG fails if the pushed one
// differs. Here the verifier serializes the entry and computes this. Same mechanism, same bytes.
//
// ⚠ The LAYOUT is BIP143's — a published specification, so implementing it from the BIP carries no
//   licence exposure. It is NOT 0.1.3's sighash: the original is O(n²) and has no hashPrevouts /
//   hashOutputs fields, so OP_PUSH_TX could not be built on it. Jetmora is therefore not "pure 0.1.3"
//   on sighash, and says so rather than pretending otherwise.
//
// ⚠ FORKID is NOT set and MUST NOT be (spec §5.0c): replay protection makes a signed transition valid
//   in exactly one place, which would rebuild the censorship freeze portability exists to prevent.
import { createHash } from 'node:crypto'
import { varint } from './entry.mjs'

const sha256 = b => [...createHash('sha256').update(Buffer.from(b)).digest()]
const dsha256 = b => sha256(sha256(b))
const ZERO32 = new Array(32).fill(0)
const u32 = n => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]
const u64 = n => { const o = []; let v = BigInt(n); for (let i = 0; i < 8; i++) { o.push(Number(v & 0xffn)); v >>= 8n } return o }

export const SIGHASH_ALL = 0x01
export const SIGHASH_NONE = 0x02
export const SIGHASH_SINGLE = 0x03
export const SIGHASH_ANYONECANPAY = 0x80

const outpointBytes = i => [...i.prevEntry, ...u32(i.index)]
const outputBytes = o => [...u64(o.value), ...varint(o.locking.length), ...o.locking]

/**
 * @param {object} p
 * @param {import('./entry.mjs').Entry} p.entry
 * @param {number} p.inputIndex     which input is being signed
 * @param {number[]} p.scriptCode   the locking script of the entry being consumed
 * @param {bigint} p.value          its value — an application-defined quantity, and MAY be 0
 * @param {number} [p.sighashType]  jetmora v1: MUST be SIGHASH_ALL. No FORKID.
 * @returns {number[]} the preimage bytes — hash twice to get what is signed
 */
export function preimage({ entry, inputIndex, scriptCode, value, sighashType = SIGHASH_ALL }) {
  const input = entry.inputs[inputIndex]
  if (!input) throw new Error(`no input at index ${inputIndex}`)
  if (sighashType & 0x40) throw new Error('FORKID must not be set (spec §5.0c)')
  const base = sighashType & 0x1f
  const anyone = (sighashType & SIGHASH_ANYONECANPAY) !== 0
  if (sighashType !== SIGHASH_ALL) throw new Error('jetmora v1 supports SIGHASH_ALL only; other flags are unassigned')

  const hashPrevouts = anyone ? ZERO32 : dsha256(entry.inputs.flatMap(outpointBytes))
  const hashSequence = (anyone || base === SIGHASH_NONE || base === SIGHASH_SINGLE)
    ? ZERO32 : dsha256(entry.inputs.flatMap(i => u32(i.sequence)))
  let hashOutputs
  if (base !== SIGHASH_NONE && base !== SIGHASH_SINGLE) hashOutputs = dsha256(entry.outputs.flatMap(outputBytes))
  else if (base === SIGHASH_SINGLE && inputIndex < entry.outputs.length) hashOutputs = dsha256(outputBytes(entry.outputs[inputIndex]))
  else hashOutputs = ZERO32

  return [
    ...u32(entry.version),
    ...hashPrevouts,
    ...hashSequence,
    ...outpointBytes(input),
    ...varint(scriptCode.length), ...scriptCode,
    ...u64(value),
    ...u32(input.sequence),
    ...hashOutputs,
    ...u32(entry.locktime),
    ...u32(sighashType),
  ]
}

/** What a signature is actually over. */
export const sighash = p => dsha256(preimage(p))

/**
 * ⚠ The varint prefixed to scriptCode makes the preimage's own length depend on the script's length,
 * which is why a covenant that peels its own state must be built, measured and rebuilt. Exposed so a
 * compiler can resolve that circularity rather than rediscovering it.
 */
export const scriptCodeVarIntSize = len => varint(len).length
