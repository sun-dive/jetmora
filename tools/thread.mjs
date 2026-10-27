// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ THE COVENANT THREAD, IN JAVASCRIPT: creating one, ticking it forward, judging a tick ════════════════════════════
//
// A PORT of CovenantThread (server/wallet/jetmora/thread.php) for the writers and readers that are pages: a writer builds
// a tick from the tip and runs its script before it signs the append, and a reader checks each tick it reads back, with
// the verdict the thread service reaches. Each function is its PHP namesake:
//
//   create(sourceHash, script, state, authorised) → { commitment, id }
//       the genesis (spec §2): commitment = LP(source_hash) ‖ LP(script) ‖ LP(state) ‖ LP(authorised), id = HASH256 of it,
//       LP a 4-byte big-endian length. The id is derived, never asserted.
//   authorisedHashes(publicKeys, k = 1) → bytes
//       a key set packed as 0x02 ‖ k ‖ n ‖ (32 ‖ SHA-256(key)) × n, ascending: the keys hashed, never in the clear
//   tick(prevEntryHash, prevIndex, prevLocking, prevValue, outputs, sequence, buildUnlocking, version = JF 3)
//       → Promise<{ entry, bytes, hash, preimage }>
//       the entry that spends output prevIndex of the tip. The preimage covers the tip's locking script and never this
//       entry's unlocking script, so it is built first and handed to buildUnlocking(preimage), which may be async (a
//       WebCrypto signature is) and must return the unlocking script. sequence is the tick index (spec §3), never a clock.
//   judge(entry, inputIndex, prevLocking, prevValue, crypto = jfCrypto) → Promise<{ accepted, stack?, error?, errorBytes? }>
//       first what CovenantEntry::decode refuses before PHP's judge ever sees an entry: an input with no unlocking script,
//       an output with no locking script, a tick reference that is not 32 bytes. Each is CovenantEntryError, thrown, as
//       decode throws it: no verdict. Then rules 1 and 2 of spec §3.3:
//         1  the lock's declaration names the interpreter (declaredVersion, tools/dispatch.mjs); JF revision 3 is the one
//            that judges. The entry's nVersion must be that version, or the tick is refused with OTHER_VERSION, its
//            script never run
//         2  the preimage is built HERE, from the entry and the output it spends (tools/preimage.mjs), never taken from
//            the caller: OP_PUSH_TX is secure only because the verifier recomputes it
//       and that interpreter's verifyTick (tools/interpreter-jf.mjs) judges the rest, rules 3 to 5, 7 and 8.
//   appendSighash(entryBytes) → SHA-256 of the entry bytes: what a secp256k1 append key signs. An Ed25519 append key
//       signs the entry bytes themselves (server/append.php).
// Bytes are Uint8Array or arrays of numbers on the way in, Uint8Array on the way out; a value is a u64, a bigint or a
// safe integer. tools/verify-judge.mjs holds judge() to the PHP judge tick for tick: the same verdict, the same refusal
// bytes, and no verdict in the same cases, with the same words. basic/test/thread.mjs does the same on every tick of the
// BASIC thread's corpus. tools/verify-writer.mjs builds every tick it sends with tick(), and the service judges each.
//
// ⚠⚠ TWO SIGNATURES, NOT ONE (spec §4.0a). buildUnlocking makes the covenant's own: over the PREIMAGE, run in the
//   script by every verifier. The append authorisation is over the ENTRY BYTES and says who submitted it. A writer makes
//   both.
//
// ⚠⚠ NO VERDICT IS NOT A REFUSAL. judge() THROWS when this host cannot judge the tick, and a caller must keep that apart
//   from { accepted: false }:
//     VersionError  the lock declares no version, or nothing here judges ticks for the version it declares (PHP's
//                   VersionError, the same words)
//     JfHostError   a crypto function the script needs was not supplied, or failed: a host fault is never a verdict
//   so no tick is refused in a page and accepted by the host, or the other way round, because one of them lacks a library.
//     CovenantEntryError  bytes that are not a covenant entry (above): the service answers 400 for them, and judges nothing
//   A PreimageError or a RangeError is the caller's mistake: no such input, or a value that is not a u64.
//   ThreadError is a tick or a genesis that cannot be built: CovenantThread's checks, in the same order. Two of its
//   messages are worded here without PHP's name for the other layer, and a value that is not a u64 is a RangeError here
//   where PHP's tick() says 'value must be 8 raw bytes'.
//
// ⚠ Crypto is the interpreter's to be SUPPLIED. The default is tools/jf-crypto.mjs: ours, with the PHP's verdict in
//   every case. A caller may pass another. Before the script runs, a crypto that is not an object, or a member that is
//   not a function, is JfHostError. Each function given is wrapped, so that while the script runs, a hash that throws or
//   gives the wrong number of bytes, or a verify that throws, is JfHostError too, never a verdict.
import { interpreterFor, versionBuild, VersionError } from './dispatch.mjs'
import { preimage, PreimageError } from './preimage.mjs'
import { serializeEntry } from './entry.mjs'
import { sha256, sha256d } from './sha256.mjs'
import { JfHostError } from './interpreter-jf.mjs'
import { jfCrypto } from './jf-crypto.mjs'

export { VersionError, JfHostError, PreimageError, jfCrypto }

/** A genesis or a tick that cannot be built: CovenantThread's ThreadError. */
export class ThreadError extends Error {}

/** Bytes that are not a covenant entry, which CovenantEntry::decode refuses: no verdict is given on them. */
export class CovenantEntryError extends Error {}

/** spec §4.2a: `open` is the single byte 0x00; a key set is 0x01 (keys, read only) or 0x02 (hashes, what is written). */
export const AUTH_OPEN = Uint8Array.of(0x00)
export const AUTH_V1_KEYS = 0x01
export const AUTH_V2_HASHES = 0x02

const U64 = 1n << 64n
const HASH_BYTES = { sha256: 32, sha1: 20, ripemd160: 20 }
const VERIFIERS = ['ed25519Verify', 'ecdsaVerify']
const bytes = b => b instanceof Uint8Array ? b : Uint8Array.from(b)
const lp = b => [(b.length >>> 24) & 0xff, (b.length >>> 16) & 0xff, (b.length >>> 8) & 0xff, b.length & 0xff, ...b]
const u32ok = n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff

// ── creating a thread ───────────────────────────────────────────────────────────────────────────────────────────────
/**
 * The genesis: its commitment, and its id, HASH256 of the commitment. The id is computed from the commitment by anyone,
 * and is never stored inside the thing it identifies.
 * @param {Uint8Array|number[]} sourceHash  hash of the covenant's source
 * @param {Uint8Array|number[]} script      the compiled locking script
 * @param {Uint8Array|number[]} state       the initial state
 * @param {Uint8Array|number[]} authorised  packed per spec §4.2a: AUTH_OPEN, or authorisedHashes()
 * @returns {{commitment: Uint8Array, id: Uint8Array}}
 */
export function create(sourceHash, script, state, authorised) {
  if (!script.length) throw new ThreadError('a covenant with no script is not a covenant')
  const commitment = Uint8Array.from([...lp(sourceHash), ...lp(script), ...lp(state), ...lp(authorised)])
  return { commitment, id: Uint8Array.from(sha256d(commitment)) }
}

/**
 * A key set, packed with the keys HASHED (version 0x02): a public key in the clear is a search key, and the hash breaks
 * the link. SHA-256, not HASH160: a k-of-n set is several parties, where 80 bits of collision resistance is attackable.
 * The hashes ascending by their bytes, none twice, so one set has one encoding.
 * @param {Array<Uint8Array|number[]>} publicKeys raw public keys; only their hashes are packed
 * @param {number} [k] how many of them must sign
 * @returns {Uint8Array}
 */
export function authorisedHashes(publicKeys, k = 1) {
  const n = publicKeys.length
  if (n === 0 || n > 255) throw new ThreadError('n must be 1..255')
  if (!Number.isInteger(k) || k < 1 || k > n) throw new ThreadError('k must be 1..n')
  const hashes = publicKeys.map(pk => sha256(bytes(pk))).sort(compareBytes)
  for (let i = 1; i < n; i++) if (compareBytes(hashes[i - 1], hashes[i]) === 0) throw new ThreadError('duplicate key')
  return Uint8Array.from([AUTH_V2_HASHES, k, n, ...hashes.flatMap(h => [h.length, ...h])])
}

/** Bytes compared as PHP's sort(SORT_STRING) compares them: byte by byte, a prefix first. */
function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]
  return a.length - b.length
}

// ── ticking it forward ──────────────────────────────────────────────────────────────────────────────────────────────
/**
 * Build the entry that spends output `prevIndex` of the tip and produces its successors.
 *
 * The order is what makes ticking possible: the preimage covers the tip's locking script, never this entry's unlocking
 * script, so it is built from the skeleton (the entry with its unlocking script empty) before the unlocking script
 * exists, and filling the unlocking script in does not change it. That is why OP_PUSH_TX works.
 *
 * @param {Uint8Array|number[]} prevEntryHash  the tip: HASH256 of its entry, or the genesis id for the first tick
 * @param {number} prevIndex                   which of the tip's outputs is spent
 * @param {Uint8Array|number[]} prevLocking    that output's locking script
 * @param {bigint|number} prevValue            that output's value, a u64
 * @param {Array<{value: bigint|number, locking: Uint8Array|number[]}>} outputs  the successors, one at least
 * @param {number} sequence                    nSequence: the tick index (spec §3, §6.3). Time derives from this, never a clock
 * @param {(preimage: Uint8Array) => Uint8Array|number[]|Promise<Uint8Array|number[]>} buildUnlocking
 *        the unlocking script, from the preimage: the covenant's own signature and whatever else it asks for. It MUST
 *        return something: an entry with no unlocking script proves nothing, and is not a tick.
 * @param {number} [version]                   nVersion; JF revision 3 unless named
 * @returns {Promise<{entry: object, bytes: Uint8Array, hash: Uint8Array, preimage: Uint8Array}>}
 *          hash is HASH256 of the bytes: what the next tick names as its tip
 */
export async function tick(prevEntryHash, prevIndex, prevLocking, prevValue, outputs, sequence, buildUnlocking,
                           version = versionBuild('JF', 3)) {
  if (prevEntryHash?.length !== 32) throw new ThreadError('the tip reference must be 32 bytes')
  if (!prevLocking?.length) throw new ThreadError('the tip has no locking script: it is not a covenant tip')
  const value = u64(prevValue)
  if (!outputs?.length) throw new ThreadError('a tick must produce at least one successor')
  // PHP's pack('V') takes what fits; here a number that does not fit is refused rather than cut down to 32 bits
  if (!u32ok(prevIndex) || !u32ok(sequence) || !u32ok(version)) throw new RangeError('prevIndex, sequence and version are u32s')

  // 1. the skeleton. The unlocking script is not needed yet and is not part of the preimage.
  const skeleton = {
    version,
    inputs: [{ prevEntry: bytes(prevEntryHash), index: prevIndex, unlocking: new Uint8Array(0), sequence }],
    outputs: outputs.map(o => ({ value: u64(o.value), locking: bytes(o.locking) })),
    locktime: 0,
  }
  // 2. the preimage over it: what OP_PUSH_TX proves
  const pre = Uint8Array.from(preimage({ entry: skeleton, inputIndex: 0, scriptCode: bytes(prevLocking), value }))
  // 3. the caller builds the unlocking script from it
  const unlocking = await buildUnlocking(pre)
  if (unlocking === null || typeof unlocking !== 'object' || !unlocking.length)
    throw new ThreadError('the unlocking script is empty: an entry that proves nothing is not a tick')
  // 4. and only now is the entry complete. Filling it in does NOT change the preimage.
  const entry = { ...skeleton, inputs: [{ ...skeleton.inputs[0], unlocking: bytes(unlocking) }] }
  const b = Uint8Array.from(serializeEntry(entry))
  return { entry, bytes: b, hash: Uint8Array.from(sha256d(b)), preimage: pre }
}

/** What a secp256k1 append key signs: SHA-256 of the entry bytes. An Ed25519 key signs the bytes themselves. */
export const appendSighash = entryBytes => Uint8Array.from(sha256(bytes(entryBytes)))

// ── judging a tick ──────────────────────────────────────────────────────────────────────────────────────────────────
/**
 * VER, the byte every lock starts with: the lock's declaration of the version its code is written for, its four bytes
 * after it as an entry's nVersion carries them (D1 03 00 4A 46 for JF 3). The host reads it before it runs anything, so
 * it is the same byte in every version. CovenantThread::VER.
 */
export const VER = 0xd1
/** A tick that names another version than its lock declares: refused, its script never run. CovenantThread::OTHER_VERSION. */
export const OTHER_VERSION = 'the tick does not name the version its lock declares'

/**
 * The version a lock declares: the four bytes after VER, read as an nVersion is read. CovenantThread::declaredVersion.
 * @param {Uint8Array|number[]} lock
 * @returns {number} the nVersion, a u32
 * @throws {VersionError} when it declares none: it is shorter than five bytes, or does not start with VER
 */
export function declaredVersion(lock) {
  if (lock.length < 5 || lock[0] !== VER) throw new VersionError('the lock declares no version: it does not start with VER and four version bytes')
  return (lock[1] | (lock[2] << 8) | (lock[3] << 16) | (lock[4] << 24)) >>> 0
}

/**
 * Judge input `inputIndex` of `entry` against the output it spends.
 * @param {import('./entry.mjs').Entry} entry  a decoded entry, as parseEntry (tools/entry.mjs) reads one
 * @param {number} inputIndex                  which input is judged; its outpoint names the spent output
 * @param {Uint8Array|number[]} prevLocking    the spent output's locking script
 * @param {bigint|number} prevValue            the spent output's value, a u64 (parseEntry gives it as a bigint)
 * @param {object} [crypto]                    { sha256, sha1, ripemd160, ed25519Verify, ecdsaVerify }; tools/jf-crypto.mjs
 * @returns {Promise<{accepted: boolean, stack?: bigint[], error?: string, errorBytes?: Uint8Array}>}
 *   verifyTick's verdict, or OTHER_VERSION's refusal: a refusal's errorBytes are the bytes the PHP judge's error carries.
 * @throws {CovenantEntryError|VersionError|JfHostError} no verdict.  @throws {PreimageError|RangeError} the caller's mistake.
 */
export async function judge(entry, inputIndex, prevLocking, prevValue, crypto = jfCrypto) {
  isCovenantEntry(entry)
  const declared = declaredVersion(prevLocking)
  const vm = interpreterFor(declared)
  if (typeof vm.verifyTick !== 'function') throw new VersionError(`${vm.name} does not judge ticks`)
  if (entry.version !== declared) return { accepted: false, error: OTHER_VERSION, errorBytes: new TextEncoder().encode(OTHER_VERSION) }
  // In Preimage::build's order: the input first, then the value
  const input = entry.inputs[inputIndex]
  if (!input) throw new PreimageError(`no input at index ${inputIndex}`)
  const value = u64(prevValue)
  const pre = preimage({ entry, inputIndex, scriptCode: prevLocking, value })
  const host = supplied(crypto)
  const v = await vm.verifyTick({ unlocking: bytes(input.unlocking), lock: bytes(prevLocking), preimage: Uint8Array.from(pre),
                                  crypto: host.crypto })
  if (host.fault) throw host.fault                            // a verify failed on this host: the verdict above is not one
  return v
}

/**
 * What CovenantEntry::decode refuses and parseEntry (tools/entry.mjs) reads: PHP's judging path decodes the bytes first,
 * so it never judges these. In decode's order: each input, then each output. A tick reference of another length cannot
 * come out of decode at all, so an entry object carrying one is refused too.
 */
function isCovenantEntry(entry) {
  for (const [k, i] of (entry?.inputs ?? []).entries()) {
    if (i?.prevEntry?.length !== 32) throw new CovenantEntryError(`input ${k}: the tick it spends is named by 32 bytes`)
    if (!i.unlocking?.length) throw new CovenantEntryError(`input ${k} has no unlocking script: it proves nothing, so it is not a covenant entry`)
  }
  for (const [k, o] of (entry?.outputs ?? []).entries())
    if (!o?.locking?.length) throw new CovenantEntryError(`output ${k} has no locking script: it carries state and no covenant, so it is not a covenant entry`)
}

/** A value as a bigint, 0 to 2^64 − 1: what 8 bytes can hold, as PHP's judge takes it. */
function u64(v) {
  const n = typeof v === 'bigint' ? v : Number.isSafeInteger(v) ? BigInt(v) : null
  if (n === null || n < 0n || n >= U64) throw new RangeError('value must be a u64: an integer from 0 to 2^64 - 1')
  return n
}

/**
 * The caller's crypto, checked: each function given is wrapped so that a fault in it is JfHostError rather than a
 * verdict. A function not given stays absent, and the interpreter throws JfHostError if a word needs it.
 */
function supplied(crypto) {
  if (crypto === null || typeof crypto !== 'object') throw new JfHostError('no crypto was supplied')
  const host = { fault: null, crypto: {} }
  for (const [name, n] of Object.entries(HASH_BYTES)) {
    const f = crypto[name]
    if (f === undefined) continue
    if (typeof f !== 'function') throw new JfHostError(`crypto.${name} is not a function`)
    host.crypto[name] = b => {
      let d
      try { d = f(b) } catch (e) { throw new JfHostError(`${name} failed on this host: ${e?.message ?? e}`) }
      if (d === null || typeof d !== 'object' || d.length !== n)
        throw new JfHostError(`${name} on this host gave ${d?.length ?? typeof d} bytes, not ${n}`)
      return bytes(d)
    }
  }
  for (const name of VERIFIERS) {
    const f = crypto[name]
    if (f === undefined) continue
    if (typeof f !== 'function') throw new JfHostError(`crypto.${name} is not a function`)
    // ⚠ The interpreter reads a verify that throws as a failed check. That is right for bad bytes, which ours never
    //   throw on, and wrong for a broken host: so the first fault is kept, and judge() throws it after the run.
    host.crypto[name] = async (...a) => {
      try { return !!(await f(...a)) }
      catch (e) { host.fault ??= new JfHostError(`${name} failed on this host: ${e?.message ?? e}`); return false }
    }
  }
  return host
}
