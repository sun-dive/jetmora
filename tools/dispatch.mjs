// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── VERSION DISPATCH (spec §6b), IN JAVASCRIPT ───────────────────────────────────────────────────────────────────────
// A PORT of server/dispatch.php: the same reading of nVersion, the same registry, and the same errors in the same words,
// so a page that cannot judge a tick says what the thread service says when it cannot. §6b: "A verifier replaying an
// entry MUST apply the semantics of the version named IN THAT ENTRY, and MUST NOT apply its own."
//
// nVersion is a u32 read as bytes. Its high half zero is a LEGACY integer version (jetmora.org's first entries are 103);
// otherwise the third and fourth bytes on the wire are the family, two characters from A to Z and 0 to 9, and the low
// half is the revision. ⚠ A family's bytes can never be zero, so `\0\0` is never a family and an unset field never
// dispatches anywhere.
//
// ⚠ What JavaScript carries is not what PHP carries, and the registry says so. JF revision 3 judges ticks here, by
//   tools/interpreter-jf.mjs's verifyTick. SV and BT are registered under the names PHP registers them by, without a
//   judge, so an entry naming them gets PHP's answer, "InterpreterSV does not judge ticks": tools/interpreter.mjs runs
//   SV scripts but judges no tick, and BT has no JavaScript interpreter. A host whose PHP does not ship a set answers
//   differently ("this host does not ship interpreter-sv.php"); either way it is no verdict, never a refusal.
import { verifyTick } from './interpreter-jf.mjs'

/** This host has no interpreter that judges ticks for the version an entry names: no verdict, never a refusal. */
export class VersionError extends Error {}

const hex2 = c => c.toString(16).padStart(2, '0')
/** Uppercase A to Z and digits only, so there is ONE spelling of one thing. `sv` is not a family. */
const legal = c => (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39)

/**
 * Split an nVersion u32 into what it names: { legacy: n } or { family: 'JF', revision: n }.
 * @throws {VersionError} on a value that is not a u32, or family bytes that are not two legal characters
 */
export function versionParse(nVersion) {
  if (!Number.isInteger(nVersion) || nVersion < 0 || nVersion > 0xffffffff) throw new VersionError('nVersion out of u32 range')
  const c0 = (nVersion >>> 16) & 0xff                         // the third byte on the wire
  const c1 = (nVersion >>> 24) & 0xff                         // the fourth
  if (c0 === 0 && c1 === 0) return { legacy: nVersion & 0xffff }
  if (!legal(c0) || !legal(c1)) throw new VersionError(`illegal family bytes ${hex2(c0)} ${hex2(c1)}`)
  return { family: String.fromCharCode(c0, c1), revision: nVersion & 0xffff }
}

/** Build an nVersion from a family and revision: versionBuild('JF', 3). The inverse of versionParse. */
export function versionBuild(family, revision) {
  if (typeof family !== 'string' || !/^[\x00-\xff]{2}$/.test(family)) throw new VersionError('a family is exactly two characters')
  if (!Number.isInteger(revision) || revision < 0 || revision > 0xffff) throw new VersionError('revision out of range')
  return ((family.charCodeAt(1) << 24) | (family.charCodeAt(0) << 16) | revision) >>> 0
}

// ── THE REGISTRY ─────────────────────────────────────────────────────────────────────────────────────────────────────
/** family → { interpreter: { name, verifyTick? }, revisions }, in the order registered (an error lists them so) */
const SETS = new Map()

/**
 * Register an instruction set: a third party registers its family and ships its interpreter, touching nothing here.
 * @param {string} family two characters
 * @param {{name: string, verifyTick?: Function}} interpreter  verifyTick({ unlocking, lock, preimage, crypto }) when it judges ticks
 * @param {number[]} revisions which revisions of the family it implements
 */
export function registerSet(family, interpreter, revisions = [1]) {
  if (typeof family !== 'string' || family.length !== 2) throw new VersionError('a family is exactly two characters')
  SETS.set(family, { interpreter, revisions })
}

/**
 * The interpreter the entry's nVersion names. ⛔ Never "the newest" or "ours": §6b forbids a verifier applying its own.
 * @throws {VersionError} when nothing here is registered for that version
 */
export function interpreterFor(nVersion) {
  const v = versionParse(nVersion)
  if (v.legacy !== undefined) {
    // PHP's words, character for character: the dash in them is PHP's, written here as its code
    throw new VersionError(
      `entry names legacy version ${v.legacy}; no interpreter is registered for legacy versions. ` +
      '⚠ Legacy entries predate the family scheme and keep their own semantics (§6b) \u2014 they are not ' +
      'reinterpretable as a family.')
  }
  const f = v.family
  const set = SETS.get(f)
  if (set === undefined) {
    const known = SETS.size ? [...SETS.keys()].join(', ') : 'none'
    throw new VersionError(`no interpreter registered for family \`${f}\` (registered: ${known})`)
  }
  if (!set.revisions.includes(v.revision))
    throw new VersionError(`family \`${f}\` is registered, but not revision ${v.revision} (has: ${set.revisions.join(', ')})`)
  return set.interpreter
}

// ── what this installation carries, in dispatch.php's order ─────────────────────────────────────────────────────────
registerSet('SV', { name: 'InterpreterSV' }, [1])
registerSet('BT', { name: 'InterpreterBT' }, [1])
registerSet('JF', { name: 'InterpreterJF', verifyTick }, [3])   // revisions 1 and 2 never reached a thread and are not served
