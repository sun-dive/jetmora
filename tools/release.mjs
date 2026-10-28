// © 2026 sun-dive. Business Source License 1.1. See LICENSE.
//
// ══ A RELEASE OF THE CODE BASE: ITS ARCHIVE, CARRIED BY A THREAD OF ITS OWN ════════════════════════════════════════
//
// A release is the archive of one commit, written to a thread service as a thread of its own: the genesis is the code
// thread's covenant (basic/code-thread.bas) with the release key as its owner, and each tick carries one part of the
// archive, in order. Joined, the parts are the archive. Its SHA-256 is what is then timestamped on the blockchains,
// with keys this tool never holds.
//
//   node tools/release.mjs archive <commit> [--out FILE]
//       the archive of the commit: its SHA-256, its size, its files and its parts. --out writes it to FILE, never over
//       a file that exists and never inside this repository
//   node tools/release.mjs publish <commit> --service URL [--send]
//       the plan: the commit, the archive, its parts, the service, the key and the thread. With --send: the genesis
//       registered, each part written as a tick, then the thread read back and verified
//   node tools/release.mjs verify <genesis-id> --service URL --owner HASH160 [--commit C]
//       the thread read back, every check below, the archive's SHA-256 and draft rows for PROVENANCE.md
//   node tools/release.mjs keygen FILE
//       a new seed written to FILE (mode 0600, never over a file that exists, never inside a git work tree); prints
//       the public key and its HASH160
// Each command takes its own options and refuses the others.
//
// ⚠⚠ THE RELEASE KEY IS NEVER ASKED FOR, NEVER AN ARGUMENT, NEVER PRINTED. publish reads it from the environment, as
//   the 32 bytes of an Ed25519 seed in 64 hex characters, set in your own shell for the one run (keygen prints these
//   lines with the seed file in place of the prompt):
//       fish  begin; read -l -x -s JETMORA_RELEASE_SEED; node tools/release.mjs publish <commit> --service URL; end
//       bash  ( read -rs JETMORA_RELEASE_SEED && export JETMORA_RELEASE_SEED && node tools/release.mjs publish ... )
//   Other users cannot read a process's environment, as they can read its arguments in `ps`; the same user and root
//   can, in /proc/PID/environ, while the run lasts. The variable is taken out of this process's environment before
//   anything else runs, and git, which this tool runs, gets an environment without it. The seed becomes a WebCrypto
//   key that cannot be exported, and the buffers this tool puts its bytes in are overwritten (the key objects node
//   makes of them are freed, not overwritten). The text the environment gave stays in memory, a JS string, until the
//   run ends; Ctrl-\ ends a run without the core dump that would hold it.
//   An argument that holds the seed is refused before git runs or anything is sent. No message names it. A key used
//   only for releases: should it leak, only releases are exposed.
// ⚠ DRY RUN BY DEFAULT, as tools/broadcast.mjs: publish writes nothing without --send. There is no default service.
//
// ══ THE ARCHIVE ══
// Every file of the commit (git ls-tree -r, which is git ls-files at that commit), its bytes read from git's objects,
// never from the working tree, as one tar, gzipped. git runs on this repository's own objects: without any GIT_
// variable (GIT_DIR and its kind would point it at another repository) and with --no-replace-objects (a local
// `git replace` would give another blob for a file, which no one else's rebuild would see):
//   tar   GNU tar's own format, as tar 1.35 writes it by default (--format=gnu): the files in git's order and no
//         directory entries; each owned by root, group root (uid and gid 0), mode 0644 (0755 for an executable), its
//         mtime 00:00 of the commit's date in the commit's own timezone (its committer line); two zero blocks after
//         the last file, then zeros to the end of a 10,240-byte record
//   gzip  GNU gzip at level 6, no name and no time (tools/gzip.mjs)
// It is the recipe of the 14 Sept archive: built here from 448b796 it is 624,949 bytes, SHA-256 8f3884e2..., the
// archive PROVENANCE.md records (tools/verify-release.mjs holds it to that). So a release made today and the one of
// 14 Sept are made the same way, and anyone with git and node rebuilds either, byte for byte.
//
// ══ THE THREAD ══
//   genesis   script      basic/code-thread.bas compiled with owner the release key's HASH160, rev 3, code 32 zeros
//             source hash SHA-256 of basic/code-thread.bas
//                         both of the file as the release's commit holds it, compiled by that commit's own compiler
//             state       its label, 'jetmora code <commit> <date>', the date the commit's: 64 bytes, which op=find,
//                         taking 1 to 64, can look up
//             authorised  the release key's hash, alone (authorisedHashes)
//   tick k    spends output 0 of the tick before it (the genesis, for the first), and carries part k as bundle$ and the
//             revision, 3, as r%. Its successor, valued one more, holds the owner, rev 3, and the SHA-256 of part k
// Each part is PART_BYTES but the last. One tick carries 65,382 bytes of bundle at most (basic/test/code-thread.mjs
// measures it): the margin keeps a part clear of that should the lock grow.
// ⚠ THE COVENANT IS THE COMMIT'S. publish and verify both build it from COVENANT_FILES as the release's commit holds
//   them, read from git's objects, never from the working tree: that commit's basic/code-thread.bas, compiled by that
//   commit's basic/basic-jf.mjs, imported with that commit's tools/ops-jf.mjs in place of the file it names. So a
//   release checks against its own commit, whatever has changed since, here or in a later commit. A commit that holds
//   no basic/code-thread.bas is refused, as is one whose COVENANT_FILES git cannot read, or whose compiler cannot
//   compile its covenant. The compiler runs in this process, as this tool's own code does. Its bytes are always from
//   this repository's objects, never code a service sends. A commit that only the genesis's label names is used only
//   when the branch checked out holds it (git merge-base --is-ancestor): the label is the service's text, and the
//   objects can hold a commit fetched from a fork or on no branch. --commit names one deliberately.
// ⚠ PUBLISHING AGAIN RESUMES. The key and the label name one genesis, which the service registers once (it answers the
//   same id again), so publish reads the thread, checks that the ticks it holds are this release's first parts, and
//   writes the rest. A part on a given tip is always the same tick (Ed25519 signs deterministically), so no run can
//   sign two different successors of one tip, and the writer's ledger can be memory.
//
// ══ VERIFY ══ checks, and reports each that fails:
//   the genesis   its label naming a commit, the one given when --commit is; the code thread's covenant as that commit
//                 holds it, for the owner given: its source hash and its script; its authorised set the release key's
//                 alone
//   the ticks     the reader's report (tools/thread-reader.mjs): the whole thread, each tick linked and accepted by
//                 the output it spends
//   each part     its tick signed by the one release key, whose HASH160 is the owner; revision 3; its successor the
//                 covenant as that commit compiles it, holding the owner, rev 3 and the SHA-256 of the part it carries;
//                 never empty
//   the parts     as many as the archive is cut into, each the size cutParts gives it
//   the archive   the parts joined in the thread's order are, byte for byte, the archive rebuilt here from git
// Some of these are second guards. The covenant refuses a tick whose key's HASH160 is not the owner, or whose successor
// keeps another owner or names another code, and the reader reports what it refuses; so those checks of each part,
// and the same key on every tick, can fail only where the reader's report would too. The revision is a first guard: the
// covenant takes any r%.
import { execFileSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, getRandomValues } from 'node:crypto'
import { realpathSync, writeFileSync } from 'node:fs'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { gzip } from './gzip.mjs'
import { unbasic, disassemble } from '../basic/unbasic-jf.mjs'
import { authorisedHashes, create } from './thread.mjs'
import { ThreadWriter, memoryLedger, ed25519Signer, basicUnlock } from './thread-writer.mjs'
import { readThread } from './thread-reader.mjs'
import { ThreadService } from './thread-service.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
/** The environment variable that holds the release key's seed */
export const SEED_VAR = 'JETMORA_RELEASE_SEED'
/** The bytes of the archive each tick carries, the last tick the rest */
export const PART_BYTES = 64_000
/** The engine revision a release implements: JF 3 */
export const REV = 3
/** The files a release's genesis is built from, as its commit holds them: the covenant, and the compiler with the
 *  module it imports */
const SOURCE = 'basic/code-thread.bas', COMPILER = 'basic/basic-jf.mjs', OPS = 'tools/ops-jf.mjs'
export const COVENANT_FILES = Object.freeze([SOURCE, COMPILER, OPS])
const ZERO = new Uint8Array(32)
const RECORD = 10_240
/** PKCS#8 for an Ed25519 key, before its 32-byte seed (RFC 8410) */
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex')

/** Something this tool will not do, or a check that failed to run: the message is for the person running it */
export class ReleaseError extends Error {}

const H = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const sha256 = H('sha256'), hash160 = b => H('ripemd160')(sha256(b))
const hex = b => Buffer.from(b).toString('hex')
const same = (a, b) => a != null && b != null && a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0
const commas = n => n.toLocaleString('en-US')
const short = c => c.slice(0, 7)
/** Text a service sent, made safe for a terminal: no control characters */
const printable = s => String(s).replace(/[\x00-\x1f\x7f-\x9f]/g, '?')

// ── git, without the seed ───────────────────────────────────────────────────────────────────────────────────────────
/** The environment git runs with: this one, without the seed's variable and without any GIT_ variable */
function gitEnv() {
  return Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== SEED_VAR && !k.startsWith('GIT_')))
}
/** git on this repository's own objects (THE ARCHIVE) */
const git = (args, input) => execFileSync('git', ['--no-replace-objects', '-C', ROOT, ...args],
  { input, maxBuffer: 1 << 30, stdio: ['pipe', 'pipe', 'pipe'], env: gitEnv() })

/** The top of the git work tree a folder is in, or null when it is in none */
function workTreeOf(dir) {
  try {
    return execFileSync('git', ['-C', dir, 'rev-parse', '--show-toplevel'], { stdio: ['ignore', 'pipe', 'ignore'], env: gitEnv() })
      .toString().trim() || null
  } catch { return null }
}

/** A file as a commit holds it, from git's objects: its bytes, or null when the commit holds none. A ReleaseError when
 *  the commit names the file and git cannot read it: an object this repository's store does not hold */
function blobAt(commit, path) {
  const at = short(commit), lost = 'this repository\'s objects do not hold it'
  let entry
  try { entry = git(['ls-tree', '-z', '--full-tree', commit, '--', path]).toString('latin1') }
  catch { throw new ReleaseError(`git cannot read the tree of commit ${at} down to ${path}: ${lost}`) }
  if (entry.split(' ')[1] !== 'blob') return null      // no entry at all, or a folder or a submodule there
  try { return git(['cat-file', 'blob', `${commit}:${path}`]) }
  catch { throw new ReleaseError(`git cannot read the blob of ${path} at commit ${at}: the commit names it, and ${lost}`) }
}

/** The full hash of the commit a name gives, or a ReleaseError. The name is never echoed: it could be anything typed */
export function resolveCommit(name) {
  if (typeof name !== 'string' || name === '' || name.startsWith('-')) throw new ReleaseError('a commit is needed: a hash, a tag or a branch')
  try { return git(['rev-parse', '--verify', '--quiet', '--end-of-options', `${name}^{commit}`]).toString().trim() }
  catch { throw new ReleaseError('the commit given is not one in this repository') }
}

/** Whether the branch checked out holds the commit: git merge-base --is-ancestor, whose exit 1 is no, as is a commit
 *  git does not know */
function onBranch(commit) {
  try { git(['merge-base', '--is-ancestor', commit, 'HEAD']); return true }
  catch { return false }
}

/** The commit's date in its own timezone, from its committer line, and 00:00 of that date as a Unix time */
function commitDate(commit) {
  const text = git(['cat-file', 'commit', commit]).toString('utf8')
  const m = /^committer .* (\d+) ([+-])(\d\d)(\d\d)$/m.exec(text)
  if (!m) throw new ReleaseError(`commit ${commit} has no committer line git would write`)
  const offset = (m[2] === '-' ? -1 : 1) * (Number(m[3]) * 3600 + Number(m[4]) * 60)
  const day = Math.floor((Number(m[1]) + offset) / 86_400)
  return { date: new Date(day * 86_400_000).toISOString().slice(0, 10), mtime: day * 86_400 - offset }
}

/** The commit's files from git's objects: [{ path (bytes), mode, bytes }], in git's order */
function filesOf(commit) {
  const list = git(['ls-tree', '-r', '-z', '--full-tree', commit])
  const files = []
  for (let at = 0; at < list.length;) {
    const end = list.indexOf(0, at), tab = list.indexOf(9, at)
    const [mode, type, oid] = list.toString('latin1', at, tab).split(' ')
    const path = list.subarray(tab + 1, end)
    const name = path.toString('utf8')
    if (type !== 'blob' || (mode !== '100644' && mode !== '100755'))
      throw new ReleaseError(`${name} is a ${mode === '120000' ? 'symbolic link' : mode === '160000' ? 'submodule' : type}: the archive holds files only`)
    if (path.length >= 100) throw new ReleaseError(`${name} is a path of ${path.length} bytes: GNU tar writes one of 100 or more with an entry of its own, which this tool does not`)
    files.push({ path, name, mode: mode === '100755' ? 0o755 : 0o644, oid })
    at = end + 1
  }
  // the bytes of every blob, in one git process
  const out = git(['cat-file', '--batch'], files.map(f => f.oid).join('\n') + '\n')
  let at = 0
  for (const f of files) {
    const nl = out.indexOf(10, at)
    const [oid, type, size] = out.toString('latin1', at, nl).split(' ')
    if (oid !== f.oid || type !== 'blob') throw new ReleaseError(`git did not give the blob of ${f.name}`)
    f.bytes = out.subarray(nl + 1, nl + 1 + Number(size))
    at = nl + 1 + Number(size) + 1
  }
  return files
}

// ── the archive ─────────────────────────────────────────────────────────────────────────────────────────────────────
/** A file's header, as GNU tar 1.35 writes it for a regular file in its default format */
function tarHeader(path, mode, size, mtime) {
  const h = new Uint8Array(512)
  const put = (at, s) => h.set(typeof s === 'string' ? Buffer.from(s, 'latin1') : s, at)
  // a number: octal, zero-padded to the field's width less one, then the field's NUL
  const octal = (at, width, v) => {
    const s = v.toString(8).padStart(width - 1, '0')
    if (s.length > width - 1) throw new ReleaseError(`${v} does not fit a tar header field of ${width} bytes`)
    put(at, s)
  }
  put(0, path)
  octal(100, 8, mode)
  octal(108, 8, 0)                             // uid
  octal(116, 8, 0)                             // gid
  octal(124, 12, size)
  octal(136, 12, mtime)
  h.fill(0x20, 148, 156)                       // the checksum is summed with its own field as spaces
  h[156] = 0x30                                // a regular file
  put(257, 'ustar  ')                          // GNU's magic and version: 'ustar  \0'
  put(265, 'root')
  put(297, 'root')
  let sum = 0
  for (const b of h) sum += b
  put(148, sum.toString(8).padStart(6, '0'))   // six digits, a NUL, and a space
  h[154] = 0
  return h
}

/** The tar of the files: each header and its bytes to a whole block, two zero blocks, zeros to the record's end */
function tarOf(files, mtime) {
  const blocks = n => Math.ceil(n / 512) * 512
  const size = Math.ceil((files.reduce((n, f) => n + 512 + blocks(f.bytes.length), 0) + 1024) / RECORD) * RECORD
  const t = new Uint8Array(size)
  let at = 0
  for (const f of files) {
    t.set(tarHeader(f.path, f.mode, f.bytes.length, mtime), at)
    t.set(f.bytes, at + 512)
    at += 512 + blocks(f.bytes.length)
  }
  return t
}

/**
 * The archive of a commit.
 * @param {string} name  a commit: a hash, a tag or a branch
 * @returns {{ commit: string, date: string, mtime: number, files: number, tar: Uint8Array, bytes: Uint8Array, sha256: string }}
 */
export function buildArchive(name) {
  const commit = resolveCommit(name)
  const { date, mtime } = commitDate(commit)
  const files = filesOf(commit)
  const tar = tarOf(files, mtime)
  const bytes = gzip(tar)
  return { commit, date, mtime, files: files.length, tar, bytes, sha256: hex(sha256(bytes)) }
}

/** The archive cut into the parts its ticks carry, in order */
export function cutParts(bytes, size = PART_BYTES) {
  const parts = []
  for (let at = 0; at < bytes.length; at += size) parts.push(bytes.subarray(at, at + size))
  return parts
}

// ── the key ─────────────────────────────────────────────────────────────────────────────────────────────────────────
/** The seed's text, taken out of the environment: after this, no child process can inherit it. undefined if not set */
export function takeSeed(env = process.env) {
  const raw = env[SEED_VAR]
  delete env[SEED_VAR]
  return raw
}

/** An Ed25519 key from its 32-byte seed: { publicKey, sign }, its private half a WebCrypto key that cannot be exported */
async function keyFromSeed(seed) {
  const der = new Uint8Array(PKCS8_ED25519.length + 32)
  der.set(PKCS8_ED25519)
  der.set(seed, PKCS8_ED25519.length)
  try {
    const subtle = globalThis.crypto.subtle
    const privateKey = await subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign'])
    // the public key, from node's own key object of the same bytes: WebCrypto gives none for a key it will not export
    const spki = createPublicKey(createPrivateKey({ key: Buffer.from(der.buffer, der.byteOffset, der.length), format: 'der', type: 'pkcs8' }))
      .export({ format: 'der', type: 'spki' })
    const publicKey = await subtle.importKey('raw', spki.subarray(spki.length - 32), { name: 'Ed25519' }, true, ['verify'])
    return await ed25519Signer({ privateKey, publicKey })
  } catch {
    throw new ReleaseError('the seed did not become an Ed25519 key')
  } finally {
    der.fill(0)
  }
}

/** A path as written to the shell: as it is when it needs no quotes, else in single quotes (bash and fish alike) */
const quoted = p => /^[\w./~-]+$/.test(p) ? p : `'${p.replace(/'/g, `'\\''`)}'`

/** How to set the seed for one run of publish in your own shell, read from the terminal or from a file: the variable is
 *  gone from the shell when the run ends, so nothing started from it later inherits the seed */
function seedLines(file) {
  const run = 'node tools/release.mjs publish <commit> --service URL'
  const from = file === undefined ? '' : ` < ${quoted(file)}`
  return [`  fish  begin; read -l -x${from ? '' : ' -s'} ${SEED_VAR}${from}; ${run}; end`,
          `  bash  ( read -r${from ? '' : 's'} ${SEED_VAR}${from} && export ${SEED_VAR} && ${run} )`].join('\n')
}

/** The release key from the seed's text (takeSeed); a ReleaseError, which never names the text, if it is not one */
export async function releaseKey(text) {
  if (text === undefined || text === '')
    throw new ReleaseError(`${SEED_VAR} is not set. Set it in your own shell, never on the command line, for the one run:\n${seedLines()}`)
  const t = text.trim()
  if (!/^[0-9a-fA-F]{64}$/.test(t)) throw new ReleaseError(`${SEED_VAR} is not a seed: a seed is 32 bytes, as 64 hex characters`)
  // memory of its own, never node's shared pool of small buffers, so the wipe below reaches the one copy made here
  const seed = Buffer.alloc(32)
  seed.write(t, 'hex')
  try { return await keyFromSeed(seed) } finally { seed.fill(0) }
}

/** A path for a file this tool writes, refused inside this repository: { path, dir }, dir its folder's real path */
function placeOf(file, why) {
  const path = resolve(file)
  let dir
  try { dir = realpathSync(dirname(path)) } catch { throw new ReleaseError(`the folder ${dirname(path)} does not exist`) }
  const where = relative(realpathSync(ROOT), join(dir, basename(path)))
  if (where === '' || (where !== '..' && !where.startsWith(`..${sep}`) && !isAbsolute(where)))
    throw new ReleaseError(`${path} is inside this repository: ${why}`)
  return { path, dir }
}

/** Bytes to a new file: never over one that exists */
function writeNew(path, data, options = {}) {
  try { writeFileSync(path, data, { ...options, flag: 'wx' }) }
  catch (e) { throw new ReleaseError(e.code === 'EEXIST' ? `${path} exists: this tool never writes over a file` : `${path} could not be written (${e.code})`) }
}

/**
 * A new random seed in FILE, mode 0600: never over a file that exists, never inside a git work tree.
 * @returns {Promise<{ file: string, publicKey: Uint8Array, owner: Uint8Array }>}
 */
export async function keygen(file) {
  const why = 'a seed is kept where git can never add it'
  const { path, dir } = placeOf(file, why)
  const top = workTreeOf(dir)
  if (top !== null) throw new ReleaseError(`${path} is inside the git work tree ${top}: ${why}`)
  const seed = getRandomValues(new Uint8Array(32))
  try {
    // its hex from a view of the seed's own memory: Buffer.from(seed) would copy it into the shared pool
    writeNew(path, `${Buffer.from(seed.buffer, seed.byteOffset, seed.length).toString('hex')}\n`, { mode: 0o600 })
    const key = await keyFromSeed(seed)
    return { file: path, publicKey: key.publicKey, owner: hash160(key.publicKey) }
  } finally { seed.fill(0) }
}

// ── the covenant, as a commit holds it ──────────────────────────────────────────────────────────────────────────────
/** A module's source as a data: URL, which import() takes */
const moduleUrl = bytes => `data:text/javascript;base64,${Buffer.from(bytes).toString('base64')}`
/** The covenants loaded in this run, by commit: each commit's compiler is imported once */
const covenants = new Map()

/**
 * The code thread's covenant as a commit holds it, compiled by that commit's own compiler (THE COVENANT IS THE COMMIT'S).
 * A ReleaseError when the commit holds no basic/code-thread.bas, or its compiler cannot be loaded or cannot compile it.
 * @param {string} name  a commit: a hash, a tag or a branch
 * @returns {Promise<{ commit: string, sourceHash: Uint8Array, names: object,
 *                     lockOf: (owner: Uint8Array, code: Uint8Array, rev?: number) => Uint8Array }>}
 *          names: the compiler's names of the fields; lockOf: the covenant compiled with this state, rev 3 unless given
 */
export async function covenantAt(name) {
  const commit = resolveCommit(name)
  if (!covenants.has(commit)) covenants.set(commit, loadCovenant(commit))
  return covenants.get(commit)
}

async function loadCovenant(commit) {
  const at = short(commit)
  const src = blobAt(commit, SOURCE)
  if (src === null)
    throw new ReleaseError(`commit ${at} holds no ${SOURCE}: it has no code thread's covenant to build a genesis from, or to check one against`)
  const compiler = blobAt(commit, COMPILER), ops = blobAt(commit, OPS)
  if (compiler === null || ops === null) throw new ReleaseError(`commit ${at} holds ${SOURCE}, but not its compiler, ${COMPILER} with ${OPS}`)
  // the compiler as the commit holds it, importing that commit's opcode table in place of the file it names
  const opsUrl = moduleUrl(ops), url = moduleUrl(compiler.toString('utf8').replaceAll(`'../${OPS}'`, `'${opsUrl}'`))
  let compileCovenant
  try { ({ compileCovenant } = await import(url)) }
  catch (e) {
    // node names a module by its URL: each is named here by its file, and the message cut
    const said = String(e?.message ?? e).replaceAll(url, COMPILER).replaceAll(opsUrl, OPS).replace(/data:[^\s"']+/g, 'a module').slice(0, 200)
    throw new ReleaseError(`the compiler of commit ${at}, ${COMPILER}, cannot be loaded: ${printable(said)}`)
  }
  if (typeof compileCovenant !== 'function') throw new ReleaseError(`the compiler of commit ${at}, ${COMPILER}, has no compileCovenant`)
  const text = src.toString('utf8')
  const compile = (owner, code, rev) => compileCovenant(text, { state: { owner: [...owner], rev, code: [...code] } })
  let names
  try { names = compile(ZERO.subarray(0, 20), ZERO, REV).names }
  catch (e) { throw new ReleaseError(`the compiler of commit ${at} cannot compile its ${SOURCE}: ${printable(String(e?.message ?? e).slice(0, 200))}`) }
  return Object.freeze({ commit, sourceHash: sha256(src), names, lockOf: (owner, code, rev = REV) => compile(owner, code, rev).bytes })
}

/** A lock's state as the reader reads it, with the names the covenant's compiler gives the fields: { owner, rev, code },
 *  or null. It only explains a lock that is not the one expected: whether it is, its bytes decide */
function stateOf(cov, lock) {
  try { return unbasic(lock, { names: cov.names }).state ?? null } catch { return null }
}

// ── the thread ──────────────────────────────────────────────────────────────────────────────────────────────────────
/** The label of a release's genesis: 64 bytes, for a commit's 40 hex characters */
export const labelOf = (commit, date) => `jetmora code ${commit} ${date}`
const LABEL = /^jetmora code ([0-9a-f]{40}) (\d{4}-\d{2}-\d{2})$/

/** The genesis of a release by this public key, of a commit's covenant (covenantAt): { fields, id, owner } */
export function genesisOf(cov, publicKey, label) {
  const owner = hash160(publicKey)
  const fields = { sourceHash: cov.sourceHash, script: cov.lockOf(owner, ZERO), state: new TextEncoder().encode(label),
                   authorised: authorisedHashes([publicKey]) }
  return { fields, id: create(fields.sourceHash, fields.script, fields.state, fields.authorised).id, owner }
}

/** What a release tick pushes: { key, bundle, r }, or null when its unlocking script is not the four pushes */
function tickPart(entry) {
  let items
  try { items = disassemble(entry.inputs[0].unlocking) } catch { return null }
  if (items.length !== 4 || items.some(x => x.data === undefined)) return null
  const [, key, bundle, r] = items.map(x => x.data)
  return { key, bundle, r: r.reduceRight((n, b) => n * 256 + b, 0) }
}

/**
 * Register the genesis and write the parts, resuming after the ticks the thread already holds.
 * @param {{ service: ThreadService, key: { publicKey, sign }, archive: object, parts?: Uint8Array[], say?: Function }} o
 *        parts are the archive's (cutParts) unless given
 * @returns {Promise<{ id: Uint8Array, label: string, owner: Uint8Array, written: number, held: number, ticks: number[] }>}
 *        held: the parts the thread held before; ticks: the size of each tick written
 */
export async function publishRelease({ service, key, archive, parts = cutParts(archive.bytes), say = () => {} }) {
  const cov = await covenantAt(archive.commit)
  const label = labelOf(archive.commit, archive.date)
  const g = genesisOf(cov, key.publicKey, label)
  const id = await service.register(g.fields)
  const writer = new ThreadWriter({ service, genesis: id, key, unlock: basicUnlock(key, [parts[0], REV]), ledger: memoryLedger() })
  const { report } = await writer.open()
  const held = report?.ticks ?? []
  if (held.length > parts.length)
    throw new ReleaseError(`the thread already holds ${held.length} ticks, more than this release's ${parts.length} parts: nothing written`)
  for (const t of held) {
    const p = t.entry ? tickPart(t.entry) : null
    if (p === null || !same(p.bundle, parts[t.position - 1]) || p.r !== REV || !same(p.key, key.publicKey))
      throw new ReleaseError(`the thread already holds tick ${t.position}, and it is not part ${t.position} of this release: nothing written`)
  }
  if (held.length === parts.length) say(`  the thread already holds all ${parts.length} parts: nothing to write`)
  else if (held.length) say(`  the thread already holds parts 1 to ${held.length}: the rest follow them`)
  const ticks = []
  for (let k = held.length; k < parts.length; k++) {
    const next = cov.lockOf(g.owner, sha256(parts[k]))
    const a = await writer.write(tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: next }] }),
                                 { unlock: basicUnlock(key, [parts[k], REV]) })
    if (!a.landed)
      throw new ReleaseError(`tick ${k + 1}: the service answered ${a.status}${a.error ? `, ${printable(a.error)}` : ''}${a.reason ? `: ${printable(a.reason)}` : ''}. `
        + 'Publishing again carries on after the ticks that landed')
    ticks.push(a.bytes.length)
    say(`  tick ${k + 1} of ${parts.length}: ${commas(parts[k].length)} B of the archive, the tick ${commas(a.bytes.length)} B`)
  }
  return { id, label, owner: g.owner, written: parts.length - held.length, held: held.length, ticks }
}

/**
 * Read a release thread back and check it (the header's VERIFY).
 * @param {{ service: ThreadService, id: Uint8Array|string, owner: Uint8Array, commit?: string|null }} o
 * @returns {Promise<{ ok: boolean, problems: string[], label: string, commit: string|null, date: string|null, owner: string,
 *                     ticks: number, parts: number[], sha256: string, bytes: number, files: number|null }>}
 */
export async function verifyRelease({ service, id, owner, commit = null }) {
  const problems = []
  const genesis = await service.genesis(id)

  // the genesis: a label naming the commit, and the code thread's covenant as that commit holds it, for this owner
  const label = new TextDecoder().decode(genesis.state)
  const m = LABEL.exec(label)
  if (!m) problems.push(`the genesis's label is not a release's ('jetmora code <commit> <date>'): ${JSON.stringify(label.slice(0, 80))}`)
  const given = commit === null ? null : resolveCommit(commit)
  if (given !== null && m && m[1] !== given) problems.push(`the thread's label names commit ${m[1]}, not ${given}`)
  let at = given ?? m?.[1] ?? null
  // a commit only the label names: its compiler runs here only if the branch checked out already holds it
  const unheld = given === null && at !== null && !onBranch(at) ? at : null
  if (unheld !== null) {
    problems.push(`the label names commit ${unheld}, which the branch checked out does not hold, so its compiler is not `
      + 'run: give --commit to check against it deliberately')
    at = null
  }
  let cov = null
  if (at !== null) {
    try { cov = await covenantAt(at) }
    catch (e) {
      if (!(e instanceof ReleaseError)) throw e
      problems.push(e.message)
    }
  }
  if (cov !== null) {
    if (!same(genesis.sourceHash, cov.sourceHash))
      problems.push(`the genesis does not name basic/code-thread.bas as its source: the file as ${short(cov.commit)} holds it`)
    if (!same(genesis.script, cov.lockOf(owner, ZERO))) {
      const s = stateOf(cov, genesis.script)
      problems.push(s !== null && same(genesis.script, cov.lockOf(s.owner, ZERO))
        ? `the genesis is the code thread's covenant for owner ${hex(s.owner)}, not ${hex(owner)}`
        : `the genesis script is not the code thread's covenant, as ${short(cov.commit)} compiles it, with rev 3 and no release in it`)
    }
  }

  // the ticks, each judged by the reader against the output it spends
  const rep = await readThread(service, genesis.id)
  for (const p of rep.problems) problems.push(`tick ${p.position}: ${p.kind}: ${p.detail}`)
  if (rep.count === 0) problems.push('the thread holds no ticks')

  // each part; where[k] is the position of the tick that carries parts[k]
  const parts = [], where = []
  let key = null
  for (const t of rep.ticks) {
    const p = t.entry ? tickPart(t.entry) : null
    if (p === null) { problems.push(`tick ${t.position}: its unlocking script is not a release tick's four pushes`); continue }
    if (p.bundle.length === 0) problems.push(`tick ${t.position}: it carries no bytes of the archive`)
    key ??= p.key
    if (!same(p.key, key)) problems.push(`tick ${t.position}: signed by another key than tick 1`)
    if (!same(hash160(p.key), owner)) problems.push(`tick ${t.position}: its key's HASH160 is ${hex(hash160(p.key))}, not the owner`)
    if (p.r !== REV) problems.push(`tick ${t.position}: revision ${p.r}, not ${REV}`)
    const next = t.entry.outputs[0]?.locking ?? new Uint8Array(0)
    if (cov !== null && !same(next, cov.lockOf(owner, sha256(p.bundle)))) {
      const s = stateOf(cov, next)
      problems.push(`tick ${t.position}: ${s !== null && !same(s.code, sha256(p.bundle)) ? 'its successor\'s code is not the SHA-256 of the part it carries'
        : s !== null && (!same(s.owner, owner) || s.rev !== BigInt(REV)) ? 'its successor\'s owner or revision is not the release\'s'
        : `its successor is not the code thread's covenant as ${short(cov.commit)} compiles it`}`)
    }
    parts.push(p.bundle)
    where.push(t.position)
  }
  if (key !== null && !same(genesis.authorised, authorisedHashes([key])))
    problems.push('the genesis does not authorise the release key, alone, to append')

  // the archive: the parts joined, against the archive rebuilt from git
  const joined = Buffer.concat(parts)
  const out = { label, commit: at, date: m?.[2] ?? null, owner: hex(owner), ticks: rep.count, parts: parts.map(p => p.length),
                sha256: hex(sha256(joined)), bytes: joined.length, files: null }
  let a = null
  if (at === null) { if (unheld === null) problems.push('no commit to rebuild the archive from: the label names none, and none was given') }
  else {
    try { a = buildArchive(at) }
    catch (e) {
      if (!(e instanceof ReleaseError)) throw e
      problems.push(`the archive of ${at} cannot be rebuilt here: ${e.message}`)
    }
  }
  if (a !== null) {
    // the parts as the archive is cut: as many, each its size. The joined bytes, below, are what they hold
    const cut = cutParts(a.bytes)
    const k = parts.findIndex((p, k) => k >= cut.length || p.length !== cut[k].length)
    if (k >= 0) problems.push(k >= cut.length
      ? `tick ${where[k]} carries ${commas(parts[k].length)} B past the end: the archive of ${short(at)} is ${cut.length} parts`
      : `tick ${where[k]} carries ${commas(parts[k].length)} B, and part ${k + 1} of the archive of ${short(at)} is ${commas(cut[k].length)} B`)
    else if (parts.length < cut.length) problems.push(`the thread carries ${parts.length} parts, and the archive of ${short(at)} is ${cut.length}`)
    if (!same(joined, a.bytes))
      problems.push(`the parts joined are ${commas(joined.length)} B, SHA-256 ${out.sha256}; the archive of ${short(at)} rebuilt from git `
        + `is ${commas(a.bytes.length)} B, ${a.sha256}: not the same bytes`)
    if (m && m[2] !== a.date) problems.push(`the label's date is ${m[2]}, and commit ${short(at)}'s is ${a.date}`)
    if (problems.length === 0) out.files = a.files
  }
  return { ok: problems.length === 0, problems, ...out }
}

// ── what the author does next, by hand ──────────────────────────────────────────────────────────────────────────────
/** The tables of PROVENANCE.md a release adds a row to, by their headings: their columns as PROVENANCE.md heads them */
const PROVENANCE_TABLES = Object.freeze({
  'Release threads': '| Date | Commit | Archive SHA-256 | Release key HASH160 | Thread | Ticks |',
  'OpenTimestamps': '| Date | Commit | Archive SHA-256 | Proof | BTC block |',
  'WAX and BSV': '| Date | Commit | Archive SHA-256 | WAX block, tx | BSV tx |',
})

/** Draft rows for PROVENANCE.md, for the author to approve before they go in: each under its table's heading and columns */
function draftRows(r, id) {
  const c = `\`${short(r.commit)}\``, h = `\`${r.sha256}\``
  const table = (heading, when, row) => {
    const head = PROVENANCE_TABLES[heading]
    return ['', `  ## ${heading}${when}`, `  ${head}`, `  ${head.replace(/[^|]/g, '-')}`, `  | ${row.join(' | ')} |`]
  }
  return [
    'Draft rows for PROVENANCE.md, for approval before they go in:',
    ...table('Release threads', '', [r.date, c, h, `\`${r.owner}\``, `\`${hex(id)}\``, r.ticks]),
    ...table('OpenTimestamps', ', once the proof is made', [r.date, c, h, `\`provenance/jetmora-${short(r.commit)}.tar.gz.ots\``, 'pending']),
    ...table('WAX and BSV', ', once foenjam has timestamped the archive', [r.date, c, h, 'pending', 'pending']),
  ].join('\n')
}

/** The stamping steps for the archive file */
function stampSteps(file, sha) {
  return [
    `Timestamp ${file} (SHA-256 ${sha}):`,
    `  BTC  ots stamp ${file}`,
    `       then copy ${basename(file)}.ots into provenance/; once mined, ots upgrade, and record the block`,
    '  WAX and BSV: timestamp the same file on foenjam, where those keys are held',
  ].join('\n')
}

// ── the command line ────────────────────────────────────────────────────────────────────────────────────────────────
const USAGE = `node tools/release.mjs archive <commit> [--out FILE]
node tools/release.mjs publish <commit> --service URL [--send]
node tools/release.mjs verify <genesis-id> --service URL --owner HASH160 [--commit C]
node tools/release.mjs keygen FILE`

class Usage extends Error {}

function serviceOf(url) {
  if (url === undefined) throw new Usage('--service URL is needed: the thread service to write to, or read from. There is no default')
  let u
  try { u = new URL(url) } catch { throw new Usage('--service is not a URL') }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Usage('--service is an http or https URL')
  return new ThreadService(u.href)
}

function printArchive(a) {
  const parts = cutParts(a.bytes)
  console.log(`  commit    ${a.commit} (${a.date})`)
  console.log(`  archive   ${a.files} files, ${commas(a.bytes.length)} B, SHA-256 ${a.sha256}`)
  console.log(`  parts     ${parts.length} ticks: ${parts.length > 1 ? `${parts.length - 1} of ${commas(PART_BYTES)} B and ` : ''}one of ${commas(parts.at(-1).length)} B`)
}

/** What verify found. The label and the problems carry the service's text, so they reach the terminal made printable:
 *  a label that is not a release's is shown quoted, and cut */
function printVerified(r, id, ms) {
  console.log(`  thread    ${hex(id)}`)
  console.log(`  label     ${LABEL.test(r.label) ? r.label : `${printable(JSON.stringify(r.label.slice(0, 80)))}${r.label.length > 80 ? '…' : ''}`}`)
  console.log(`  ticks     ${r.ticks}, the parts joined ${commas(r.bytes)} B`)
  console.log(`  archive   SHA-256 ${r.sha256}${r.files === null ? '' : `, ${r.files} files`}`)
  if (!r.ok) {
    for (const p of r.problems) console.log(`  ✗ ${printable(p)}`)
    console.log(`\n⚠ NOT VERIFIED: ${r.problems.length} problem${r.problems.length === 1 ? '' : 's'} (${(ms / 1000).toFixed(1)} s)`)
    return
  }
  console.log(`  ✓ verified in ${(ms / 1000).toFixed(1)} s: the code thread's covenant for this owner, every tick judged, every part `
    + `the SHA-256 its tick names, and the parts joined the archive rebuilt from git at ${short(r.commit)}\n`)
  console.log(draftRows(r, id))
}

/** The options each command takes */
const OPTIONS = { archive: ['out'], publish: ['service', 'send'], verify: ['service', 'owner', 'commit'], keygen: [] }

/** Refuses when an argument holds the seed: a seed, a genesis id and a hash are all 64 hex characters */
function refuseSeedIn(args, text) {
  const seed = text?.trim().toLowerCase() ?? ''
  if (/^[0-9a-f]{64}$/.test(seed) && args.some(v => typeof v === 'string' && v.toLowerCase().includes(seed)))
    throw new ReleaseError(`an argument holds the release key's seed, ${SEED_VAR}: nothing was run or sent. A seed, a genesis id `
      + 'and a hash all look alike: check which was copied')
}

async function main(argv) {
  let seedText = takeSeed()                    // first, before git or anything else runs
  const [cmd, ...rest] = argv
  let parsed
  try {
    parsed = parseArgs({ args: rest, allowPositionals: true, strict: true, options: {
      out: { type: 'string' }, service: { type: 'string' }, owner: { type: 'string' }, commit: { type: 'string' }, send: { type: 'boolean' } } })
  } catch { throw new Usage(`not an option this tool takes`) }
  const { values: o, positionals: p } = parsed
  refuseSeedIn([cmd, ...p, ...Object.values(o)], seedText)
  if (cmd !== 'publish') seedText = undefined  // publish alone uses it
  if (Object.hasOwn(OPTIONS, cmd))
    for (const name of Object.keys(o)) if (!OPTIONS[cmd].includes(name)) throw new Usage(`${cmd} does not take --${name}`)
  const one = what => { if (p.length !== 1) throw new Usage(`${cmd} takes ${what}, and nothing else`); return p[0] }

  if (cmd === 'archive') {
    const out = o.out === undefined ? null : placeOf(o.out, 'the archive is written outside it, where git can never add it').path
    const a = buildArchive(one('one commit'))
    printArchive(a)
    if (out !== null) {
      writeNew(out, a.bytes)
      console.log(`  written   ${out}\n\n${stampSteps(o.out, a.sha256)}`)
    }
    return 0
  }

  if (cmd === 'publish') {
    const name = one('one commit')
    const service = serviceOf(o.service)
    const commit = resolveCommit(name)         // once: a branch that moves during the run never splits the plan
    const cov = await covenantAt(commit)       // a commit with no covenant is refused before the key is made
    const key = await releaseKey(seedText)
    seedText = undefined                       // the key holds it now
    const t0 = performance.now()
    const archive = buildArchive(commit)
    const parts = cutParts(archive.bytes)
    const label = labelOf(archive.commit, archive.date)
    const g = genesisOf(cov, key.publicKey, label)
    console.log('The release:')
    printArchive(archive)
    console.log(`  service   ${service.base}`)
    console.log(`  key       public key ${hex(key.publicKey)}, HASH160 ${hex(g.owner)}`)
    console.log(`  thread    genesis ${hex(g.id)}, label '${label}'`)
    if (!o.send) {
      console.log('\nDry run: nothing is written. Add --send to register the genesis and write the ticks.')
      return 0
    }
    console.log('\nWriting:')
    const w = await publishRelease({ service, key, archive, parts, say: m => console.log(m) })
    const t1 = performance.now()
    console.log(`  ${w.written} tick${w.written === 1 ? '' : 's'} written in ${((t1 - t0) / 1000).toFixed(1)} s\n\nRead back and verified:`)
    const r = await verifyRelease({ service, id: w.id, owner: w.owner, commit: archive.commit })
    printVerified(r, w.id, performance.now() - t1)
    if (!r.ok) return 1
    console.log(`\nThe archive file, the same bytes: node tools/release.mjs archive ${short(archive.commit)} --out jetmora-${short(archive.commit)}.tar.gz`
      + '\n(outside this repository), then:\n' + stampSteps(`jetmora-${short(archive.commit)}.tar.gz`, archive.sha256))
    return 0
  }

  if (cmd === 'verify') {
    const id = one('one genesis id')
    if (!/^[0-9a-fA-F]{64}$/.test(id)) throw new Usage('a genesis id is 64 hex characters')
    if (o.owner === undefined || !/^[0-9a-fA-F]{40}$/.test(o.owner))
      throw new Usage('--owner HASH160 is needed: the release key\'s HASH160, 40 hex characters, which keygen and publish print')
    const service = serviceOf(o.service)
    const t0 = performance.now()
    const r = await verifyRelease({ service, id, owner: Buffer.from(o.owner, 'hex'), commit: o.commit ?? null })
    printVerified(r, Buffer.from(id, 'hex'), performance.now() - t0)
    return r.ok ? 0 : 1
  }

  if (cmd === 'keygen') {
    const k = await keygen(one('one file'))
    console.log(`  seed      written to ${k.file}, mode 0600: never shown here`)
    console.log(`  key       public key ${hex(k.publicKey)}`)
    console.log(`  owner     HASH160 ${hex(k.owner)}, what verify --owner takes`)
    console.log(`\nTo use it, in your own shell, set for the one run of publish and gone from the shell when it ends:\n${seedLines(k.file)}`)
    return 0
  }

  throw new Usage(cmd === undefined ? 'a command is needed' : 'not a command this tool has')
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.on('SIGQUIT', () => process.exit(131))   // Ctrl-\ without a core dump, which would hold the seed
  main(process.argv.slice(2)).then(code => process.exit(code), e => {
    if (e instanceof Usage) console.error(`⚠ ${e.message}\n\n${USAGE}`)
    else if (e instanceof ReleaseError) console.error(`⚠ ${e.message}`)
    else console.error(`⚠ ${e?.constructor?.name ?? 'Error'}: ${printable(e?.message ?? e)}`)
    process.exit(e instanceof Usage ? 2 : 1)
  })
}
