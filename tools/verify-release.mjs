// © 2026 sun-dive. Business Source License 1.1. See LICENSE.
//
// The release tool, tools/release.mjs, end to end. Nothing is sent to a live host: every write goes to the thread
// service staged in a temp folder as .cpanel.yml deploys it, and served by php -S.
//   node tools/verify-release.mjs
//   gzip      tools/gzip.mjs gives GNU gzip -6 -n's bytes, on the two archives' tars, on inputs around the edges of its
//             window and its blocks, and on an end matched past itself (when gzip is on the PATH; reported when not)
//   archive   448b796 rebuilt from git's objects is the 14 Sept archive, PROVENANCE.md's row: 129 files, 624,949 B,
//             SHA-256 8f3884e2..., its date 2026-09-14 and its mtime 1789315200. HEAD built twice is the same bytes, its
//             date the one git prints. The tar holds every file of the commit, each hashing to the blob git names,
//             owned by root, mode 0644, its mtime the commit's date; GNU tar makes the same tar from a checkout (when it
//             is on the PATH). The parts join to the archive. GIT_DIR pointing elsewhere changes nothing. --out
//             refused over a file that exists, and inside the repository
//   keygen    a seed file of mode 0600, only the public key and its HASH160 printed; a file that exists, one inside
//             the repository (by its path, and through a link), and one inside another git work tree, refused. The
//             shell lines it prints give the seed to the one run, and leave nothing in the shell (bash, and fish when
//             it is on the PATH)
//   publish   refused without the key, with a seed that is not one, and without --service; takeSeed empties the
//             variable, and process.env with no argument; the seed is in no pooled buffer once the key is made; the
//             seed on the command line refused, as an option or a second commit, and an argument holding the seed set
//             in the environment refused before git runs or a request is sent; each command refuses the options it
//             does not take; a dry run prints the plan, its HASH160 and label, writes nothing, and git never sees the
//             seed; then HEAD published in full (every part a tick), the plan printed before the writing, read back and
//             verified, its draft rows under PROVENANCE.md's own headings and columns; run again, nothing more written;
//             a release stopped part way carried on to the end; a thread whose first tick is not the first part
//             refused, nothing written; 448b796, which holds no basic/code-thread.bas, refused before a host is asked,
//             and a genesis naming it NOT VERIFIED; a host that changes a tick once written makes publish exit 1, and a
//             host's error with control characters reaches the terminal without them
//   verify    a release verifies; and is refused for a part missing, parts out of order, a part changed, another key's
//             thread, the wrong commit, an empty part at the start, middle or end, parts cut at another size, a host
//             that changes one byte of a tick's signature, a host that counts a tick more than it gives, a genesis
//             naming another source, a label of another date, a label that is not a release's, a genesis that lets
//             anyone append, and a tick of another revision; --owner is required; a label holding control characters
//             reaches the terminal without them
//   clone     from a clone of the repository: a local `git replace` changes nothing; the covenant, the compiler and
//             its opcode table changed and not committed change nothing either: the same genesis as here, and the
//             release verifies. COVENANT_FILES is the compiler's import closure. A later commit, made there with git
//             plumbing, its covenant's comment changed and its compiler bumped, so its covenant is other bytes: with
//             the clone moved on to it, the release of HEAD still verifies; the later commit published, against its own
//             covenant, and verified; a branch that moves on to it once publish has read it, the plan all the first
//             commit's; a genesis labelled for either commit with the other's covenant refused; a commit whose compiler
//             cannot be loaded, one whose compiler cannot compile its covenant, and one naming the covenant or the
//             compiler by a blob the store does not hold (git cannot read it, not a commit without it), refused. Synthetic
//             commits: an executable is mode 0755, the mtime is the committer's date when the author's is another day
//             (as GNU tar makes it), and a path of 100 bytes refused
//   signal    Ctrl-\ (SIGQUIT) ends a run with exit 131, without a core dump
//   secret    no seed appears in anything the tool printed, as hex either case or as base64
// Every key is a throwaway, made for the run. The temp folder and the servers go when the run ends (tools/run-folder.mjs).
import { execFileSync, spawn, spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, statSync, symlinkSync, unlinkSync, writeFileSync, chmodSync } from 'node:fs'
import { createServer as httpServer } from 'node:http'
import { createServer, connect } from 'node:net'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { gunzipSync } from 'node:zlib'
import { gzip } from './gzip.mjs'
import { buildArchive, cutParts, publishRelease, verifyRelease, releaseKey, takeSeed, covenantAt, genesisOf, labelOf, PART_BYTES, REV,
         SEED_VAR, COVENANT_FILES } from './release.mjs'
import { ThreadService, ServiceError } from './thread-service.mjs'
import { ThreadWriter, memoryLedger, basicUnlock } from './thread-writer.mjs'
import { AUTH_OPEN } from './thread.mjs'
import { parseEntry } from './entry.mjs'
import { runFolder } from './run-folder.mjs'

// a seed the person running this test has set is never used, and never reaches a run of the tool
delete process.env[SEED_VAR]
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const TOOL = join(ROOT, 'tools', 'release.mjs')
const hex = b => Buffer.from(b).toString('hex')
const sha = b => createHash('sha256').update(b).digest('hex')
const same = (a, b) => a != null && b != null && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0
const commas = n => n.toLocaleString('en-US')
const has = cmd => spawnSync('sh', ['-c', `command -v ${cmd}`]).status === 0
const GNU_TAR = has('tar') && /GNU tar/.test(spawnSync('tar', ['--version'], { encoding: 'utf8' }).stdout ?? '')
/** Control characters other than a newline: none may reach the terminal from a host */
const CONTROL = /[\x00-\x09\x0b-\x1f\x7f-\x9f]/
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }

/** The 14 Sept archive, as PROVENANCE.md records it */
const SEPT = { commit: '448b796955317b9cbe8c737e8b6079254e0dc9e5', files: 129, bytes: 624_949,
               sha256: '8f3884e2a2ddfad74ce2ac4bc0c769b85a0ee45613c7d1a600b28fa28d03ce90' }
const RUN = runFolder('release'), TMP = RUN.dir

/** Everything the tool printed, in every run: searched for the seeds at the end */
const printed = []
/** One run of the tool: { status, out, ms }. It blocks this process, so it never asks a host served here */
function tool(args, env = {}, script = TOOL) {
  const t0 = performance.now()
  const r = spawnSync(process.execPath, [script, ...args], { cwd: TMP, env: { ...process.env, ...env }, encoding: 'utf8', maxBuffer: 1 << 26 })
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`
  printed.push(out)
  return { status: r.status, out, ms: performance.now() - t0 }
}
/** One run of the tool that leaves this process free, for a run whose host is served here: { status, signal, out }.
 *  command and pre run it through something else (a shell); started(child) is called once it runs */
function toolAsync(args, env = {}, { script = TOOL, command = process.execPath, pre = [], started } = {}) {
  return new Promise(res => {
    const c = spawn(command, [...pre, script, ...args], { cwd: TMP, env: { ...process.env, ...env } })
    let out = ''
    c.stdout.on('data', d => { out += d })
    c.stderr.on('data', d => { out += d })
    started?.(c)
    c.on('close', (status, signal) => { printed.push(out); res({ status, signal, out }) })
  })
}
const seedHex = () => randomBytes(32).toString('hex')

// ── gzip ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── tools/gzip.mjs, against GNU gzip -6 -n ──')
const SEPT_ARCHIVE = buildArchive(SEPT.commit)
const HEAD = buildArchive('HEAD')
/** The code thread's covenant as HEAD holds it, compiled by HEAD's compiler: every genesis here is built from it */
const COV = await covenantAt('HEAD')
{
  const gnu = has('gzip') && /GNU|gzip 1\./.test(spawnSync('gzip', ['--version'], { encoding: 'utf8' }).stdout ?? '')
  if (!gnu) console.log('  · not checked: no GNU gzip on the PATH (the 14 Sept archive below holds the port to its bytes all the same)')
  else {
    const text = HEAD.tar.subarray(0, 300_000)
    // gzip zeroes the two bytes past the end of its input, so they never extend a match: an input whose last bytes
    // match twice, once followed by zeros and once by the bytes the window held there before, tells that apart. Its
    // bytes are a generator's, which compress a little, so the last block is coded and the match's distance shows
    let seed = 7
    const past = Uint8Array.from({ length: 70_000 }, () => (seed = (seed * 1103515245 + 12345) >>> 0) >>> 24)
    past.set([81, 82, 83, 84], past.length - 4)
    past.set([81, 82, 83, 84, past[past.length - 32_768], past[past.length - 32_767]], past.length - 1000)
    past.set([81, 82, 83, 84, 0, 0], past.length - 2000)
    const inputs = [['the tar of HEAD', HEAD.tar], ['the tar of 448b796', SEPT_ARCHIVE.tar], ['nothing', new Uint8Array(0)],
      ['the end of the input, matched past it', past],
      ['one byte', Uint8Array.of(7)], ['random, 70,000 B', randomBytes(70_000)], ['zeros, 1 MB', new Uint8Array(1 << 20)],
      ...[261, 262, 32_506, 65_274, 65_536, 65_537].map(n => [`text, ${commas(n)} B`, text.subarray(0, n)]),
      ['text and random, interleaved', Buffer.concat([text.subarray(0, 40_000), randomBytes(50_000), text.subarray(40_000, 200_000)])]]
    let agree = 0
    for (const [what, b] of inputs) {
      const theirs = execFileSync('gzip', ['-6n'], { input: b, maxBuffer: 1 << 28 })
      if (same(gzip(b), theirs)) agree++
      else console.log(`    ${what}: not the same bytes`)
    }
    ok(agree === inputs.length, `the same bytes as GNU gzip on each of ${inputs.length} inputs: the two tars, nothing, one byte, random bytes, `
       + 'zeros, text cut at the edges of the lookahead and of the window, and an end matched past itself')
  }
}

// ── the archive ──────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── the archive ──')
/** The headers of a tar, read back: [{ path, mode, uid, gid, mtime, type, magic, uname, gname, sum, oid }], and where
 *  the last file ends */
function tarRead(tar) {
  const read = []
  let at = 0
  const field = (h, o, n) => h.subarray(o, o + n).toString('latin1').replace(/\0.*$/s, '')
  while (at + 512 <= tar.length && tar[at] !== 0) {
    const h = tar.subarray(at, at + 512)
    const size = parseInt(field(h, 124, 12), 8)
    const body = tar.subarray(at + 512, at + 512 + size)
    let sum = 0
    for (let k = 0; k < 512; k++) sum += k >= 148 && k < 156 ? 0x20 : h[k]
    read.push({ path: field(h, 0, 100), mode: field(h, 100, 8), uid: field(h, 108, 8), gid: field(h, 116, 8), mtime: parseInt(field(h, 136, 12), 8),
                type: String.fromCharCode(h[156]), magic: field(h, 257, 8), uname: field(h, 265, 32), gname: field(h, 297, 32),
                sum: parseInt(field(h, 148, 8), 8) === sum,
                oid: createHash('sha1').update(`blob ${size}\0`).update(body).digest('hex') })
    at += 512 + Math.ceil(size / 512) * 512
  }
  return { read, end: at }
}
/** GNU tar's tar of a commit, from a checkout in dir, with the recipe's settings */
function gnuTar(gitDir, commit, mtime, dir) {
  mkdirSync(dir)
  execFileSync('tar', ['-x', '-C', dir], { input: execFileSync('git', ['-C', gitDir, 'archive', commit], { maxBuffer: 1 << 28 }) })
  const list = execFileSync('git', ['-C', gitDir, 'ls-tree', '-r', '--name-only', commit]).toString()
  return execFileSync('tar', ['--format=gnu', '--owner=root', '--group=root', '--mode=go-w', `--mtime=@${mtime}`, '-cf', '-', '-T', '-'],
                      { cwd: dir, input: list, maxBuffer: 1 << 28 })
}
{
  const a = SEPT_ARCHIVE
  ok(a.commit === SEPT.commit && a.files === SEPT.files && a.bytes.length === SEPT.bytes && a.sha256 === SEPT.sha256,
     `★ 448b796, rebuilt from git's objects alone, is the 14 Sept archive: ${a.files} files, ${commas(a.bytes.length)} B, SHA-256 ${a.sha256.slice(0, 16)}…`)
  const ledger = readFileSync(join(ROOT, 'PROVENANCE.md'), 'utf8')
  ok(ledger.includes(`| 2026-09-14 | \`448b796\` | \`${SEPT.sha256}\``), 'that is the hash PROVENANCE.md records for 448b796, in its first row')
  const gitDate = execFileSync('git', ['-C', ROOT, 'log', '-1', '--format=%cd', '--date=format:%Y-%m-%d', 'HEAD']).toString().trim()
  ok(a.date === '2026-09-14' && a.mtime === 1_789_315_200 && HEAD.date === gitDate,
     `its date is 2026-09-14 and its mtime 1789315200, 00:00 of that day at +0800; HEAD's date is ${gitDate}, as git prints the committer's`)
  const again = buildArchive('HEAD')
  ok(same(again.bytes, HEAD.bytes) && again.sha256 === HEAD.sha256,
     `HEAD built twice is the same bytes, byte for byte: ${HEAD.files} files, ${commas(HEAD.bytes.length)} B, SHA-256 ${HEAD.sha256.slice(0, 16)}…`)

  // the tar, read back: every file of the commit, its bytes the blob git names, its header the recipe's
  const tree = execFileSync('git', ['-C', ROOT, 'ls-tree', '-r', '-z', HEAD.commit]).toString('utf8').split('\0').filter(Boolean)
    .map(l => { const [meta, path] = l.split('\t'); const [mode, , oid] = meta.split(' '); return { mode, oid, path } })
  const tar = gunzipSync(HEAD.bytes)
  const { read, end } = tarRead(tar)
  ok(same(tar, HEAD.tar) && tar.length % 10_240 === 0 && tar.subarray(end).every(b => b === 0),
     `the gzip unpacks to the tar, ${commas(tar.length)} B: whole records of 10,240 B, zeros after the last file`)
  ok(read.length === tree.length && read.every((r, k) => r.path === tree[k].path && r.oid === tree[k].oid),
     `it holds the commit's ${tree.length} files, in git's order, each hashing to the blob git names: none from the working tree`)
  ok(read.every(r => r.mode === '0000644' && r.uid === '0000000' && r.gid === '0000000' && r.uname === 'root' && r.gname === 'root'
                     && r.type === '0' && r.magic === 'ustar  ' && r.sum && r.mtime === HEAD.mtime),
     `each header is GNU tar's: owner and group root (0), mode 0644, a good checksum, mtime ${new Date(HEAD.mtime * 1000).toISOString()}, `
     + `00:00 of ${HEAD.date} in the commit's own timezone`)

  if (!GNU_TAR) console.log('  · GNU tar not checked: not on the PATH')
  else {
    for (const x of [SEPT_ARCHIVE, HEAD]) {
      ok(same(gnuTar(ROOT, x.commit, x.mtime, join(TMP, `checkout-${x.commit.slice(0, 7)}`)), x.tar),
         `GNU tar makes the same tar of ${x.commit.slice(0, 7)} from a checkout: --format=gnu --owner=root --group=root `
         + `--mtime=@${x.mtime}, the files in git's order`)
    }
  }

  const parts = cutParts(HEAD.bytes)
  ok(parts.length === Math.ceil(HEAD.bytes.length / PART_BYTES) && parts.slice(0, -1).every(p => p.length === PART_BYTES)
     && same(Buffer.concat(parts), HEAD.bytes),
     `HEAD's archive is ${parts.length} parts, ${parts.length - 1} of ${commas(PART_BYTES)} B and one of ${commas(parts.at(-1).length)} B, `
     + 'which join to it')

  // git pointed at another repository by the environment: the tool's git reads this one all the same
  const empty = join(TMP, 'empty-repo')
  execFileSync('git', ['init', '-q', empty])
  const elsewhere = tool(['archive', 'HEAD'], { GIT_DIR: join(empty, '.git') })
  ok(elsewhere.status === 0 && elsewhere.out.includes(HEAD.commit) && elsewhere.out.includes(HEAD.sha256),
     'with GIT_DIR naming an empty repository, archive HEAD is still this repository\'s HEAD, the same hash')

  const file = join(TMP, 'jetmora-448b796.tar.gz')
  const r = tool(['archive', '448b796', '--out', file])
  ok(r.status === 0 && r.out.includes(SEPT.sha256) && r.out.includes('624,949 B') && r.out.includes('129 files') && r.out.includes('ots stamp')
     && sha(readFileSync(file)) === SEPT.sha256,
     'the command line: archive 448b796 --out FILE prints the hash, the size and the files, writes those bytes, and says how to stamp them')
  const precious = join(TMP, 'precious.seed')
  writeFileSync(precious, `${seedHex()}\n`)
  const kept = readFileSync(precious, 'utf8')
  const over = tool(['archive', 'HEAD', '--out', precious])
  const inside = join(ROOT, `.release-test-${randomBytes(6).toString('hex')}.tar.gz`)
  let inRepo, made
  try { inRepo = tool(['archive', 'HEAD', '--out', inside]); made = existsSync(inside) } finally { if (existsSync(inside)) unlinkSync(inside) }
  ok(over.status === 1 && /exists/.test(over.out) && readFileSync(precious, 'utf8') === kept
     && inRepo.status === 1 && /inside this repository/.test(inRepo.out) && !made,
     'archive --out refuses a file that exists, which is left as it was, and a file inside the repository, never made')
}

// ── keygen ───────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── keygen ──')
{
  const file = join(TMP, 'release.seed')
  const r = tool(['keygen', file])
  const text = existsSync(file) ? readFileSync(file, 'utf8') : ''
  const seed = text.trim()
  const key = /^[0-9a-f]{64}$/.test(seed) ? await releaseKey(seed) : null
  ok(r.status === 0 && /^[0-9a-f]{64}\n$/.test(text) && (statSync(file).mode & 0o777) === 0o600,
     'keygen writes a new seed, 64 hex characters, to a file of mode 0600')
  ok(key !== null && r.out.includes(hex(key.publicKey)) && r.out.includes(hex(genesisOf(COV, key.publicKey, '').owner))
     && !r.out.toLowerCase().includes(seed),
     'and prints the public key and its HASH160, never the seed')

  // the lines it prints, each run with a probe in place of publish: the probe sees the seed, and nothing after it does
  const RUNS = 'node tools/release.mjs publish <commit> --service URL'
  const probe = `${process.execPath} -e "process.exit(process.env.${SEED_VAR} === undefined ? 3 : 0)"`
  const after = { fish: `; and not set -q ${SEED_VAR}; and sh -c 'test -z "$${SEED_VAR}"'`,
                  bash: ` && [ -z "\${${SEED_VAR}+x}" ] && sh -c 'test -z "$${SEED_VAR}"'` }
  const shells = ['bash', ...(has('fish') ? ['fish'] : [])]
  const scoped = shells.map(sh => {
    const line = r.out.split('\n').find(l => l.startsWith(`  ${sh}  `))?.slice(8) ?? ''
    const flags = sh === 'fish' ? ['--no-config', '-c'] : ['-c']
    return { sh, line, status: line.includes(RUNS) ? spawnSync(sh, [...flags, line.replace(RUNS, probe) + after[sh]], { cwd: ROOT }).status : null }
  })
  if (!has('fish')) console.log('  · fish not checked: not on the PATH')
  ok(scoped.every(s => s.status === 0 && s.line.includes(file)),
     `the lines it prints for ${shells.join(' and ')} read the seed file for one run of publish: that run has the seed, and after it `
     + 'neither the shell nor a program it starts does')

  const again = tool(['keygen', file])
  ok(again.status === 1 && /exists/.test(again.out) && readFileSync(file, 'utf8') === text, 'a file that exists is refused, and left as it was')
  const inside = join(ROOT, 'tools', `.release-test-${randomBytes(6).toString('hex')}.seed`)
  const link = join(TMP, 'repo-link')
  symlinkSync(ROOT, link)
  const throughLink = join(link, `.release-test-${randomBytes(6).toString('hex')}.seed`)
  try {
    const a = tool(['keygen', inside]), b = tool(['keygen', throughLink])
    ok(a.status === 1 && /inside this repository/.test(a.out) && !existsSync(inside)
       && b.status === 1 && /inside this repository/.test(b.out) && !existsSync(join(ROOT, throughLink.split('/').at(-1))),
       'a file inside the repository is refused and never made, named directly or through a link to it')
  } finally {
    for (const f of [inside, join(ROOT, throughLink.split('/').at(-1))]) if (existsSync(f)) unlinkSync(f)
  }
  const other = join(TMP, 'other-repo')
  execFileSync('git', ['init', '-q', other])
  const o = tool(['keygen', join(other, 'release.seed')])
  ok(o.status === 1 && /inside the git work tree/.test(o.out) && !existsSync(join(other, 'release.seed')),
     'a file inside another git work tree is refused and never made')
}

// ── the thread service, staged as .cpanel.yml deploys it ─────────────────────────────────────────────────────────────
console.log('\n── the thread service, staged as .cpanel.yml deploys it ──')
const HOME = join(TMP, 'home'), DOCROOT = join(HOME, 'jetmora.org')
mkdirSync(HOME)
{
  const lines = readFileSync(join(ROOT, '.cpanel.yml'), 'utf8').split('\n')
    .map(l => l.match(/^\s*-\s+(\/bin\/(?:mkdir|cp)\s.*)$/)?.[1])
    .filter(c => c && (c.includes('$DEPLOYPATH/threads') || c.includes('$HOME/jetmora-data')))
  const bad = []
  for (const cmd of lines) {
    try { execFileSync('/bin/sh', ['-c', cmd], { cwd: ROOT, env: { HOME, DEPLOYPATH: `${DOCROOT}/`, PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'ignore', 'pipe'] }) }
    catch (e) { bad.push(e.stderr?.toString().trim() || cmd) }
  }
  ok(lines.length > 3 && bad.length === 0 && existsSync(join(DOCROOT, 'threads/index.php')),
     `${lines.length} lines of .cpanel.yml stage the thread service${bad.length ? `: ${bad.join('; ')}` : ''}`)
}
const freePort = () => new Promise(res => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
const listening = port => new Promise(res => { const c = connect(port, '127.0.0.1', () => { c.end(); res(true) }); c.on('error', () => res(false)) })
const PORT = await freePort()
RUN.start('php', ['-S', `127.0.0.1:${PORT}`, '-t', DOCROOT], { stdio: 'ignore' })
let up = false
for (let k = 0; k < 100 && !(up = await listening(PORT)); k++) await new Promise(r => setTimeout(r, 50))
ok(up, `php -S serves it on port ${PORT}`)
if (!up) { console.log(`\n⚠  ${pass} passed, ${fail + 1} failed   [the release tool]`); process.exit(1) }
const URL_ = `http://127.0.0.1:${PORT}/threads/`
const service = new ThreadService(URL_)
/** Whether the service holds a genesis of this id */
const registered = async id => { try { await service.genesis(id); return true } catch (e) { if (e instanceof ServiceError && e.status === 404) return false; throw e } }

/** One byte of a tick's signature changed: the first push of its unlocking script is the 64-byte signature */
function flipSignature(entryHex) {
  const b = Buffer.from(entryHex, 'hex')
  const at = b.indexOf(Buffer.from(parseEntry(b).inputs[0].unlocking))
  b[at + 11] ^= 0x01
  return b.toString('hex')
}
/**
 * A host in front of the staged service, served here, which notes the path of every request and lies as its mode says:
 *   flip    the first page of entries carries tick 3 with one byte of its signature changed
 *   count   op=tip counts one tick more than the service holds
 *   escape  every append is answered 400, its error holding control characters
 *   hold    no request is answered
 */
const PROXY = { mode: null, seen: [], held: [] }
const proxy = httpServer((req, res) => {
  const body = []
  req.on('data', c => body.push(c))
  req.on('end', async () => {
    PROXY.seen.push(req.url)
    const q = new URL(req.url, 'http://host').searchParams
    if (PROXY.mode === 'hold') { PROXY.held.push(res); return }
    if (PROXY.mode === 'escape' && q.get('op') === 'append') {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'refused\x1b[8m, the rest hidden\x9b2J' }))
      return
    }
    const type = req.headers['content-type']
    const answer = await fetch(`http://127.0.0.1:${PORT}${req.url}`, { method: req.method, body: req.method === 'POST' ? Buffer.concat(body) : undefined,
                                                                        headers: { Accept: req.headers.accept ?? '*/*', ...(type ? { 'Content-Type': type } : {}) } })
    let out = Buffer.from(await answer.arrayBuffer())
    if (PROXY.mode === 'flip' && q.get('op') === 'entries' && q.get('after') === '-1') {
      const page = JSON.parse(out)
      if (page.entries?.length >= 3) page.entries[2].entry = flipSignature(page.entries[2].entry)
      out = Buffer.from(JSON.stringify(page))
    }
    if (PROXY.mode === 'count' && q.get('op') === 'tip') {
      const t = JSON.parse(out)
      t.count += 1
      out = Buffer.from(JSON.stringify(t))
    }
    res.writeHead(answer.status, { 'Content-Type': answer.headers.get('content-type') ?? 'application/json' })
    res.end(out)
  })
})
await new Promise(r => proxy.listen(0, '127.0.0.1', r))
const PROXY_URL = `http://127.0.0.1:${proxy.address().port}/threads/`
const lying = new ThreadService(PROXY_URL)

// ── publish ──────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── publish ──')
const SEEDS = Object.fromEntries(['owner', 'resume', 'wrong', 'other', 'missing', 'order', 'changed', 'argv', 'asArg', 'sept', 'lying',
                                  'escape', 'end', 'middle', 'start', 'wide', 'meta', 'clone', 'later'].map(k => [k, seedHex()]))
const KEYS = Object.fromEntries(await Promise.all(Object.entries(SEEDS).map(async ([k, s]) => [k, await releaseKey(s)])))
const LABEL = labelOf(HEAD.commit, HEAD.date)
const G = Object.fromEntries(Object.entries(KEYS).map(([k, key]) => [k, genesisOf(COV, key.publicKey, LABEL)]))
const PARTS = cutParts(HEAD.bytes)
let published = null
{
  ok(Buffer.byteLength(LABEL) === 64, `the genesis's label is '${LABEL}': 64 bytes, as op=find takes`)
  const env = { [SEED_VAR]: seedHex(), OTHER: '1' }
  const taken = takeSeed(env)
  ok(/^[0-9a-f]{64}$/.test(taken) && !(SEED_VAR in env) && env.OTHER === '1', 'takeSeed takes the seed out of the environment it reads, and nothing else')
  process.env[SEED_VAR] = seedHex()
  const own = takeSeed()
  ok(/^[0-9a-f]{64}$/.test(own) && !(SEED_VAR in process.env), 'takeSeed() with no argument takes it out of this process\'s own environment')

  // the seed's bytes, in node's shared pool of small buffers once the key is made: nothing would ever wipe them there
  let pooled = null
  for (let k = 0; k < 3 && pooled === null; k++) {
    const s = seedHex(), raw = Buffer.alloc(32)
    raw.write(s, 'hex')
    const pool = Buffer.from('a').buffer
    await releaseKey(s)
    if (Buffer.from('b').buffer === pool) pooled = Buffer.from(pool).indexOf(raw) !== -1
  }
  ok(pooled === false, 'releaseKey leaves no copy of the seed\'s bytes in node\'s shared buffer pool, where its wipe would not reach')

  const none = tool(['publish', 'HEAD', '--service', URL_, '--send'])
  ok(none.status === 1 && none.out.includes(`${SEED_VAR} is not set`) && none.out.includes(`begin; read -l -x -s ${SEED_VAR}; `)
     && none.out.includes(`( read -rs ${SEED_VAR} && export ${SEED_VAR} && `),
     `without ${SEED_VAR} in the environment: refused, and told how to set it in your own shell for the one run`)
  const notOne = `zz${seedHex().slice(2)}`
  const badSeed = tool(['publish', 'HEAD', '--service', URL_, '--send'], { [SEED_VAR]: notOne })
  ok(badSeed.status === 1 && /is not a seed/.test(badSeed.out) && !badSeed.out.includes(notOne.slice(2)), 'with a seed that is not one: refused, and never shown')
  const noService = tool(['publish', 'HEAD', '--send'], { [SEED_VAR]: SEEDS.owner })
  ok(noService.status === 2 && /--service URL is needed/.test(noService.out) && /no default/.test(noService.out), 'without --service: refused, there being no default')
  ok(!await registered(G.owner.id), 'none of the three registered anything')

  // the seed on the command line, as an option or as a second commit: refused, nothing registered
  const asOption = tool(['publish', 'HEAD', '--service', URL_, '--send', '--seed', SEEDS.argv])
  const asCommit = tool(['publish', 'HEAD', SEEDS.argv, '--service', URL_, '--send'])
  ok(asOption.status === 2 && /not an option this tool takes/.test(asOption.out) && asCommit.status === 2 && /takes one commit, and nothing else/.test(asCommit.out)
     && !await registered(G.argv.id),
     'the seed on the command line, as --seed or as a second commit: refused, and nothing registered')

  // each command its own options
  const outFile = join(TMP, 'never-written')
  const archiveSend = tool(['archive', 'HEAD', '--send', '--service', URL_])
  const publishOut = tool(['publish', 'HEAD', '--service', URL_, '--out', outFile], { [SEED_VAR]: SEEDS.argv })
  ok(archiveSend.status === 2 && /archive does not take --send/.test(archiveSend.out) && publishOut.status === 2 && /publish does not take --out/.test(publishOut.out)
     && !existsSync(outFile),
     'a command refuses an option it does not take: archive --send, publish --out (no file written)')

  // a dry run, with git watched: what git runs with, and its arguments, noted by a git in front of the real one
  const bin = join(TMP, 'bin'), seen = join(TMP, 'git-env'), args = join(TMP, 'git-args')
  mkdirSync(bin)
  const realGit = execFileSync('sh', ['-c', 'command -v git']).toString().trim()
  writeFileSync(join(bin, 'git'), `#!/bin/sh\nenv >> '${seen}'\nprintf '%s\\n' "$*" >> '${args}'\nexec '${realGit}' "$@"\n`)
  chmodSync(join(bin, 'git'), 0o755)
  const watched = { PATH: `${bin}:${process.env.PATH}` }
  const dry = tool(['publish', 'HEAD', '--service', URL_], { [SEED_VAR]: SEEDS.owner, ...watched })
  const gitEnv = existsSync(seen) ? readFileSync(seen, 'utf8') : ''
  ok(dry.status === 0 && dry.out.includes(HEAD.commit) && dry.out.includes(HEAD.sha256) && dry.out.includes(`${PARTS.length} ticks`)
     && dry.out.includes(URL_) && dry.out.includes(`HASH160 ${hex(G.owner.owner)}`) && dry.out.includes(`genesis ${hex(G.owner.id)}, label '${LABEL}'`)
     && /Dry run: nothing is written/.test(dry.out),
     'a dry run prints the plan: the commit, the archive\'s hash, its parts, the service, the key\'s HASH160, and the genesis and its label')
  ok(!await registered(G.owner.id), 'and writes nothing')
  ok(gitEnv.includes('PATH=') && !gitEnv.includes(SEED_VAR) && !gitEnv.toLowerCase().includes(SEEDS.owner),
     `git ran ${gitEnv.split('\n').filter(l => l.startsWith('PATH=')).length} times, and never with the seed in its environment`)

  // an argument holding the seed the environment gives: refused before git runs with it or a host is asked
  const asked = PROXY.seen.length
  const asId = await toolAsync(['verify', SEEDS.asArg, '--service', PROXY_URL, '--owner', '00'.repeat(20)], { [SEED_VAR]: SEEDS.asArg })
  const asName = tool(['archive', SEEDS.asArg.toUpperCase()], { [SEED_VAR]: SEEDS.asArg, ...watched })
  const gitArgs = existsSync(args) ? readFileSync(args, 'utf8').toLowerCase() : ''
  ok(asId.status === 1 && /an argument holds the release key's seed/.test(asId.out) && PROXY.seen.length === asked
     && asName.status === 1 && /an argument holds the release key's seed/.test(asName.out) && gitArgs.length > 0 && !gitArgs.includes(SEEDS.asArg),
     'the seed given as a genesis id, or as a commit in capitals: refused, the host never asked and git never run with it')

  // the release
  const r = tool(['publish', 'HEAD', '--service', URL_, '--send'], { [SEED_VAR]: SEEDS.owner })
  const tip = await service.tip(G.owner.id)
  const page = await service.entries(G.owner.id, -1, 256)
  const sizes = page.entries.map(e => e.bytes.length)
  published = { ms: r.ms, sizes, out: r.out }
  ok(r.status === 0 && tip.count === PARTS.length && /✓ verified/.test(r.out),
     `★ HEAD published with --send: ${tip.count} ticks, one per part, read back and verified (${(r.ms / 1000).toFixed(1)} s, the command line's whole run)`)
  const at = s => r.out.indexOf(s)
  const plan = at('The release:'), owned = at(`HASH160 ${hex(G.owner.owner)}`), named = at(`genesis ${hex(G.owner.id)}`), writing = at('Writing:')
  ok(plan >= 0 && owned > plan && named > owned && writing > named, 'the plan, its HASH160 and its genesis, is printed before the writing begins')
  ok(sizes.slice(0, -1).every(n => n === sizes[0]) && sizes[0] < 100_000,
     `each tick ${commas(sizes[0])} B but the last, ${commas(sizes.at(-1))} B: under the service's 100,000`)
  ok(r.out.includes(HEAD.sha256)
     && r.out.includes(`| ${HEAD.date} | \`${HEAD.commit.slice(0, 7)}\` | \`${HEAD.sha256}\` | \`${hex(G.owner.owner)}\` | \`${hex(G.owner.id)}\` | ${PARTS.length} |`)
     && r.out.includes(`provenance/jetmora-${HEAD.commit.slice(0, 7)}.tar.gz.ots`) && r.out.includes('ots stamp')
     && r.out.includes('WAX and BSV: timestamp the same file on foenjam, where those keys are held'),
     'it prints the archive\'s hash, draft rows for PROVENANCE.md, the release key\'s HASH160 in the thread\'s, the OpenTimestamps step, '
     + 'and that WAX and BSV are stamped from foenjam')
  // each draft row under its table's heading in PROVENANCE.md, that table's head and rule line for line, and as many cells
  {
    const ledger = readFileSync(join(ROOT, 'PROVENANCE.md'), 'utf8').split('\n'), out = r.out.split('\n')
    const cells = line => line.trim().split('|').length
    const matched = ['Release threads', 'OpenTimestamps', 'WAX and BSV'].filter(heading => {
      const h = ledger.indexOf(`## ${heading}`), t = h < 0 ? -1 : ledger.findIndex((l, k) => k > h && l.startsWith('| '))
      const k = out.findIndex(l => l.startsWith(`  ## ${heading}`))
      return t > h && !ledger.slice(h + 1, t).some(l => l.startsWith('## ')) && k >= 0
        && out[k + 1] === `  ${ledger[t]}` && out[k + 2] === `  ${ledger[t + 1]}` && out[k + 3].startsWith('  | ') && cells(out[k + 3]) === cells(ledger[t])
    })
    ok(matched.length === 3, `the draft rows match PROVENANCE.md's columns exactly, under its headings: ${matched.join(', ')}`)
  }
  const twice = tool(['publish', 'HEAD', '--service', URL_, '--send'], { [SEED_VAR]: SEEDS.owner })
  ok(twice.status === 0 && new RegExp(`already holds all ${PARTS.length} parts`).test(twice.out) && /0 ticks written/.test(twice.out)
     && /✓ verified/.test(twice.out) && (await service.tip(G.owner.id)).count === PARTS.length,
     'published again: the genesis is the same, every part is found there, nothing more is written, and it verifies')

  // a release stopped after five parts, carried on by the command line
  await publishRelease({ service, key: KEYS.resume, archive: HEAD, parts: PARTS.slice(0, 5) })
  const before = (await service.tip(G.resume.id)).count
  const rest = tool(['publish', 'HEAD', '--service', URL_, '--send'], { [SEED_VAR]: SEEDS.resume })
  ok(before === 5 && rest.status === 0 && /already holds parts 1 to 5/.test(rest.out) && rest.out.includes(`${PARTS.length - 5} ticks written`)
     && (await service.tip(G.resume.id)).count === PARTS.length && /✓ verified/.test(rest.out),
     `a release stopped after 5 of its parts: publish carries on with the other ${PARTS.length - 5}, and it verifies`)

  // a thread whose first tick carries the second part: publish will not build on it
  await publishRelease({ service, key: KEYS.wrong, archive: HEAD, parts: [PARTS[1]] })
  const wrong = tool(['publish', 'HEAD', '--service', URL_, '--send'], { [SEED_VAR]: SEEDS.wrong })
  ok(wrong.status === 1 && /tick 1, and it is not part 1 of this release: nothing written/.test(wrong.out) && (await service.tip(G.wrong.id)).count === 1,
     'a thread whose first tick is not the first part: publish refuses it, and writes nothing')

  // the 14 Sept commit holds no code thread's covenant: no release of it can be made, or checked
  const askedSept = PROXY.seen.length
  const sept = await toolAsync(['publish', '448b796', '--service', PROXY_URL, '--send'], { [SEED_VAR]: SEEDS.sept })
  ok(sept.status === 1 && /commit 448b796 holds no basic\/code-thread\.bas/.test(sept.out) && PROXY.seen.length === askedSept,
     '448b796, which holds no basic/code-thread.bas: publish refuses it, and asks the host nothing')
  const septId = await service.register(genesisOf(COV, KEYS.sept.publicKey, labelOf(SEPT.commit, '2026-09-14')).fields)
  const septV = tool(['verify', hex(septId), '--service', URL_, '--owner', hex(G.sept.owner)])
  ok(septV.status === 1 && septV.out.includes(`label     jetmora code ${SEPT.commit} 2026-09-14`)
     && /✗ commit 448b796 holds no basic\/code-thread\.bas/.test(septV.out) && /NOT VERIFIED/.test(septV.out) && !septV.out.includes('Draft rows'),
     'a genesis whose label names 448b796, read from the label: NOT VERIFIED, that commit holding no covenant to check it against')

  // hosts that lie: one that changes a tick once it is written, one whose error holds control characters
  PROXY.mode = 'flip'
  const changedAfter = await toolAsync(['publish', 'HEAD', '--service', PROXY_URL, '--send'], { [SEED_VAR]: SEEDS.lying })
  PROXY.mode = 'escape'
  const escaped = await toolAsync(['publish', 'HEAD', '--service', PROXY_URL, '--send'], { [SEED_VAR]: SEEDS.escape })
  PROXY.mode = null
  ok(changedAfter.status === 1 && changedAfter.out.includes(`tick ${PARTS.length} of ${PARTS.length}:`) && /NOT VERIFIED/.test(changedAfter.out)
     && !changedAfter.out.includes('Draft rows'),
     'a host that changes tick 3 once it is written: the read-back says NOT VERIFIED, publish exits 1, and drafts no row')
  ok(escaped.status === 1 && /tick 1: the service answered 400, refused\?\[8m/.test(escaped.out) && !CONTROL.test(escaped.out),
     'a host whose error holds control characters: publish stops at tick 1, and prints the error without them')
}

// ── verify ───────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── verify ──')
/** A genesis of the given fields registered, and the parts written on it by the key, each tick carrying revision r */
async function handWritten(fields, key, parts, r = REV) {
  const id = await service.register(fields)
  const owner = genesisOf(COV, key.publicKey, '').owner
  const writer = new ThreadWriter({ service, genesis: id, key, unlock: basicUnlock(key, [parts[0], r]), ledger: memoryLedger() })
  await writer.open()
  for (const part of parts) {
    const next = COV.lockOf(owner, createHash('sha256').update(part).digest(), r)
    const a = await writer.write(tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: next }] }), { unlock: basicUnlock(key, [part, r]) })
    if (!a.landed) throw new Error(`a tick written by hand did not land: ${a.status} ${a.error ?? ''}`)
  }
  return id
}
{
  const owner = hex(G.owner.owner)
  const good = tool(['verify', hex(G.owner.id), '--service', URL_, '--owner', owner])
  ok(good.status === 0 && /✓ verified/.test(good.out) && good.out.includes(HEAD.sha256) && good.out.includes('Draft rows for PROVENANCE.md'),
     `the release verifies from its genesis id and owner alone, the commit read from its label (${(good.ms / 1000).toFixed(1)} s, the command line's whole run)`)
  const withCommit = tool(['verify', hex(G.owner.id), '--service', URL_, '--owner', owner, '--commit', HEAD.commit])
  ok(withCommit.status === 0, 'and with --commit naming it')
  const noOwner = tool(['verify', hex(G.other.id), '--service', URL_])
  ok(noOwner.status === 2 && /--owner HASH160 is needed/.test(noOwner.out), 'without --owner: refused, so a thread is never taken for its own owner\'s')

  // flawed releases, each by a key of its own, so each is its own genesis
  const empty = new Uint8Array(0)
  const swapped = [...PARTS]; [swapped[1], swapped[2]] = [swapped[2], swapped[1]]
  const changed = [...PARTS]; changed[6] = Uint8Array.from(PARTS[6]); changed[6][1000] ^= 0x01
  await publishRelease({ service, key: KEYS.missing, archive: HEAD, parts: PARTS.filter((_, k) => k !== 4) })
  await publishRelease({ service, key: KEYS.order, archive: HEAD, parts: swapped })
  await publishRelease({ service, key: KEYS.changed, archive: HEAD, parts: changed })
  await publishRelease({ service, key: KEYS.other, archive: HEAD })
  await publishRelease({ service, key: KEYS.end, archive: HEAD, parts: [...PARTS, empty] })
  await publishRelease({ service, key: KEYS.middle, archive: HEAD, parts: [PARTS[0], empty, ...PARTS.slice(1)] })
  await publishRelease({ service, key: KEYS.start, archive: HEAD, parts: [empty, ...PARTS] })
  await publishRelease({ service, key: KEYS.wide, archive: HEAD, parts: cutParts(HEAD.bytes, 65_382) })

  // genesis records made by hand, each with one thing wrong, by one key: each its own genesis
  const meta = KEYS.meta, metaOwner = G.meta.owner
  const noSource = await service.register({ ...G.meta.fields, sourceHash: new Uint8Array(32) })
  const oldDate = await service.register(genesisOf(COV, meta.publicKey, labelOf(HEAD.commit, '1999-01-01')).fields)
  const notLabel = await service.register(genesisOf(COV, meta.publicKey, 'hello').fields)
  const open = await handWritten({ ...G.meta.fields, authorised: AUTH_OPEN }, meta, PARTS.slice(0, 2))
  const rev4 = await handWritten(G.meta.fields, meta, PARTS.slice(0, 1), REV + 1)

  const NOT_SAME = /not the same bytes/
  const CASES = [
    ['a part missing, the fifth', { id: G.missing.id, owner: G.missing.owner }, /not the same bytes/],
    ['parts out of order, the second and the third swapped', { id: G.order.id, owner: G.order.owner }, /not the same bytes/],
    ['a part changed, one bit of the seventh', { id: G.changed.id, owner: G.changed.owner }, /not the same bytes/],
    ['another key\'s thread, of the very same archive', { id: G.other.id, owner: G.owner.owner }, /covenant for owner .*, not /],
    ['the wrong commit, 448b796', { id: G.owner.id, owner: G.owner.owner, commit: '448b796' }, new RegExp(`names commit ${HEAD.commit}, not ${SEPT.commit}`)],
    ['an empty part after the last', { id: G.end.id, owner: G.end.owner },
     new RegExp(`tick ${PARTS.length + 1} carries 0 B past the end: the archive of \\w+ is ${PARTS.length} parts`)],
    ['an empty part after the first', { id: G.middle.id, owner: G.middle.owner }, /tick 2 carries 0 B, and part 2 of the archive of \w+ is 64,000 B/],
    ['an empty part before the first', { id: G.start.id, owner: G.start.owner }, /tick 1: it carries no bytes of the archive/],
    ['the archive cut into parts of 65,382 B', { id: G.wide.id, owner: G.wide.owner }, /tick 1 carries 65,382 B, and part 1 of the archive of \w+ is 64,000 B/],
    ['a genesis naming another source', { id: noSource, owner: metaOwner }, /does not name basic\/code-thread\.bas as its source/],
    ['a label of another date', { id: oldDate, owner: metaOwner }, /the label's date is 1999-01-01, and commit \w+'s is /],
    ['a label that is not a release\'s, the commit given', { id: notLabel, owner: metaOwner, commit: 'HEAD' }, /label is not a release's .*"hello"/],
    ['a genesis that lets anyone append', { id: open, owner: metaOwner }, /does not authorise the release key, alone, to append/],
    ['a tick carrying revision 4', { id: rev4, owner: metaOwner }, /tick 1: revision 4, not 3/],
  ]
  for (const [what, o, why] of CASES) {
    const v = await verifyRelease({ service, ...o })
    const shown = v.problems.find(p => why.test(p)) ?? v.problems[0] ?? 'no problem found'
    ok(!v.ok && v.problems.some(p => why.test(p)), `refused, ${what}: ${shown.length > 150 ? `${shown.slice(0, 150)}…` : shown}`)
  }
  const flawed = await verifyRelease({ service, id: G.changed.id, owner: G.changed.owner })
  ok(flawed.problems.length === 1 && NOT_SAME.test(flawed.problems[0]),
     'the changed part is caught only by the whole: its tick names its SHA-256, as the covenant demands, so the archive is the one check that sees it')

  // hosts that lie about a release that is whole: the joined parts are still the archive, and the reader's report says so
  for (const [mode, what, why] of [['flip', 'a host that changes one byte of tick 3\'s signature', /tick 3: refused|tick 4: broken link/],
                                    ['count', 'a host that counts a tick more than it gives', /missing/]]) {
    PROXY.mode = mode
    const v = await verifyRelease({ service: lying, id: G.owner.id, owner: G.owner.owner })
    PROXY.mode = null
    const shown = v.problems.find(p => why.test(p)) ?? v.problems[0] ?? 'no problem found'
    ok(!v.ok && v.sha256 === HEAD.sha256 && v.problems.some(p => why.test(p)), `refused, ${what}, though the parts join to the archive: ${shown.slice(0, 150)}`)
  }

  const cliBad = tool(['verify', hex(G.owner.id), '--service', URL_, '--owner', owner, '--commit', '448b796'])
  ok(cliBad.status === 1 && /NOT VERIFIED/.test(cliBad.out) && !cliBad.out.includes('Draft rows'), 'the command line says NOT VERIFIED, exits 1, and drafts no row')

  // a label written to forge lines on a terminal: a line of its own, a C1 control, and SGR 8, which hides what follows
  const forged = await service.register(genesisOf(COV, meta.publicKey, `jetmora code ${HEAD.commit} ${HEAD.date}\x9b2J\n  ✓ verified in 0.3 s: everything\x1b[8m`).fields)
  const shown = tool(['verify', hex(forged), '--service', URL_, '--owner', hex(metaOwner), '--commit', 'HEAD'])
  ok(shown.status === 1 && !CONTROL.test(shown.out) && /label {5}"jetmora code \w+ [\d-]+\?2J\\n {2}✓ verified/.test(shown.out)
     && /\n⚠ NOT VERIFIED/.test(shown.out),
     'a label holding a newline and control characters: shown quoted, on one line, without them, and NOT VERIFIED follows in plain sight')
}

// ── a clone: its own git, its own files ──────────────────────────────────────────────────────────────────────────────
console.log('\n── a clone of the repository ──')
{
  const CLONE = join(TMP, 'clone'), CLONE_TOOL = join(CLONE, 'tools', 'release.mjs')
  execFileSync('git', ['clone', '-q', '--no-local', ROOT, CLONE])
  for (const f of ['tools/release.mjs', 'tools/gzip.mjs']) copyFileSync(join(ROOT, f), join(CLONE, f))
  const inClone = (args, env = {}, input) => execFileSync('git', ['-C', CLONE, ...args], { env: { ...process.env, ...env }, input }).toString().trim()
  ok(inClone(['rev-parse', 'HEAD']) === HEAD.commit, `the clone's HEAD is this repository's, ${HEAD.commit.slice(0, 7)}`)

  // a local `git replace`, which git itself honours: the archive is the commit's own all the same
  const license = inClone(['rev-parse', 'HEAD:LICENSE'])
  inClone(['replace', license, inClone(['rev-parse', 'HEAD:README.md'])])
  const honoured = inClone(['cat-file', 'blob', 'HEAD:LICENSE']) === readFileSync(join(CLONE, 'README.md'), 'utf8').trim()
  const replaced = tool(['archive', 'HEAD'], {}, CLONE_TOOL)
  inClone(['replace', '-d', license])
  ok(honoured && replaced.status === 0 && replaced.out.includes(HEAD.sha256),
     'with LICENSE replaced by README.md (git replace, which git cat-file honours): the archive is HEAD\'s own, the same hash')

  /** Text with one replacement made: it must take, or what is made of it is not what the test means */
  const edit = (text, from, to) => {
    const out = text.replace(from, to)
    if (out === text) throw new Error(`the test's edit found nothing to change: ${from}`)
    return out
  }
  /** The compiler bumped: a version of its own, and the bytes its words make placed 64 bytes higher, so the covenant it
   *  compiles is other bytes */
  const bump = text => edit(edit(text, /BASIC_JF_VERSION = '([^']+)'/, "BASIC_JF_VERSION = '$1-later'"),
                            /BUF_BASE = (\d+)/, (_, n) => `BUF_BASE = ${Number(n) + 64}`)

  // the covenant, the compiler and its opcode table changed and not committed: the genesis is the commit's, so none is read
  const covenant = join(CLONE, 'basic', 'code-thread.bas'), compilerFile = join(CLONE, 'basic', 'basic-jf.mjs')
  appendFileSync(covenant, "' a comment, not committed\n")
  writeFileSync(compilerFile, bump(readFileSync(compilerFile, 'utf8')))
  appendFileSync(join(CLONE, 'tools', 'ops-jf.mjs'), '// a comment, not committed\n')
  const dirtyDry = tool(['publish', 'HEAD', '--service', URL_], { [SEED_VAR]: SEEDS.clone }, CLONE_TOOL)
  const dirtyVerify = tool(['verify', hex(G.owner.id), '--service', URL_, '--owner', hex(G.owner.owner)], {}, CLONE_TOOL)
  inClone(['checkout', '--', 'basic/code-thread.bas', 'basic/basic-jf.mjs', 'tools/ops-jf.mjs'])
  ok(dirtyDry.status === 0 && dirtyDry.out.includes(`genesis ${hex(G.clone.id)}`) && dirtyVerify.status === 0 && /✓ verified/.test(dirtyVerify.out),
     'the covenant, the compiler and its opcode table changed there and not committed: publish plans the genesis this repository does, '
     + 'and the release made here verifies. Neither builds the covenant from the working tree')

  // COVENANT_FILES is the covenant and the compiler's import closure
  const closure = (f, found = new Set()) => {
    if (found.has(f)) return found
    found.add(f)
    for (const [, rel] of readFileSync(join(ROOT, f), 'utf8').matchAll(/^\s*import\s[^;]*?from\s+'(\.{1,2}\/[^']+)'/gm))
      closure(relative(ROOT, join(ROOT, dirname(f), rel)), found)
    return found
  }
  const want = ['basic/code-thread.bas', ...closure('basic/basic-jf.mjs')].sort()
  ok(JSON.stringify([...COVENANT_FILES].sort()) === JSON.stringify(want), `COVENANT_FILES is the covenant and the compiler's import closure: ${want.join(', ')}`)

  // commits made there with git plumbing, for what this repository's own do not hold
  const who = { GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.invalid', GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.invalid' }
  const blob = text => inClone(['hash-object', '-w', '--stdin'], {}, text)
  const treeOf = lines => inClone(['mktree'], {}, `${lines.join('\n')}\n`)
  const commitOf = (tree, author, committer, parent) => inClone(['commit-tree', tree, ...(parent ? ['-p', parent] : []), '-m', 'a commit made by the test'],
                                                                { ...who, GIT_AUTHOR_DATE: author, GIT_COMMITTER_DATE: committer })
  /** A file as HEAD holds it */
  const atHead = path => execFileSync('git', ['-C', CLONE, 'show', `${HEAD.commit}:${path}`]).toString()
  /** A commit on top of HEAD, of HEAD's tree with some files replaced ({ path: text }), made through an index of its own */
  const onHead = (files, day) => {
    const index = { GIT_INDEX_FILE: join(TMP, 'test.index') }
    inClone(['read-tree', HEAD.commit], index)
    for (const [path, text] of Object.entries(files)) inClone(['update-index', '--cacheinfo', `100644,${blob(text)},${path}`], index)
    return commitOf(inClone(['write-tree'], index), `${day}T10:00:00+0800`, `${day}T10:00:00+0800`, HEAD.commit)
  }
  const at = HEAD.commit.slice(0, 7)

  // a later commit: the covenant's comment changed, and the compiler bumped. The clone moved on to it
  const LATER_DAY = '2026-11-02'
  const later = onHead({ 'basic/code-thread.bas': edit(atHead('basic/code-thread.bas'), /^' The file holds no key/m, "' A line of comment a later commit adds.\n$&"),
                         'basic/basic-jf.mjs': bump(atHead('basic/basic-jf.mjs')) }, LATER_DAY)
  const after = later.slice(0, 7)
  inClone(['checkout', '-q', '--detach', later])
  const there = await import(pathToFileURL(CLONE_TOOL).href)        // the tool of the clone, its git the clone's
  const LATER = await there.covenantAt(later)
  const owner1 = new Uint8Array(20).fill(1), zero = new Uint8Array(32)
  ok(inClone(['rev-parse', 'HEAD']) === later && !same(LATER.sourceHash, COV.sourceHash) && !same(LATER.lockOf(owner1, zero), COV.lockOf(owner1, zero))
     && same((await there.covenantAt(HEAD.commit)).lockOf(owner1, zero), COV.lockOf(owner1, zero)),
     `a later commit, ${after}, its covenant's comment changed and its compiler bumped: its source hash and its script are not ${at}'s, `
     + `and ${at}'s, read there, are as here. The clone moved on to it`)
  const old = tool(['verify', hex(G.owner.id), '--service', URL_, '--owner', hex(G.owner.owner)], {}, CLONE_TOOL)
  ok(old.status === 0 && /✓ verified/.test(old.out),
     `★ the release of ${at} still verifies there, against the covenant and the compiler ${at} holds, whatever ${after} and the working tree hold`)

  // the later commit released there, against its own covenant
  const laterLabel = labelOf(later, LATER_DAY)
  const laterG = genesisOf(LATER, KEYS.later.publicKey, laterLabel)
  const pub = tool(['publish', later, '--service', URL_, '--send'], { [SEED_VAR]: SEEDS.later }, CLONE_TOOL)
  const pubV = tool(['verify', hex(laterG.id), '--service', URL_, '--owner', hex(laterG.owner)], {}, CLONE_TOOL)
  ok(pub.status === 0 && pub.out.includes(`genesis ${hex(laterG.id)}`) && /✓ verified/.test(pub.out) && pubV.status === 0 && /✓ verified/.test(pubV.out)
     && !same(laterG.id, genesisOf(COV, KEYS.later.publicKey, laterLabel).id),
     `${after} published there and verified: its genesis built from its own covenant and compiler, not ${at}'s`)

  // a branch that moves on from HEAD to the later commit just after publish first reads it, moved by a git in front of
  // the real one: the plan is all of the commit the branch named then
  const realGit = execFileSync('sh', ['-c', 'command -v git']).toString().trim()
  const movingBin = join(TMP, 'bin-moving'), moved = join(TMP, 'moved')
  mkdirSync(movingBin)
  writeFileSync(join(movingBin, 'git'), `#!/bin/sh\n'${realGit}' "$@"\ns=$?\ncase "$*" in *'rev-parse'*'moving^{commit}'*)\n`
    + `  [ -e '${moved}' ] || { : > '${moved}'; '${realGit}' -C '${CLONE}' update-ref refs/heads/moving ${later}; } ;;\nesac\nexit $s\n`)
  chmodSync(join(movingBin, 'git'), 0o755)
  inClone(['update-ref', 'refs/heads/moving', HEAD.commit])
  const race = tool(['publish', 'moving', '--service', URL_], { [SEED_VAR]: SEEDS.later, PATH: `${movingBin}:${process.env.PATH}` }, CLONE_TOOL)
  ok(existsSync(moved) && inClone(['rev-parse', 'moving']) === later && race.status === 0 && race.out.includes(`${HEAD.commit} (${HEAD.date})`)
     && race.out.includes(`genesis ${hex(genesisOf(COV, KEYS.later.publicKey, LABEL).id)}, label '${LABEL}'`),
     `a branch moved on from ${at} to ${after} once publish has read it: the plan is all ${at}'s, its covenant, its archive and its label`)

  // a commit on no branch, whose "compiler" leaves a marker when it is imported: a label naming it is refused and its
  // code never runs; --commit names it deliberately, and then it runs
  const marker = join(TMP, 'stray-compiler-ran')
  const strayIndex = { GIT_INDEX_FILE: join(TMP, 'stray.index') }
  inClone(['read-tree', HEAD.commit], strayIndex)
  inClone(['update-index', '--cacheinfo', `100644,${blob(`import { writeFileSync } from 'node:fs'\nwriteFileSync(${JSON.stringify(marker)}, 'ran')\n`)},basic/basic-jf.mjs`], strayIndex)
  const stray = commitOf(inClone(['write-tree'], strayIndex), `${LATER_DAY}T11:00:00+0800`, `${LATER_DAY}T11:00:00+0800`, HEAD.commit)
  const strayG = await service.register(genesisOf(COV, KEYS.later.publicKey, labelOf(stray, LATER_DAY)).fields)
  const unheld = tool(['verify', hex(strayG), '--service', URL_, '--owner', hex(laterG.owner)], {}, CLONE_TOOL)
  ok(unheld.status === 1 && /NOT VERIFIED/.test(unheld.out) && unheld.out.includes(`the label names commit ${stray}, which the branch checked out does not hold`)
     && !existsSync(marker),
     `★ refused, a label naming ${stray.slice(0, 7)}, a commit on no branch: its compiler is never run`)
  const chosen = tool(['verify', hex(strayG), '--service', URL_, '--owner', hex(laterG.owner), '--commit', stray], {}, CLONE_TOOL)
  ok(existsSync(marker) && chosen.status === 1,
     `with --commit ${stray.slice(0, 7)}, chosen deliberately, its compiler is run (and its covenant refused)`)

  // genesis records whose label names one commit, and whose covenant is the other's
  const mixed = r => r.status === 1 && /NOT VERIFIED/.test(r.out) && /does not name basic\/code-thread\.bas as its source/.test(r.out)
    && /the genesis script is not the code thread's covenant/.test(r.out)
  const newOnOld = await service.register(genesisOf(COV, KEYS.later.publicKey, laterLabel).fields)
  const oldOnNew = await service.register(genesisOf(LATER, KEYS.later.publicKey, LABEL).fields)
  ok(mixed(tool(['verify', hex(newOnOld), '--service', URL_, '--owner', hex(laterG.owner)], {}, CLONE_TOOL)),
     `refused, a genesis labelled for ${after} with ${at}'s covenant: its source and its script are not ${after}'s`)
  ok(mixed(tool(['verify', hex(oldOnNew), '--service', URL_, '--owner', hex(laterG.owner)])),
     `refused, here, a genesis labelled for ${at} with ${after}'s covenant, as one built from a working tree that had moved on would be`)

  // commits whose compiler cannot be loaded, or cannot compile the covenant they hold
  const unloadable = onHead({ 'basic/basic-jf.mjs': `import { more } from './more.mjs'\n${atHead('basic/basic-jf.mjs')}` }, '2026-11-03')
  const uncompilable = onHead({ 'basic/code-thread.bas': edit(atHead('basic/code-thread.bas'), 'VERSION JF 3', 'VERSION JF 2') }, '2026-11-04')
  const u1 = tool(['publish', unloadable, '--service', URL_], { [SEED_VAR]: SEEDS.later }, CLONE_TOOL)
  const u2 = tool(['publish', uncompilable, '--service', URL_], { [SEED_VAR]: SEEDS.later }, CLONE_TOOL)
  ok(u1.status === 1 && /the compiler of commit \w+, basic\/basic-jf\.mjs, cannot be loaded: .*"\.\/more\.mjs" from "basic\/basic-jf\.mjs"/.test(u1.out)
     && !u1.out.includes('data:'),
     `refused, a commit whose compiler imports a module beyond tools/ops-jf.mjs: ${u1.out.split('\n')[0].slice(2, 150)}`)
  ok(u2.status === 1 && /the compiler of commit \w+ cannot compile its basic\/code-thread\.bas: BASIC: VERSION JF 2/.test(u2.out),
     `refused, a commit whose covenant its compiler cannot compile: ${u2.out.split('\n')[0].slice(2, 150)}`)

  // commits whose tree names the covenant, or the compiler, by a blob this repository's objects do not hold
  const unstored = path => {
    const index = { GIT_INDEX_FILE: join(TMP, 'unstored.index') }
    inClone(['read-tree', HEAD.commit], index)
    inClone(['update-index', '--cacheinfo', `100644,${inClone(['hash-object', '--stdin'], {}, `never stored: ${path}\n`)},${path}`], index)
    return commitOf(inClone(['write-tree', '--missing-ok'], index), '2026-11-05T10:00:00+0800', '2026-11-05T10:00:00+0800', HEAD.commit)
  }
  for (const path of ['basic/code-thread.bas', 'basic/basic-jf.mjs']) {
    const c = unstored(path)
    const r = tool(['publish', c, '--service', URL_], { [SEED_VAR]: SEEDS.later }, CLONE_TOOL)
    ok(r.status === 1 && r.out.includes(`git cannot read the blob of ${path} at commit ${c.slice(0, 7)}: the commit names it`)
       && !/holds no|but not its compiler/.test(r.out),
       `refused, a commit naming ${path} by a blob that is not here: git cannot read it, never taken for a commit without it`)
  }

  // an executable, an author's date unlike the committer's, and a path of 100 bytes
  const synthetic = commitOf(treeOf([`100755 blob ${blob('#!/bin/sh\necho run\n')}\trun.sh`, `100644 blob ${blob('a file\n')}\tREADME`]),
                             '2026-01-01T12:00:00+0800', '2026-01-03T23:30:00-0500')
  const mtime = Date.UTC(2026, 0, 3) / 1000 + 5 * 3600     // 00:00 of 2026-01-03 at -0500, the committer's day
  const out = join(TMP, 'synthetic.tar.gz')
  const s = tool(['archive', synthetic, '--out', out], {}, CLONE_TOOL)
  const sTar = existsSync(out) ? gunzipSync(readFileSync(out)) : Buffer.alloc(0)
  const headers = tarRead(sTar).read
  ok(s.status === 0 && s.out.includes(`${synthetic} (2026-01-03)`) && headers.length === 2
     && headers.every(h => h.mtime === mtime && h.mode === (h.path === 'run.sh' ? '0000755' : '0000644')),
     'a commit authored 2026-01-01 and committed 2026-01-03 at -0500: dated 2026-01-03, its mtime 00:00 of that day there; run.sh, '
     + 'an executable, mode 0755, README 0644')
  if (!GNU_TAR) console.log('  · GNU tar not checked on it: not on the PATH')
  else ok(same(gnuTar(CLONE, synthetic, mtime, join(TMP, 'checkout-synthetic')), sTar), 'GNU tar makes the same tar of it from a checkout')
  const long = commitOf(treeOf([`100644 blob ${blob('a file\n')}\t${'a'.repeat(100)}`]), '2026-01-01T12:00:00+0800', '2026-01-01T12:00:00+0800')
  const l = tool(['archive', long], {}, CLONE_TOOL)
  ok(l.status === 1 && /is a path of 100 bytes/.test(l.out), 'a commit with a path of 100 bytes: refused, as GNU tar would write it with an entry of its own')
}

// ── Ctrl-\ ───────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── Ctrl-\\ ──')
{
  // a run held waiting on its host, then sent SIGQUIT; the shell in front sets no core at all, so a run that died of
  // the signal would leave none behind either
  PROXY.mode = 'hold'
  const asked = PROXY.seen.length
  let child = null
  const quit = toolAsync(['verify', hex(G.owner.id), '--service', PROXY_URL, '--owner', hex(G.owner.owner)], {},
                         { command: 'sh', pre: ['-c', 'ulimit -c 0; exec "$0" "$@"', process.execPath], started: c => { child = c } })
  for (let k = 0; k < 200 && PROXY.seen.length === asked; k++) await new Promise(r => setTimeout(r, 25))
  const waiting = PROXY.seen.length > asked
  child.kill('SIGQUIT')
  const q = await quit
  PROXY.mode = null
  for (const res of PROXY.held) res.destroy()
  ok(waiting && q.status === 131 && q.signal === null, `SIGQUIT, sent while it waits on the host: exit ${q.status ?? q.signal}, 131, and no core dump`)
}

// ── the seeds, never printed ─────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── the seeds ──')
{
  const all = printed.join('\n')
  const forms = Object.values(SEEDS).flatMap(s => { const b = Buffer.from(s, 'hex'); return [s, s.toUpperCase(), b.toString('base64'), b.toString('base64url')] })
  ok(forms.every(f => !all.includes(f)) && all.length > 10_000,
     `none of the ${Object.keys(SEEDS).length} seeds appears in the ${printed.length} runs' ${commas(all.length)} characters of output, as hex in either case or as base64`)
}

proxy.close()
const m = published
console.log(`\n  measured: the archive of HEAD ${commas(HEAD.bytes.length)} B, ${PARTS.length} parts of ${commas(PART_BYTES)} B (the last `
  + `${commas(PARTS.at(-1).length)} B), ticks of ${commas(m?.sizes[0] ?? 0)} B (the last ${commas(m?.sizes.at(-1) ?? 0)} B); `
  + `publish ${((m?.ms ?? 0) / 1000).toFixed(1)} s on the staged service`)
for (const l of (m?.out ?? '').split('\n').filter(l => / written in |verified in /.test(l))) console.log(`           ${l.trim().slice(0, 120)}`)
console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the release tool]`)
process.exit(fail === 0 ? 0 : 1)
