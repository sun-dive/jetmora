// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// The JavaScript writer and reader, end to end, against the thread service as .cpanel.yml deploys it.
//   node tools/verify-writer.mjs [--no-browser]
//
// The service is staged in a temp folder by running .cpanel.yml's thread-service lines, as server/verify-tip.php does,
// and served by php -S. Most threads are the BASIC covenant verify-tip.php compiles (basic/basic-jf.mjs): signed by the
// owner over HASH256(PREIMAGE), value + 1 with nSequence that number, the same script. Some are a signed lock, which
// takes any successor its owner signs, so a tick can carry what a post would. Keys are WebCrypto Ed25519 keys, as a
// page's are. Ticks are written by tools/thread-writer.mjs and read back by tools/thread-reader.mjs:
//   lands     ticks land (201) over JSON and packed in turn; read back, each linked and accepted, each verdict the PHP
//             judge's (tools/judge-run.php)
//   refused   a tick the script refuses is refused here with the PHP judge's reason, byte for byte, and never sent; an
//             nSequence not past the tip's is refused before the script runs; a step naming another version than the
//             lock declares is refused by the judge; then the tick the script accepts lands. A lock declaring JF 2: the
//             tick names JF 2, and gets no verdict. A lock that declares no version, the thread's or a tip's second
//             output's: no verdict, before anything is recorded or signed
//   stale     two writers on one tip: the second gets the service's 409 and the service's tip, and sends nothing more
//             until it has read the thread again
//   lost      an answer lost: the same bytes sent again, and the 409 recognised as that tick having landed. A send that
//             never left: another successor refused before it is signed, and resend() sends the recorded one
//   reload    a new writer on the same ledger, as a page reloaded: another successor is refused, and the same transition
//             signed in another push form sends the recorded bytes, never a second entry
//   tabs      two writers on one ledger, interleaved on one tip: one records the successor and waits in its unlock while
//             the other lands it; the first then sends nothing. And a refusal takes back no record but its own
//   rollback  the host restored to earlier copies of itself: the recorded successor's own bytes sent again; another
//             successor of a tip it ticked refused; after a reload, resend() puts the lost ticks back in order; a fork
//             another device made on the restored host, without this writer's newest tick, refused
//   putback   three ticks, the host cut back to the first: resend() sends the second and the third, their very bytes
//   cross     one key, two threads, one ledger: a host files one thread's tick under the other, after a pruned body. No
//             output gets two successors signed, and nothing is sent
//   forged    ticks put into the host's rows: one naming JF 2 on a lock that declares JF 3 (refused), and one spending a
//             lock that declares no version (no verdict). The writer extends neither
//   limits    a tick over the service's 100,000 bytes, and a genesis that needs two signatures: refused before anything
//             is recorded or signed; 100,000 bytes exactly lands
//   liars     a host whose pages stop short, repeat, give nothing, or never end: each a problem, never a loop
//   paging    260 ticks, read back in the service's pages of 256 and in pages of 7
//   reader    ticks put straight into the store, past the judge: a refusal, a lock that declares no version, two inputs, an
//             output that is not there, a broken link, an entry with no unlocking script, bytes that are not an entry, and a
//             tick after them. Each reported by position, nothing skipped, the verdicts PHP's; a writer will not extend it
//   pruned    bodies pruned by the store's retention: each a gap, by position and seq, its entry a 410; the writer that
//             wrote the tip extends the thread, and a writer with no tick of its own in it does not
//   genesis   a service that gives another script for a genesis is caught
//   pins      SERVICE_LIMITS and the reader's words held to server/append.php's source
//   layers    the cross-thread attack against copies with each of its two guards taken out: either one alone holds
//   mutants   the writer, the reader, the client and tick() altered in copies: each copy must fail a scenario above
//   page      what a page loads names nothing of node's
//   browser   ONE headless Chromium run, the page served by the same php -S as the service: it compiles the covenant,
//             registers a thread, writes with a WebCrypto key and the default ledger, which is IndexedDB there, loses a
//             send, is reloaded, and must then send the recorded successor and never another; a second store name on the
//             same database works, and so does a database made earlier without the ledger's object store. Then the same
//             page from a second origin: it registers and writes in JSON with no CORS preflight; how a packed append
//             fares from there is measured and shown. Each read back is held to the PHP judge
// One temp folder per run, removed however the run ends, with the server and the browser; what a run killed outright
// left behind is cleared by the next (tools/run-folder.mjs).
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync, rmSync, existsSync, openSync, closeSync } from 'node:fs'
import { createServer, connect } from 'node:net'
import { join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { compileCovenant } from '../basic/basic-jf.mjs'
import { sha256, sha256d } from './sha256.mjs'
import { ripemd160 } from './ripemd160.mjs'
import { tick, create, authorisedHashes, OTHER_VERSION } from './thread.mjs'
import { serializeEntry, varint } from './entry.mjs'
import { preimage } from './preimage.mjs'
import { versionBuild } from './dispatch.mjs'
import { JF_LIT, JF_WORD } from './ops-jf.mjs'
import { runFolder } from './run-folder.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..')
const BROWSER = !process.argv.includes('--no-browser')
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const same = (a, b) => a != null && b != null && a.length === b.length && a.every((x, i) => x === b[i])
const le64 = v => { const o = Buffer.alloc(8); o.writeBigUInt64LE(BigInt(v)); return o.toString('hex') }
const utf8 = s => new TextEncoder().encode(s)

// ── the run's temp folder, its server and its browser: gone however the run ends ──────────────────────────────────────
const RUN = runFolder('writer'), TMP = RUN.dir
const freePort = () => new Promise(res => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
const listening = port => new Promise(res => { const c = connect(port, '127.0.0.1', () => { c.end(); res(true) }); c.on('error', () => res(false)) })

// ── the docroot, staged as .cpanel.yml deploys it, and served ────────────────────────────────────────────────────────
console.log('── the thread service, staged as .cpanel.yml deploys it ──')
const HOME = join(TMP, 'home'), DOCROOT = join(HOME, 'jetmora.org'), DB = join(HOME, 'jetmora-data', 'log.db')
mkdirSync(HOME)
{
  // every deploy line that builds the thread service: what it copies into threads/, and the database folder beside it
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
const PORT = await freePort()
const LOG = join(TMP, 'server.log')
{
  const fd = openSync(LOG, 'a')
  RUN.start('php', ['-S', `127.0.0.1:${PORT}`, '-t', DOCROOT], { stdio: ['ignore', fd, fd] })
  closeSync(fd)
}
let up = false
for (let k = 0; k < 100 && !(up = await listening(PORT)); k++) await new Promise(r => setTimeout(r, 50))
const BASE = `http://127.0.0.1:${PORT}/threads/`
const info = up ? await (await fetch(`${BASE}?op=info`)).json().catch(() => null) : null
ok(up && info?.size === 0 && existsSync(DB), `php -S serves it on port ${PORT}: op=info answers, an empty store, its database in jetmora-data beside the docroot`)
if (!up) { console.log(`\n⚠  ${pass} passed, ${fail + 1} failed   [no service to write to]`); process.exit(1) }

// ── the modules: the real ones, and copies altered for the layers and the mutants ──────────────────────────────────────
const stripComments = text => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '')
/** The files a page loads, from these, by their static imports */
function importGraph(dir, starts) {
  const seen = new Set(), queue = [...starts]
  while (queue.length) {
    const f = queue.shift()
    if (seen.has(f)) continue
    seen.add(f)
    for (const m of stripComments(readFileSync(join(dir, f), 'utf8')).matchAll(/^\s*(?:import|export)\b[^'"]*?\bfrom\s*['"]\.\/([^'"]+)['"]/gm)) queue.push(m[1])
  }
  return [...seen]
}
const GRAPH = importGraph(HERE, ['thread-writer.mjs', 'thread-reader.mjs', 'thread-service.mjs'])
const load = async dir => {
  const mods = await Promise.all(['thread-writer.mjs', 'thread-reader.mjs', 'thread-service.mjs'].map(f => import(pathToFileURL(join(dir, f)).href)))
  return Object.assign({}, ...mods)
}
/** The modules, copied into a folder of the run with each [file, from, to] change made; null when a text is not found */
async function copyWith(name, changes) {
  const dir = join(TMP, name)
  mkdirSync(dir)
  for (const f of GRAPH) copyFileSync(join(HERE, f), join(dir, f))
  for (const [file, from, to] of changes) {
    const src = readFileSync(join(dir, file), 'utf8')
    if (!src.includes(from)) return null
    writeFileSync(join(dir, file), src.replace(from, to))
  }
  return load(dir)
}
const REAL = await load(HERE)
const SERVICE = new REAL.ThreadService(BASE)                   // the true service, for the test's own reads
const subtle = globalThis.crypto.subtle
const newKey = async () => REAL.ed25519Signer(await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']))
const OWNER = await newKey(), OTHER = await newKey()
const SRC = 'VERSION JF 3\nDIM owner$20'
const covenantFor = key => compileCovenant(SRC, { state: { owner: [...ripemd160(Uint8Array.from(sha256(key.publicKey)))] } }).bytes
const JF3 = versionBuild('JF', 3)
const W = JF_WORD, lit16 = n => [JF_LIT.LIT16, n & 0xff, n >> 8]
/** The lock's declaration, VER JF 3, which every lock starts with */
const DECLARATION = [W.VER, 3, 0, 0x4a, 0x46]
/** The signed lock: VER JF 3 <key> 1000 PREIMAGE 3000 HASH256 3000 32 ED25519-CHECKSIG. Any successor its owner signs is accepted */
const signedLock = key => Uint8Array.from([...DECLARATION, 32, ...key.publicKey, ...lit16(1000), W.PREIMAGE, ...lit16(3000), W.HASH256, ...lit16(3000),
                                           JF_LIT.LIT8, 32, W['ED25519-CHECKSIG']])
/** A lock that declares no version: the judge gives no verdict on a tick that spends it */
const UNDECLARED = Uint8Array.of(W['2DROP'], W.TRUE)
/** Its unlocking script: the owner's signature over HASH256(PREIMAGE), one direct push, 65 bytes */
const signedUnlock = key => { const u = async pre => Uint8Array.from([64, ...await key.sign(Uint8Array.from(sha256d(pre)))]); u.size = 65; return u }

/** The PHP judge, CovenantThread::judge, through tools/judge-run.php */
const judgePhp = cases => cases.length === 0 ? [] : JSON.parse(execFileSync('php', [join(HERE, 'judge-run.php'), 'judge'],
  { input: JSON.stringify(cases), maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'inherit'] }).toString())
/** A reader's verdict in judge-run.php's form */
const norm = v => v.noVerdict ? { noVerdict: v.noVerdict, message: v.message }
                : v.stack !== undefined ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.reasonBytes) }
/** Every tick the reader judged by its script, judged again by the PHP judge against the same output */
function phpAgrees(report) {
  const judged = report.ticks.filter(t => t.spent)
  const php = judgePhp(judged.map(t => ({ entry: hex(t.bytes), input: 0, lock: hex(t.spent.locking), value: le64(t.spent.value) })))
  return { judged: judged.length, differ: judged.filter((t, k) => JSON.stringify(norm(t.verdict)) !== JSON.stringify(php[k])) }
}

/** The store, through the staged service's own store.php, past the append rule: as a host with a fault would hold it */
const STORE_PHP = `[, $dir, $db, $op] = $argv; require "$dir/store.php"; $s = new ThreadStore($db);
$pdo = new PDO('sqlite:' . $db, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); $pdo->exec('PRAGMA busy_timeout=10000');
switch ($op) {
  case 'append':   $g = hex2bin($argv[4]); echo $s->append(hex2bin($argv[5]), $g, $s->tipHashOf($g)); break;
  case 'age':      $pdo->prepare('UPDATE entries SET ts = 1 WHERE genesis = ?')->execute([hex2bin($argv[4])]); break;
  case 'prune':    echo $s->pruneOlderThan(60); break;
  case 'snapshot': $pdo->exec('VACUUM INTO ' . $pdo->quote($argv[4])); break;
}`
const store = (op, ...a) => execFileSync('php', ['-r', STORE_PHP, '--', join(DOCROOT, 'threads'), DB, op, ...a]).toString()
/** The host copied, and restored from a copy: the database file replaced between two requests, as a restore from backup does */
let snaps = 0
const snapshot = tag => { const f = join(TMP, `copy-${++snaps}-${tag}.db`); store('snapshot', f); return f }
const restore = file => { copyFileSync(file, DB); for (const x of ['-wal', '-shm']) rmSync(DB + x, { force: true }) }

/** A thread, its owner the key given, registered through the client (which checks the id) */
let nth = 0
async function thread(name, key = OWNER, { script = covenantFor(key), authorised = authorisedHashes([key.publicKey]) } = {}) {
  const fields = { sourceHash: sha256(utf8(SRC)), script, state: utf8(`${name} ${++nth}`), authorised }
  const id = await SERVICE.register(fields)
  return { id, script, fields }
}
/** The steps: the next tick by the covenant's rules, and one that skips a value. bump(v) for the signed lock */
const counter = tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: tip.outputs[0].locking }], sequence: Number(tip.outputs[0].value) + 1 })
const skip = tip => ({ outputs: [{ value: tip.outputs[0].value + 2n, locking: tip.outputs[0].locking }], sequence: Number(tip.outputs[0].value) + 2 })
const bump = v => tip => ({ outputs: [{ value: tip.outputs[0].value + BigInt(v), locking: tip.outputs[0].locking }] })
/** The same unlocking script with the signature in the STR8 push form: other bytes, and as valid */
const str8Unlock = key => async pre => Uint8Array.from([JF_LIT.STR8, 64, ...await key.sign(Uint8Array.from(sha256d(pre))), 32, ...key.publicKey])

/** A fetch that counts the appends that reach the service, and can drop one before it leaves or lose its answer */
function tap() {
  const t = { requests: [], drop: 0, lose: 0, genesisLie: null }
  t.fetch = async (url, init = {}) => {
    const op = new URL(url).searchParams.get('op')
    if (op === 'append' && t.drop > 0) { t.drop--; t.requests.push({ op, dropped: true }); throw new TypeError('the network failed before the request left') }
    const res = await fetch(url, init)
    t.requests.push({ op, status: res.status })
    if (op === 'append' && t.lose > 0) { t.lose--; await res.arrayBuffer(); throw new TypeError('the answer was lost') }
    if (op === 'genesis' && t.genesisLie) return new Response(JSON.stringify(t.genesisLie(await res.json())), { status: res.status, headers: { 'Content-Type': 'application/json' } })
    return res
  }
  t.appends = () => t.requests.filter(x => x.op === 'append' && !x.dropped).length
  return t
}
const writerOf = (M, T, { ledger = M.memoryLedger(), key = OWNER, unlock = M.basicUnlock(key), packed = false } = {}) => {
  const t = tap(), service = new M.ThreadService(BASE, { fetch: t.fetch, packed })
  return { w: new M.ThreadWriter({ service, genesis: T.id, key, unlock, ledger }), t, service, ledger }
}
const thrown = async f => { try { await f(); return null } catch (e) { return e } }
/** e is an instance of C, and false (never a TypeError) when a module has no such class */
const is = (e, C) => typeof C === 'function' && e instanceof C
const settle = async f => { try { return { value: await f() } } catch (e) { return { error: e } } }

/** Every preimage an unlock was asked to sign, by the output it spends: the outpoint, bytes 68 to 104 of a preimage */
function signings() {
  const by = new Map()
  let count = 0
  return {
    unlock(key, base = REAL.basicUnlock(key)) {
      const u = async (pre, tip) => {
        count++
        const out = hex(pre.subarray(68, 104))
        if (!by.has(out)) by.set(out, new Set())
        by.get(out).add(hex(sha256d(pre)))
        return base(pre, tip)
      }
      u.size = base.size
      return u
    },
    twice: () => [...by.values()].filter(s => s.size > 1).length,
    count: () => count,
  }
}
/** A gate an unlock waits at: `entered` when one gets there, and on through it once the test releases it */
function gate() {
  const g = {}
  g.entered = new Promise(r => { g.arrive = r })
  g.opened = new Promise(r => { g.release = r })
  g.unlock = base => async (pre, tip) => { g.arrive(); await g.opened; return base(pre, tip) }
  return g
}
/** A host that answers from rows it is given, as a lying or broken one would: the true genesis, the rest its own */
function hostOf(rows, change = {}) {
  const h = { appends: 0, pages: 0 }
  const last = () => rows.at(-1)?.seq ?? null
  return Object.assign(h, {
    genesis: id => SERVICE.genesis(id),
    tip: async () => ({ seq: last(), count: rows.length }),
    entries: async (id, after = -1, limit = 256) => {
      if (++h.pages > 60) throw new Error('sixty pages asked for: the reader loops')
      const page = rows.filter(r => r.seq > after).slice(0, Math.min(limit, 256))
      return { entries: page, tip: last(), more: page.length > 0 && page.at(-1).seq < last() }
    },
    entry: async seq => { const r = rows.find(x => x.seq === seq); return r === undefined ? null : r.bytes.length ? { seq, bytes: r.bytes } : { seq, pruned: true } },
    append: async () => { h.appends++; return { status: 201, seq: 1e9 + h.appends } },
  }, change)
}

/**
 * The cross-thread attack of 26 Oct. One key owns threads X and Y, both the signed lock, and one ledger serves both
 * writers, as one page's would. Y ticks three times, its third tick spending its second's output. Then a host shows Y's
 * second tick as X's tip, after a pruned body, and X's writer is asked for another successor of it.
 */
async function crossAttack(M) {
  const S = signedLock(OWNER)
  const X = await thread('cross X', OWNER, { script: S }), Y = await thread('cross Y', OWNER, { script: S })
  const ledger = M.memoryLedger(), seen = signings()
  const y = writerOf(M, Y, { ledger, unlock: seen.unlock(OWNER, signedUnlock(OWNER)) })
  const ys = []
  for (let k = 0; k < 3; k++) ys.push(await y.w.write(bump(1)))
  const s1 = ys[1]
  const host = hostOf([{ seq: s1.seq - 1, bytes: new Uint8Array(0) }, { seq: s1.seq, bytes: s1.bytes }])
  const x = new M.ThreadWriter({ service: host, genesis: X.id, key: OWNER, unlock: seen.unlock(OWNER, signedUnlock(OWNER)), ledger })
  const e = await thrown(() => x.write(bump(5)))
  return { e, ys: ys.map(r => r.status), twice: seen.twice(), appends: host.appends }
}

// ── the scenarios. Each takes the modules (the real ones, or a mutant's) and an ok() to report to ───────────────────
const SCENARIOS = {
  async lands(M, c) {
    const T = await thread('lands')
    c.ok(same(T.id, create(T.fields.sourceHash, T.fields.script, T.fields.state, T.fields.authorised).id),
         'a thread registered: the id the service answers is the id tools/thread.mjs create() derives')
    const { w, service } = writerOf(M, T)
    const st = []
    for (let k = 0; k < 6; k++) { service.packed = k % 2 === 1; st.push((await w.write(counter)).status) }
    c.ok(st.every(s => s === 201), `six ticks written, over JSON and packed in turn, each lands: ${st.join(' ')}`)
    const tip = await SERVICE.tip(T.id), body = (await SERVICE.entry(tip.seq))?.bytes
    c.ok(tip.count === 6 && same(sha256d(body), w.tip.hash), 'the service holds six, and its tip is the one the writer stands on')
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(rep.count === 6 && rep.complete && rep.ticks.every(x => x.link === true && x.verdict?.accepted === true),
         'read back: six ticks, each linked to the one before and accepted by the output it spends; no gap, no problem')
    c.ok(same(rep.tip.hash, w.tip.hash) && rep.tip.index === 6 && rep.tip.outputs?.[0].value === 6n && rep.tip.checked,
         'the reader\'s tip is the writer\'s: tick index 6, its output\'s value 6')
    const { judged, differ } = phpAgrees(rep)
    c.ok(judged === 6 && differ.length === 0, `each verdict is CovenantThread::judge's (${judged - differ.length}/${judged})`)
  },

  async refused(M, c) {
    const T = await thread('refused')
    const { w, t } = writerOf(M, T)
    const r1 = await w.write(counter)
    const sent = t.appends()
    const e1 = await thrown(() => w.write(skip))
    c.ok(e1 instanceof M.TickRefused && t.appends() === sent, `a tick skipping a value is refused here, and not sent: ${e1?.message}`)
    if (e1 instanceof M.TickRefused) {
      const [p] = judgePhp([{ entry: hex(e1.tick.bytes), input: 0, lock: hex(T.script), value: le64(1) }])
      c.ok(p.accepted === false && p.error === hex(e1.reasonBytes), `its reason is the PHP judge's, byte for byte: "${Buffer.from(e1.reasonBytes).toString('latin1')}"`)
    }
    const e2 = await thrown(() => w.write(counter, { unlock: M.basicUnlock(OTHER) }))
    c.ok(e2 instanceof M.TickRefused && t.appends() === sent, `signed for the covenant by somebody else: refused here, and not sent (${e2?.reason})`)
    let unlocked = 0
    const e3 = await thrown(() => w.write(tip => ({ ...counter(tip), sequence: tip.index }), { unlock: async pre => { unlocked++; return M.basicUnlock(OWNER)(pre) } }))
    c.ok(e3?.constructor === M.WriterError && /tick index/.test(e3.message) && unlocked === 0 && t.appends() === sent,
         `an nSequence that is not past the tip's: refused before anything is signed or run (${e3?.constructor.name}: ${e3?.message})`)
    // a step that names its own version keeps it: JF 2, on a lock that declares JF 3, is the judge's to refuse
    const ev = await thrown(() => w.write(tip => ({ ...counter(tip), version: versionBuild('JF', 2) })))
    c.ok(ev instanceof M.TickRefused && hex(ev.reasonBytes ?? []) === hex(utf8(OTHER_VERSION)) && t.appends() === sent && await w.pending() === null,
         `a step naming JF 2 on a lock that declares JF 3: refused here, its record taken back, and not sent (${ev?.reason})`)
    c.ok((await SERVICE.tip(T.id)).count === 1, 'the service still holds one tick')
    const r2 = await w.write(counter)
    c.ok(r1.status === 201 && r2.status === 201, `then the tick the script accepts lands: a refused tick is no successor, so its record was taken back (${r2.status})`)
    // a thread whose lock declares no version: the tick would name none, so nothing is recorded or signed
    const seen = signings(), N = await thread('undeclared', OWNER, { script: UNDECLARED })
    const n = writerOf(M, N, { unlock: seen.unlock(OWNER, signedUnlock(OWNER)) })
    const e4 = await thrown(() => n.w.write(bump(1)))
    c.ok(e4 instanceof M.NoVerdict && seen.count() === 0 && n.t.appends() === 0 && await n.w.pending() === null,
         `a thread whose lock declares no version: no verdict, nothing recorded, signed or sent (${e4?.message})`)
    // a lock that declares JF 2: the tick names JF 2, as the preimage's first four bytes show, and gets no verdict
    const pres = [], J2 = await thread('declares JF 2', OWNER, { script: Uint8Array.from([W.VER, 2, 0, 0x4a, 0x46, W['2DROP'], W.TRUE]) })
    const j2 = writerOf(M, J2, { unlock: async pre => { pres.push(pre); return Uint8Array.of(1, 1) } })
    const e5 = await thrown(() => j2.w.write(bump(1)))
    c.ok(e5 instanceof M.NoVerdict && pres.length === 1 && hex(pres[0].subarray(0, 4)) === '02004a46' && j2.t.appends() === 0 && await j2.w.pending() === null,
         `a thread whose lock declares JF 2: the tick names JF 2 (its preimage opens ${pres.length ? hex(pres[0].subarray(0, 4)) : 'nowhere'}), `
         + `and gets no verdict here, so its record is taken back and nothing is sent (${e5?.message})`)
    // the lock read is the spent output's: output 1 of a tip, which declares nothing where output 0 declares JF 3
    const S = signedLock(OWNER), seen2 = signings(), X = await thread('two outputs', OWNER, { script: S })
    const x = writerOf(M, X, { unlock: seen2.unlock(OWNER, signedUnlock(OWNER)) })
    const rx = await x.w.write({ outputs: [{ value: 1n, locking: S }, { value: 1n, locking: UNDECLARED }] })
    const signed = seen2.count()
    const e6 = await thrown(() => x.w.write({ index: 1, outputs: [{ value: 2n, locking: S }] }))
    c.ok(rx.status === 201 && e6 instanceof M.NoVerdict && seen2.count() === signed && x.t.appends() === 1 && await x.w.pending() === null,
         `output 1 of a tip, its lock declaring no version where output 0's declares JF 3: no verdict, nothing recorded, signed or sent (${e6?.message})`)
  },

  async stale(M, c) {
    const T = await thread('stale')
    const A = writerOf(M, T), B = writerOf(M, T, { unlock: str8Unlock(OWNER) })
    await A.w.open(); await B.w.open()
    const ra = await A.w.write(counter), rb = await B.w.write(counter)
    c.ok(ra.status === 201 && rb.status === 409, `two writers on one tip: the first lands (${ra.status}), the second is rejected as spent (${rb.status} ${rb.error})`)
    c.ok(rb.landed === false && same(rb.serviceTip?.hash, ra.hash) && rb.serviceTip?.count === 1,
         'the 409 is reported with the service\'s tip, fetched: the first writer\'s tick')
    c.ok(B.t.appends() === 1 && B.w.tip === null, 'the second writer sent that one tick and nothing more, and stands on no tip')
    const rb2 = await B.w.write(counter)
    c.ok(rb2.status === 201 && B.t.appends() === 2 && rb2.tip?.position === 2,
         `asked again, it reads the thread and ticks on from the first writer's tick (${rb2.status})`)
  },

  async lost(M, c) {
    const T = await thread('lost')
    const { w, t } = writerOf(M, T)
    await w.write(counter)
    t.lose = 1
    const r = await w.write(counter)
    c.ok(r.status === 0, `the answer to the second tick is lost: status ${r.status}, so whether it landed is not known`)
    const r2 = await w.write(counter)
    c.ok(r2.status === 409 && r2.landed === true && same(r2.hash, r.hash) && same(w.tip?.hash, r.hash),
         'written again: the same bytes sent, and the 409 recognised as that very tick having landed')
    const r3 = await w.write(counter)
    c.ok(r3.status === 201 && r3.tip?.index === 3, `the thread ticks on from it (${r3.status})`)
    t.drop = 1
    const r4 = await w.write(counter)
    const sent = t.appends()
    const e = await thrown(() => w.write(skip))
    c.ok(r4.status === 0 && e instanceof M.TipAlreadyAdvanced && t.appends() === sent,
         `a send that never left; another successor of that tip is then refused before it is signed (${e?.constructor.name})`)
    const p = await w.pending(), r5 = await w.resend()
    c.ok(same(p?.hash, r4.hash) && r5?.status === 201 && same(r5.hash, r4.hash), 'resend() sends the recorded successor, its very bytes, and it lands')
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(rep.count === 4 && rep.complete, 'read back: four ticks, all good')
  },

  async reload(M, c) {
    const T = await thread('reload')
    const ledger = M.memoryLedger()                            // the page's storage, which a reload keeps
    const one = writerOf(M, T, { ledger })
    await one.w.write(counter)
    one.t.drop = 1
    const r = await one.w.write(counter)
    const two = writerOf(M, T, { ledger })                     // the page, reloaded
    const { tip } = await two.w.open()
    c.ok(r.status === 0 && tip.position === 1, 'a tick signed and recorded, its send failed; the page reloads, and the service\'s tip is still the first tick')
    const e = await thrown(() => two.w.write(skip))
    c.ok(e instanceof M.TipAlreadyAdvanced && two.t.appends() === 0, `another successor of that tip: refused by the ledger, nothing sent (${e?.constructor.name})`)
    const r2 = await two.w.write(counter, { unlock: str8Unlock(OWNER) })
    c.ok(r2.status === 201 && same(r2.hash, r.hash),
         `the same transition, its signature in another push form: the recorded bytes are what lands, never a second entry (${r2.status})`)
  },

  async tabs(M, c) {
    const T = await thread('tabs')
    const ledger = M.memoryLedger()
    // one tab records the first tick's successor and waits in its unlock; the other, on the same ledger, signs the same
    // transition in another push form, records its bytes and sends them
    const g = gate()
    const A = writerOf(M, T, { ledger, unlock: g.unlock(M.basicUnlock(OWNER)) }), B = writerOf(M, T, { ledger, unlock: str8Unlock(OWNER) })
    await A.w.open(); await B.w.open()
    const pa = thrown(() => A.w.write(counter))
    await g.entered
    const rb = await B.w.write(counter)
    g.release()
    const ea = await pa
    const tip = await SERVICE.tip(T.id)
    c.ok(rb.status === 201 && ea instanceof M.TipAlreadyAdvanced && A.t.appends() === 0 && B.t.appends() === 1 && tip.count === 1,
         `two tabs on one tip: the second lands the successor the first recorded (${rb.status}); the first, out of its unlock, finds other bytes recorded and sends nothing (${ea?.constructor.name})`)
    // a refusal takes back only its own record: a tab records, waits, and then gives a signature by another key, while
    // the other tab lands the same successor meanwhile
    const h = gate()
    const C = writerOf(M, T, { ledger, unlock: h.unlock(M.basicUnlock(OTHER)) }), D = writerOf(M, T, { ledger })
    await C.w.open(); await D.w.open()
    const pc = thrown(() => C.w.write(counter))
    await h.entered
    const rd = await D.w.write(counter)
    h.release()
    const ec = await pc
    const e2 = await thrown(() => C.w.write(skip))
    c.ok(rd.status === 201 && ec instanceof M.TickRefused && e2 instanceof M.TipAlreadyAdvanced && C.t.appends() === 0,
         `the refused tab takes back no record that is not its own: another successor of that tip is still refused (${ec?.constructor.name}, then ${e2?.constructor.name})`)
  },

  async rollback(M, c) {
    const T = await thread('rollback')
    const ledger = M.memoryLedger()
    const A = writerOf(M, T, { ledger })
    const r = []
    for (let k = 0; k < 3; k++) r.push(await A.w.write(counter))
    const at3 = snapshot('at3')
    r.push(await A.w.write(counter))
    const at4 = snapshot('at4')
    r.push(await A.w.write(counter))
    c.ok(r.every(x => x.status === 201), 'five ticks, the host copied after the third and after the fourth')

    restore(at4)
    const A2 = writerOf(M, T, { ledger })                      // the page reloads, its ledger kept
    const r5 = await A2.w.write(counter, { unlock: str8Unlock(OWNER) })
    c.ok(r5.status === 201 && same(r5.hash, r[4].hash),
         'the host restored to the fourth tick: asked for its successor again, the writer sends the fifth tick\'s own bytes')
    restore(at3)
    const r6 = await A2.w.write(counter, { unlock: str8Unlock(OWNER) })
    c.ok(r6.status === 409 && !r6.landed && same(r6.serviceTip?.hash, r[2].hash),
         'the host restored to the third: the sixth tick is rejected as spent, and the service\'s tip is the third')
    const n = A2.t.appends()
    const e = await thrown(() => A2.w.write(skip))
    c.ok(e instanceof M.TipAlreadyAdvanced && A2.t.appends() === n, `another successor of the third, which this writer ticked: refused, nothing signed or sent (${e?.constructor.name})`)
    const A3 = writerOf(M, T, { ledger })
    const back = await A3.w.resend()
    c.ok(back?.answers?.map(x => x.status).join(' ') === '201 201 201' && [r[3], r[4], r6].every((x, k) => same(back.answers[k].hash, x.hash)),
         `after a reload, resend() puts the thread back: the fourth, fifth and sixth ticks, in order, their very bytes (${back?.answers?.map(x => x.status).join(' ')})`)
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(rep.count === 6 && rep.complete && same(rep.tip.hash, r6.hash), 'read back: six ticks, whole')
    // a fork the host shows: restored to the third again, and another device, with no record of its own, ticks the third on
    restore(at3)
    const B = writerOf(M, T, { unlock: str8Unlock(OWNER) })
    const b4 = await B.w.write(counter), b5 = await B.w.write(counter)
    const A4 = writerOf(M, T, { ledger })
    const e3 = await thrown(() => A4.w.write(counter))
    c.ok(b4.status === 201 && b5.status === 201 && !same(b4.hash, r[3].hash) && e3 instanceof M.TipRolledBack && A4.t.appends() === 0,
         `another device ticks the restored third on to a fifth of its own: this writer's newest tick is not in that thread, so it is refused (${e3?.constructor.name})`)
  },

  async putback(M, c) {
    const T = await thread('put back')
    const ledger = M.memoryLedger()
    const A = writerOf(M, T, { ledger })
    const r1 = await A.w.write(counter)
    const at1 = snapshot('at1')
    const r2 = await A.w.write(counter), r3 = await A.w.write(counter)
    restore(at1)
    const B = writerOf(M, T, { ledger })                       // the owner's page, reloaded
    const e = await thrown(() => B.w.write(skip))
    c.ok([r1, r2, r3].every(x => x.status === 201) && e instanceof M.TipAlreadyAdvanced && B.t.appends() === 0,
         `three ticks, the host cut back to the first: another successor of it is refused (${e?.constructor.name})`)
    const p = await B.w.pending()
    c.ok(same(p?.hash, r2.hash) && same(p?.bytes, r2.bytes), 'pending() names the second tick, its bytes kept on the device')
    const back = await B.w.resend()
    c.ok(back?.answers?.map(x => x.status).join(' ') === '201 201' && same(back.answers[0].hash, r2.hash) && same(back.answers[1].hash, r3.hash),
         `resend() walks them in order: the second and the third, their very bytes (${back?.answers?.map(x => x.status).join(' ') ?? back})`)
    const rep = await M.readThread(SERVICE, T.id)
    const r4 = await B.w.write(counter)
    c.ok(rep.count === 3 && rep.complete && same(rep.tip.hash, r3.hash) && r4.status === 201 && r4.tip?.index === 4,
         'the thread is back, three ticks whole, and ticks on from the third')
  },

  async cross(M, c) {
    const r = await crossAttack(M)
    c.ok(r.ys.every(s => s === 201), `thread Y: three ticks, the third spending the second's output (${r.ys.join(' ')})`)
    c.ok(r.twice === 0 && r.appends === 0,
         `a host shows Y's second tick as thread X's tip, after a pruned body: no output gets two successors signed, and nothing is sent (${r.twice} signed twice, ${r.appends} sent)`)
    c.ok(r.e instanceof M.ThreadBroken && r.e.problem?.kind === 'pruned' && r.e.problem.position === 1,
         `X's writer does not stand on that tip: ${r.e?.message}`)
  },

  async forged(M, c) {
    const T = await thread('forged')
    const ledger = M.memoryLedger(), seen = signings()
    const one = writerOf(M, T, { ledger })
    const t1 = await one.w.write(counter), t2 = await one.w.write(counter)
    // the host puts a tick into its rows: nVersion JF 2, spending the second tick's output, whose lock declares JF 3, no signature
    const forged = { version: versionBuild('JF', 2), locktime: 0, outputs: [{ value: 1000000n, locking: T.script }],
                     inputs: [{ prevEntry: t2.hash, index: 0, unlocking: Uint8Array.of(1, 0x66), sequence: 50 }] }
    store('append', hex(T.id), hex(Uint8Array.from(serializeEntry(forged))))
    const two = writerOf(M, T, { ledger, unlock: seen.unlock(OWNER) })      // the page, reloaded
    const e = await thrown(() => two.w.write(counter))
    c.ok(t1.status === 201 && t2.status === 201 && e instanceof M.ThreadBroken && e.problem?.kind === 'refused' && e.problem.position === 3
         && two.t.appends() === 0 && seen.count() === 0,
         `a forged tick naming JF 2 after this writer's own, on a lock that declares JF 3: refused, and the writer does not stand on it, nothing signed or sent: ${e?.message}`)
    // a forged tick nothing has a verdict on: it spends an output of this writer's own tick whose lock declares no version
    const S = signedLock(OWNER), U = await thread('forged, no verdict', OWNER, { script: S })
    const w1 = writerOf(M, U, { ledger, unlock: signedUnlock(OWNER) })
    const u1 = await w1.w.write(tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: S }, { value: 1n, locking: UNDECLARED }] }))
    const loose = { version: JF3, locktime: 0, outputs: [{ value: 7n, locking: S }],
                    inputs: [{ prevEntry: u1.hash, index: 1, unlocking: Uint8Array.of(1, 0x66), sequence: 2 }] }
    store('append', hex(U.id), hex(Uint8Array.from(serializeEntry(loose))))
    const w2 = writerOf(M, U, { ledger, unlock: seen.unlock(OWNER, signedUnlock(OWNER)) })   // the page, reloaded
    const e2 = await thrown(() => w2.w.write(bump(1)))
    c.ok(u1.status === 201 && e2 instanceof M.ThreadBroken && e2.problem?.kind === 'no verdict' && e2.problem.position === 2
         && w2.t.appends() === 0 && seen.count() === 0,
         `a forged tick spending an output of this writer's own whose lock declares no version: no verdict, and the writer does not stand on it, nothing signed or sent: ${e2?.message}`)
  },

  async limits(M, c) {
    const S = signedLock(OWNER), seen = signings()
    const T = await thread('limits', OWNER, { script: S })
    const unlock = seen.unlock(OWNER, signedUnlock(OWNER))
    const { w, t } = writerOf(M, T, { unlock })
    await w.write(bump(1))
    const post = n => tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: S }, { value: 1n, locking: new Uint8Array(n).fill(0x6a) }] })
    // a post's size from bytes actually built, its unlocking script the signed lock's 65 bytes
    const sizeOf = async n => (await tick(new Uint8Array(32), 0, S, 1n, post(n)({ outputs: [{ value: 1n, locking: S }] }).outputs, 2, () => new Uint8Array(65))).bytes.length
    const exact = 70000 + 100000 - await sizeOf(70000)
    let sent = t.appends(), signed = seen.count()
    const e1 = await thrown(() => w.write(post(120000)))
    c.ok(is(e1, M.ServiceLimit) && e1.limit === 'entryBytes' && t.appends() === sent && seen.count() === signed && await w.pending() === null,
         `a post with a payload of 120,000 bytes: refused, nothing recorded, signed or sent: ${e1?.message ?? `${t.appends() - sent} sent`}`)
    const r1 = await settle(() => w.write(post(1000)))
    c.ok(r1.value?.status === 201, `the same post made smaller lands: nothing stood in its way (${r1.value?.status ?? r1.error?.constructor.name})`)
    signed = seen.count()
    const e2 = await thrown(() => w.write(post(exact + 1)))
    c.ok(is(e2, M.ServiceLimit) && seen.count() === signed, `100,001 bytes, from an unlock whose size is known: refused before it is signed (${e2?.constructor.name})`)
    const r2 = await w.write(post(exact))
    c.ok(r2.status === 201 && r2.bytes.length === 100000, `exactly 100,000 bytes lands (${r2.status}, ${r2.bytes?.length} bytes)`)
    // an unlock that says no size: refused once its unlocking script is known, and its record taken back
    sent = t.appends()
    const e3 = await thrown(() => w.write(post(exact + 1), { unlock: async pre => unlock(pre) }))
    const r3 = await w.write(post(exact))
    c.ok(is(e3, M.ServiceLimit) && t.appends() === sent + 1 && r3.status === 201,
         `100,001 bytes from an unlock that gives no size: refused once its unlocking script is known, never sent, and the tip still free (${r3.status})`)
    // a genesis that needs two of its keys to sign
    const K = await thread('two of two', OWNER, { authorised: authorisedHashes([OWNER.publicKey, OTHER.publicKey], 2) })
    const k = writerOf(M, K, { unlock: seen.unlock(OWNER) })
    signed = seen.count()
    const e4 = await thrown(() => k.w.write(counter))
    c.ok(is(e4, M.ServiceLimit) && e4.limit === 'signatures' && k.t.appends() === 0 && seen.count() === signed && await k.w.pending() === null,
         `a genesis whose set needs 2 signatures: refused, nothing recorded, signed or sent: ${e4?.message}`)
  },

  async liars(M, c) {
    const T = await thread('liars')
    const { w } = writerOf(M, T)
    for (let k = 0; k < 5; k++) await w.write(counter)
    const rows = (await SERVICE.entries(T.id)).entries
    // op=entries stops at the third tick and names the fifth as the tip, with no more; op=tip still counts five
    const short = hostOf(rows, { entries: async () => ({ entries: rows.slice(0, 3), tip: rows[4].seq, more: false }) })
    const r1 = await M.readThread(short, T.id)
    const m = r1.problems.find(p => p.kind === 'missing')
    c.ok(r1.count === 3 && !r1.complete && m?.position === 4, `a read cut short, three ticks of five: not complete, and the shortfall reported (${m?.detail})`)
    const w1 = new M.ThreadWriter({ service: short, genesis: T.id, key: OWNER, unlock: M.basicUnlock(OWNER), ledger: M.memoryLedger() })
    const e1 = await thrown(() => w1.write(counter))
    c.ok(e1 instanceof M.ThreadBroken && e1.problem?.kind === 'missing' && short.appends === 0, `and a writer does not tick on from the third: ${e1?.message}`)
    // a page that repeats: the first tick, and more, every time
    let asked = 0
    const again = hostOf(rows, { entries: async () => { if (++asked > 50) throw new Error('fifty pages asked for: the reader loops'); return { entries: rows.slice(0, 1), tip: rows[4].seq, more: true } } })
    const r2 = await settle(() => M.readThread(again, T.id))
    c.ok(r2.value?.problems.some(p => p.kind === 'paging') && r2.value.count === 1 && asked === 2,
         `a page that repeats: a problem, after ${asked} pages, never a loop (${r2.value?.problems.find(p => p.kind === 'paging')?.detail ?? r2.error?.message})`)
    // more, and no entries
    const empty = hostOf(rows, { entries: async (id, after) => after < 0 ? { entries: rows.slice(0, 2), tip: rows[4].seq, more: true } : { entries: [], tip: rows[4].seq, more: true } })
    const r3 = await settle(() => M.readThread(empty, T.id))
    c.ok(r3.value?.problems.some(p => p.kind === 'paging') && r3.value.count === 2, `a page that says there is more and gives nothing: a problem (${r3.value?.problems.at(-1)?.kind ?? r3.error?.message})`)
    // pages that move forward and never end
    let asked2 = 0
    const endless = hostOf(rows, { entries: async (id, after) => {
      if (++asked2 > 200) throw new Error('two hundred pages asked for: nothing bounds the reading')
      return { entries: [{ seq: after + 1, bytes: rows[0].bytes }], tip: after + 2, more: true }
    } })
    const r4 = await settle(() => M.readThread(endless, T.id, { slack: 20 }))
    c.ok(r4.value?.problems.some(p => p.kind === 'paging') && r4.value.count <= 5 + 20 + 1,
         `pages that go on past op=tip's count of 5 and a slack of 20: stopped at ${r4.value?.count ?? r4.error?.message} ticks, with a problem`)
  },

  async paging(M, c) {
    const T = await thread('paging')
    const { w } = writerOf(M, T)
    const st = new Set()
    for (let k = 0; k < 260; k++) st.add((await w.write(counter)).status)
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(st.size === 1 && st.has(201) && rep.count === 260 && rep.complete && rep.tip.index === 260 && same(rep.tip.hash, w.tip.hash),
         `260 ticks written, and read back past the service's page of 256: ${rep.count}, complete: ${rep.complete}`)
    const rep7 = await M.readThread(SERVICE, T.id, { limit: 7 })
    c.ok(rep7.count === 260 && rep7.complete && rep7.ticks.every((x, k) => x.position === k + 1 && x.verdict?.accepted === true),
         'and in pages of 7: the same 260, in order, each linked and accepted')
  },

  async reader(M, c) {
    const T = await thread('reader')
    const { w } = writerOf(M, T)
    const good = []
    for (let k = 0; k < 3; k++) good.push(await w.write(counter))
    const S = T.script, unlock = REAL.basicUnlock(OWNER)
    const put = b => store('append', hex(T.id), hex(b))
    const t4 = await tick(good[2].hash, 0, S, 3n, [{ value: 5n, locking: S }, { value: 1n, locking: UNDECLARED }], 5, unlock)   // a value skipped
    put(t4.bytes)
    const t5 = await tick(t4.hash, 1, UNDECLARED, 1n, [{ value: 6n, locking: S }], 6, unlock)                  // a lock with no declaration
    put(t5.bytes)
    const two = { version: JF3, locktime: 0, outputs: [{ value: 7n, locking: S }], inputs: [                   // two inputs
      { prevEntry: t5.hash, index: 0, unlocking: Uint8Array.of(1, 1), sequence: 7 },
      { prevEntry: new Uint8Array(32).fill(7), index: 0, unlocking: Uint8Array.of(1, 1), sequence: 7 }] }
    two.inputs[0].unlocking = await unlock(Uint8Array.from(preimage({ entry: two, inputIndex: 0, scriptCode: S, value: 6n })))
    const b6 = Uint8Array.from(serializeEntry(two))
    put(b6)
    const t7 = await tick(sha256d(b6), 1, S, 7n, [{ value: 8n, locking: S }], 8, unlock)                       // output 1 of a tick with one
    put(t7.bytes)
    const t8 = await tick(new Uint8Array(32).fill(0x42), 0, S, 8n, [{ value: 9n, locking: S }], 9, unlock)     // names no tick of the thread
    put(t8.bytes)
    // an entry with no unlocking script, which proves nothing. Bytes laid out by hand, as no encoder here writes one
    const b9 = Uint8Array.from([0x03, 0x00, 0x4a, 0x46, 1, ...t8.hash, 0, 0, 0, 0, 0, 10, 0, 0, 0, 1, ...unhex(le64(10)), ...varint(S.length), ...S, 0, 0, 0, 0])
    put(b9)
    const junk = utf8('these bytes are not an entry')
    put(junk)
    const t11 = await tick(sha256d(junk), 0, S, 10n, [{ value: 11n, locking: S }], 11, unlock)                 // a tick after them
    put(t11.bytes)
    const rep = await M.readThread(SERVICE, T.id)
    const kinds = {}
    for (const p of rep.problems) (kinds[p.position] ??= []).push(p.kind)
    const want = { 4: ['refused'], 5: ['no verdict'], 6: ['inputs not judged'], 7: ['refused'], 8: ['broken link'], 9: ['malformed'], 10: ['malformed'], 11: ['unjudged'] }
    c.ok(rep.ticks.length === 11 && rep.ticks.every((x, k) => x.position === k + 1) && rep.count === 11, 'every entry the service lists is in the report, in order: eleven')
    c.ok(JSON.stringify(kinds) === JSON.stringify(want), `each reported by position: ${Object.entries(kinds).map(([k, v]) => `${k} ${v.join(', ')}`).join(' · ')}`)
    c.ok(rep.ticks.slice(0, 3).every(x => x.link === true && x.verdict?.accepted) && rep.ticks[5].verdict?.accepted === true,
         'the three written ticks, and input 0 of the tick with two inputs, accepted')
    c.ok(rep.ticks[6].verdict?.reason === 'the tip has no output 1 to spend' && rep.ticks[6].verdict.ran === false,
         `the tick spending an output that is not there: "${rep.ticks[6].verdict?.reason}", the service's words`)
    c.ok(rep.ticks[7].link === false && rep.ticks[10].link === true && rep.ticks[10].verdict === null,
         `the broken link reported; the tick after the bytes that are not an entry linked to them, and not judged: ${rep.ticks[10].why}`)
    const { judged, differ } = phpAgrees(rep)
    c.ok(judged === 6 && differ.length === 0,
         `the ${judged} ticks judged by their script, the refusal and the no verdict among them: CovenantThread::judge's answer on each (${judged - differ.length}/${judged})`)
    c.ok(norm(rep.ticks[4].verdict).noVerdict === 'VersionError', `no verdict on a tick spending a lock that declares no version, in PHP's words: ${rep.ticks[4].verdict?.message}`)
    const fresh = writerOf(M, T)
    const e = await thrown(() => fresh.w.write(counter))
    c.ok(e instanceof M.ThreadBroken && fresh.t.appends() === 0, `a writer will not extend it: ${e?.message}`)
  },

  async pruned(M, c) {
    const T = await thread('pruned')
    const { w, ledger } = writerOf(M, T)
    const r = []
    for (let k = 0; k < 4; k++) r.push(await w.write(counter))
    store('age', hex(T.id))
    // ⚠ at least three: an earlier run of this scenario (a mutant's) left aged ticks behind its own tip, pruned now too.
    //   Which bodies are this thread's is checked by the gaps below
    const n = Number(store('prune'))
    c.ok(n >= 3, `the store's retention prunes the bodies behind the tip: ${n}`)
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(JSON.stringify(rep.gaps) === JSON.stringify(r.slice(0, 3).map((x, k) => ({ position: k + 1, seq: x.seq }))),
         `each pruned body is a gap, by position and seq: ${rep.gaps.map(g => `${g.position} (seq ${g.seq})`).join(', ')}`)
    c.ok(rep.ticks.length === 4 && rep.ticks[3].link === null && rep.ticks[3].verdict === null
         && JSON.stringify(rep.problems.map(p => [p.position, p.kind])) === '[[4,"unjudged"]]',
         `the tip is held whole; its link and its script cannot be checked, and the report says so: ${rep.ticks[3]?.why}`)
    c.ok(same(rep.tip.hash, r[3].hash) && rep.tip.outputs?.[0].value === 4n && !rep.tip.checked, 'its tip and outputs are returned, marked unchecked')
    const client = new M.ThreadService(BASE)
    const gone = await client.entry(r[0].seq), none = await client.entry(99999999)
    c.ok(gone?.pruned === true && gone.bytes === undefined && none === null, 'one entry asked for: a pruned body is the service\'s 410, told apart from a seq it never had (404)')
    const fresh = writerOf(M, T)
    const e = await thrown(() => fresh.w.write(counter))
    c.ok(e instanceof M.ThreadBroken && e.problem?.kind === 'pruned' && e.problem.position === 1 && fresh.t.appends() === 0,
         `a writer with no tick of its own in the thread cannot stand behind a tip nothing can check: ${e?.message}`)
    const again = writerOf(M, T, { ledger })                   // the writer of the tip, its page reloaded
    const r5 = await again.w.write(counter)
    const rep2 = await M.readThread(SERVICE, T.id)
    c.ok(r5.status === 201 && rep2.ticks[4]?.link === true && rep2.ticks[4].verdict?.accepted === true,
         `the writer of the tip stands behind it, and extends the pruned thread (${r5.status}); that tick reads back linked and accepted`)
  },

  async genesis(M, c) {
    const T = await thread('genesis')
    const t = tap()
    t.genesisLie = j => ({ ...j, script: hex(covenantFor(OTHER)) })
    const e = await thrown(() => M.readThread(new M.ThreadService(BASE, { fetch: t.fetch }), T.id))
    c.ok(e instanceof M.ServiceError && /hashes to/.test(e.message), `a service that gives another script for the genesis is caught: ${e?.message?.slice(0, 90)}…`)
    const rep = await M.readThread(SERVICE, T.id)
    c.ok(rep.count === 0 && same(rep.tip.hash, T.id) && same(rep.genesis.script, T.script) && rep.tip.index === 0,
         'the true genesis is read: no ticks, and the tip is the genesis, at tick index 0')
  },
}

for (const [name, run] of Object.entries(SCENARIOS)) {
  console.log(`\n── ${name} ──`)
  try { await run(REAL, { ok }) } catch (e) { ok(false, `${name} threw: ${e?.stack?.split('\n').slice(0, 3).join(' | ')}`) }
}

// ── pins: what the writer and the reader copy from server/append.php ──────────────────────────────────────────────────
console.log('\n── pins: SERVICE_LIMITS and the reader\'s words, held to server/append.php ──')
{
  const src = readFileSync(join(ROOT, 'server/append.php'), 'utf8')
  const size = src.match(/strlen\(\$entry\) > ([\d_]+)\) return new AppendResult\(false, null, 'entry too large', 413\)/)?.[1]
  const k = src.match(/if \(\(\$set\['k'\] \?\? 1\) > (\d+)\)\s*return new AppendResult\(false, null, '[^']*', 501\)/)?.[1]
  ok(Number(size?.replace(/_/g, '')) === REAL.SERVICE_LIMITS?.entryBytes && Number(k) === REAL.SERVICE_LIMITS?.signatures,
     `SERVICE_LIMITS is what append.php refuses: over ${size} bytes (413), and more than ${k} signature (501)`)
  ok(typeof REAL.NOT_ONE === 'string' && src.includes(`'${REAL.NOT_ONE}'`), `a run that does not end with one non-zero item: the reader and the writer give append.php's words, "${REAL.NOT_ONE}"`)
}

// ── layers: the cross-thread attack against copies with each guard taken out ──────────────────────────────────────────
console.log('\n── layers: the cross-thread attack, each of its two guards alone ──')
{
  const STAND = ['thread-writer.mjs', '    await this.#standBehind(report)\n', '']
  const PER_THREAD = ['thread-writer.mjs', '  #key(tick, index) { return spentKey(tick, index) }', '  #key(tick, index) { return `${spentKey(tick, index)} ${this.id}` }']
  const SETS = [
    ['the tip it stands on not checked: the ledger keyed by output holds it alone', [STAND], true],
    ['the ledger keyed per thread: the rule of the tip it stands behind holds it alone', [PER_THREAD], true],
    ['both taken out: the attack must then show, or this test could not see it', [STAND, PER_THREAD], false],
  ]
  for (const [k, [what, changes, safe]] of SETS.entries()) {
    const M = await copyWith(`layer-${k}`, changes)
    if (M === null) { ok(false, `${what}: a text to alter is not in thread-writer.mjs`); continue }
    const r = await crossAttack(M)
    const held = r.twice === 0 && r.appends === 0
    ok(held === safe, `${what}: ${held ? 'no output signed for twice, nothing sent' : `${r.twice} output signed for twice, ${r.appends} sent`} (${r.e?.constructor.name ?? 'no error'})`)
  }
}

// ── mutants ──────────────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── mutants: the modules altered in copies; each copy must fail a scenario ──')
{
  const MUTANTS = [
    ['thread-writer.mjs', 'the ledger keyed by the thread, so it holds one record per thread', '  #key(tick, index) { return spentKey(tick, index) }', '  #key(tick, index) { return `spent ${this.id}` }', ['putback', 'rollback']],
    ['thread-writer.mjs', 'no ledger: every successor recorded afresh', "  if (rec === null) return 'record'", "  if (true) return 'record'", ['lost', 'reload']],
    ['thread-writer.mjs', 'the script not run before sending', 'try { v = await judge(built.entry, 0, spent.locking, spent.value, this.crypto) }', 'try { v = { accepted: true } }', ['refused']],
    ['thread-writer.mjs', 'a refused tick\'s record not taken back', '    if (!v.accepted) {\n      if (fresh) await this.#takeBack(key, next)\n', '    if (!v.accepted) {\n', ['refused']],
    ['thread-writer.mjs', 'a record taken back whoever made it', 'await this.ledger.update(key, rec => rec !== null && rec.thread === this.id && rec.next === next && rec.bytes === null ? null : rec)', 'await this.ledger.update(key, () => null)', ['tabs']],
    ['thread-writer.mjs', 'the bytes not recorded before they are sent', '    if (!recorded) {\n      const b = toHex(built.bytes)', '    if (false) {\n      const b = toHex(built.bytes)', ['reload']],
    ['thread-writer.mjs', 'the bytes recorded whatever another tab recorded meanwhile', 'kept = rec !== null && rec.thread === this.id && rec.next === next && (rec.bytes === null || rec.bytes === b)', 'kept = rec !== null', ['tabs']],
    ['thread-writer.mjs', 'after a 409, the writer stays on the spent tip', '      this.#tip = null\n      return { ...out, error: a.error, serviceTip }', '      return { ...out, error: a.error, serviceTip }', ['stale']],
    ['thread-writer.mjs', 'the writer stands on any tip the reader returns', '    await this.#standBehind(report)\n', '', ['forged', 'pruned']],
    ['thread-writer.mjs', '\'unjudged\' and \'no verdict\' let through after its own tick', '      if (p === undefined && t.link === true && t.verdict?.accepted === true) continue', '      if (!t.pruned) continue', ['forged']],
    ['thread-writer.mjs', 'a thread without this writer\'s newest tick extended', '        if (report.gaps.length === 0) throw new TipRolledBack(mine, tip)', '        if (report.gaps.length === 0) return', ['rollback']],
    ['thread-writer.mjs', 'a tick the service confirmed not noted', '    await this.ledger.update(threadKey(this.id), p => p === null || index > p.index ? { hash: toHex(built.hash), index, seq } : p)', '    return', ['rollback']],
    ['thread-writer.mjs', 'the nSequence check gone', 'step.sequence <= tip.index || ', '', ['refused']],
    ['thread-writer.mjs', 'the tick names JF 3 whatever the lock it spends declares', 'version: declaredVersion(spent.locking)', 'version: (declaredVersion(spent.locking), 0x464a0003)', ['refused']],
    ['thread-writer.mjs', 'the version read from output 0, whatever output is spent', 'version: declaredVersion(spent.locking)', 'version: declaredVersion(tip.outputs[0].locking)', ['refused']],
    ['thread-writer.mjs', 'the version a step names not kept', '    if (step.version === undefined) {', '    if (true) {', ['refused']],
    ['thread-writer.mjs', 'the lock\'s declaration not read before signing, so the judge finds none after', 'version: declaredVersion(spent.locking)', 'version: 0x464a0003', ['refused']],
    ['thread-writer.mjs', 'the size limit not checked before signing', '    if (size > SERVICE_LIMITS.entryBytes)\n', '    if (false)\n', ['limits']],
    ['thread-writer.mjs', 'a genesis needing several signatures let through', 'a[1] > SERVICE_LIMITS.signatures)', 'a[1] > 99)', ['limits']],
    ['thread-writer.mjs', 'resend() sends one tick, and does not walk on', '      if (!a.landed) break', '      break', ['putback']],
    ['thread-reader.mjs', 'the link not checked', 'same(input.prevEntry, before.hash)', 'true', ['reader']],
    ['thread-reader.mjs', 'a pruned body passed over without a gap', '    report.gaps.push({ position, seq })\n', '', ['pruned']],
    ['thread-reader.mjs', 'the output spent taken as output 0, whatever the outpoint', 'before.outputs[input.index]', 'before.outputs[0]', ['reader']],
    ['thread-reader.mjs', 'the genesis output valued 1, not 0', '{ value: 0n, locking: genesis.script }', '{ value: 1n, locking: genesis.script }', ['lands']],
    ['thread-reader.mjs', 'the canonical form not checked', 'try { e = parseEntry(b); assertCanonical(b) }', 'try { e = parseEntry(b) }', ['reader']],
    ['thread-reader.mjs', 'only the first page read', '    if (stuck || !page.more) break', '    break', ['paging']],
    ['thread-reader.mjs', 'pages not required to move forward', '      if (!Number.isInteger(seq) || seq <= after) {', '      if (false) {', ['liars']],
    ['thread-reader.mjs', 'no bound past op=tip\'s count', '    } else if (position > held.count + slack) {', '    } else if (false) {', ['liars']],
    ['thread-reader.mjs', 'the shortfall not reported', '    if (short.length) problem(', '    if (false) problem(', ['liars']],
    ['thread-service.mjs', 'the genesis not checked against its id', 'if (got !== want || String(g.id).toLowerCase() !== want)', 'if (false)', ['genesis']],
    ['thread-service.mjs', 'a pruned entry (410) read as no such entry', '    if (r.status === 410) return { seq, pruned: true }', '    if (r.status === 410) return null', ['pruned']],
    ['thread.mjs', 'tick(): the skeleton\'s preimage over a value of 0', 'scriptCode: bytes(prevLocking), value }))', 'scriptCode: bytes(prevLocking), value: 0n }))', ['lands']],
    ['thread.mjs', 'tick(): the unlocking script built over another preimage than the entry\'s', 'const unlocking = await buildUnlocking(pre)', 'const unlocking = await buildUnlocking(pre.map((x, i) => i === 4 ? x ^ 1 : x))', ['lands']],
  ]
  for (const [k, [file, what, from, to, scenarios]] of MUTANTS.entries()) {
    const M = await copyWith(`mutant-${k}`, [[file, from, to]])
    if (M === null) { ok(false, `${what}: the text to alter is not in ${file}, so the copy would be the original`); continue }
    const caught = []
    for (const name of scenarios) {
      const failed = []
      try { await SCENARIOS[name](M, { ok: (c, w) => { if (!c) failed.push(w) } }) } catch (e) { failed.push(`threw ${e?.constructor?.name}: ${e?.message}`) }
      if (failed.length) caught.push(`${name}: ${failed[0].slice(0, 110)}`)
    }
    ok(caught.length > 0, `${what} (${file}): ${caught.length ? `caught by ${caught[0]}` : `NOT caught by ${scenarios.join(', ')}`}`)
  }
}

// ── what a page loads ────────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── page: what a page loads to write and read ──')
{
  const foreign = /\b(require|process|Buffer|importScripts|eval)\b|\bimport\s*\(|['"]node:/g
  const problems = []
  for (const f of GRAPH) {
    const code = stripComments(readFileSync(join(HERE, f), 'utf8'))
    for (const m of code.matchAll(/\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]/gm)) if (!/^\.\/[\w-]+\.mjs$/.test(m[1] ?? m[2])) problems.push(`${f} imports ${m[1] ?? m[2]}`)
    for (const m of code.matchAll(foreign)) problems.push(`${f} names ${m[0]}`)
  }
  ok(problems.length === 0, `the writer, the reader and the client, and the ${GRAPH.length - 3} files they load (${GRAPH.slice(3).join(', ')}), import only each other and name nothing of node's`
     + (problems.length ? `: ${[...new Set(problems)].join('; ')}` : ''))
}

// ── the browser ──────────────────────────────────────────────────────────────────────────────────────────────────────
if (!BROWSER) console.log('\n  - headless Chromium not run (--no-browser)')
else {
  console.log('\n── browser: one headless Chromium run, the page and the service from the same php -S ──')
  await inBrowser()
}

async function inBrowser() {
  // the page's files beside the service, so the page and the service are one origin; the service's own files untouched
  const page = join(DOCROOT, 'page'), profile = join(TMP, 'profile')
  mkdirSync(join(page, 'tools'), { recursive: true }); mkdirSync(join(page, 'basic')); mkdirSync(profile)
  for (const f of GRAPH) copyFileSync(join(HERE, f), join(page, 'tools', f))
  copyFileSync(join(ROOT, 'basic/basic-jf.mjs'), join(page, 'basic/basic-jf.mjs'))
  writeFileSync(join(page, 'index.html'), `<!doctype html><meta charset="utf-8"><title>writer</title><script type="module">
import { ThreadService } from './tools/thread-service.mjs'
import { ThreadWriter, indexedDbLedger, ed25519Signer, basicUnlock } from './tools/thread-writer.mjs'
import { readThread } from './tools/thread-reader.mjs'
import { authorisedHashes } from './tools/thread.mjs'
import { sha256, sha256d } from './tools/sha256.mjs'
import { ripemd160 } from './tools/ripemd160.mjs'
import { JF_LIT } from './tools/ops-jf.mjs'
import { compileCovenant } from './basic/basic-jf.mjs'
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const unhex = h => Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))
// the page's own store for its key and its thread, which a reload keeps, as the ledger is kept
const kv = (mode, f) => new Promise((res, rej) => {
  const r = indexedDB.open('page', 1)
  r.onupgradeneeded = () => r.result.createObjectStore('kv')
  r.onerror = () => rej(r.error)
  r.onsuccess = () => { const tx = r.result.transaction('kv', mode), q = f(tx.objectStore('kv')); tx.oncomplete = () => res(q?.result); tx.onerror = () => rej(tx.error) }
})
let appends = 0, drop = 0
const net = (url, init) => {
  if (new URL(url).searchParams.get('op') === 'append') { if (drop) { drop--; return Promise.reject(new TypeError('the network failed')) } appends++ }
  return fetch(url, init)
}
const params = new URLSearchParams(location.search)
const service = new ThreadService(params.get('service') ?? new URL('/threads/', location.href).href, { fetch: net })
const SRC = 'VERSION JF 3\\nDIM owner$20'
const counter = tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: tip.outputs[0].locking }], sequence: Number(tip.outputs[0].value) + 1 })
const skip = tip => ({ outputs: [{ value: tip.outputs[0].value + 2n, locking: tip.outputs[0].locking }], sequence: Number(tip.outputs[0].value) + 2 })
const phase = params.get('phase')
const report = rep => ({ count: rep.count, complete: rep.complete, ticks: rep.ticks.map(t => ({ entry: hex(t.bytes), lock: hex(t.spent.locking),
  value: t.spent.value.toString(), verdict: t.verdict.stack ? { accepted: t.verdict.accepted, stack: t.verdict.stack.map(String) }
                                                              : { accepted: false, error: hex(t.verdict.reasonBytes) } })) })
const keyAndThread = async state => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
  const key = await ed25519Signer(pair)
  const script = compileCovenant(SRC, { state: { owner: [...ripemd160(Uint8Array.from(sha256(key.publicKey)))] } }).bytes
  const id = await service.register({ sourceHash: sha256(new TextEncoder().encode(SRC)), script, state: new TextEncoder().encode(state),
                                      authorised: authorisedHashes([key.publicKey]) })
  return { pair, key, id }
}
window.done = (async () => {
  const out = { phase, node: typeof process !== 'undefined', agent: navigator.userAgent }
  if (phase === '1') {
    const { pair, key, id } = await keyAndThread('a page')
    await kv('readwrite', s => { s.put(pair, 'pair'); s.put(hex(id), 'id') })
    // no ledger named: the default, IndexedDB in a page, which the reload below keeps
    const w = new ThreadWriter({ service, genesis: id, key, unlock: basicUnlock(key) })
    out.statuses = []
    for (let k = 0; k < 3; k++) { service.packed = k === 1; out.statuses.push((await w.write(counter)).status) }
    service.packed = false
    drop = 1
    const r = await w.write(counter)
    out.dropped = { status: r.status, hash: hex(r.hash) }
    out.appends = appends
    out.extractable = pair.privateKey.extractable
  } else if (phase === '2') {
    const pair = await kv('readonly', s => s.get('pair')), id = await kv('readonly', s => s.get('id'))
    const key = await ed25519Signer(pair)
    const w = new ThreadWriter({ service, genesis: id, key, unlock: basicUnlock(key) })
    out.tipPosition = (await w.open()).tip.position
    try { await w.write(skip); out.other = 'sent' } catch (e) { out.other = e.constructor.name }
    const str8 = async pre => Uint8Array.from([JF_LIT.STR8, 64, ...await key.sign(Uint8Array.from(sha256d(pre))), 32, ...key.publicKey])
    const r = await w.write(counter, { unlock: str8 })
    out.sent = { status: r.status, hash: hex(r.hash) }
    out.appends = appends
    out.read = report(await readThread(service, id))
    // a second store name on the database the default ledger made: its own records, beside the default's
    try {
      const second = indexedDbLedger({ store: 'a second name' })
      await second.update('probe', () => ({ kept: 1 }))
      out.secondStore = (await second.get('probe'))?.kept === 1 && (await indexedDbLedger().get('probe')) === null
    } catch (e) { out.secondStore = String(e) }
    // a database of that name already there without the ledger's object store, as an earlier ledger made it at version 1
    try {
      await new Promise((res, rej) => { const r = indexedDB.open('made-before', 1); r.onupgradeneeded = () => r.result.createObjectStore('ledger')
                                        r.onsuccess = () => { r.result.close(); res() }; r.onerror = () => rej(r.error) })
      const older = indexedDbLedger({ name: 'made-before' })
      await older.update('probe', () => ({ kept: 2 }))
      const version = await new Promise(res => { const r = indexedDB.open('made-before'); r.onsuccess = () => { res(r.result.version); r.result.close() } })
      out.olderDb = (await older.get('probe'))?.kept === 2 && version === 2 ? true : \`version \${version}\`
    } catch (e) { out.olderDb = String(e) }
  } else {
    // a page of another origin than the service's: JSON, then one tick packed
    out.origin = location.origin
    out.serviceOrigin = new URL(service.base).origin
    const { key, id } = await keyAndThread('another origin')
    out.id = hex(id)
    const w = new ThreadWriter({ service, genesis: id, key, unlock: basicUnlock(key), ledger: indexedDbLedger() })
    out.statuses = []
    for (let k = 0; k < 2; k++) out.statuses.push((await w.write(counter)).status)
    service.packed = true
    const p = await w.write(counter)
    out.packed = { status: p.status, error: p.error }
    service.packed = false
    const again = await w.resend()                            // the recorded successor, in JSON
    out.again = again && { status: again.status, landed: again.landed, same: hex(again.hash) === hex(p.hash) }
    out.read = report(await readThread(service, id))
  }
  return out
})()
</script>`)
  const url = phase => `http://127.0.0.1:${PORT}/page/index.html?phase=${phase}`
  // a second origin: another port, serving the page alone, its service the first
  const other = join(TMP, 'other'), PORT2 = await freePort()
  mkdirSync(other)
  copyDir(page, join(other, 'page'))
  RUN.start('php', ['-S', `127.0.0.1:${PORT2}`, '-t', other], { stdio: 'ignore' })
  for (let k = 0; k < 100 && !(await listening(PORT2)); k++) await new Promise(r => setTimeout(r, 50))
  const elsewhere = `http://127.0.0.1:${PORT2}/page/index.html?phase=3&service=${encodeURIComponent(BASE)}`
  const port = await freePort()
  const browser = RUN.start('chromium', ['--headless', '--disable-gpu', '--no-sandbox', `--user-data-dir=${profile}`,
                                         `--remote-debugging-port=${port}`, url(1)], { stdio: 'ignore' })
  const gone = new Promise(res => browser.exitCode !== null ? res() : browser.once('exit', res))
  let r1 = null, r2 = null, r3 = null, why = null
  try {
    let target = null
    for (let k = 0; k < 150 && !target; k++) {
      try { target = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find(t => t.type === 'page' && t.url.includes('/page/index.html')) } catch {}
      if (!target) await new Promise(r => setTimeout(r, 100))
    }
    if (!target) throw new Error('Chromium did not open the page')
    const ws = new WebSocket(target.webSocketDebuggerUrl)
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('no DevTools connection')) })
    let id = 0
    const waiting = new Map()
    ws.onmessage = m => { const d = JSON.parse(m.data); waiting.get(d.id)?.(d); waiting.delete(d.id) }
    const send = (method, params, ms = 120000) => new Promise((res, rej) => {
      const n = ++id, timer = setTimeout(() => { waiting.delete(n); rej(new Error(`${method}: no answer in ${ms / 1000} s`)) }, ms)
      waiting.set(n, d => { clearTimeout(timer); res(d) })
      ws.send(JSON.stringify({ id: n, method, params }))
    })
    const evaluate = async expression => {
      const d = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
      if (d.result?.exceptionDetails) throw new Error(d.result.exceptionDetails.exception?.description ?? 'the page threw')
      return d.result?.result?.value
    }
    // the module may not have run yet when the page appears: wait for window.done in the document of this phase
    const result = async phase => {
      for (let k = 0; k < 200; k++) {
        const at = await evaluate("new URLSearchParams(location.search).get('phase')").catch(() => null)
        if (at === String(phase)) break
        await new Promise(r => setTimeout(r, 50))
      }
      return evaluate('new Promise(r => { const w = () => window.done ? r(window.done) : setTimeout(w, 50); w() })')
    }
    r1 = await result(1)
    await send('Page.navigate', { url: url(2) })                 // a reload: a new document, the same profile and storage
    r2 = await result(2)
    await send('Page.navigate', { url: elsewhere })              // the same browser, a page of another origin
    r3 = await result(3)
    ws.close()
  } catch (e) { why = e.message }
  RUN.stop(browser)
  await gone
  rmSync(profile, { recursive: true, force: true })
  if (!r1 || !r2 || !r3) { ok(false, `headless Chromium: ${why}`); return }
  const agent = r1.agent.match(/Chrome\/[\d.]+/)?.[0] ?? r1.agent
  ok(!r1.node && !r2.node && r1.statuses?.every(s => s === 201) && r1.statuses.length === 3 && r1.extractable === false,
     `${agent}, no node in the page: the covenant compiled there, a thread registered, three ticks written over JSON and packed with a non-extractable WebCrypto key: ${r1.statuses?.join(' ')}`)
  ok(r1.dropped?.status === 0 && r1.appends === 3, 'the fourth tick signed and recorded in IndexedDB, and its send failed before it left')
  ok(r2.tipPosition === 3 && r2.other === 'TipAlreadyAdvanced',
     `reloaded, no ledger named either time: the tip is the third tick, and another successor of it is refused by the default ledger, IndexedDB (${r2.other})`)
  ok(r2.secondStore === true, `a ledger of a second store name on the same database keeps its own records (${r2.secondStore})`)
  ok(r2.olderDb === true, `a database of that name made earlier without the ledger's object store: opened at the next version, which makes it (${r2.olderDb})`)
  ok(r2.sent?.status === 201 && r2.sent.hash === r1.dropped?.hash && r2.appends === 1,
     'the same transition, signed in another push form: the recorded bytes land, the one append the reloaded page made')
  const agreeing = read => { const php = judgePhp(read.ticks.map(t => ({ entry: t.entry, input: 0, lock: t.lock, value: le64(t.value) })))
                            return read.ticks.filter((t, k) => JSON.stringify(t.verdict) === JSON.stringify(php[k])).length }
  const agree = agreeing(r2.read)
  ok(r2.read.count === 4 && r2.read.complete && agree === 4, `read back in the page: four ticks, complete, each verdict CovenantThread::judge's (${agree}/4)`)
  ok(r3.origin !== r3.serviceOrigin && r3.statuses.every(s => s === 201),
     `a page of another origin (${r3.origin}, the service at ${r3.serviceOrigin}): a thread registered and two ticks written in JSON, with no CORS preflight: ${r3.statuses.join(' ')}`)
  const served = readFileSync(LOG, 'utf8').split('\n')
  const preflights = served.filter(l => l.includes(`OPTIONS /threads/?op=append&genesis=${r3.id}`)).map(l => l.match(/\[(\d{3})\]/)?.[1])
  const posts = served.filter(l => l.includes(`POST /threads/?op=append&genesis=${r3.id}`)).length
  console.log(`  - from that origin a packed append got ${r3.packed.status} (${r3.packed.error ?? ''}): the service saw ${preflights.length} preflight`
    + ` for it, answered ${preflights.join(', ') || 'nothing'}, and ${posts} packed POST. threads.php answers no CORS preflight`)
  const agree3 = agreeing(r3.read)
  ok((r3.packed.status === 0 ? r3.again?.status === 201 : r3.packed.status === 201 && r3.again?.landed) && r3.again.same
     && r3.read.count === 3 && r3.read.complete && agree3 === 3,
     `the tick recorded for it then sent with resend() in JSON, its very bytes (${r3.again?.status}); read back from there: three ticks, complete, each verdict PHP's (${agree3}/3)`)
}

/** A folder copied, for the second origin's page */
function copyDir(from, to) {
  mkdirSync(to, { recursive: true })
  for (const f of readdirSync(from, { withFileTypes: true }))
    f.isDirectory() ? copyDir(join(from, f.name), join(to, f.name)) : copyFileSync(join(from, f.name), join(to, f.name))
}

if (fail) { console.log('\n── the server\'s log, last lines ──'); console.log(readFileSync(LOG, 'utf8').split('\n').slice(-12).join('\n')) }
console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the writer and the reader in JavaScript · against the thread service]`)
process.exit(fail === 0 ? 0 : 1)
