// © 2026 sun-dive. Apache License 2.0.
//
// The code thread's covenant, basic/code-thread.bas, end to end: a release is accepted, and nothing else is.
//   node basic/test/code-thread.mjs
// A throwaway Ed25519 key, made for the run and never exported, is the release key. The genesis is the covenant with
// owner the key's HASH160, rev 3 and code 32 zero bytes: no part yet, so every byte of the archive is in a tick, the
// first part's too. The first tick carries a part of the engine's code, a gzip of server/interpreter-jf.php and
// tools/interpreter-jf.mjs, and revision 3; a second, on top of it, carries those and their opcode tables, and revision 4.
// Each tick is built by tick() of tools/thread.mjs with basicUnlock(key, inputs), and judged from its bytes by
// CovenantThread::judge (tools/judge-run.php) and by judge() of tools/thread.mjs: the same verdict, and the same stack
// or refusal bytes. Then the largest bundle one tick can carry, measured. Last, once through the thread service, staged
// as .cpanel.yml deploys it and served by php -S: the genesis registered, the two ticks written by
// tools/thread-writer.mjs and read back by tools/thread-reader.mjs, and the tip's state and each tick's part read
// from the thread alone. The temp folder and the server go when the run ends (tools/run-folder.mjs).
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, mkdirSync, existsSync } from 'node:fs'
import { createServer, connect } from 'node:net'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync, gunzipSync } from 'node:zlib'
import { compileCovenant } from '../basic-jf.mjs'
import { unbasic, disassemble } from '../unbasic-jf.mjs'
import { tick, judge, create, authorisedHashes, VersionError, JfHostError } from '../../tools/thread.mjs'
import { parseEntry } from '../../tools/entry.mjs'
import { JF_LIT } from '../../tools/ops-jf.mjs'
import { ThreadWriter, memoryLedger, ed25519Signer, basicUnlock, SERVICE_LIMITS } from '../../tools/thread-writer.mjs'
import { readThread } from '../../tools/thread-reader.mjs'
import { ThreadService } from '../../tools/thread-service.mjs'
import { runFolder } from '../../tools/run-folder.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..', '..')
const hex = b => Buffer.from(b).toString('hex')
const same = (a, b) => a != null && b != null && hex(a) === hex(b)
const H = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const sha = H('sha256'), hash160 = b => H('ripemd160')(sha(b))
const le64 = v => { const o = Buffer.alloc(8); o.writeBigUInt64LE(BigInt(v)); return o.toString('hex') }
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }

// ── the covenant, the key, the bundles ───────────────────────────────────────────────────────────────────────────────
const SRC = readFileSync(join(HERE, '..', 'code-thread.bas'), 'utf8')
/** The release script as approved, without its comments: the file must compile to its bytes */
const APPROVED = 'VERSION JF 3\nDIM owner$20\nDIM rev%2\nDIM code$32\nINPUT bundle$, r%\ncode = SHA256(bundle)\nrev = r'
const subtle = globalThis.crypto.subtle
const newKey = async () => ed25519Signer(await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']))
const OWNER = await newKey(), OTHER = await newKey()
const OWNER_HASH = hash160(OWNER.publicKey)
const ZERO = new Uint8Array(32)
const compiled = (rev, code, src = SRC) => compileCovenant(src, { state: { owner: [...OWNER_HASH], rev, code: [...code] } })
const lockOf = (rev, code) => compiled(rev, code).bytes
const GENESIS_LOCK = lockOf(3, ZERO)
const NAMES = compiled(3, ZERO).names
/** A lock's state, read back by the reader: { owner, rev, code } */
const stateOf = lock => unbasic(lock, { names: NAMES }).state

const file = f => readFileSync(join(ROOT, f))
const ENGINE = ['server/interpreter-jf.php', 'tools/interpreter-jf.mjs']
const TABLES = ['server/ops-jf.php', 'tools/ops-jf.mjs']
/** A release's bundle: its files one after another, gzipped */
const bundleOf = files => gzipSync(Buffer.concat(files.map(file)), { level: 9 })
const B3 = bundleOf(ENGINE), B4 = bundleOf([...ENGINE, ...TABLES])

/** The genesis: the covenant with no release yet, its append key the release key */
const FIELDS = { sourceHash: sha(Buffer.from(SRC)), script: GENESIS_LOCK, state: new TextEncoder().encode('the jetmora code thread'),
                 authorised: authorisedHashes([OWNER.publicKey]) }
const ID = create(FIELDS.sourceHash, FIELDS.script, FIELDS.state, FIELDS.authorised).id

console.log('\n── the covenant: basic/code-thread.bas ──')
{
  const c = compiled(3, ZERO)
  ok(same(GENESIS_LOCK, compiled(3, ZERO, APPROVED).bytes),
     `the file compiles to the approved script's bytes, its comments aside: ${GENESIS_LOCK.length} B`)
  ok(JSON.stringify(c.inputs) === JSON.stringify([{ name: 'bundle', width: null, bytes: true }, { name: 'r', width: 8, bytes: false }])
     && JSON.stringify(c.layout.map(f => [f.name, f.width])) === '[["owner",20],["rev",2],["code",32]]',
     'its state is owner$20, rev%2, code$32, and a tick carries bundle$ of any length and r% of at most 8 bytes')
  const s = stateOf(GENESIS_LOCK)
  ok(same(s?.owner, OWNER_HASH) && s.rev === 3n && same(s.code, ZERO), 'the genesis reads back as owner the release key\'s HASH160, rev 3, code 32 zero bytes')
}

// ── the ticks ────────────────────────────────────────────────────────────────────────────────────────────────────────
/** A release tick: it spends output 0 of `tip`, its successor `next`, and carries `inputs` after the signature and the key */
const release = (tip, next, inputs, key = OWNER, wrap = u => u) =>
  tick(tip.hash, 0, tip.locking, tip.value, [{ value: tip.value + 1n, locking: next }], Number(tip.value) + 1, wrap(basicUnlock(key, inputs)))
/** The same unlocking script with one push more, below the signature: the frame's bindings are all as they were */
const under = u => Object.assign(async pre => Uint8Array.from([1, 0x01, ...await u(pre)]), { size: u.size + 2 })
const GENESIS = { hash: ID, locking: GENESIS_LOCK, value: 0n }
const NEXT3 = lockOf(3, sha(B3)), NEXT4 = lockOf(4, sha(B4))
const T1 = await release(GENESIS, NEXT3, [B3, 3])
const AFTER1 = { hash: T1.hash, locking: NEXT3, value: 1n }
const T2 = await release(AFTER1, NEXT4, [B4, 4])

/** CovenantThread::judge, through tools/judge-run.php */
const judgePhp = cases => JSON.parse(execFileSync('php', [join(ROOT, 'tools/judge-run.php'), 'judge'],
  { input: JSON.stringify(cases), maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'inherit'] }).toString())
/** judge() of tools/thread.mjs on a tick's bytes, its verdict in judge-run.php's form */
async function judgeJs(bytes, tip) {
  try {
    const v = await judge(parseEntry(bytes), 0, tip.locking, tip.value)
    return v.stack !== undefined ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.errorBytes) }
  } catch (e) {
    if (e instanceof VersionError || e instanceof JfHostError) return { noVerdict: e.constructor.name, message: e.message }
    throw e
  }
}
/** Both judges on each [what, tip, tick]: [{ php, js }] */
async function judged(list) {
  const php = judgePhp(list.map(([, tip, t]) => ({ entry: hex(t.bytes), input: 0, lock: hex(tip.locking), value: le64(tip.value) })))
  return Promise.all(list.map(async ([, tip, t], k) => ({ php: php[k], js: await judgeJs(t.bytes, tip) })))
}
const said = v => v.accepted ? 'accepted' : v.error ? `refused: ${Buffer.from(v.error, 'hex').toString('latin1')}`
                : v.stack ? `refused, ${v.stack.length} items left` : JSON.stringify(v)

console.log(`\n── release ticks, judged by CovenantThread::judge and by tools/thread.mjs ──`)
{
  const CASES = [
    ['the first release: the engine\'s code, revision 3', GENESIS, T1, true],
    ['a second release on top of the first: the engine and its opcode tables, revision 4', AFTER1, T2, true],
    ['signed by another key', GENESIS, await release(GENESIS, NEXT3, [B3, 3], OTHER), false],
    ['the successor names the SHA-256 of another bundle', GENESIS, await release(GENESIS, lockOf(3, sha(B4)), [B3, 3]), false],
    ['the successor keeps the code it had, 32 zero bytes', GENESIS, await release(GENESIS, lockOf(3, ZERO), [B3, 3]), false],
    ['the tick carries revision 4, and the successor says 3', GENESIS, await release(GENESIS, NEXT3, [B3, 4]), false],
    ['the tick carries revision 3, and the successor says 4', GENESIS, await release(GENESIS, lockOf(4, sha(B3)), [B3, 3]), false],
    ['a push more than INPUT names, after the revision', GENESIS, await release(GENESIS, NEXT3, [B3, 3, Uint8Array.of(1)]), false],
    ['a push below the signature, the rest as the first release', GENESIS, await release(GENESIS, NEXT3, [B3, 3], OWNER, under), false],
    ['no bundle: the revision alone carried', GENESIS, await release(GENESIS, NEXT3, [3]), false],
    ['nothing carried: the signature and the key alone', GENESIS, await release(GENESIS, NEXT3, []), false],
  ]
  const res = await judged(CASES)
  let agree = 0
  for (const [k, [what, , , want]] of CASES.entries()) {
    const { php, js } = res[k]
    if (JSON.stringify(php) === JSON.stringify(js)) agree++
    ok(php.accepted === want, `${what}: ${said(php)}`)
  }
  ok(agree === CASES.length, `★ tools/thread.mjs's judge gives CovenantThread::judge's verdict on every one, the same stack or the same refusal bytes (${agree}/${CASES.length})`)
  const below = res[CASES.findIndex(c => c[0].startsWith('a push below'))].php
  ok(below.accepted === false && below.stack?.length > 1,
     `the push below the signature passes the whole lock, and is refused only because a tick leaves exactly one item: ${said(below)}`)
  for (const [t, bundle, rev, what] of [[T1, B3, 3n, 'first'], [T2, B4, 4n, 'second']]) {
    const s = stateOf(t.entry.outputs[0].locking)
    ok(same(s?.owner, OWNER_HASH) && s.rev === rev && same(s.code, sha(bundle)),
       `the ${what} release's successor holds the bundle's SHA-256 and revision ${rev}, the owner unchanged: code ${hex(s?.code ?? []).slice(0, 16)}…`)
  }
  const u = T1.entry.inputs[0].unlocking
  ok(u[2 + 64 + 32] === JF_LIT.STR16 && T1.bytes.length < SERVICE_LIMITS.entryBytes && T2.bytes.length < SERVICE_LIMITS.entryBytes,
     `the first release's bundle is ${B3.length} B, one STR16 push after the key, and its tick ${T1.bytes.length} B; the second's ${B4.length} B and ${T2.bytes.length} B: `
     + `each under the service's ${SERVICE_LIMITS.entryBytes}`)
}

// ── the largest bundle one tick can carry ────────────────────────────────────────────────────────────────────────────
console.log('\n── the largest bundle one tick can carry ──')
{
  /* Every byte a tick pushes goes to the push space, 65,536 bytes, and the lock's own literals after them. The size is
     found by bisection with the JavaScript judge, then the largest and one byte more are judged by both. */
  const bytesOf = n => Uint8Array.from({ length: n }, (_, k) => (k * 131 + 7) & 0xff)
  const carrying = async n => { const b = bytesOf(n); return release(GENESIS, lockOf(3, sha(b)), [b, 3]) }
  let lo = B3.length, hi = 1 << 17
  while (hi - lo > 1) { const m = (lo + hi) >> 1; if ((await judgeJs((await carrying(m)).bytes, GENESIS)).accepted) lo = m; else hi = m }
  const at = await carrying(lo), past = await carrying(lo + 1)
  const [a, p] = await judged([['', GENESIS, at], ['', GENESIS, past]])
  const exhausted = hex(Buffer.from('push space exhausted'))
  const lits = compiled(3, ZERO).pushed - (64 + 32) - 8        // the compiler's count, less the signature, the key and r at its width
  ok(a.php.accepted && JSON.stringify(a.php) === JSON.stringify(a.js) && !p.php.accepted && p.php.error === exhausted
     && JSON.stringify(p.php) === JSON.stringify(p.js),
     `a bundle of ${lo} B is accepted by both judges, and ${lo + 1} B is refused by both: ${said(p.php)}`)
  ok(lo === 65536 - 64 - 32 - 1 - lits,
     `that is the push space less the signature, the key, r in one byte and the lock's own ${lits} B of literals, as the compiler counts them`)
  ok(at.bytes.length < SERVICE_LIMITS.entryBytes,
     `its tick is ${at.bytes.length} B: the push space bounds a release, not the service's ${SERVICE_LIMITS.entryBytes} bytes`)
}

// ── once through the thread service ──────────────────────────────────────────────────────────────────────────────────
console.log('\n── through the thread service, staged as .cpanel.yml deploys it ──')
const RUN = runFolder('code-thread'), TMP = RUN.dir
const HOME = join(TMP, 'home'), DOCROOT = join(HOME, 'jetmora.org')
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
const freePort = () => new Promise(res => { const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)) }) })
const listening = port => new Promise(res => { const c = connect(port, '127.0.0.1', () => { c.end(); res(true) }); c.on('error', () => res(false)) })
const PORT = await freePort()
RUN.start('php', ['-S', `127.0.0.1:${PORT}`, '-t', DOCROOT], { stdio: 'ignore' })
let up = false
for (let k = 0; k < 100 && !(up = await listening(PORT)); k++) await new Promise(r => setTimeout(r, 50))
ok(up, `php -S serves it on port ${PORT}`)
if (up) {
  const service = new ThreadService(`http://127.0.0.1:${PORT}/threads/`)
  const id = await service.register(FIELDS)
  ok(same(id, ID), 'the genesis registered: the covenant with no release yet, its id the one create() derives')
  const w = new ThreadWriter({ service, genesis: id, key: OWNER, unlock: basicUnlock(OWNER, [B3, 3]), ledger: memoryLedger() })
  const to = next => tip => ({ outputs: [{ value: tip.outputs[0].value + 1n, locking: next }] })
  const r1 = await w.write(to(NEXT3))
  const r2 = await w.write(to(NEXT4), { unlock: basicUnlock(OWNER, [B4, 4]) })
  ok(r1.status === 201 && r2.status === 201 && same(r1.bytes, T1.bytes) && same(r2.bytes, T2.bytes),
     `the two releases written by the writer land (${r1.status} ${r2.status}), each the very bytes judged above`)
  const rep = await readThread(service, id)
  ok(rep.count === 2 && rep.complete && rep.ticks.every(t => t.link === true && t.verdict?.accepted === true),
     'read back by the reader: two ticks, complete, each linked and accepted by the output it spends')
  const php = judgePhp(rep.ticks.map(t => ({ entry: hex(t.bytes), input: 0, lock: hex(t.spent.locking), value: le64(t.spent.value) })))
  ok(rep.ticks.every((t, k) => php[k].accepted === true && JSON.stringify(php[k].stack) === JSON.stringify(t.verdict.stack.map(String))),
     'each verdict is CovenantThread::judge\'s')
  const s = stateOf(rep.tip.outputs[0].locking)
  ok(rep.tip.index === 2 && same(s?.owner, OWNER_HASH) && s.rev === 4n && same(s.code, sha(B4)),
     `the tip's state: the second release's SHA-256 and revision 4, what an anchor to BSV or WAX carries (code ${hex(s?.code ?? []).slice(0, 16)}…)`)
  // each release's code from the thread alone: the bundle its tick pushes hashes to the code its successor names
  const got = rep.ticks.map(t => {
    const [, , bundle, r] = disassemble(t.entry.inputs[0].unlocking).map(x => x.data)
    return { bundle, r, s: stateOf(t.entry.outputs[0].locking) }
  })
  ok(got.every(g => same(sha(g.bundle), g.s.code) && BigInt(g.r[0]) === g.s.rev)
     && same(gunzipSync(got[0].bundle), Buffer.concat(ENGINE.map(file))) && same(gunzipSync(got[1].bundle), Buffer.concat([...ENGINE, ...TABLES].map(file))),
     'each release\'s code, read from the thread alone: the bundle its tick carries hashes to the code its successor names, and unpacks to the files')
}

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [the code thread's covenant]`)
process.exit(fail === 0 ? 0 : 1)
