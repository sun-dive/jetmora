// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// Grade the JavaScript `JF` interpreter (tools/interpreter-jf.mjs) against the PHP one (server/interpreter-jf.php):
//   1. the opcode table: tools/ops-jf.mjs must equal server/ops-jf.php, entry for entry
//   2. the PHP interpreter's own test cases (server/verify-jf.php --export), run here
//   3. side by side: generated programs run through BOTH, and every stack and every refusal must be identical
// A difference is a bug in one of them; a refusal PHP raises from outside the interpreter is a PHP fault, reported.
//   node tools/verify-jf.mjs [programs=3000] [seed]
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify as nodeVerify, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as OPS from './ops-jf.mjs'
import { InterpreterJF } from './interpreter-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '..')
const N_PROGRAMS = Number(process.argv[2] ?? 3000), SEED = Number(process.argv[3] ?? 20261003)
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; if (!c || process.env.V) console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const hex = b => Buffer.from(b).toString('hex'), unhex = h => Uint8Array.from(Buffer.from(h, 'hex'))
const latin1 = b => Buffer.from(b).toString('utf8')

// ── crypto, supplied ──
const h = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex')
let ecdsa = null
try { ecdsa = await import('../../PharLap2/impl/js/ecdsa.mjs') } catch {}
const crypto = {
  sha256: h('sha256'), sha1: h('sha1'), ripemd160: h('ripemd160'),
  ed25519Verify: (sig, pub, msg) => nodeVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI_ED25519, pub]), format: 'der', type: 'spki' }), sig),
  ...(ecdsa ? { ecdsaVerify: (sig, pub, d) => ecdsa.verifyDigest(sig, pub, d) } : {}),
}
const runJs = async (script, preimage = null) => {
  const vm = new InterpreterJF({ crypto }); vm.setPreimage(preimage)
  try { return { stack: (await vm.run(script)).map(String) } }
  // ⚠ PHP's message is BYTES: its own text in UTF-8, and an abort's diagnostic appended raw. The same bytes here.
  catch (e) { const bytes = e.diagnostic ? Buffer.concat([Buffer.from(e.diagnostic.length ? 'ABORT: ' : 'ABORT'), Buffer.from(e.diagnostic)]) : Buffer.from(e.message, 'utf8')
              return { error: hex(bytes), diag: e.diagnostic ? hex(e.diagnostic) : null, jf: e.constructor.name.startsWith('Jf') } }
}
// ⚠ One line per program: a program that ENDS the PHP process (an allocation it cannot make) is marked and skipped,
//   and the runner restarts after it. That is a PHP defect, reported, never a pass.
const runPhp = cases => {
  const input = JSON.stringify(cases), out = []
  while (out.length < cases.length) {
    let text
    try { text = execFileSync('php', [join(HERE, 'jf-run.php'), String(out.length)], { input, maxBuffer: 1 << 28, stdio: ['pipe', 'pipe', 'ignore'] }).toString() }
    catch (e) { text = e.stdout?.toString() ?? '' }
    for (const line of text.split('\n')) if (line.trim()) out.push(JSON.parse(line))
    // stopped early: the program it was running is the one that ended the process
    if (out.length < cases.length) out.push({ error: Buffer.from('the PHP process ended (fatal error)').toString('hex'), diag: null, jf: false })
  }
  return out
}

// ── 1. the opcode table ──
console.log('── 1. the opcode table: tools/ops-jf.mjs against server/ops-jf.php')
const php = JSON.parse(execFileSync('php', ['-r', `require '${join(ROOT, 'server/ops-jf.php')}'; echo json_encode(['PUSH_MAX' => JF_PUSH_MAX, 'SMALL0' => JF_SMALL0, 'SMALL_NEG1' => JF_SMALL_NEG1, 'LIT' => JF_LIT, 'WORD' => JF_WORD, 'SECTION' => JF_SECTION, 'ESC0' => JF_ESC0, 'PLANE' => JF_PLANE, 'RESERVED0' => JF_RESERVED0, 'BANK' => (object)JF_BANK, 'BANK_WORD' => JF_BANK_WORD, 'CORE_KIND' => JF_CORE_KIND, 'PROMOTED' => JF_PROMOTED, 'NAMES' => array_map('jf_op_name', range(0, 255))]);`]).toString())
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)
for (const k of ['PUSH_MAX', 'SMALL0', 'SMALL_NEG1', 'LIT', 'WORD', 'SECTION', 'ESC0', 'PLANE', 'RESERVED0', 'BANK', 'BANK_WORD', 'CORE_KIND', 'PROMOTED'])
  ok(same(OPS[`JF_${k}`], php[k]), `JF_${k} is the same in both`)
ok(same(Array.from({ length: 256 }, (_, n) => OPS.jf_op_name(n)), php.NAMES), 'every byte has the same name in both')

// ── 2. the PHP interpreter's own cases ──
console.log('── 2. the PHP interpreter\'s own test cases, run in JavaScript')
const tmp = mkdtempSync(join(tmpdir(), 'jf-'))
execFileSync('php', [join(ROOT, 'server/verify-jf.php'), `--export=${join(tmp, 'cases.json')}`])
const cases = JSON.parse(readFileSync(join(tmp, 'cases.json'), 'utf8')); rmSync(tmp, { recursive: true })
let caseFails = 0
for (const c of cases) {
  const r = await runJs(unhex(c.script))
  const good = c.diag !== null ? r.diag === c.diag
             : c.err !== null ? r.error !== undefined && latin1(unhex(r.error)).includes(c.err)
             : same(r.stack, c.want)
  if (!good) { caseFails++; console.log(`  ✗ ${c.id}: want ${c.diag ?? c.err ?? c.want.join(' ')}, got ${r.stack ? r.stack.join(' ') : latin1(unhex(r.error))}`) }
}
ok(caseFails === 0, `${cases.length - caseFails} of ${cases.length} cases pass`)

// ── 3. side by side ──
console.log(`── 3. side by side: ${N_PROGRAMS} generated programs through both (seed ${SEED})`)
let s = SEED >>> 0
const rnd = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 2 ** 32 }
const pick = a => a[Math.floor(rnd() * a.length)]
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1))
const bytes = n => Uint8Array.from({ length: n }, () => int(0, 255))
const W = OPS.JF_WORD, L = OPS.JF_LIT
const le = (v, w) => { let x = BigInt.asUintN(8 * w, BigInt(v)); const o = []; for (let k = 0; k < w; k++) { o.push(Number(x & 0xffn)); x >>= 8n } return o }
const plain = Object.keys(W).filter(w => !['BRANCH', '0BRANCH', '(?DO)', '(LOOP)', '(+LOOP)', 'LEAVE', 'CALL', 'EXECUTE', '(FRAME)', '(LOCAL@)', '(LOCAL!)', 'INVOKE', '(ABORT")'].includes(w))
const edKeys = Array.from({ length: 3 }, () => generateKeyPairSync('ed25519'))
const edPub = k => Uint8Array.from(k.publicKey.export({ format: 'der', type: 'spki' }).subarray(12))
const token = depthOk => {
  const r = rnd()
  if (r < 0.18) return [OPS.JF_SMALL0 + int(0, 9)]                                     // 0..8, -1
  if (r < 0.26) { const w = pick([1, 2, 4, 8]); const lit = { 1: 'LIT8', 2: 'LIT16', 4: 'LIT32', 8: 'LIT64' }[w]
                  const v = pick([0, 1, -1, 2 ** (8 * w - 1) - 1, -(2 ** (8 * w - 1)), int(-300, 300), int(-70000, 70000)])
                  return [L[lit], ...le(v, w)] }
  if (r < 0.32) { const n = pick([0, 1, 2, 8, 20, 32, 40]); return [n, ...bytes(n)] }  // direct push
  if (r < 0.34) { const n = int(0, 12); return [L.STR8, n, ...bytes(n)] }
  if (r < 0.35) { const n = int(0, 9); return [L.LITBIG, n, ...bytes(n)] }
  if (r < 0.37) return [W['0BRANCH'], ...le(int(0, 6), 2)]                              // forward only: no loops
  if (r < 0.38) return [W.BRANCH, ...le(int(0, 6), 2)]
  if (r < 0.39) return [W['(ABORT")'], 3, 0x61, 0x62, 0x63]
  if (r < 0.40) return [W['(FRAME)'], int(0, 3)]
  if (r < 0.41) return [pick([W['(LOCAL@)'], W['(LOCAL!)']]), int(0, 3)]
  if (r < 0.42) return [W['(UNFRAME)']]
  if (r < 0.43) { const k = pick(edKeys); const msg = bytes(int(0, 40)); const sig = Uint8Array.from(nodeSign(null, msg, k.privateKey))
                  if (rnd() < 0.3) sig[int(0, 63)] ^= 1
                  return [64, ...sig, 32, ...edPub(k), msg.length, ...msg, W['ED25519-CHECKSIG']] }
  if (r < 0.45) return [int(0xf0, 0xff), int(0, 140)]                                   // bank escape (illegal here)
  if (r < 0.46) return [int(0, 255)]                                                      // any byte at all
  return [W[pick(plain)]]
}
const program = () => {
  const out = []
  // sometimes a DEFS header with functions, called by INVOKE
  if (rnd() < 0.25) {
    const defs = Array.from({ length: int(1, 2) }, () => {
      const body = []; for (let k = int(0, 8); k > 0; k--) body.push(...token(true))
      if (rnd() < 0.3) body.push(int(0xf0, 0xf8), int(0, 130))                         // a bank word, legal inside a function
      return { nin: int(0, 2), nout: int(0, 2), inm: pick([0, 0, 8]), outm: pick([0, 0, 16]), body }
    })
    out.push(OPS.JF_RESERVED0, defs.length)
    for (const d of defs) out.push(d.nin, d.nout, d.inm, d.outm, d.body.length, ...d.body)
    for (let k = int(0, 4); k > 0; k--) out.push(...token(false))
    out.push(W.INVOKE, int(0, defs.length))
  }
  for (let k = int(1, 25); k > 0; k--) out.push(...token(false))
  return Uint8Array.from(out)
}
const progs = Array.from({ length: N_PROGRAMS }, () => ({ script: program(), preimage: rnd() < 0.3 ? bytes(int(0, 200)) : null }))
// ★ and the shape a real covenant has: PREIMAGE, hashed, its words checked
for (let k = 0; k < 50; k++) progs.push({ script: Uint8Array.from([L.LIT16, ...le(1000, 2), W.PREIMAGE, L.LIT16, ...le(3000, 2), W.HASH256, L.LIT16, ...le(3000, 2), 32, ...(rnd() < 0.5 ? [] : [W['2DUP']]), W.DROP]), preimage: bytes(int(0, 300)) })
const phpOut = runPhp(progs.map(p => ({ script: hex(p.script), preimage: p.preimage ? hex(p.preimage) : null })))
let agree = 0, differ = 0, phpFaults = 0, stacks = 0, refusals = 0
const firstDiffs = [], faults = []
for (let k = 0; k < progs.length; k++) {
  const p = phpOut[k], j = await runJs(progs[k].script, progs[k].preimage)
  if (p.error !== undefined && !p.jf) { phpFaults++; if (faults.length < 5) faults.push({ script: hex(progs[k].script), php: latin1(unhex(p.error)), js: j.stack ? j.stack.join(' ') : latin1(unhex(j.error)) }); continue }
  const eq = p.stack ? same(p.stack, j.stack) : (p.error === j.error && p.diag === j.diag)
  if (eq) { agree++; p.stack ? stacks++ : refusals++ } else { differ++; if (firstDiffs.length < 8) firstDiffs.push({ script: hex(progs[k].script), php: p.stack ? p.stack.join(' ') : latin1(unhex(p.error)), js: j.stack ? j.stack.join(' ') : latin1(unhex(j.error)) }) }
}
for (const d of firstDiffs) console.log(`  ✗ differ  ${d.script}\n      php: ${d.php}\n      js:  ${d.js}`)
ok(differ === 0, `${agree} of ${progs.length - phpFaults} programs identical in both (${stacks} finished with a stack, ${refusals} refused, with the same message)`)
if (phpFaults) {
  console.log(`  ⚠ ${phpFaults} programs hit the PHP fault outside the interpreter (a defect: every refusal should be the interpreter's own):`)
  for (const f of faults) console.log(`      ${f.script}\n        php: ${f.php}\n        js:  ${f.js}`)
}
ok(phpFaults === 0, `no program made PHP fail outside the interpreter (${phpFaults})`)
if (!ecdsa) console.log('  ⚠ secp256k1 (PharLap2) not found beside this repo: CHECKSIG cases ran without a verifier')

console.log(`\n${fail ? '⚠' : '✅'}  ${pass} passed · ${fail} failed   [JF in JavaScript · against the PHP interpreter]`)
process.exit(fail ? 1 : 0)
