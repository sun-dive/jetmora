// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ THE TRIAL RUN — the first time phase 1 and phase 2 touch.
//
// A real covenant is compiled, ticked through the interpreter, and every state transition is written
// to a running log as an entry. Then an INDEPENDENT pass reads the log back, replays each transition,
// and checks the physics agrees — plus an inclusion proof for every entry against the signed head.
//
// ⚠ Nothing here trusts the log. It is a witness: it records what it was given and never validates.
//   Everything the log says is checked against a recomputation.
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { evaluate } from './interpreter.mjs'
import { serialize } from './serialize.mjs'
import { bsvToJetmora } from './transcode.mjs'
import { serializeEntry, entryHash } from './entry.mjs'
import * as M from './merkle.mjs'

const BASE = process.env.LOG ?? 'http://127.0.0.1:8787/log.php'
const MINT = process.env.BASIC ?? '/home/sundive/Documents/GitHub/grafverse/mint'
const hex = b => Buffer.from(b).toString('hex')
const unhex = h => [...Buffer.from(h, 'hex')]
const sha256 = b => [...createHash('sha256').update(Buffer.from(b)).digest()]

const L = await import(`${MINT}/src/betaLane.ts`)
const { compileState } = await import(`${MINT}/src/basic.ts`)

// ── the covenant ─────────────────────────────────────────────────────────────────────────────
const inputs = L.laneInputNames()
const consts = L.laneConsts(L.BETA_LANE_REGS, L.AURORA_FIG8)
const HEADER = [0x01, 0x50], SUFFIX = [0x51, 0x52, 0x93]
const fieldOffset = HEADER.length + 1
const st = compileState(L.LANE_SRC, { fieldOffset, consts, stack: [...inputs, 'spenderOutputs', 'newValue'] })
const script = serialize(bsvToJetmora(st.ops))

const num = n => { n = BigInt(n); if (n === 0n) return []
  const g = n < 0n; let x = g ? -n : n; const o = []
  while (x > 0n) { o.push(Number(x & 0xffn)); x >>= 8n }
  if (o[o.length-1] & 0x80) o.push(g ? 0x80 : 0); else if (g) o[o.length-1] |= 0x80; return o }
const fixed = (n, w) => { n = BigInt(n); const g = n < 0n; let x = g ? -n : n
  const o = new Array(w).fill(0)
  for (let i = 0; i < w && x > 0n; i++, x >>= 8n) o[i] = Number(x & 0xffn)
  if (g) o[w-1] |= 0x80; return o }
const scriptCodeFor = v => {
  const out = [...HEADER]
  for (const f of st.layout) out.push(f.width, ...(f.bytes ? v[f.name] : fixed(v[f.name] ?? 0, f.width)))
  return [...out, ...SUFFIX]
}
const readField = (sc, name) => {
  let off = fieldOffset
  for (const f of st.layout) {
    if (f.name === name) { const b = sc.slice(off, off + f.width); let v = 0n
      for (let i = f.width - 1; i >= 0; i--) v = (v << 8n) | BigInt(i === f.width-1 ? (b[i] & 0x7f) : b[i])
      return (b[f.width-1] & 0x80) ? -v : v }
    off += 1 + f.width
  }
  throw new Error(`no field ${name}`)
}

// ── an author key, and the genesis it authorises ─────────────────────────────────────────────
const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const pk = [...publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const signEd = m => [...nodeSign(null, Buffer.from(m), privateKey)]

const j = async (path, body) => {
  const r = await fetch(BASE + path, body ? {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {})
  return { status: r.status, body: await r.json() }
}

let state = { phase: 1, section: 0, lap: 0, v: L.f(0.6), fuel: 40000, t: 0, eng: 14, tyr: 10, dia: 10,
              raceId: new Array(32).fill(9), driver: new Array(24).fill(3) }

const reg = await j('?op=register', {
  source_hash: hex(sha256(Buffer.from(L.LANE_SRC))),   // ⏭ H(source); §7 wants H(AST), not settled yet
  script: hex(script), state: hex(scriptCodeFor(state)), authorised: [hex(pk)],
})
if (reg.status !== 201) { console.log('register failed:', reg.body); process.exit(1) }
const genesis = reg.body.genesis
console.log(`\n  ── THE TRIAL: a race, recorded ──\n`)
console.log(`  covenant   ${script.length} B · ${st.layout.length} state fields`)
console.log(`  genesis    ${genesis.slice(0, 24)}…`)

// ── run the race, appending each tick ────────────────────────────────────────────────────────
const TICKS = 24, THROTTLE = 10
const history = []
let prevHash = new Array(32).fill(0), seq0 = null
for (let tick = 0; tick < TICKS; tick++) {
  const sc = scriptCodeFor(state)
  const initial = [...inputs.map(n => num(/^th/.test(n) ? THROTTLE : 0)), num(0), num(1), sc]
  const r = evaluate(script, { stack: initial })
  if (!r.ok) { console.log(`  tick ${tick}: covenant refused — ${r.error}`); break }
  const next = r.stack[r.stack.length - 1]

  const entry = { version: 103,
    inputs: [{ prevEntry: prevHash, index: 0, unlocking: [], sequence: tick }],
    outputs: [{ value: 0n, locking: next }], locktime: 0 }
  const bytes = serializeEntry(entry)
  const res = await j('?op=append', { genesis, entry: hex(bytes), pubkey: hex(pk), signature: hex(signEd(bytes)) })
  if (res.status !== 201) { console.log(`  tick ${tick}: append refused — ${JSON.stringify(res.body)}`); break }
  if (seq0 === null) seq0 = res.body.seq

  history.push({ seq: res.body.seq, before: sc, after: next, tick })
  prevHash = entryHash(entry)
  state = { ...state, v: Number(readField(next, 'v')), section: Number(readField(next, 'section')),
            lap: Number(readField(next, 'lap')), fuel: Number(readField(next, 'fuel')),
            t: Number(readField(next, 't')), phase: Number(readField(next, 'phase')) }
  if (state.phase !== 1) { console.log(`  tick ${tick}: phase ${state.phase} — the race ended here`); break }
}
console.log(`  recorded   ${history.length} ticks as entries ${seq0}..${seq0 + history.length - 1}`)
const last = history[history.length - 1]
console.log(`  final      v=${(Number(readField(last.after,'v'))/2**32).toFixed(3)} m/s · section ${readField(last.after,'section')} · lap ${readField(last.after,'lap')} · fuel ${readField(last.after,'fuel')}`)

// ── ⇒ AND NOW A COLD VERIFIER, TRUSTING NOTHING ──────────────────────────────────────────────
console.log(`\n  ── an independent pass, trusting nothing ──\n`)
const info = (await j('?op=info')).body
let replayed = 0, proved = 0, wrong = 0
for (const h of history) {
  const e = (await j(`?op=entry&seq=${h.seq}`)).body
  const got = unhex(e.entry)
  // ★ 1. replay the physics: does this transition follow from the previous state under the script?
  const initial = [...inputs.map(n => num(/^th/.test(n) ? THROTTLE : 0)), num(0), num(1), h.before]
  const r = evaluate(script, { stack: initial })
  const recomputed = r.ok ? r.stack[r.stack.length - 1] : null
  recomputed && hex(recomputed) === hex(h.after) ? replayed++ : wrong++
  // ★ 2. and prove the entry is in the log
  const p = (await j(`?op=inclusion&leaf=${h.seq}&size=${info.size}`)).body
  M.verifyInclusion(h.seq, p.tree_size, got, p.proof.map(unhex), unhex(p.root)) ? proved++ : wrong++
}
console.log(`  physics replayed and agreed   ${replayed}/${history.length}`)
console.log(`  inclusion proofs verified     ${proved}/${history.length}`)
console.log(`  disagreements                 ${wrong}`)
