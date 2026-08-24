// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★★ BITCOIN RACERS ON A JETMORA TEST CHAIN — the quarter mile, tick by tick.
//
// ⚠ THE POINT IS NOT THE FEE. On a proof-of-work chain a car is compiled for ONE RUN AND NO OTHER: the
//   race is SIMULATED to its last tick before anything is minted, and the whole run is unrolled into a
//   single locking script. The covenant then refuses the car if its physics disagree.
//   ⇒ So the race is PREDICTED at mint. The driver cannot change their mind at tick 40.
//
// ★ Here every tick is an entry, and the throttle is a DECISION rather than a plan. Four races, four
//   endings — finish, off, blown, stopped — each individually witnessed and individually provable.
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { serializeEntry, entryHash } from './entry.mjs'
import * as M from './merkle.mjs'

const BASE = process.env.LOG ?? 'http://127.0.0.1:8787/log.php'
const MINT = process.env.BASIC ?? '/home/sundive/Documents/GitHub/grafverse/mint'
const hex = b => Buffer.from(b).toString('hex')
const unhex = h => [...Buffer.from(h, 'hex')]
const sha = b => [...createHash('sha256').update(Buffer.from(b)).digest()]

const P = await import(`${MINT}/src/racerPhysics.ts`)
const SH = await import(`${MINT}/src/shell.ts`)
const T = await import(`${MINT}/src/racerTick.ts`)
const R = P.ONE_RACE_REGS, S = 2 ** 32
const QUARTER = Math.round(402.336 * S)

const { publicKey, privateKey } = generateKeyPairSync('ed25519')
const pk = [...publicKey.export({ format: 'der', type: 'spki' }).subarray(-32)]
const signEd = m => [...nodeSign(null, Buffer.from(m), privateKey)]
const j = async (p, b) => { const r = await fetch(BASE + p, b ? { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) } : {})
  return { status: r.status, body: await r.json() } }

// The covenant's own source — one tick of it, which is what a log needs.
const tickSrc = T.tickLoopSrc(1)

const RACES = [
  ['finishes',   { eng: 8, tyr: 4, th: 8,  slip: 1000, tank: 50000 }],
  ['goes off',   { eng: 8, tyr: 2, th: 8,  slip: 1000, tank: 50000 }],
  ['grenades',   { eng: 8, tyr: 2, th: 14, slip: 400,  tank: 50000 }],
  ['runs dry',   { eng: 8, tyr: 2, th: 8,  slip: 400,  tank: 50000 }],
]

console.log(`\n  ═══ BITCOIN RACERS — THE QUARTER MILE, TICK BY TICK ═══\n`)
console.log(`  finish     ${(QUARTER / S).toFixed(1)} m · throttle 0..${R.THROTTLE_MAX} · blows above ${(R.BLOW_V / S).toFixed(1)} m/s or throttle ${R.BLOW_T} while spinning`)
console.log(`  covenant   one tick, ${tickSrc.split('\n').length} lines of BASIC\n`)

const all = []
for (const [label, cfg] of RACES) {
  const g = await j('?op=register', { source_hash: hex(sha(Buffer.from(tickSrc))),
    // ⚠⚠ PACKED, NOT JSON. This hash goes into a genesis commitment, and a commitment is anchored.
    //    `JSON.stringify` is not canonical — reorder the keys or add a space and the same car gets a
    //    different identity. ⇒ ON CHAIN IS ALWAYS PACKED BYTES; JSON is for off-chain only.
    //    ⏭ the compiled tick belongs here, packed the same way.
    script: hex(sha([cfg.eng, cfg.tyr, cfg.th, cfg.slip & 0xff, (cfg.slip >> 8) & 0xff,
                     ...Buffer.from(BigInt(cfg.tank).toString(16).padStart(8, '0'), 'hex')])),
    state: hex([cfg.eng, cfg.tyr, cfg.th, cfg.slip & 0xff]), authorised: [hex(pk)] })
  const genesis = g.body.genesis

  let st = { phase: SH.PHASE.ARMED, driver: new Array(20).fill(0), pool: new Array(36).fill(0),
             eng: cfg.eng, tyr: cfg.tyr, finish: QUARTER, slip: cfg.slip,
             green: 0, gap: 0, last: 0, s: 0, v: 0, n: 0 }
  let fuel = cfg.tank, ended = null, prevHash = new Array(32).fill(0)
  const seqs = []
  for (let i = 0; i < 400; i++) {
    let r
    try { r = P.racerRefTick(st, { throttle: cfg.th, lockTime: i + 1, fuel }, R) }
    catch (e) { ended = 'refused'; break }
    // ★ one tick, one entry. The state after the tick is the entry's output.
    const after = [...[st.n + 1, r.throttle].map(x => x & 0xff),
                   ...Buffer.from(BigInt(r.state.v).toString(16).padStart(16, '0'), 'hex'),
                   ...Buffer.from(BigInt(r.state.s).toString(16).padStart(16, '0'), 'hex'),
                   ...Buffer.from(BigInt(Math.max(0, fuel - r.burn)).toString(16).padStart(12, '0'), 'hex')]
    const entry = { version: 103, inputs: [{ prevEntry: prevHash, index: 0, unlocking: [], sequence: i }],
                    outputs: [{ value: BigInt(Math.max(0, fuel - r.burn)), locking: after }], locktime: 0 }
    const bytes = serializeEntry(entry)
    const res = await j('?op=append', { genesis, entry: hex(bytes), pubkey: hex(pk), signature: hex(signEd(bytes)) })
    if (res.status !== 201) { ended = 'append refused'; break }
    seqs.push(res.body.seq); prevHash = entryHash(entry)
    fuel = Math.max(0, fuel - r.burn); st = { ...r.state, phase: SH.PHASE.RACING }
    if (r.ended) { ended = r.ended; break }
    if (st.s >= st.finish) { ended = 'FINISH'; break }
  }
  const et = (ended ?? '?').toUpperCase()
  console.log(`  ${label.padEnd(10)} eng ${String(cfg.eng).padStart(2)} tyr ${String(cfg.tyr).padStart(2)} th ${String(cfg.th).padStart(2)} slip ${String(cfg.slip).padStart(4)}  ` +
    `${String(seqs.length).padStart(3)} entries  ${(st.s/S).toFixed(1).padStart(6)} m  ${(st.v/S).toFixed(2).padStart(5)} m/s  ⇒ ${et}`)
  all.push({ label, seqs, ended })
}

const info = (await j('?op=info')).body
console.log(`\n  log size ${info.size} entries across ${RACES.length} races · root ${info.root.slice(0,24)}…`)

console.log(`\n  ── every tick of every race, proved ──\n`)
let proved = 0, total = 0
for (const race of all) for (const seq of race.seqs) {
  total++
  const e = (await j(`?op=entry&seq=${seq}`)).body
  const p = (await j(`?op=inclusion&leaf=${seq}&size=${info.size}`)).body
  if (M.verifyInclusion(seq, p.tree_size, unhex(e.entry), p.proof.map(unhex), unhex(p.root))) proved++
}
console.log(`  inclusion proofs verified   ${proved}/${total}`)
console.log(`\n  ⇒ four races, four endings, ${total} individually provable ticks.`)
console.log(`    On a chain the run is unrolled and PREDICTED at mint — the driver cannot`)
console.log(`    change their mind at tick 40. Here the throttle is a decision, not a plan.`)
