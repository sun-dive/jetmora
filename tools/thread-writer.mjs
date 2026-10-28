// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ THE WRITER: a tick built from the tip, its script run, the append signed and sent ══════════════════════════════
//
// What a page uses to tick a thread forward, so that no app brings its own writer. One tick, in order:
//   1  the tip: the service's tip when it is a tick this writer recorded for the thread itself; otherwise the reader's
//      (tools/thread-reader.mjs), which checked every tick from the genesis, and only a tip this writer can stand
//      behind (below)
//   2  the service's own limits (server/append.php), before anything is recorded or signed: a tick over 100,000 bytes,
//      or a genesis whose authorised set needs more than one signature, is one the service cannot store: ServiceLimit
//   3  the skeleton: the tick with its unlocking script empty, built by tick() of tools/thread.mjs, a port of
//      CovenantThread::tick, naming the version the lock of the output it spends declares. Its preimage covers
//      everything but the unlocking script, so HASH256 of it names the successor before anything is signed
//   4  the ledger records that successor for the output it spends BEFORE anything is signed (below)
//   5  the caller's unlock(preimage, tip) builds the unlocking script: the covenant's own signature
//   6  the judge runs the script, as the service will (tools/thread.mjs judge). A tick it refuses is never sent: the
//      writer throws TickRefused with the script's reason, and takes its record back, since nothing left this writer
//   7  the ledger records the tick's bytes, BEFORE they are sent
//   8  the append signature, over the entry bytes, and the POST to the thread service (tools/thread-service.mjs)
//
// ══ STRICT WRITING: THE TICK LEDGER ══
// His rules: only an unspent output can be spent; "Strict writing is more important than strict reading." A writer
// never signs two different successors of one spent output, whatever a service shows it, and across a page reload.
// The ledger holds a record for each OUTPUT this writer has spent, keyed by that output: HASH256 of the tick it belongs
// to (the genesis id for the genesis's one output) and its index. One ledger serves every thread a page writes, so an
// output is known as spent whatever thread a host files it under:
//     spent <tick> <index>  →  { thread, at, next, hash, bytes, step }
//         thread       the genesis id of the thread the successor was written for;  at  the spent tick's tick index
//         next         HASH256 of the successor's preimage: the transition, named before anything is signed
//         hash, bytes  the successor's HASH256 and its bytes, once signed. Kept for good: they are the owner's own ticks,
//                      and what puts a thread back after a host has lost them (resend)
//         step         what built the successor, until its bytes are recorded
// and before signing a successor of an output it decides:
//     no record                                 record this successor, and sign
//     this thread's record, the same successor  sign it again; once its bytes are recorded, send exactly those bytes
//     any other record                          refuse: TipAlreadyAdvanced. resend() sends this thread's recorded one
// The decision and the record are one atomic update of the ledger, so two tabs of one page cannot both record a
// successor of one output; and the bytes are recorded only if the record is still this one, so a tab never sends bytes
// another tab's record does not name.
//
// ══ THE TIP IT STANDS ON ══
// His rule: the writer extends only a tip it can stand behind. The ledger also keeps, per thread, this writer's newest
// tick the service confirmed (a 201, or a 409 showing that very tick as the tip):
//     thread <genesis>  →  { hash, index, seq }
// and open() stands on the tip the reader returns only when one of these holds:
//   - the tip is a tick this writer recorded for this thread: it built it on the output it spends and judged it
//   - this writer recorded a successor of one of the tip's outputs for this thread: it stood on the tip before, and the
//     record decides what may follow (the same successor, or resend)
//   - every tick after this writer's newest confirmed tick (after the genesis, when it has none in this thread) is
//     linked and judged accepted by the reader, or is this writer's own. A pruned body, or a tick 'unjudged', with
//     'no verdict' or with 'inputs not judged' there stops it: ThreadBroken, with the reason
// Wherever they are, a broken link, a refused tick, an entry that is not one, and a read the service did not let finish
// ('missing', 'paging') stop it too: ThreadBroken. And when this writer's newest confirmed tick is not in the thread at
// all (and neither of the first two holds), the service is rolled back below it or shows a fork: TipRolledBack.
// ⚠ The tick index is the tip's nSequence (spec §3: "nSequence: the tick index"), 0 for the genesis, read from the tip's
//   own bytes. A tick's nSequence must be past its tip's: the writer refuses one that is not.
//
// ══ THE API ══
//   new ThreadWriter({ service, genesis, key, unlock, ledger, crypto = jfCrypto })
//       service  a ThreadService;  genesis  the thread's id (32 bytes or hex)
//       key      the append key: { publicKey, sign(bytes) → signature }, async allowed. Ed25519 (32-byte key) signs the
//                entry bytes; a secp256k1 key signs appendSighash(bytes) (tools/thread.mjs), as server/append.php checks
//       unlock   (preimage, tip) → the unlocking script: basicUnlock(key) for a BASIC covenant. A number unlock.size,
//                the unlocking script's length, lets the size limit be checked before anything is signed
//       ledger   the tick ledger: by default indexedDbLedger() where IndexedDB exists, so a page that names none keeps
//                its records across a reload; memory otherwise, one ledger for every writer in the process
//       crypto   what the judge runs the script with (tools/jf-crypto.mjs)
//   open() → { tip, report }            find the tip (report is the reader's, or null when the tip is this writer's own
//                                       tick). Throws ThreadBroken or TipRolledBack (above): such a tip is not extended
//   tip                                 the tip it stands on: { position, seq, hash, bytes, entry, outputs, index }
//   write(next, { unlock }) → answer    next(tip) or an object: { outputs, sequence = tip.index + 1, index = 0, version },
//                                       index being which of the tip's outputs it spends, and version by default the one
//                                       that output's lock declares (another is refused by the judge: TickRefused)
//   resend({ unlock }) → answer | null  the successors this writer recorded for this thread, sent again in order from the
//                                       tip, each its very bytes: the recorded successor of the tip, then that tick's,
//                                       until one does not land. Its answer is the last one's, with answers, all of
//                                       them in order. null when nothing is recorded for the tip. A successor recorded
//                                       whose bytes are not (it was never signed to the end) is built again with
//                                       unlock, the writer's by default: give that tick's own when its unlocking script
//                                       carries more than the signature, as a covenant's INPUT asks
//   pending() → { hash, bytes, step, index } | null   the successor recorded for the tip, without sending it
// write() and resend() run one at a time per writer. They THROW when nothing was sent:
//     TickRefused (reason, reasonBytes)   the script refuses the tick, so it is not sent
//     NoVerdict                           the judge cannot judge it here, or the lock it spends declares no version,
//                                         so it is not sent
//     ServiceLimit (limit)                the service could not store it: 'entryBytes' or 'signatures'
//     TipAlreadyAdvanced (record)         another successor of this output is recorded
//     TipRolledBack (mine, tip)           from open(): this writer's newest confirmed tick is not in the thread
//     ThreadBroken (report, problem)      from open(): a tip it cannot stand behind, and why
// and RETURN the service's answer when it was sent: { status, hash, bytes, entry, landed, ... }
//     201  landed: seq, and tip, the new tip the writer now stands on
//     409  the tip was spent: serviceTip { seq, count, hash, bytes }, the service's tip, fetched. landed is true when that
//          is this very tick (an earlier send whose answer was lost); otherwise the writer stands on no tip until opened
//          again, and signs nothing on its own: the caller decides
//     422  the service's script refused it: reason, reasonBytes. The judge here accepted it, so one of the two is wrong
//     501  no verdict on the service;  0  no answer, so whether it landed is not known: resend() it
//     other  the service's own checks (a key it does not authorise, a bad signature): error
//
//   SERVICE_LIMITS                       { entryBytes: 100000, signatures: 1 }: what server/append.php stores
//   memoryLedger()                       a ledger in memory: for node, and for a test
//   indexedDbLedger({ name, store })     a ledger in IndexedDB: each decision is one readwrite transaction. One object
//                                        store holds every ledger of a database, `store` being a prefix on its keys, so
//                                        any store name works. Give every thread of a page the same one
//   ed25519Signer({ privateKey, publicKey }) → key     a WebCrypto Ed25519 key pair as a key here. WebCrypto signs by
//                                        RFC 8032, deterministically, so a successor signed again has the same bytes
//   basicUnlock(key, inputs = []) → unlock  what a BASIC covenant's frame asks for (basic/basic-jf.mjs, rule 1): the
//                                        key's Ed25519 signature over HASH256(PREIMAGE), and the key, as two direct
//                                        pushes; then what the covenant's INPUT line names, in its order: bytes (a
//                                        Uint8Array or an array of byte values), or a number for a % input. Anything
//                                        else is refused: WriterError
// A ledger is { get(key), update(key, fn) }: update calls fn(record or null) once, synchronously, and stores what it
// returns (null deletes), atomically. Records are plain objects of strings and numbers.
import { tick, judge, declaredVersion, jfCrypto, VersionError, JfHostError, AUTH_V1_KEYS, AUTH_V2_HASHES } from './thread.mjs'
import { parseEntry } from './entry.mjs'
import { sha256d, toHex } from './sha256.mjs'
import { readThread, NOT_ONE } from './thread-reader.mjs'
import { JF_LIT } from './ops-jf.mjs'

/**
 * What server/append.php refuses before it judges a tick: an entry over 100,000 bytes ('entry too large', 413), and an
 * append for a genesis whose authorised set needs more than one signature (501: the endpoint carries one).
 */
export const SERVICE_LIMITS = Object.freeze({ entryBytes: 100_000, signatures: 1 })

/** Something the writer will not do, or cannot: nothing was sent. */
export class WriterError extends Error {}
/** The script refuses the tick, so it was not sent. reasonBytes are the judge's refusal bytes, as the service gives them. */
export class TickRefused extends WriterError {
  constructor(reason, reasonBytes, built) { super(`the script refuses this tick: ${reason}`); this.reason = reason; this.reasonBytes = reasonBytes; this.tick = built }
}
/** The judge has no verdict here (VersionError or JfHostError), so the tick was not sent. */
export class NoVerdict extends WriterError {
  constructor(message, cause) { super(`no verdict: ${message}`); this.cause = cause }
}
/** The thread service could not store this tick, for a limit of its own: nothing was recorded, and nothing sent. */
export class ServiceLimit extends WriterError {
  constructor(limit, message) { super(message); this.limit = limit }
}
/** Another successor of this output is recorded: for this thread, resend() sends that one. */
export class TipAlreadyAdvanced extends WriterError {
  constructor(record, thread) {
    super(record.thread === thread ? 'this writer has already signed another successor of this tip: resend() sends that one'
                                   : `this writer has already spent this output, for thread ${record.thread}: it signs no other successor of it`)
    this.record = record
  }
}
/** This writer's newest confirmed tick is not in the thread the service shows: it is rolled back, or shows a fork. */
export class TipRolledBack extends WriterError {
  constructor(mine, tip) {
    super(`this writer's newest confirmed tick, at tick index ${mine.index}, is not in the thread the service shows, whose tip is at tick index ${tip.index}: `
        + 'the service is rolled back or shows a fork, and this writer signs no successor of it')
    this.record = mine; this.tip = tip
  }
}
/** A tip this writer cannot stand behind: problem says which tick, and why. */
export class ThreadBroken extends WriterError {
  constructor(report, problem) {
    super(`this writer cannot stand behind the thread's tip: tick ${problem.position}, ${problem.kind}: ${problem.detail}`)
    this.report = report; this.problem = problem
  }
}

/** Problems that stop a writer wherever they are: a thread its script did not permit, or a read the service cut short */
const BROKEN = new Set(['malformed', 'broken link', 'refused', 'missing', 'paging'])
const bytes = b => b instanceof Uint8Array ? b : Uint8Array.from(b)
const unhex = h => Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))
/** Two byte strings, equal byte for byte */
function same(a, b) {
  if (a.length !== b.length) return false
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false
  return true
}
const push = b => { if (b.length < 1 || b.length > 72) throw new WriterError('a direct push is 1 to 72 bytes'); return [b.length, ...b] }
const spentKey = (tick, index) => `spent ${tick} ${index}`
const threadKey = id => `thread ${id}`

/**
 * The ledger's rule, before a successor of an output is signed.
 * @param {object|null} rec  the output's record;  @param {string} thread  this writer's thread;  @param {string} next  the successor
 * @returns {'record'|'same'|'advanced'}
 */
function decide(rec, thread, next) {
  if (rec === null) return 'record'
  if (rec.thread === thread && rec.next === next) return 'same'
  return 'advanced'
}

/** The bytes a tick will take, its unlocking script `unlocking` bytes long, as serializeEntry lays them out */
const varintSize = n => n < 0xfd ? 1 : n <= 0xffff ? 3 : 5
function entrySize(step, unlocking) {
  let n = 4 + 1 + 32 + 4 + varintSize(unlocking) + unlocking + 4 + varintSize(step.outputs.length) + 4
  for (const o of step.outputs) n += 8 + varintSize(o.locking.length) + o.locking.length
  return n
}

export class ThreadWriter {
  #tip = null
  #turn = Promise.resolve()
  #fields = null

  constructor({ service, genesis, key, unlock, ledger = defaultLedger(), crypto = jfCrypto }) {
    if (typeof unlock !== 'function') throw new TypeError('unlock(preimage, tip) builds the unlocking script, and is required')
    if (!key?.publicKey?.length || typeof key.sign !== 'function') throw new TypeError('key is { publicKey, sign(bytes) }')
    this.service = service
    this.genesis = typeof genesis === 'string' ? unhex(genesis) : bytes(genesis)
    this.id = toHex(this.genesis)
    this.key = key
    this.unlock = unlock
    this.ledger = ledger
    this.crypto = crypto
  }

  get tip() { return this.#tip }

  /** Calls run one at a time: each starts once the one before it has finished, however that one ended. */
  #oneAtATime(task) {
    const ahead = this.#turn
    let finished
    this.#turn = new Promise(resolve => { finished = resolve })
    return ahead.then(task).finally(finished)
  }

  open() { return this.#oneAtATime(() => this.#open()) }
  write(next, { unlock = this.unlock } = {}) { return this.#oneAtATime(() => this.#write(next, unlock)) }
  resend({ unlock = this.unlock } = {}) { return this.#oneAtATime(() => this.#resend(unlock)) }
  pending() {
    return this.#oneAtATime(async () => {
      if (this.#tip === null) await this.#open()
      const found = await this.#recordOn(this.#tip)
      if (found === null) return null
      const { rec, index } = found
      return { hash: rec.hash ? unhex(rec.hash) : null, bytes: rec.bytes ? unhex(rec.bytes) : null, step: stepFrom(rec, index), index }
    })
  }

  /** The key of the record for output `index` of the tick named by `tick` (hex) */
  #key(tick, index) { return spentKey(tick, index) }

  /** Whether a tick is one this writer recorded for this thread: its spent output's record names its hash */
  async #own(entry, hash) {
    const input = entry.inputs[0]
    const rec = await this.ledger.get(this.#key(toHex(input.prevEntry), input.index))
    return rec !== null && rec.thread === this.id && rec.hash === toHex(hash)
  }

  /** The successor this writer recorded for this thread of one of the tip's outputs: { rec, index }, or null */
  async #recordOn(tip) {
    for (let i = 0; i < (tip.outputs?.length ?? 0); i++) {
      const rec = await this.ledger.get(this.#key(toHex(tip.hash), i))
      if (rec !== null && rec.thread === this.id) return { rec, index: i }
    }
    return null
  }

  async #open() {
    this.#tip = null
    // The service's tip is a tick this writer recorded and judged before sending it: nothing to read
    const st = await this.#serviceTip()
    if (st.bytes) {
      let entry = null
      try { entry = parseEntry(st.bytes) } catch {}
      if (entry !== null && await this.#own(entry, st.hash)) {
        this.#tip = { position: st.count, seq: st.seq, hash: st.hash, bytes: st.bytes, entry, outputs: entry.outputs,
                      index: entry.inputs[0].sequence, checked: true }
        return { tip: this.#tip, report: null }
      }
    }
    const report = await readThread(this.service, this.genesis, { crypto: this.crypto })
    this.#fields = report.genesis
    const broken = report.problems.find(p => BROKEN.has(p.kind))
    if (broken) throw new ThreadBroken(report, broken)
    if (report.tip.outputs === null) throw new WriterError('the thread\'s tip is pruned: no output of it is held to spend')
    await this.#standBehind(report)
    this.#tip = report.tip
    return { tip: this.#tip, report }
  }

  /** Throws unless this writer can stand behind the report's tip (the header's rule) */
  async #standBehind(report) {
    const { tip, ticks } = report
    if (tip.entry !== null && await this.#own(tip.entry, tip.hash)) return
    if (await this.#recordOn(tip) !== null) return
    const mine = await this.ledger.get(threadKey(this.id))
    let from = 0
    if (mine !== null) {
      const at = ticks.find(t => t.hash !== null && toHex(t.hash) === mine.hash)
      if (at === undefined) {
        if (report.gaps.length === 0) throw new TipRolledBack(mine, tip)
        const g = report.gaps.at(-1)
        throw new ThreadBroken(report, { position: g.position, seq: g.seq, kind: 'pruned',
          detail: `this writer's newest tick, at tick index ${mine.index}, is not among the ticks the service holds whole, so the ticks after it cannot be judged` })
      }
      from = at.position
    }
    for (const t of ticks) {
      if (t.position <= from) continue
      const p = report.problems.find(x => x.position === t.position)
      if (p === undefined && t.link === true && t.verdict?.accepted === true) continue
      if (t.entry !== null && await this.#own(t.entry, t.hash)) continue
      throw new ThreadBroken(report, p ?? { position: t.position, seq: t.seq, kind: t.pruned ? 'pruned' : 'unjudged',
                                            detail: t.pruned ? 'its body is pruned, so it cannot be judged' : t.why ?? 'not judged' })
    }
  }

  async #write(next, unlock) {
    if (this.#tip === null) await this.#open()
    const tip = this.#tip
    const step = { index: 0, sequence: tip.index + 1, ...(typeof next === 'function' ? await next(tip) : next) }
    if (!Number.isInteger(step.sequence) || step.sequence <= tip.index || step.sequence > 0xffffffff)
      throw new WriterError(`nSequence is the tick index (spec §3): this tick's must be a u32 past the tip's, ${tip.index}`)
    return this.#send(tip, step, unlock)
  }

  async #resend(unlock) {
    if (this.#tip === null) await this.#open()
    const answers = []
    for (let found = await this.#recordOn(this.#tip); found !== null; found = await this.#recordOn(this.#tip)) {
      const a = await this.#send(this.#tip, stepFrom(found.rec, found.index), unlock)
      answers.push(a)
      if (!a.landed) break
    }
    return answers.length === 0 ? null : { ...answers.at(-1), answers }
  }

  /** Step 2 of the header: what the service could not store is refused before anything is recorded or signed */
  async #withinLimits(step, unlock) {
    const a = (this.#fields ??= await this.service.genesis(this.genesis)).authorised
    if ((a[0] === AUTH_V1_KEYS || a[0] === AUTH_V2_HASHES) && a[1] > SERVICE_LIMITS.signatures)
      throw new ServiceLimit('signatures', `this thread's genesis needs ${a[1]} of its keys to sign each append, and the thread service `
        + `carries ${SERVICE_LIMITS.signatures} (server/append.php answers 501): nothing is recorded or signed`)
    const size = entrySize(step, Number.isInteger(unlock?.size) ? unlock.size : 1)
    if (size > SERVICE_LIMITS.entryBytes)
      throw new ServiceLimit('entryBytes', `this tick is ${size} bytes${Number.isInteger(unlock?.size) ? '' : ' or more'}, and the thread `
        + `service stores ${SERVICE_LIMITS.entryBytes} at most (server/append.php answers 413): nothing is recorded or signed`)
  }

  /** Steps 2 to 8 of the header, for one tip and one step. */
  async #send(tip, step, unlock) {
    const spent = tip.outputs[step.index]
    if (spent === undefined) throw new TickRefused(`the tip has no output ${step.index} to spend`, null, null)
    // the tick names the version the spent output's lock declares, unless the step names one; a lock that declares none
    // gets no verdict, so nothing is recorded or signed
    if (step.version === undefined) {
      try { step = { ...step, version: declaredVersion(spent.locking) } }
      catch (e) { if (e instanceof VersionError) throw new NoVerdict(e.message, e); throw e }
    }
    await this.#withinLimits(step, unlock)
    const key = this.#key(toHex(tip.hash), step.index)
    let next = null, fresh = false, recorded = null
    // 3 and 4: the skeleton's preimage names the successor; the ledger decides, and records it, before anything is signed
    const build = async pre => {
      next = toHex(sha256d(pre))
      let said = null, seen = null
      await this.ledger.update(key, rec => {
        seen = rec
        said = decide(rec, this.id, next)
        return said === 'record' ? { thread: this.id, at: tip.index, next, hash: null, bytes: null, step: stepRecord(step) } : rec
      })
      if (said === 'advanced') throw new TipAlreadyAdvanced(seen, this.id)
      fresh = said === 'record'
      // the same successor, its bytes recorded: its own unlocking script, so the bytes are the recorded bytes exactly
      if (seen?.bytes) { recorded = seen.bytes; return parseEntry(unhex(recorded)).inputs[0].unlocking }
      return unlock(pre, tip)                                   // 5
    }
    let built
    try { built = await tick(tip.hash, step.index, spent.locking, spent.value, step.outputs, step.sequence, build, step.version) }
    catch (e) { if (fresh) await this.#takeBack(key, next); throw e }
    if (recorded && toHex(built.bytes) !== recorded) throw new WriterError('the recorded successor did not build again to its own bytes')
    // the size again, now that the unlocking script is known: an unlock that gave no size could still take it over
    if (!recorded && built.bytes.length > SERVICE_LIMITS.entryBytes) {
      if (fresh) await this.#takeBack(key, next)
      throw new ServiceLimit('entryBytes', `this tick is ${built.bytes.length} bytes, and the thread service stores ${SERVICE_LIMITS.entryBytes} at most `
        + '(server/append.php answers 413): it is not sent')
    }

    // 6. the script runs here first, as the service will run it
    let v
    try { v = await judge(built.entry, 0, spent.locking, spent.value, this.crypto) }
    catch (e) {
      if (fresh) await this.#takeBack(key, next)
      if (e instanceof VersionError || e instanceof JfHostError) throw new NoVerdict(e.message, e)
      throw e
    }
    if (!v.accepted) {
      if (fresh) await this.#takeBack(key, next)
      throw new TickRefused(v.error ?? NOT_ONE, v.errorBytes ?? new TextEncoder().encode(NOT_ONE), built)
    }

    // 7. the bytes are recorded before they leave, only if the record is still this successor's
    if (!recorded) {
      const b = toHex(built.bytes)
      let kept = false, now = null
      await this.ledger.update(key, rec => {
        now = rec
        kept = rec !== null && rec.thread === this.id && rec.next === next && (rec.bytes === null || rec.bytes === b)
        return kept ? { ...rec, hash: toHex(built.hash), bytes: b, step: null } : rec
      })
      // another tab of this writer recorded something else for this output meanwhile: this tick is not sent
      if (!kept && now !== null) throw new TipAlreadyAdvanced(now, this.id)
      if (!kept) throw new WriterError('this tip\'s record is gone from the ledger: the tick is not sent')
    }

    // 8. the append signature, over the entry bytes, and the service's answer
    const signature = await this.key.sign(built.bytes)
    const a = await this.service.append(this.genesis, built.bytes, this.key.publicKey, signature)
    return this.#answer(a, tip, step, built)
  }

  /** Take back a record this call made, when nothing was sent: only if it is still the record this call put. */
  async #takeBack(key, next) {
    await this.ledger.update(key, rec => rec !== null && rec.thread === this.id && rec.next === next && rec.bytes === null ? null : rec)
  }

  /** A tick of this writer's the service confirmed: the thread's newest confirmed tick, unless a newer one is noted */
  async #confirmed(built, index, seq) {
    await this.ledger.update(threadKey(this.id), p => p === null || index > p.index ? { hash: toHex(built.hash), index, seq } : p)
  }

  async #answer(a, tip, step, built) {
    const out = { status: a.status, hash: built.hash, bytes: built.bytes, entry: built.entry, landed: false }
    const successor = { position: tip.position + 1, seq: null, hash: built.hash, bytes: built.bytes, entry: built.entry,
                        outputs: built.entry.outputs, index: step.sequence, checked: true }
    if (a.status === 201) {
      successor.seq = a.seq
      this.#tip = successor
      await this.#confirmed(built, step.sequence, a.seq)
      return { ...out, landed: true, seq: a.seq, tip: successor }
    }
    if (a.status === 409) {
      // Spent. The service's tip, fetched and reported; this writer signs no other successor on its own.
      const serviceTip = await this.#serviceTip()
      if (serviceTip.hash && same(serviceTip.hash, built.hash)) {
        successor.seq = serviceTip.seq
        successor.position = serviceTip.count
        this.#tip = successor
        await this.#confirmed(built, step.sequence, serviceTip.seq)
        return { ...out, error: a.error, landed: true, seq: serviceTip.seq, tip: successor, serviceTip }
      }
      this.#tip = null
      return { ...out, error: a.error, serviceTip }
    }
    return { ...out, error: a.error, ...(a.reasonBytes ? { reason: a.reason, reasonBytes: a.reasonBytes } : {}) }
  }

  /** The service's tip: { seq, count, hash, bytes }, hash being HASH256 of its body (the genesis id when it has none). */
  async #serviceTip() {
    try {
      const { seq, count } = await this.service.tip(this.genesis)
      if (seq === null) return { seq, count, hash: this.genesis, bytes: null }
      const e = await this.service.entry(seq)
      if (e === null || e.pruned) return { seq, count, hash: null, bytes: null, pruned: e?.pruned === true }
      return { seq, count, hash: Uint8Array.from(sha256d(e.bytes)), bytes: e.bytes }
    } catch (x) {
      return { error: x.message, hash: null }
    }
  }
}

/** A step as the ledger keeps it until the bytes are recorded: strings and numbers only, so any storage can hold it. */
const stepRecord = s => ({ index: s.index, sequence: s.sequence, version: s.version,
                           outputs: s.outputs.map(o => ({ value: BigInt(o.value).toString(), locking: toHex(bytes(o.locking)) })) })
/** The step a record names: read from its bytes once they are recorded, from its step before */
function stepFrom(rec, index) {
  if (rec.bytes) {
    const e = parseEntry(unhex(rec.bytes))
    return { index, sequence: e.inputs[0].sequence, version: e.version, outputs: e.outputs.map(o => ({ value: o.value, locking: bytes(o.locking) })) }
  }
  const r = rec.step
  return { index: r.index, sequence: r.sequence, version: r.version, outputs: r.outputs.map(o => ({ value: BigInt(o.value), locking: unhex(o.locking) })) }
}

// ── the ledger's storage ────────────────────────────────────────────────────────────────────────────────────────────
/** A ledger in memory. */
export function memoryLedger() {
  const m = new Map()
  const copy = v => v === undefined || v === null ? null : JSON.parse(JSON.stringify(v))
  return {
    async get(key) { return copy(m.get(key)) },
    async update(key, fn) {
      const v = fn(copy(m.get(key)))
      if (v === null) m.delete(key); else m.set(key, copy(v))
      return copy(v)
    },
  }
}

/** Where no ledger is named: IndexedDB where it exists, which a reload keeps; otherwise one ledger in memory for all */
const inMemory = memoryLedger()
const defaultLedger = () => globalThis.indexedDB ? indexedDbLedger() : inMemory

/**
 * A ledger in IndexedDB. Each update is one readwrite transaction: the record is read, decided on and written inside
 * it, with no wait between, so the browser runs no other transaction on the store in between.
 * ⚠ A database's object stores can be made only while it is opened at a new version. So every ledger keeps its records
 *   in one object store, `store` being a prefix on the keys: any number of store names share a database. Should a
 *   database of this name exist without that object store, it is opened once more at the next version, which makes it.
 * @param {{name?: string, store?: string, indexedDB?: IDBFactory}} [options]
 */
export function indexedDbLedger({ name = 'jetmora-ticks', store = 'ledger', indexedDB = globalThis.indexedDB } = {}) {
  const OBJECTS = 'records', prefix = `${store}:`
  let db = null
  const connect = version => new Promise((resolve, reject) => {
    const r = version === undefined ? indexedDB.open(name) : indexedDB.open(name, version)
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains(OBJECTS)) r.result.createObjectStore(OBJECTS) }
    r.onsuccess = () => {
      const d = r.result
      d.onversionchange = () => { d.close(); db = null }      // another page making the store: let it
      resolve(d)
    }
    r.onerror = () => reject(r.error)
  })
  const open = () => db ??= connect().then(d => {
    if (d.objectStoreNames.contains(OBJECTS)) return d
    const v = d.version + 1
    d.close()
    return connect(v)
  }).catch(e => { db = null; throw e })
  const run = (mode, body) => open().then(d => new Promise((resolve, reject) => {
    const tx = d.transaction(OBJECTS, mode)
    let out = null, fault = null
    body(tx.objectStore(OBJECTS), v => { out = v }, e => { fault = e; tx.abort() })
    tx.oncomplete = () => resolve(out)
    tx.onabort = tx.onerror = () => reject(fault ?? tx.error ?? new Error('the ledger transaction did not complete'))
  }))
  return {
    get: key => run('readonly', (os, done) => { const r = os.get(prefix + key); r.onsuccess = () => done(r.result ?? null) }),
    update: (key, fn) => run('readwrite', (os, done, fail) => {
      const r = os.get(prefix + key)
      r.onsuccess = () => {
        let v
        try { v = fn(r.result ?? null) } catch (e) { fail(e); return }
        if (v === null) os.delete(prefix + key); else os.put(v, prefix + key)
        done(v)
      }
    }),
  }
}

// ── keys ────────────────────────────────────────────────────────────────────────────────────────────────────────────
/** A WebCrypto Ed25519 key pair as a key: { publicKey (32 raw bytes), sign(bytes) → 64 bytes }. */
export async function ed25519Signer({ privateKey, publicKey }) {
  const subtle = globalThis.crypto.subtle
  const pub = new Uint8Array(await subtle.exportKey('raw', publicKey))
  return { publicKey: pub, sign: async b => new Uint8Array(await subtle.sign('Ed25519', privateKey, bytes(b))) }
}

/** A number a % input carries, as BIN2NUM reads it: unsigned, little-endian, in the fewest bytes, one at least */
function numberBytes(v) {
  let n = typeof v === 'bigint' ? v : Number.isSafeInteger(v) ? BigInt(v) : null
  if (n === null || n < 0n || n >= 1n << 63n) throw new WriterError('a number an input carries is a whole number from 0 to 2^63 - 1')
  const o = []
  do { o.push(Number(n & 0xffn)); n >>= 8n } while (n > 0n)
  return o
}
/** What an input pushes: bytes as they are, a Uint8Array or an array of byte values; a number as a % input reads it */
function inputBytes(v) {
  if (typeof v === 'number' || typeof v === 'bigint') return numberBytes(v)
  if (v instanceof Uint8Array) return v
  if (Array.isArray(v) && v.every(x => Number.isInteger(x) && x >= 0 && x <= 0xff)) return Uint8Array.from(v)
  throw new WriterError('an input is bytes, a Uint8Array or an array of byte values, or for a % input a whole number')
}
/** Bytes as one byte push, in the smallest form that holds them: a direct push to 72 bytes, then STR8, STR16, STR32 */
function bytePush(b) {
  const n = b.length, le = w => Array.from({ length: w }, (_, k) => (n >>> (8 * k)) & 0xff)
  const head = n <= 72 ? [n] : n <= 0xff ? [JF_LIT.STR8, n] : n <= 0xffff ? [JF_LIT.STR16, ...le(2)] : [JF_LIT.STR32, ...le(4)]
  const out = new Uint8Array(head.length + n)
  out.set(head); out.set(b, head.length)
  return out
}

/**
 * The unlocking script of a BASIC covenant's frame: <signature over HASH256(preimage)> <key>, two direct pushes, then
 * one push for each input the covenant's INPUT line names, in its order: bytes, or for a % input a number, pushed as
 * BIN2NUM reads it. Its size is known before anything is signed (an Ed25519 signature is 64 bytes), so the writer checks
 * the service's size limit first.
 */
export const basicUnlock = (key, inputs = []) => {
  const carried = inputs.map(v => bytePush(inputBytes(v)))
  const size = 2 + 64 + bytes(key.publicKey).length + carried.reduce((n, b) => n + b.length, 0)
  const unlock = async pre => {
    const sig = bytes(await key.sign(Uint8Array.from(sha256d(pre))))
    const parts = [push(sig), push(bytes(key.publicKey)), ...carried]
    const out = new Uint8Array(parts.reduce((n, b) => n + b.length, 0))
    let at = 0
    for (const b of parts) { out.set(b, at); at += b.length }
    return out
  }
  unlock.size = size
  return unlock
}
