// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ READ A THREAD BACK, AND CHECK EVERY TICK FROM THE GENESIS ══════════════════════════════════════════════════════
//
// A thread is a tip, ticked forward, only valid links. The reader takes what a thread service holds (op=genesis, op=tip,
// then op=entries page by page, through tools/thread-service.mjs) and checks each tick as the service checked it before
// it stored it:
//   the link        input 0 names HASH256 of the tick before it; the first tick names the genesis id
//   the form        the bytes are a covenant entry, canonically serialized (tools/entry.mjs)
//   the script      the output it spends, run against it, accepts it: judge() of tools/thread.mjs, the PHP judge's
//                   verdict. The first tick spends the genesis: one output, the genesis script, value 0 (server/append.php)
// and returns the thread's tip and its outputs: what a writer spends next. It also checks that it read the whole thread
// the service says it holds: op=tip is asked first, and the last page's tip and op=tip's count are compared with what was
// read, so a page cut short, a stale cache or a service that stops early is reported, never taken for the whole thread.
//
// ⚠⚠ NOTHING IS SKIPPED, AND NOTHING IS THROWN AWAY. His rule: "Threads can still be read and gaps noted, not silently
//   thrown away." Every entry the service lists is in `ticks`, by position, whatever it is; what is wrong with one is in
//   `problems`, and a pruned body is in `gaps`. A tick after a problem is still read and checked against what it spends,
//   so one bad tick never hides the rest. The reader decides nothing about the thread: a writer does
//   (tools/thread-writer.mjs extends only a tip it can stand behind).
//
//   readThread(service, genesisId, { crypto = jfCrypto, limit = 256, slack = 1024 }) → Promise<report>
//     limit            entries asked for per page (the service gives 256 at most)
//     slack            how many ticks past op=tip's count a read may run, for ticks appended while it reads; past that
//                      the reading stops, with a 'paging' problem
//     report.genesis   { id, sourceHash, script, state, authorised, commitment }: the service's genesis, its id checked
//     report.service   { seq, count }: op=tip's answer, asked before the first page
//     report.ticks     [{ position, seq, bytes, hash, entry, link, spent, verdict, pruned?, why? }], oldest first
//         position     1 for the first tick; seq is the service's own sequence number, across all its threads
//         link         true, false (a broken link), or null: not checked, because the body before it is pruned
//         spent        { locking, value }: the output it was judged against, or null when it was not judged
//         verdict      { accepted: true, stack } | { accepted: false, reason, reasonBytes, stack? } (the script refused
//                      it; the stack when the run ended without exactly one non-zero item)
//                      | { accepted: false, reason, ran: false } (it spends an output the tick before does not have:
//                      the service's words, "the tip has no output N to spend") | { noVerdict, message } (VersionError
//                      or JfHostError, the PHP judge's words) | null when it could not be judged, and `why` says why
//     report.gaps      [{ position, seq }]: each pruned body. Its tick cannot be checked, and nor can the link of the
//                      tick after it, nor that tick's script: the output it spends is in the pruned body
//     report.problems  [{ position, seq, kind, detail }], kind one of
//                      'malformed'          not a covenant entry, or not canonical
//                      'broken link'        input 0 does not name the tick before it
//                      'refused'            the script refused it, or it spends an output that is not there
//                      'no verdict'         this reader cannot judge it (an nVersion nothing here judges, a library missing)
//                      'unjudged'           the output it spends is in a pruned body, or in an entry that does not decode
//                      'inputs not judged'  more than one input: input 0 is judged, the others spend outputs of other
//                                           threads, which this reader does not hold (the service refuses such a tick)
//                      'paging'             the service's pages did not move forward (a page that repeats, or says
//                                           there is more and gives nothing), or ran past op=tip's count plus slack.
//                                           Reading stops there: never a loop
//                      'missing'            fewer ticks read than the service says it holds: the last seq read is not
//                                           the tip the last page names, or below op=tip's, or the count read is below
//                                           op=tip's count. position is where the missing ticks begin
//     report.tip       { position, seq, hash, bytes, entry, outputs, index, checked }: the newest tick read, or the
//                      genesis (position 0, seq null, its one output) when the thread has none. index is the tip's tick
//                      index: its nSequence (spec §3), 0 for the genesis. outputs is null when the tip's body is pruned,
//                      and then nothing can spend it. checked: its link and its script both held
//     report.count     how many ticks were read;  report.complete  no gaps and no problems
//
// ⚠ A HOLDER CAN RE-ENCODE A TIP'S PUSHES. The unlocking script must be byte pushes only, and no rule asks for the
//   shortest form of a push (his ruling, 23 Oct): a direct push of 64 bytes and STR8 of the same 64 bytes are both good.
//   So whoever holds a tick can rewrite its pushes without its key, and its hash changes while its meaning does not: the
//   reader reports the rewritten tip as whole, and cannot tell the two forms apart, since the service keeps no append
//   signature to show. The next tick's link exposes it: it names the hash of the form its writer signed on.
//
// ⚠ It reads from the genesis every time: O(n) in the thread's length, each tick judged. ⏭ A reader that resumes from a
//   tick it checked before is not built.
import { parseEntry, assertCanonical } from './entry.mjs'
import { sha256d } from './sha256.mjs'
import { judge, jfCrypto, VersionError, JfHostError } from './thread.mjs'

/** server/append.php's reason when a run ends without exactly one non-zero item: the writer gives the same words */
export const NOT_ONE = 'the script did not end with exactly one non-zero item'
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
/** Two byte strings, equal byte for byte */
function same(a, b) {
  if (a.length !== b.length) return false
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false
  return true
}

/**
 * @param {import('./thread-service.mjs').ThreadService} service
 * @param {Uint8Array|string} genesisId  32 bytes, or their hex
 * @param {{crypto?: object, limit?: number, slack?: number}} [options]
 *        crypto for the judge (tools/jf-crypto.mjs); entries per page; ticks a read may run past op=tip's count
 */
export async function readThread(service, genesisId, { crypto = jfCrypto, limit = 256, slack = 1024 } = {}) {
  const genesis = await service.genesis(genesisId)
  // what the service says it holds, asked first: ticks appended while the pages are read can only add to it
  const held = await service.tip(genesis.id)
  const report = { genesis, service: held, ticks: [], gaps: [], problems: [], tip: null, count: 0, complete: false }
  const problem = (position, seq, kind, detail) => report.problems.push({ position, seq, kind, detail })
  // what the next tick spends. The genesis has one output: its script, with a value of zero.
  let before = { hash: genesis.id, outputs: [{ value: 0n, locking: genesis.script }], why: null }
  let position = 0, after = -1, last = null, stuck = false
  while (!stuck) {
    const page = await service.entries(genesis.id, after, limit)
    last = page
    for (const { seq, bytes } of page.entries) {
      // each page must move forward: every seq past the one before it
      if (!Number.isInteger(seq) || seq <= after) {
        problem(position + 1, seq, 'paging', `the service gave seq ${seq} after seq ${after}: its pages do not move forward, so reading stops here`)
        stuck = true
        break
      }
      const t = await check(++position, seq, bytes, before, crypto, report)
      report.ticks.push(t.tick)
      before = t.next
      after = seq
    }
    if (stuck || !page.more) break
    if (page.entries.length === 0) {
      problem(position + 1, null, 'paging', `the service says there is more after seq ${after}, and gave no entries: reading stops here`)
      stuck = true
    } else if (position > held.count + slack) {
      problem(position + 1, null, 'paging', `${position} ticks read, and the service said it holds ${held.count}: more than ${slack} past that, so reading stops here`)
      stuck = true
    }
  }
  report.count = position
  // ⚠ The whole thread, or a shortfall reported: the last seq read against the tip the last page names and op=tip's
  if (!stuck) {
    const lastSeq = report.ticks.at(-1)?.seq ?? null
    const short = []
    if ((last?.tip ?? null) !== lastSeq) short.push(`the last page names seq ${last?.tip} as the tip, and the last tick read is seq ${lastSeq}`)
    if (held.seq !== null && (lastSeq === null || lastSeq < held.seq)) short.push(`op=tip named seq ${held.seq}, and the last tick read is seq ${lastSeq}`)
    if (position < held.count) short.push(`op=tip counted ${held.count} ticks, and ${position} were read`)
    if (short.length) problem(position + 1, last?.tip ?? held.seq, 'missing', `the thread's newest ticks were not read: ${short.join('; ')}`)
  }
  const tip = report.ticks.at(-1)
  report.tip = tip === undefined
    ? { position: 0, seq: null, hash: genesis.id, bytes: null, entry: null, outputs: before.outputs, index: 0, checked: true }
    : { position: tip.position, seq: tip.seq, hash: tip.hash, bytes: tip.pruned ? null : tip.bytes, entry: tip.entry,
        outputs: tip.entry?.outputs ?? null, index: tip.entry?.inputs[0].sequence ?? null,
        checked: tip.link === true && tip.verdict?.accepted === true }
  report.complete = report.gaps.length === 0 && report.problems.length === 0
  return report
}

/** One tick: its report, and what the tick after it spends. */
async function check(position, seq, b, before, crypto, report) {
  const tick = { position, seq, bytes: b, hash: null, entry: null, link: null, spent: null, verdict: null }
  const problem = (kind, detail) => report.problems.push({ position, seq, kind, detail })
  if (b.length === 0) {
    tick.pruned = true
    tick.why = 'pruned: the service no longer holds this body'
    report.gaps.push({ position, seq })
    return { tick, next: { hash: null, outputs: null, why: 'the output it spends is in a pruned body' } }
  }
  tick.hash = Uint8Array.from(sha256d(b))
  let e
  try { e = parseEntry(b); assertCanonical(b) }
  catch (x) {
    tick.why = `not a covenant entry: ${x.message}`
    problem('malformed', tick.why)
    return { tick, next: { hash: tick.hash, outputs: null, why: 'the output it spends is in an entry that does not decode' } }
  }
  tick.entry = e
  const input = e.inputs[0]
  tick.link = before.hash === null ? null : same(input.prevEntry, before.hash)
  if (tick.link === false) {
    tick.why = `it names ${hex(input.prevEntry)}, and the tick before it is ${hex(before.hash)}`
    problem('broken link', tick.why)
  } else if (before.outputs === null) {
    tick.why = before.why
    problem('unjudged', tick.why)
  } else {
    const spent = before.outputs[input.index]
    if (spent === undefined) {
      tick.verdict = { accepted: false, reason: `the tip has no output ${input.index} to spend`, ran: false }
      problem('refused', tick.verdict.reason)
    } else {
      tick.spent = { locking: spent.locking, value: spent.value }
      try {
        const v = await judge(e, 0, spent.locking, spent.value, crypto)
        // A run that ends without exactly one non-zero item leaves its stack and no error: the service's reason then is
        // its own words for it (server/append.php)
        tick.verdict = v.accepted ? { accepted: true, stack: v.stack }
                     : v.stack !== undefined ? { accepted: false, stack: v.stack, reason: NOT_ONE, reasonBytes: new TextEncoder().encode(NOT_ONE) }
                     : { accepted: false, reason: v.error, reasonBytes: v.errorBytes }
      } catch (x) {
        if (!(x instanceof VersionError || x instanceof JfHostError)) throw x
        tick.verdict = { noVerdict: x.constructor.name, message: x.message }
      }
      if (tick.verdict.noVerdict) problem('no verdict', tick.verdict.message)
      else if (!tick.verdict.accepted) problem('refused', tick.verdict.reason)
    }
  }
  if (e.inputs.length > 1)
    problem('inputs not judged', `${e.inputs.length - 1} more input${e.inputs.length > 2 ? 's' : ''}: input 0 is judged, and the outputs the others spend are not held here`)
  return { tick, next: { hash: tick.hash, outputs: e.outputs, why: null } }
}
