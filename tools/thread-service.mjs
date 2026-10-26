// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ THE THREAD SERVICE, FROM A PAGE OR NODE: server/threads.php, asked and answered ══════════════════════════════════
//
// A client of the thread service's one endpoint (/threads/ on jetmora.org; server/threads.php). It uses fetch and
// nothing else, so the same file runs in a page and in node. Bytes are Uint8Array both ways; the service's hex never
// reaches a caller.
//
//   new ThreadService(base, { fetch, packed = false })
//       base     the endpoint, 'https://jetmora.org/threads/'
//       fetch    the fetch to use: the global one unless given (a test passes one that counts or drops requests)
//       packed   append and register in the packed form (bytes on the wire, a 4-byte big-endian length before each
//                field, as threads.php reads them); JSON when false. Packed works from the service's own origin only
//                (below). Reads are JSON either way: the packed form of op=entries carries no sequence numbers, so it
//                cannot be paged.
//   genesis(id) → { id, sourceHash, script, state, authorised, commitment }
//       the genesis as registered, its authorised set packed again from the service's JSON. ⚠ The id is computed from
//       the fields and must be the id asked for, or this throws: a service that gave another script for a genesis would
//       have every tick judged against the wrong lock.
//   tip(id) → { seq, count }       the newest entry's sequence number (null when the thread has none), and how many
//   entries(id, after = -1, limit = 256) → { entries: [{ seq, bytes }], tip, more }
//       one page of the thread, oldest first. ⚠ A pruned body is held as zero bytes: bytes.length === 0.
//   entry(seq) → { seq, bytes } | { seq, pruned: true } | null      one entry by its sequence number; null if none
//   register({ sourceHash, script, state, authorised }) → id
//       authorised packed (tools/thread.mjs: AUTH_OPEN or authorisedHashes). The id the service answers must be the id
//       the fields hash to (tools/thread.mjs create), or this throws.
//   append(genesis, entry, pubkey, signature) → { status, seq?, treeSize?, error?, reason?, reasonBytes? }
//       one tick, with the append signature over its bytes. NEVER throws for an answer: every status comes back, and a
//       request that got no answer comes back as status 0, because the writer must tell "refused" from "not known":
//         201  stored: seq, and treeSize          409  the tip it names is spent: another tick spent it first
//         422  the script refused it: reason as text, reasonBytes exactly    501  no verdict on that host
//         400, 402, 403, 404, 413, 507  the service's own checks; 0  no answer, so whether it landed is not known
//
// Every other method throws ServiceError for an answer it cannot use (an error status, a body that is not the JSON it
// should be), with the status and the service's words.
//
// ⚠ A PAGE ON ANOTHER ORIGIN (a page on its own domain, calling jetmora.org) reads and writes in JSON, and not in the
//   packed form. threads.php answers no CORS preflight: an OPTIONS gets 405 on append and register, and 400 on entries (measured
//   26 Oct on the staged service). So every request here is one a browser sends without a preflight: a GET carries
//   only Accept, and a JSON POST goes as text/plain, which threads.php reads as JSON, as it reads any body that is not
//   application/octet-stream. The packed form's application/octet-stream needs a preflight, so packed writes work from
//   the service's own origin only. tools/verify-writer.mjs measures both from a second origin.
import { sha256d } from './sha256.mjs'
import { create } from './thread.mjs'

/** An answer the client cannot use: an error status, no answer, or a body that is not what the service sends. */
export class ServiceError extends Error {
  constructor(message, status = 0, body = null) { super(message); this.status = status; this.body = body }
}

/** JSON is sent as text: threads.php reads any body that is not application/octet-stream as JSON, and text needs no preflight */
const JSON_AS_TEXT = 'text/plain;charset=UTF-8'
const HEX = /^(?:[0-9a-fA-F]{2})*$/
const unhex = h => {
  if (typeof h !== 'string' || !HEX.test(h)) throw new ServiceError(`the service gave ${JSON.stringify(h)?.slice(0, 40)} where hex belongs`)
  return Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))
}
const hex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const bytes = b => b instanceof Uint8Array ? b : Uint8Array.from(b)
const idHex = id => typeof id === 'string' ? (HEX.test(id) && id.length === 64 ? id.toLowerCase() : bad('a genesis id is 32 bytes'))
                                           : (id?.length === 32 ? hex(id) : bad('a genesis id is 32 bytes'))
function bad(m) { throw new TypeError(m) }
/** LP: a 4-byte big-endian length, then the bytes */
const lp = b => [(b.length >>> 24) & 0xff, (b.length >>> 16) & 0xff, (b.length >>> 8) & 0xff, b.length & 0xff, ...b]
/** Two byte strings, equal byte for byte */
function same(a, b) {
  if (a.length !== b.length) return false
  for (let k = 0; k < a.length; k++) if (a[k] !== b[k]) return false
  return true
}

export class ThreadService {
  /**
   * @param {string} base  the endpoint, ending in '/': 'https://jetmora.org/threads/'
   * @param {{fetch?: Function, packed?: boolean}} [options]
   */
  constructor(base, { fetch: f = null, packed = false } = {}) {
    this.base = base
    this.fetch = f ?? ((...a) => fetch(...a))
    this.packed = packed
  }

  /** One request. @returns {Promise<{status: number, body: Uint8Array, json: any, headers: Headers}>} */
  async request(query, { method = 'GET', body = null, type = null, accept = 'application/json' } = {}) {
    const headers = { Accept: accept }
    if (type !== null) headers['Content-Type'] = type
    let res
    try {
      res = await this.fetch(`${this.base}?${query}`, { method, body, headers })
    } catch (e) {
      throw new ServiceError(`no answer from the thread service: ${e?.message ?? e}`, 0)
    }
    const raw = new Uint8Array(await res.arrayBuffer())
    let json = null
    if (!(res.headers.get('Content-Type') ?? '').startsWith('application/octet-stream')) {
      try { json = JSON.parse(new TextDecoder().decode(raw)) } catch { json = null }
    }
    return { status: res.status, body: raw, json, headers: res.headers }
  }

  /** A GET whose answer must be 200 JSON. */
  async #get(query, what) {
    const r = await this.request(query)
    if (r.status !== 200 || r.json === null || typeof r.json !== 'object')
      throw new ServiceError(`${what}: ${r.status} ${r.json?.error ?? 'and no JSON'}`, r.status, r.json)
    return r.json
  }

  async genesis(id) {
    const want = idHex(id)
    const g = await this.#get(`op=genesis&id=${want}`, 'the genesis')
    const sourceHash = unhex(g.source_hash), script = unhex(g.script), state = unhex(g.state)
    const authorised = packAuthorised(g.authorised)
    const commitment = Uint8Array.from([...lp(sourceHash), ...lp(script), ...lp(state), ...lp(authorised)])
    const got = hex(sha256d(commitment))
    if (got !== want || String(g.id).toLowerCase() !== want)
      throw new ServiceError(`the genesis the service gave for ${want} hashes to ${got}: it is not that thread's genesis`, 200, g)
    return { id: unhex(want), sourceHash, script, state, authorised, commitment }
  }

  async tip(id) {
    const t = await this.#get(`op=tip&genesis=${idHex(id)}`, 'the tip')
    if (!(t.tip === null || Number.isInteger(t.tip)) || !Number.isInteger(t.count)) throw new ServiceError('the tip: not the JSON the service sends', 200, t)
    return { seq: t.tip, count: t.count }
  }

  async entries(id, after = -1, limit = 256) {
    const p = await this.#get(`op=entries&genesis=${idHex(id)}&after=${after}&limit=${limit}`, 'the entries')
    if (!Array.isArray(p.entries)) throw new ServiceError('the entries: not the JSON the service sends', 200, p)
    return { entries: p.entries.map(e => ({ seq: e.seq, bytes: unhex(e.entry) })), tip: p.tip, more: p.more === true }
  }

  async entry(seq) {
    const r = await this.request(`op=entry&seq=${seq}`)
    if (r.status === 404) return null
    if (r.status === 410) return { seq, pruned: true }
    if (r.status !== 200 || typeof r.json?.entry !== 'string') throw new ServiceError(`entry ${seq}: ${r.status} ${r.json?.error ?? ''}`, r.status, r.json)
    return { seq, bytes: unhex(r.json.entry) }
  }

  async register({ sourceHash, script, state, authorised }) {
    const [sh, sc, st, au] = [sourceHash, script, state, authorised].map(bytes)
    const r = this.packed
      ? await this.request('op=register', { method: 'POST', body: Uint8Array.from([...lp(sh), ...lp(sc), ...lp(st), ...lp(au)]),
                                            type: 'application/octet-stream', accept: 'application/octet-stream' })
      : await this.request('op=register', { method: 'POST', type: JSON_AS_TEXT, body: JSON.stringify({ source_hash: hex(sh), script: hex(sc),
                                                                                                    state: hex(st), authorised_packed: hex(au) }) })
    if (r.status !== 201) throw new ServiceError(`register: ${r.status} ${r.json?.error ?? ''}`, r.status, r.json)
    const id = r.json === null ? r.body : unhex(r.json.genesis)
    if (!same(id, create(sh, sc, st, au).id)) throw new ServiceError('register: the service answered an id that is not the one the genesis hashes to', 201, r.json)
    return id
  }

  async append(genesis, entry, pubkey, signature) {
    const g = idHex(genesis)
    const [e, pk, sig] = [entry, pubkey, signature].map(bytes)
    let r
    try {
      r = this.packed
        ? await this.request(`op=append&genesis=${g}`, { method: 'POST', body: Uint8Array.from([...lp(e), ...lp(pk), ...lp(sig)]),
                                                          type: 'application/octet-stream', accept: 'application/octet-stream' })
        : await this.request('op=append', { method: 'POST', type: JSON_AS_TEXT, body: JSON.stringify({ genesis: g, entry: hex(e), pubkey: hex(pk), signature: hex(sig) }) })
    } catch (x) {
      return { status: 0, error: x.message }
    }
    if (r.status === 201) {
      // packed: the 4-byte sequence number, and X-Tree-Size; JSON: { seq, tree_size, root }
      if (r.json === null) {
        const b = r.body
        const seq = b.length === 4 ? ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0 : Number(r.headers.get('X-Seq'))
        return { status: 201, seq, treeSize: Number(r.headers.get('X-Tree-Size')) }
      }
      return { status: 201, seq: r.json.seq, treeSize: r.json.tree_size }
    }
    const out = { status: r.status, error: r.json?.error ?? (r.json === null ? 'the service answered with no JSON' : '') }
    // the script's reason travels as text and as hex: the hex is its bytes, exactly
    if (typeof r.json?.reason_hex === 'string') { out.reason = r.json.reason; out.reasonBytes = unhex(r.json.reason_hex) }
    return out
  }
}

/**
 * The authorised set as genesis.php packs it, from the service's JSON: 'open' is 0x00; { v, k, items } is
 * v ‖ k ‖ n ‖ (len ‖ item) × n, items being keys (v 1) or their hashes (v 2), as GenesisRegistry::unpackAuthorised gave them.
 */
function packAuthorised(a) {
  if (a === 'open') return Uint8Array.of(0)
  if (a === null || typeof a !== 'object' || !Array.isArray(a.items)) throw new ServiceError('the genesis: an authorised set that is not one')
  const items = a.items.map(unhex)
  return Uint8Array.from([a.v, a.k, items.length, ...items.flatMap(i => [i.length, ...i])])
}
