// © 2026 sun-dive. Business Source License 1.1. See LICENSE.
//
// ══ GZIP AS GNU gzip WRITES IT ═════════════════════════════════════════════════════════════════════════════════════
//
// The bytes GNU gzip writes at its default level, 6, with no name and no time: `gzip -6 -n`, and what `tar -czf` gets
// from it through a pipe. A port of GNU gzip's own deflate (deflate.c, trees.c, bits.c), so one input gives one output
// on any machine, with no gzip installed. node:zlib cannot stand in for it: zlib grew from the same code but chooses
// other blocks and other matches, so its bytes differ; and the gzip a system ships is not always GNU's.
//
//   gzip(bytes) → Uint8Array    the header (no name, mtime 0, extra flags 0, OS 3 for Unix), one deflate stream, then
//                               the CRC-32 and the length mod 2^32, both little-endian
//
// Level 6 only, and only what gzip does by default (no --rsyncable). The input is read as gzip reads a regular file,
// whole reads into its window. No dependencies, synchronous.

// ── deflate.c ───────────────────────────────────────────────────────────────────────────────────────────────────────
const WSIZE = 0x8000, WMASK = WSIZE - 1, WINDOW_SIZE = 2 * WSIZE
const HASH_BITS = 15, HASH_SIZE = 1 << HASH_BITS, HASH_MASK = HASH_SIZE - 1
const MIN_MATCH = 3, MAX_MATCH = 258
const H_SHIFT = Math.floor((HASH_BITS + MIN_MATCH - 1) / MIN_MATCH)
const MIN_LOOKAHEAD = MAX_MATCH + MIN_MATCH + 1, MAX_DIST = WSIZE - MIN_LOOKAHEAD
/** A match of length 3 further back than this is not worth its distance code */
const TOO_FAR = 4096
/** Level 6 of gzip's configuration table: good_length, max_lazy, nice_length, max_chain */
const GOOD_MATCH = 8, MAX_LAZY = 16, NICE_MATCH = 128, MAX_CHAIN = 128

// ── trees.c ─────────────────────────────────────────────────────────────────────────────────────────────────────────
const LIT_BUFSIZE = 0x8000, DIST_BUFSIZE = LIT_BUFSIZE
const MAX_BITS = 15, MAX_BL_BITS = 7, LENGTH_CODES = 29, LITERALS = 256, END_BLOCK = 256
const L_CODES = LITERALS + 1 + LENGTH_CODES, D_CODES = 30, BL_CODES = 19, HEAP_SIZE = 2 * L_CODES + 1
const STORED_BLOCK = 0, STATIC_TREES = 1, DYN_TREES = 2
const REP_3_6 = 16, REPZ_3_10 = 17, REPZ_11_138 = 18
const EXTRA_LBITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
const EXTRA_DBITS = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
const EXTRA_BLBITS = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7]
const BL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

/** A tree's nodes. gzip keeps freq and code in one union, and dad and len in another; nothing reads a field after the
 *  other one has overwritten it, so here each has its own array. */
const nodes = n => ({ freq: new Int32Array(n), code: new Int32Array(n), dad: new Int32Array(n), len: new Int32Array(n) })

/** The first `len` bits of `code`, reversed: deflate sends Huffman codes from their last bit */
function reverse(code, len) {
  let r = 0
  do { r |= code & 1; code >>>= 1; r <<= 1 } while (--len > 0)
  return r >>> 1
}

/** The codes of a tree whose lengths are set, from the count of codes of each length (gen_codes) */
function genCodes(tree, maxCode, blCount) {
  const next = new Int32Array(MAX_BITS + 1)
  let code = 0
  for (let bits = 1; bits <= MAX_BITS; bits++) next[bits] = code = (code + blCount[bits - 1]) << 1
  for (let n = 0; n <= maxCode; n++) {
    const len = tree.len[n]
    if (len !== 0) tree.code[n] = reverse(next[len]++, len)
  }
}

// ct_init: the code of each length and distance, and the static trees
const lengthCode = new Uint8Array(256), distCode = new Uint8Array(512)
const baseLength = new Int32Array(LENGTH_CODES), baseDist = new Int32Array(D_CODES)
const staticL = nodes(L_CODES + 2), staticD = nodes(D_CODES)
{
  let length = 0, code
  for (code = 0; code < LENGTH_CODES - 1; code++) {
    baseLength[code] = length
    for (let n = 0; n < 1 << EXTRA_LBITS[code]; n++) lengthCode[length++] = code
  }
  // length 255, a match of 258, has two codes: 284 with five extra bits, or 285. gzip takes the shorter, 285
  lengthCode[length - 1] = code
  let dist = 0
  for (code = 0; code < 16; code++) {
    baseDist[code] = dist
    for (let n = 0; n < 1 << EXTRA_DBITS[code]; n++) distCode[dist++] = code
  }
  dist >>= 7                                   // from here on, distances are divided by 128
  for (; code < D_CODES; code++) {
    baseDist[code] = dist << 7
    for (let n = 0; n < 1 << (EXTRA_DBITS[code] - 7); n++) distCode[256 + dist++] = code
  }
  const count = new Int32Array(MAX_BITS + 1)
  let n = 0
  while (n <= 143) { staticL.len[n++] = 8; count[8]++ }
  while (n <= 255) { staticL.len[n++] = 9; count[9]++ }
  while (n <= 279) { staticL.len[n++] = 7; count[7]++ }
  while (n <= 287) { staticL.len[n++] = 8; count[8]++ }
  genCodes(staticL, L_CODES + 1, count)
  for (n = 0; n < D_CODES; n++) { staticD.len[n] = 5; staticD.code[n] = reverse(n, 5) }
}
/** The distance code of a distance less one */
const dCode = dist => dist < 256 ? distCode[dist] : distCode[256 + (dist >>> 7)]

const CRC = new Int32Array(256)
for (let n = 0; n < 256; n++) {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  CRC[n] = c
}
function crc32(b) {
  let c = -1
  for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8)
  return (c ^ -1) >>> 0
}

/**
 * @param {Uint8Array|number[]} input
 * @returns {Uint8Array} the .gz bytes, as `gzip -6 -n` writes them
 */
export function gzip(input) {
  const src = input instanceof Uint8Array ? input : Uint8Array.from(input)

  // ── bits.c: the output, its bits sent least significant first ─────────────────────────────────────────────────────
  let out = new Uint8Array(Math.max(1 << 16, src.length + (src.length >>> 3) + 1024)), outcnt = 0
  const putByte = b => {
    if (outcnt === out.length) { const o = new Uint8Array(out.length * 2); o.set(out); out = o }
    out[outcnt++] = b
  }
  let biBuf = 0, biValid = 0
  const sendBits = (value, length) => {
    biBuf |= value << biValid
    biValid += length
    while (biValid >= 8) { putByte(biBuf & 0xff); biBuf >>>= 8; biValid -= 8 }
  }
  const biWindup = () => { if (biValid > 0) putByte(biBuf & 0xff); biBuf = 0; biValid = 0 }
  const putLong = v => { for (let k = 0; k < 4; k++) putByte((v >>> (8 * k)) & 0xff) }

  // the header zip() writes: magic, deflate, no flags, no time, extra flags 0 at level 6, OS 3
  for (const b of [0x1f, 0x8b, 8, 0]) putByte(b)
  putLong(0)
  putByte(0)
  putByte(3)

  // ── trees.c: the block being gathered, and its trees ──────────────────────────────────────────────────────────────
  const dynL = nodes(HEAP_SIZE), dynD = nodes(2 * D_CODES + 1), blTree = nodes(2 * BL_CODES + 1)
  const lDesc = { dyn: dynL, stat: staticL, extra: EXTRA_LBITS, base: LITERALS + 1, elems: L_CODES, maxLength: MAX_BITS, maxCode: 0 }
  const dDesc = { dyn: dynD, stat: staticD, extra: EXTRA_DBITS, base: 0, elems: D_CODES, maxLength: MAX_BITS, maxCode: 0 }
  const blDesc = { dyn: blTree, stat: null, extra: EXTRA_BLBITS, base: 0, elems: BL_CODES, maxLength: MAX_BL_BITS, maxCode: 0 }
  const heap = new Int32Array(HEAP_SIZE), depth = new Uint8Array(HEAP_SIZE), blCount = new Int32Array(MAX_BITS + 1)
  let heapLen = 0, heapMax = 0
  const lBuf = new Uint8Array(LIT_BUFSIZE), dBuf = new Uint16Array(DIST_BUFSIZE), flagBuf = new Uint8Array(LIT_BUFSIZE / 8)
  let lastLit = 0, lastDist = 0, lastFlags = 0, flags = 0, flagBit = 1
  let optLen = 0, staticLen = 0

  function initBlock() {
    dynL.freq.fill(0, 0, L_CODES); dynD.freq.fill(0, 0, D_CODES); blTree.freq.fill(0, 0, BL_CODES)
    dynL.freq[END_BLOCK] = 1
    optLen = staticLen = 0
    lastLit = lastDist = lastFlags = 0
    flags = 0; flagBit = 1
  }

  /** Node n is smaller than m: less frequent, or as frequent and no deeper */
  const smaller = (tree, n, m) => tree.freq[n] < tree.freq[m] || (tree.freq[n] === tree.freq[m] && depth[n] <= depth[m])
  function pqdownheap(tree, k) {
    const v = heap[k]
    let j = k << 1
    while (j <= heapLen) {
      if (j < heapLen && smaller(tree, heap[j + 1], heap[j])) j++
      if (smaller(tree, v, heap[j])) break
      heap[k] = heap[j]; k = j
      j <<= 1
    }
    heap[k] = v
  }

  /** The bit length of each code, at most maxLength; and the block's length in bits, in optLen and staticLen */
  function genBitlen(desc) {
    const tree = desc.dyn, stree = desc.stat, extra = desc.extra, base = desc.base, maxCode = desc.maxCode, maxLength = desc.maxLength
    let overflow = 0, h
    blCount.fill(0)
    tree.len[heap[heapMax]] = 0                // the root
    for (h = heapMax + 1; h < HEAP_SIZE; h++) {
      const n = heap[h]
      let bits = tree.len[tree.dad[n]] + 1
      if (bits > maxLength) { bits = maxLength; overflow++ }
      tree.len[n] = bits
      if (n > maxCode) continue                // not a leaf
      blCount[bits]++
      const xbits = n >= base ? extra[n - base] : 0
      const f = tree.freq[n]
      optLen += f * (bits + xbits)
      if (stree) staticLen += f * (stree.len[n] + xbits)
    }
    if (overflow === 0) return
    // the deepest codes are too long: find the first length that can grow, as gzip does
    do {
      let bits = maxLength - 1
      while (blCount[bits] === 0) bits--
      blCount[bits]--
      blCount[bits + 1] += 2
      blCount[maxLength]--
      overflow -= 2
    } while (overflow > 0)
    for (let bits = maxLength; bits !== 0; bits--) {
      let n = blCount[bits]
      while (n !== 0) {
        const m = heap[--h]
        if (m > maxCode) continue
        if (tree.len[m] !== bits) { optLen += (bits - tree.len[m]) * tree.freq[m]; tree.len[m] = bits }
        n--
      }
    }
  }

  function buildTree(desc) {
    const tree = desc.dyn, stree = desc.stat, elems = desc.elems
    let maxCode = -1, node = elems
    heapLen = 0; heapMax = HEAP_SIZE
    for (let n = 0; n < elems; n++) {
      if (tree.freq[n] !== 0) { heap[++heapLen] = maxCode = n; depth[n] = 0 }
      else tree.len[n] = 0
    }
    // at least two codes of non-zero frequency, so that at least one bit is sent even for one code
    while (heapLen < 2) {
      const fresh = heap[++heapLen] = maxCode < 2 ? ++maxCode : 0
      tree.freq[fresh] = 1
      depth[fresh] = 0
      optLen--
      if (stree) staticLen -= stree.len[fresh]
    }
    desc.maxCode = maxCode
    for (let n = heapLen >> 1; n >= 1; n--) pqdownheap(tree, n)
    do {
      const n = heap[1]                        // pqremove: the least frequent
      heap[1] = heap[heapLen--]
      pqdownheap(tree, 1)
      const m = heap[1]                        // the next least frequent
      heap[--heapMax] = n
      heap[--heapMax] = m
      tree.freq[node] = tree.freq[n] + tree.freq[m]
      depth[node] = Math.max(depth[n], depth[m]) + 1
      tree.dad[n] = tree.dad[m] = node
      heap[1] = node++
      pqdownheap(tree, 1)
    } while (heapLen >= 2)
    heap[--heapMax] = heap[1]
    genBitlen(desc)
    genCodes(tree, maxCode, blCount)
  }

  /** How often each code of the bit length tree is used to send this tree (scan_tree) */
  function scanTree(tree, maxCode) {
    let prevlen = -1, nextlen = tree.len[0], count = 0, maxCount = 7, minCount = 4
    if (nextlen === 0) { maxCount = 138; minCount = 3 }
    tree.len[maxCode + 1] = 0xffff             // a guard
    for (let n = 0; n <= maxCode; n++) {
      const curlen = nextlen
      nextlen = tree.len[n + 1]
      if (++count < maxCount && curlen === nextlen) continue
      else if (count < minCount) blTree.freq[curlen] += count
      else if (curlen !== 0) {
        if (curlen !== prevlen) blTree.freq[curlen]++
        blTree.freq[REP_3_6]++
      } else if (count <= 10) blTree.freq[REPZ_3_10]++
      else blTree.freq[REPZ_11_138]++
      count = 0; prevlen = curlen
      if (nextlen === 0) { maxCount = 138; minCount = 3 }
      else if (curlen === nextlen) { maxCount = 6; minCount = 3 }
      else { maxCount = 7; minCount = 4 }
    }
  }

  /** A tree sent in the bit length tree's codes (send_tree): scanTree's walk, sending what it counted */
  function sendTree(tree, maxCode) {
    let prevlen = -1, nextlen = tree.len[0], count = 0, maxCount = 7, minCount = 4
    const send = c => sendBits(blTree.code[c], blTree.len[c])
    if (nextlen === 0) { maxCount = 138; minCount = 3 }
    for (let n = 0; n <= maxCode; n++) {
      const curlen = nextlen
      nextlen = tree.len[n + 1]
      if (++count < maxCount && curlen === nextlen) continue
      else if (count < minCount) { do send(curlen); while (--count !== 0) }
      else if (curlen !== 0) {
        if (curlen !== prevlen) { send(curlen); count-- }
        send(REP_3_6); sendBits(count - 3, 2)
      } else if (count <= 10) { send(REPZ_3_10); sendBits(count - 3, 3) }
      else { send(REPZ_11_138); sendBits(count - 11, 7) }
      count = 0; prevlen = curlen
      if (nextlen === 0) { maxCount = 138; minCount = 3 }
      else if (curlen === nextlen) { maxCount = 6; minCount = 3 }
      else { maxCount = 7; minCount = 4 }
    }
  }

  /** The bit length tree; returns the index in BL_ORDER of the last of its codes to send, 3 at least */
  function buildBlTree() {
    scanTree(dynL, lDesc.maxCode)
    scanTree(dynD, dDesc.maxCode)
    buildTree(blDesc)
    let maxBlindex
    for (maxBlindex = BL_CODES - 1; maxBlindex >= 3; maxBlindex--) if (blTree.len[BL_ORDER[maxBlindex]] !== 0) break
    optLen += 3 * (maxBlindex + 1) + 5 + 5 + 4
    return maxBlindex
  }

  function sendAllTrees(lcodes, dcodes, blcodes) {
    sendBits(lcodes - 257, 5)
    sendBits(dcodes - 1, 5)
    sendBits(blcodes - 4, 4)
    for (let rank = 0; rank < blcodes; rank++) sendBits(blTree.len[BL_ORDER[rank]], 3)
    sendTree(dynL, lcodes - 1)
    sendTree(dynD, dcodes - 1)
  }

  function compressBlock(lt, dt) {
    let lx = 0, dx = 0, fx = 0, flag = 0
    if (lastLit !== 0) do {
      if ((lx & 7) === 0) flag = flagBuf[fx++]
      let lc = lBuf[lx++]
      if ((flag & 1) === 0) sendBits(lt.code[lc], lt.len[lc])            // a literal
      else {                                                              // a match: lc is its length less 3
        let code = lengthCode[lc]
        sendBits(lt.code[code + LITERALS + 1], lt.len[code + LITERALS + 1])
        let extra = EXTRA_LBITS[code]
        if (extra !== 0) sendBits(lc - baseLength[code], extra)
        const dist = dBuf[dx++]                                           // its distance less one
        code = dCode(dist)
        sendBits(dt.code[code], dt.len[code])
        extra = EXTRA_DBITS[code]
        if (extra !== 0) sendBits(dist - baseDist[code], extra)
      }
      flag >>= 1
    } while (lx < lastLit)
    sendBits(lt.code[END_BLOCK], lt.len[END_BLOCK])
  }

  /** The block, as stored, static or dynamic, whichever is shortest; `at` is where its bytes start in the window, or
   *  -1 when they are no longer all there. gzip never writes the whole file as stored (its seekable() is 0). */
  function flushBlock(at, storedLen, eof) {
    flagBuf[lastFlags] = flags
    buildTree(lDesc)
    buildTree(dDesc)
    const maxBlindex = buildBlTree()
    let optLenb = Math.floor((optLen + 3 + 7) / 8)
    const staticLenb = Math.floor((staticLen + 3 + 7) / 8)
    if (staticLenb <= optLenb) optLenb = staticLenb
    const last = eof ? 1 : 0
    if (storedLen + 4 <= optLenb && at >= 0) {
      sendBits((STORED_BLOCK << 1) + last, 3)
      biWindup()
      putByte(storedLen & 0xff); putByte((storedLen >>> 8) & 0xff)
      putByte(~storedLen & 0xff); putByte((~storedLen >>> 8) & 0xff)
      for (let k = 0; k < storedLen; k++) putByte(window[at + k])
    } else if (staticLenb === optLenb) {
      sendBits((STATIC_TREES << 1) + last, 3)
      compressBlock(staticL, staticD)
    } else {
      sendBits((DYN_TREES << 1) + last, 3)
      sendAllTrees(lDesc.maxCode + 1, dDesc.maxCode + 1, maxBlindex + 1)
      compressBlock(dynL, dynD)
    }
    initBlock()
    if (eof) biWindup()
  }

  // ── deflate.c: the window, the hash chains, the lazy match ────────────────────────────────────────────────────────
  const window = new Uint8Array(WINDOW_SIZE)
  const prev = new Uint16Array(WSIZE), head = new Uint16Array(HASH_SIZE)
  let inPos = 0, insH = 0, strstart = 0, blockStart = 0, lookahead = 0, eofile = false, matchStart = 0, prevLength = 0
  const readBuf = (at, size) => {
    const n = Math.min(size, src.length - inPos)
    window.set(src.subarray(inPos, inPos + n), at)
    inPos += n
    return n
  }

  /** More input into the window, its upper half moved down first when the lookahead runs short near its end */
  function fillWindow() {
    let more = WINDOW_SIZE - lookahead - strstart
    if (strstart >= WSIZE + MAX_DIST) {
      window.copyWithin(0, WSIZE, WINDOW_SIZE)
      matchStart -= WSIZE; strstart -= WSIZE; blockStart -= WSIZE
      for (let n = 0; n < HASH_SIZE; n++) { const m = head[n]; head[n] = m >= WSIZE ? m - WSIZE : 0 }
      for (let n = 0; n < WSIZE; n++) { const m = prev[n]; prev[n] = m >= WSIZE ? m - WSIZE : 0 }
      more += WSIZE
    }
    if (!eofile) {
      const n = readBuf(strstart + lookahead, more)
      if (n === 0) { eofile = true; window.fill(0, strstart + lookahead, strstart + lookahead + MIN_MATCH - 1) }
      else lookahead += n
    }
  }

  /** The string at s into the dictionary; returns the head of its hash chain before it */
  function insertString(s) {
    insH = ((insH << H_SHIFT) ^ window[s + MIN_MATCH - 1]) & HASH_MASK
    const h = head[insH]
    prev[s & WMASK] = h
    head[insH] = s
    return h
  }

  /** The longest match along the chain from curMatch, longer than prevLength; sets matchStart (longest_match) */
  function longestMatch(curMatch) {
    let chain = MAX_CHAIN, bestLen = prevLength
    const s = strstart, strend = strstart + MAX_MATCH
    const limit = strstart > MAX_DIST ? strstart - MAX_DIST : 0
    let scanEnd1 = window[s + bestLen - 1], scanEnd = window[s + bestLen]
    if (prevLength >= GOOD_MATCH) chain >>>= 2
    do {
      let match = curMatch
      // as gzip does, byte 2 is not compared: the hash keys are equal, so it is too
      if (window[match + bestLen] !== scanEnd || window[match + bestLen - 1] !== scanEnd1
          || window[match] !== window[s] || window[match + 1] !== window[s + 1]) continue
      let scan = s + 2
      match += 2
      while (window[++scan] === window[++match] && window[++scan] === window[++match]
             && window[++scan] === window[++match] && window[++scan] === window[++match]
             && window[++scan] === window[++match] && window[++scan] === window[++match]
             && window[++scan] === window[++match] && window[++scan] === window[++match]
             && scan < strend) {}
      const len = MAX_MATCH - (strend - scan)
      if (len > bestLen) {
        matchStart = curMatch
        bestLen = len
        if (len >= NICE_MATCH) break
        scanEnd1 = window[s + bestLen - 1]
        scanEnd = window[s + bestLen]
      }
    } while ((curMatch = prev[curMatch & WMASK]) > limit && --chain !== 0)
    return bestLen
  }

  /** One literal or one match into the block; true when the block should be flushed here (ct_tally) */
  function tally(dist, lc) {
    lBuf[lastLit++] = lc
    if (dist === 0) dynL.freq[lc]++
    else {
      dist--
      dynL.freq[lengthCode[lc] + LITERALS + 1]++
      dynD.freq[dCode(dist)]++
      dBuf[lastDist++] = dist
      flags |= flagBit
    }
    flagBit <<= 1
    if ((lastLit & 7) === 0) { flagBuf[lastFlags++] = flags; flags = 0; flagBit = 1 }
    // every 4096 symbols, stop the block when it is compressing well and matches are few
    if ((lastLit & 0xfff) === 0) {
      let outLength = lastLit * 8
      const inLength = strstart - blockStart
      for (let d = 0; d < D_CODES; d++) outLength += dynD.freq[d] * (5 + EXTRA_DBITS[d])
      outLength = Math.floor(outLength / 8)
      if (lastDist < Math.floor(lastLit / 2) && outLength < Math.floor(inLength / 2)) return true
    }
    return lastLit === LIT_BUFSIZE - 1 || lastDist === DIST_BUFSIZE
  }
  const flush = eof => flushBlock(blockStart >= 0 ? blockStart : -1, strstart - blockStart, eof)

  initBlock()
  // lm_init
  lookahead = readBuf(0, WINDOW_SIZE)
  if (lookahead === 0) eofile = true
  else {
    while (lookahead < MIN_LOOKAHEAD && !eofile) fillWindow()
    for (let j = 0; j < MIN_MATCH - 1; j++) insH = ((insH << H_SHIFT) ^ window[j]) & HASH_MASK
  }
  // deflate, with lazy evaluation of matches
  let matchAvailable = false, matchLength = MIN_MATCH - 1
  while (lookahead !== 0) {
    const hashHead = insertString(strstart)
    prevLength = matchLength
    const prevMatch = matchStart
    matchLength = MIN_MATCH - 1
    if (hashHead !== 0 && prevLength < MAX_LAZY && strstart - hashHead <= MAX_DIST && strstart <= WINDOW_SIZE - MIN_LOOKAHEAD) {
      matchLength = longestMatch(hashHead)
      if (matchLength > lookahead) matchLength = lookahead
      if (matchLength === MIN_MATCH && strstart - matchStart > TOO_FAR) matchLength--
    }
    if (prevLength >= MIN_MATCH && matchLength <= prevLength) {
      // the match at the previous position is the better one: send it
      const full = tally(strstart - 1 - prevMatch, prevLength - MIN_MATCH)
      lookahead -= prevLength - 1
      prevLength -= 2
      do { strstart++; insertString(strstart) } while (--prevLength !== 0)
      matchAvailable = false
      matchLength = MIN_MATCH - 1
      strstart++
      if (full) { flush(false); blockStart = strstart }
    } else if (matchAvailable) {
      // no better match: the byte before goes as a literal
      if (tally(0, window[strstart - 1])) { flush(false); blockStart = strstart }
      strstart++
      lookahead--
    } else {
      matchAvailable = true
      strstart++
      lookahead--
    }
    while (lookahead < MIN_LOOKAHEAD && !eofile) fillWindow()
  }
  if (matchAvailable) tally(0, window[strstart - 1])
  flush(true)

  putLong(crc32(src))
  putLong(src.length >>> 0)
  return out.slice(0, outcnt)
}
