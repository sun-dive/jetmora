// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// How a tick is judged: verifyTick, in PHP (server/interpreter-jf.php) and JavaScript (tools/interpreter-jf.mjs).
//   node tools/verify-tick.mjs
// As a BSV node judges a spend (bitcoin-sv VerifyScript): the unlocking script is byte pushes only; it runs, then the
// lock runs as a separate second run on the data stack and pushed bytes it left; one non-zero item accepts. Each case is judged
// by both interpreters, which must agree, and each has the verdict the rules give it.
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyTick, InterpreterJF, JfHostError, TICK_LIMITS, TICK_MAX_SCRIPT } from './interpreter-jf.mjs'
import { JF_WORD, JF_LIT, JF_SMALL0, JF_RESERVED0, JF_ESC0, jf_bank_name } from './ops-jf.mjs'
let ecdsa = null                                             // secp256k1 signing, from PharLap2 beside this repo
try { ecdsa = await import('../../PharLap2/impl/js/ecdsa.mjs') } catch {}
import { compileBasic } from '../basic/basic-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const hex = b => Buffer.from(b).toString('hex')
const W = n => JF_WORD[n], S = n => JF_SMALL0 + n
const le16 = v => [v & 0xff, (v >> 8) & 0xff]
const sha256 = b => Uint8Array.from(createHash('sha256').update(b).digest())
const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex')
const crypto = {
  sha256, sha1: b => Uint8Array.from(createHash('sha1').update(b).digest()), ripemd160: b => Uint8Array.from(createHash('ripemd160').update(b).digest()),
  ed25519Verify: (sig, pub, msg) => nodeVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI_ED25519, pub]), format: 'der', type: 'spki' }), sig),
  ...(ecdsa ? { ecdsaVerify: (sig, pub, d) => ecdsa.verifyDigest(sig, pub, d) } : {}),
}
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }

/** A loop of `n` trips doing nothing: `n 0 (DO) (LOOP)`, then TRUE. One instruction a trip: (LOOP) branches to itself. */
const loop = n => [JF_LIT.LIT32, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff, S(0), W('(DO)'), W('(LOOP)'), ...le16(-3 & 0xffff), W('TRUE')]
/** `n 0 (DO) body (LOOP)` */
const doLoop = (n, body) => [JF_LIT.LIT32, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff, S(0), W('(DO)'), ...body, W('(LOOP)'), ...le16(-(3 + body.length) & 0xffff)]
const lit64 = v => [JF_LIT.LIT64, ...Array.from({ length: 8 }, (_, k) => Number((BigInt.asUintN(64, v) >> BigInt(8 * k)) & 0xffn))]
/** One byte push: direct up to 72 bytes, STR8 or STR16 above. */
const push = b => b.length <= 72 ? [b.length, ...b] : b.length <= 255 ? [JF_LIT.STR8, b.length, ...b]
  : b.length <= 0xffff ? [JF_LIT.STR16, ...le16(b.length), ...b] : [JF_LIT.STR32, ...le16(b.length & 0xffff), ...le16(b.length >>> 16), ...b]
const INT_MAX = (1n << 63n) - 1n
const lit32 = n => [JF_LIT.LIT32, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]
const vint = n => n < 0xfd ? [n] : n <= 0xffff ? [0xfd, ...le16(n)] : [0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]
/** A DEFS header: each definition with the given out_max, in_max, and cells out (0 when absent). */
const defs = ds => [JF_RESERVED0, ds.length, ...ds.flatMap(([outMax, body, inMax = 0, nOut = 0]) => [0, nOut, ...vint(inMax), ...vint(outMax), ...vint(body.length), ...body])]
const bank = (set, sel) => [Array.from({ length: 256 - JF_ESC0 }, (_, k) => JF_ESC0 + k).find(op => jf_bank_name(op) === set), sel]
const TYPE = bank('CORE', 118), EMIT = bank('CORE', 72), SPACES = bank('CORE', 114), ACCEPT = bank('CORE', 45), EMITQ = bank('FACILITY', 10)
const sig0 = [S(0), S(0), S(0), S(0), S(0), S(0), W('CHECKSIG'), W('DROP')]   // an empty-span CHECKSIG: counted, no maths
const many = (n, b) => Array.from({ length: n }, () => b).flat()
const pushes = n => Array.from({ length: n }, () => push([7])).flat()

// a secp256k1 signature over a digest whose first byte is 0, so the 31 bytes after it are the same number
const D = BigInt('0x' + Buffer.from(sha256(Buffer.from('a test key'))).toString('hex')), PUB = ecdsa?.publicKey(D)
const DIGEST = Uint8Array.from([0, ...sha256(Buffer.from('a message')).subarray(0, 31)])
const SIG = ecdsa?.sign(D, DIGEST)
const checksig = (sig, digest) => [[...push(sig), ...push(PUB), ...push(digest)], [W('CHECKSIG')]]
/** the same signature with R given a needless leading 0x00 */
const padR = sig => { const lr = sig[3]; return Uint8Array.from([0x30, sig[1] + 1, 0x02, lr + 1, 0, ...sig.subarray(4)]) }

const CASES = [
  // [what, unlocking, lock, accepted?]
  ['an empty unlocking script and a lock that leaves TRUE', [], [W('TRUE')], true],
  ['a lock that leaves FALSE', [], [W('FALSE')], false],
  ['a lock that leaves TRUE twice: exactly one item is required', [], [W('TRUE'), W('TRUE')], false],
  ['a lock that leaves nothing', [], [], false],
  ['byte pushes: a direct push, then a lock that checks its length', [3, 1, 2, 3], [W('NIP'), S(3), W('=')], true],
  ['byte pushes: an empty push', [0], [W('NIP'), S(0), W('=')], true],
  ['byte pushes: 72 bytes, the longest direct push', [72, ...new Array(72).fill(7)], [W('NIP'), JF_LIT.LIT8, 72, W('=')], true],
  ['byte pushes: STR8', [JF_LIT.STR8, 100, ...new Array(100).fill(9)], [W('NIP'), JF_LIT.LIT8, 100, W('=')], true],
  ['★ the attack: TRUE EXIT as the unlocking script', [W('TRUE'), W('EXIT')], [W('FALSE')], false],
  ['not a byte push: a number (LIT8)', [JF_LIT.LIT8, 5], [S(5), W('=')], false],
  ['not a byte push: a small number', [S(1)], [W('TRUE')], false],
  ['a push cut short', [5, 1, 2], [W('TRUE')], false],
  ['STR8 cut short', [JF_LIT.STR8, 9, 1], [W('TRUE')], false],
  /* ★ Rule 2 alone. The unlocking script pushes two bytes that happen to be TRUE EXIT. The lock drops the
     push and branches back 6 bytes. Joined as one script, that lands on those bytes, runs them, and leaves
     one TRUE. As a separate run, there is nothing before the lock to land on. */
  ['★ the lock jumps back into the unlocking script\'s bytes', [2, W('TRUE'), W('EXIT')], [W('2DROP'), W('BRANCH'), ...le16(-6 & 0xffff)], false],
  ['the limit: a loop within 500,000 instructions', [], loop(400000), true],
  ['the limit: a loop past 500,000 instructions', [], loop(600000), false],
  ['the limit: a lock longer than 500,000 bytes', [], [...new Array(166667).fill([2, 0, 0]).flat(), W('TRUE')], false],
  /* ★ Pushed bytes have their own 65,536 bytes, read-only (his call, 23 Oct). Pushes that fill it exactly are
     accepted; one more is refused. */
  ['pushes that fill the push space exactly, then one more: refused', [...push(new Array(65535).fill(1)), ...push([2]), ...push([3])], [W('2DROP'), W('2DROP'), W('2DROP'), W('TRUE')], false],
  ['pushes that fill the push space exactly: accepted', [...push(new Array(65535).fill(1)), ...push([2])], [W('2DROP'), W('2DROP'), W('TRUE')], true],
  ['a push is read where it landed: accepted', push([0, 0, 42, 0]), [W('DROP'), S(2), W('+'), W('C@'), JF_LIT.LIT8, 42, W('=')], true],
  ['a store into a pushed byte: refused', push([1, 2, 3, 4]), [W('DROP'), S(0), W('SWAP'), W('C!'), W('TRUE')], false],
  ['a MOVE into pushed bytes: refused', push([1, 2, 3, 4]), [W('DROP'), S(0), W('SWAP'), S(4), W('MOVE'), W('TRUE')], false],
  ['a hash written over a push: refused', [...push(new Array(40).fill(1)), ...push([5])], [W('2SWAP'), W('DROP'), W('SHA256'), W('TRUE')], false],
  ['a MOVE out of a push into program memory: accepted', push([7, 7, 7, 7]), [W('DROP'), S(0), S(4), W('MOVE'), S(3), W('C@'), S(7), W('=')], true],
  ['a read that runs past the last push: refused', push([1, 2]), [W('DROP'), W('1+'), S(0), S(2), W('MOVE'), W('TRUE')], false],
  ['...the same read of the last byte only: accepted', push([1, 2]), [W('DROP'), W('1+'), S(0), S(1), W('MOVE'), S(0), W('C@'), S(2), W('=')], true],
  ['CAT into pushed bytes: refused', push([1, 2, 3, 4]), [W('2DUP'), W('2OVER'), W('DROP'), W('CAT'), W('TRUE')], false],
  ['a function cannot read its caller\'s pushes', push([9, 9, 9, 9]),
    [...defs([[0, [JF_LIT.LIT32, 0, 0, 0, 1, W('C@'), W('DROP')]]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], false],
  ['...while the caller can', push([9, 9, 9, 9]), [W('DROP'), W('C@'), JF_LIT.LIT8, 9, W('=')], true],
  /* ★ At most 100 signature checks a tick (his call, 23 Oct), weighted as BSV weights them, CHECKSIG and
     ED25519-CHECKSIG 1, CHECKMULTISIG its number of keys, and counted as each runs. Empty spans make each check cheap. */
  ['100 CHECKSIGs: accepted', [], [...doLoop(100, [S(0), S(0), S(0), S(0), S(0), S(0), W('CHECKSIG'), W('DROP')]), W('TRUE')], true],
  ['101 CHECKSIGs: refused', [], [...doLoop(101, [S(0), S(0), S(0), S(0), S(0), S(0), W('CHECKSIG'), W('DROP')]), W('TRUE')], false],
  ['101 ED25519-CHECKSIGs: refused', [], [...doLoop(101, [S(0), S(0), S(0), S(0), S(0), S(0), W('ED25519-CHECKSIG'), W('DROP')]), W('TRUE')], false],
  ['3 CHECKMULTISIGs of 32 keys and 4 CHECKSIGs: 100, accepted', [],
    [...doLoop(3, [S(0), S(0), ...Array(64).fill(S(0)), JF_LIT.LIT8, 32, S(0), W('CHECKMULTISIG'), W('DROP')]),
     ...doLoop(4, [S(0), S(0), S(0), S(0), S(0), S(0), W('CHECKSIG'), W('DROP')]), W('TRUE')], true],
  ['...and one CHECKSIG more: refused', [],
    [...doLoop(3, [S(0), S(0), ...Array(64).fill(S(0)), JF_LIT.LIT8, 32, S(0), W('CHECKMULTISIG'), W('DROP')]),
     ...doLoop(5, [S(0), S(0), S(0), S(0), S(0), S(0), W('CHECKSIG'), W('DROP')]), W('TRUE')], false],
  ...(ecdsa ? [
    ['CHECKSIG: a strict DER signature', ...checksig(SIG, DIGEST), true],
    ['CHECKSIG: the same signature with R padded', ...checksig(padR(SIG), DIGEST), false],
    ['CHECKSIG: the same signature with a byte after it', ...checksig(Uint8Array.from([...SIG, 1]), DIGEST), false],
    ['CHECKSIG: the digest as 31 bytes, the same number', ...checksig(SIG, DIGEST.subarray(1)), false],
  ] : []),
  ['ALIGNED of the largest cell wraps', [], [...lit64(INT_MAX), W('ALIGNED')], true],
  ['SPLIT at the largest cell wraps', [], [...lit64(INT_MAX), S(5), S(3), W('SPLIT'), W('2SWAP'), W('2DROP'), W('DROP')], true],
  ['2@ eight bytes below the largest cell: out of range', [], [...lit64(INT_MAX - 3n), W('2@')], false],
  ['2! eight bytes below the largest cell: out of range', [], [S(0), S(0), ...lit64(INT_MAX - 3n), W('2!')], false],
  /* ★ At most 1,000 items held at once, counting the data and return stacks, locals, and what INVOKE set aside.
     A running loop holds 2 of them on the return stack (its index and limit). */
  ['998 on the data stack and a loop\'s 2: 1,000, accepted', [], [S(1), ...doLoop(997, [W('DUP')]), ...doLoop(997, [W('DROP')])], true],
  ['999 on the data stack and a loop\'s 2: 1,001, refused', [], [S(1), ...doLoop(998, [W('DUP')]), ...doLoop(998, [W('DROP')])], false],
  ['499 pushes (998 items) and a loop\'s 2 on the return stack: accepted', pushes(499), [...doLoop(499, [W('2DROP')]), W('TRUE')], true],
  ['500 pushes and a loop\'s 2 on the return stack: refused', pushes(500), [...doLoop(500, [W('2DROP')]), W('TRUE')], false],
  ['501 pushes: refused in the unlocking run', pushes(501), [W('TRUE')], false],
  ['200 items moved into locals still count: 1,001 held, refused', [], [S(1), ...doLoop(599, [W('DUP')]), W('(FRAME)'), 200, ...doLoop(399, [W('DUP')]), ...doLoop(799, [W('DROP')]), W('(UNFRAME)'), W('TRUE')], false],
  ['the same with 1,000 held: accepted', [], [S(1), ...doLoop(599, [W('DUP')]), W('(FRAME)'), 200, ...doLoop(398, [W('DUP')]), ...doLoop(798, [W('DROP')]), W('(UNFRAME)'), W('TRUE')], true],
  ['items set aside by INVOKE still count: 900 held, a function at 99 and its loop\'s 2, refused',
    [], [...defs([[0, [S(0), ...doLoop(98, [W('DUP')]), ...doLoop(99, [W('DROP')])]]]), S(1), ...doLoop(899, [W('DUP')]), W('INVOKE'), 0, ...doLoop(899, [W('DROP')])], false],
  ['the same with the function at 98: 1,000, accepted',
    [], [...defs([[0, [S(0), ...doLoop(97, [W('DUP')]), ...doLoop(98, [W('DROP')])]]]), S(1), ...doLoop(899, [W('DUP')]), W('INVOKE'), 0, ...doLoop(899, [W('DROP')])], true],
  /* ★ A function's output is pushed into its caller's push space on return, so it may not outgrow the room there. Checked as each
     byte is written. 4,000 trips of 64 KB is 256 MB, which no PHP host at the default 128 MB can hold. */
  ['a function\'s output past the room it returns into: refused at once',
    [], [...defs([[0xffffffff, doLoop(4000, [S(0), ...lit32(65536), ...TYPE])]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], false],
  ['a function\'s output that fits: accepted',
    [], [...defs([[0xffffffff, doLoop(1, [S(0), ...lit32(65000), ...TYPE])]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], true],
  ['2,147,483,647 SPACES in a function: refused before they are built',
    [], [...defs([[0xffffffff, [...lit32(2147483647), ...SPACES]]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], false],
  ['100 SPACES in a function: accepted', [], [...defs([[0xffffffff, [JF_LIT.LIT8, 100, ...SPACES]]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], true],
  // the return stack's share of the 1,000, and the check after the last instruction
  ['999 on the return stack and 2 on the data stack: 1,001, refused', [], [...many(999, [S(1), W('>R')]), S(1), S(1), W('DROP')], false],
  ['998 on the return stack and 2 on the data stack: 1,000, accepted', [], [...many(998, [S(1), W('>R')]), S(1), S(1), W('DROP')], true],
  ['1,000 on the return stack, then TRUE as the last instruction: refused', [], [...many(1000, [S(1), W('>R')]), W('TRUE')], false],
  ['999 on the return stack, then TRUE: accepted', [], [...many(999, [S(1), W('>R')]), W('TRUE')], true],
  // a local made by (LOCAL!) counts, and (UNFRAME) gives it back
  ['745 on the stack and 256 locals made by (LOCAL!): 1,001, refused',
    [], [S(1), ...doLoop(744, [W('DUP')]), W('(FRAME)'), 0, ...Array.from({ length: 256 }, (_, k) => [S(1), W('(LOCAL!)'), k]).flat(), W('(UNFRAME)'), ...doLoop(744, [W('DROP')])], false],
  ['744 and 256 locals: 1,000, accepted',
    [], [S(1), ...doLoop(743, [W('DUP')]), W('(FRAME)'), 0, ...Array.from({ length: 256 }, (_, k) => [S(1), W('(LOCAL!)'), k]).flat(), W('(UNFRAME)'), ...doLoop(743, [W('DROP')])], true],
  ['a local made and given back 1,100 times: accepted', [], [...doLoop(1100, [W('(FRAME)'), 0, S(1), W('(LOCAL!)'), 0, W('(UNFRAME)')]), W('TRUE')], true],
  // INVOKE sets aside the caller's return stack and locals too
  ['INVOKE inside a loop: 898 held, the loop\'s 2 and a function at 101: refused',
    [], [...defs([[0, [S(0), ...doLoop(98, [W('DUP')]), ...doLoop(99, [W('DROP')])]]]), S(1), ...doLoop(897, [W('DUP')]), ...doLoop(1, [W('INVOKE'), 0]), ...doLoop(897, [W('DROP')])], false],
  ['...897 held: 1,000, accepted',
    [], [...defs([[0, [S(0), ...doLoop(98, [W('DUP')]), ...doLoop(99, [W('DROP')])]]]), S(1), ...doLoop(896, [W('DUP')]), ...doLoop(1, [W('INVOKE'), 0]), ...doLoop(896, [W('DROP')])], true],
  ['INVOKE with 250 in locals and 400 on the stack, a function at 351: refused',
    [], [...defs([[0, [S(0), ...doLoop(348, [W('DUP')]), ...doLoop(349, [W('DROP')])]]]), S(1), ...doLoop(649, [W('DUP')]), W('(FRAME)'), 250, W('INVOKE'), 0, W('(UNFRAME)'), ...doLoop(399, [W('DROP')])], false],
  ['...a function at 350: 1,000, accepted',
    [], [...defs([[0, [S(0), ...doLoop(347, [W('DUP')]), ...doLoop(348, [W('DROP')])]]]), S(1), ...doLoop(649, [W('DUP')]), W('(FRAME)'), 250, W('INVOKE'), 0, W('(UNFRAME)'), ...doLoop(399, [W('DROP')])], true],
  /* ★ Each function depth has its own push space, from 16,777,216 × (d + 1) at INVOKE depth d, the lock being 0 (his
     call, 23 Oct): a push address a function returns is out of range in its caller, so it can never name the
     spender's push there. */
  ['a function\'s first push is at 16,777,216 × 2', [], [...defs([[0, push([1, 2, 3]), 0, 2]]), W('INVOKE'), 0, W('DROP'), ...lit32(33554432), W('=')], true],
  ['a function inside a function: × 3', [], [...defs([[0, push([1, 2, 3]), 0, 2], [0, [W('INVOKE'), 0], 0, 2]]), W('INVOKE'), 1, W('DROP'), ...lit32(50331648), W('=')], true],
  ['reading a returned push address in the caller: refused', push([9, 9, 9]), [...defs([[0, push([9, 9, 9]), 0, 2]]), W('INVOKE'), 0, W('DROP'), W('C@'), W('DROP'), W('2DROP'), W('TRUE')], false],
  ['...the caller\'s own push at that place reads: accepted', push([9, 9, 9]), [W('DROP'), W('C@'), JF_LIT.LIT8, 9, W('=')], true],
  /* ★ EMIT? answers for the room the next byte really has: the function's out_max, and what is left in the push
     space its output returns into. 65,000 bytes pushed leave 536. */
  ['EMIT? stops at the room left: 536 bytes, accepted', push(new Array(65000).fill(0)),
    [...defs([[1000, [...EMITQ, W('0BRANCH'), ...le16(7), JF_LIT.LIT8, 65, ...EMIT, W('BRANCH'), ...le16(-12 & 0xffff)]]]), W('INVOKE'), 0, W('NIP'), W('NIP'), W('NIP'), JF_LIT.LIT16, ...le16(536), W('=')], true],
  /* ★ Every 64 bytes read, written or pushed count as one more instruction (his call, 23 Oct). These sit exactly
     at 500,000: a 64-byte push costs 1 for the push and 1 for the SHA256 that reads it. */
  ['63 bytes pushed and hashed, 500,000 instructions: accepted', push(new Array(63).fill(1)), [S(0), W('SHA256'), ...loop(499993)], true],
  ['64 bytes pushed and hashed: 500,002, refused', push(new Array(64).fill(1)), [S(0), W('SHA256'), ...loop(499993)], false],
  ['64 bytes pushed and hashed, two fewer loop trips: accepted', push(new Array(64).fill(1)), [S(0), W('SHA256'), ...loop(499991)], true],
  ['MOVE of 64 bytes costs 2 more (read and write): accepted at 500,000', push(new Array(64).fill(1)), [W('DROP'), S(0), JF_LIT.LIT8, 64, W('MOVE'), ...loop(499988)], true],
  ['...one trip more: refused', push(new Array(64).fill(1)), [W('DROP'), S(0), JF_LIT.LIT8, 64, W('MOVE'), ...loop(499989)], false],
  // the signature count runs through INVOKE
  ['60 signature checks in a function and 41 in its caller: 101, refused', [], [...defs([[0, doLoop(60, sig0)]]), W('INVOKE'), 0, ...doLoop(41, sig0), W('TRUE')], false],
  ['60 in a function and 40 in its caller: 100, accepted', [], [...defs([[0, doLoop(60, sig0)]]), W('INVOKE'), 0, ...doLoop(40, sig0), W('TRUE')], true],
]
/* Each case runs a word until the instruction budget ends it, and must stay under the bound on both hosts. A word
   over 60,000 bytes costs about 940 instructions, so the budget ends those soon. Timed on their own. */
const BIG = push(new Array(60000).fill(7))
const until = body => doLoop(500000, body)
const SLOW = [
  ...['SHA256', 'HASH256', 'SHA1', 'RIPEMD160', 'HASH160'].map(h => [`${h} of 60,000 bytes until the budget ends`, BIG, [...until([W('2DUP'), S(0), W(h)]), W('TRUE')], false]),
  ['BYTES= of two 60,000-byte spans until the budget ends', BIG, [...until([W('2DUP'), W('2OVER'), W('BYTES='), W('DROP')]), W('TRUE')], false],
  ['CAT of two 30,000-byte spans until the budget ends', BIG, [W('DROP'), JF_LIT.LIT16, ...le16(30000), ...until([W('2DUP'), W('2DUP'), S(0), W('CAT'), W('2DROP')]), W('TRUE')], false],
  ['SUBSTR of 60,000 bytes until the budget ends', BIG, [...until([W('2DUP'), S(0), JF_LIT.LIT16, ...le16(60000), S(0), W('SUBSTR'), W('2DROP')]), W('TRUE')], false],
  ['MOVE of 60,000 bytes until the budget ends', BIG, [...until([W('OVER'), S(0), JF_LIT.LIT16, ...le16(60000), W('MOVE')]), W('TRUE')], false],
  ['FILL of 64 KB until the budget ends', [], [...until([S(0), ...lit32(65536), S(0), W('FILL')]), W('TRUE')], false],
  ['NUM2BIN to 64 KB until the budget ends', [], [S(0), ...lit32(65536), ...until([W('OVER'), W('NUM2BIN')]), W('NIP')], false],
  ['BIN2NUM of 60,000 bytes until the budget ends', BIG, [...until([W('2DUP'), W('BIN2NUM'), W('DROP')]), W('TRUE')], false],
  ['ACCEPT of 60,000 bytes in a function until the budget ends', BIG,
    [...defs([[0, [S(0), ...lit32(65536), ...ACCEPT, W('DROP')], 65536]]), ...until([W('2DUP'), W('INVOKE'), 0]), W('TRUE')], false],
  ['an empty INVOKE until the budget ends', [], [...defs([[0, []]]), ...until([W('INVOKE'), 0]), W('TRUE')], false],
  ['an empty INVOKE with 995 items held, until the budget ends', [], [...defs([[0, []]]), S(1), ...doLoop(994, [W('DUP')]), ...until([W('INVOKE'), 0]), W('TRUE')], false],
  ['an INVOKE whose function touches its memory, until the budget ends', [], [...defs([[0, [S(0), W('@'), W('DROP')]]]), ...until([W('INVOKE'), 0]), W('TRUE')], false],
  ['EMIT? in a function, 160,000 times', [], [...defs([[1, doLoop(160000, [...EMITQ, W('DROP')])]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], true],
  ['EMIT 65,000 bytes into a function\'s output', [], [...defs([[65536, doLoop(65000, [JF_LIT.LIT8, 65, ...EMIT])]]), W('INVOKE'), 0, W('2DROP'), W('TRUE')], true],
  ['ROLL 994 deep, 160,000 times', [], [S(1), ...doLoop(994, [W('DUP')]), ...doLoop(160000, [JF_LIT.LIT16, ...le16(994), W('ROLL')]), ...doLoop(994, [W('DROP')])], true],
  ['ROT, 2SWAP and TUCK NIP, 80,000 times each on a 997-item stack', [], [S(1), ...doLoop(996, [W('DUP')]), ...doLoop(80000, [W('ROT')]), ...doLoop(80000, [W('2SWAP')]), ...doLoop(40000, [W('TUCK'), W('NIP')]), ...doLoop(996, [W('DROP')])], true],
]

const runPhp = cases => execFileSync('php', [join(HERE, 'jf-run.php'), '0'], {
  input: JSON.stringify(cases.map(([, u, l]) => ({ unlocking: hex(u), script: hex(l), preimage: null }))), maxBuffer: 1 << 28,
}).toString().trim().split('\n').map(l => JSON.parse(l))
const judge = async cases => {
  const php = runPhp(cases)
  for (const [k, [what, u, l, want]] of cases.entries()) {
    const v = await verifyTick({ unlocking: Uint8Array.from(u), lock: Uint8Array.from(l), preimage: null, crypto })
    const js = v.stack ? { accepted: v.accepted, stack: v.stack.map(String) } : { accepted: false, error: hex(v.errorBytes) }
    const same = JSON.stringify(js) === JSON.stringify(php[k])
    ok(same && js.accepted === want, `${what} — ${js.accepted ? 'accepted' : 'refused'}${same ? '' : ` · PHP ${JSON.stringify(php[k]).slice(0, 80)} · JS ${JSON.stringify(js).slice(0, 80)}`}`)
  }
}
console.log('\n── how a tick is judged: verifyTick, in PHP and JavaScript ──')
await judge(CASES)

/* ★ A compiled hash-lock against pushes of every length around 60,896, the length at which its literal would land
   on its own SHA256 buffer if pushes shared program memory. None may be accepted; the secret is the control. */
console.log('\n── a compiled hash-lock, against pushes of every length around 60,896 ──')
{
  const H = Buffer.from(sha256(Buffer.from('the secret'))).toString('hex')
  const lock = [...compileBasic(`VERSION JF 3\nVERIFY SAMEBYTES(SHA256(k), &H${H})\nx = 1`, { stack: ['k$'], leave: ['x'] }).bytes]
  const lens = [0, 1, 32, 4640, ...Array.from({ length: 201 }, (_, k) => 60796 + k), 65500, 65535, 65536]
  const sweep = lens.map(n => [`${n} zero bytes`, push(new Array(n).fill(0)), lock, false])
  const php = runPhp(sweep)
  let agree = 0, accepted = 0
  for (const [k, [, u]] of sweep.entries()) {
    const v = await verifyTick({ unlocking: Uint8Array.from(u), lock: Uint8Array.from(lock), preimage: null, crypto })
    if (v.accepted === php[k].accepted) agree++
    if (v.accepted || php[k].accepted) accepted++
  }
  ok(agree === sweep.length && accepted === 0, `${sweep.length} lengths from 0 to 65,536, 60,796 to 60,996 among them: none accepted, PHP and JS agree (${agree})`)
  await judge([['the secret itself: accepted', push([...Buffer.from('the secret')]), lock, true],
               ['one wrong byte: refused', push([...Buffer.from('the secreT')]), lock, false]])
}

console.log('\n── one instruction, about one instruction\'s time ──')
for (const c of SLOW) {
  let t = performance.now(); runPhp([c]); const tp = performance.now() - t
  t = performance.now(); await verifyTick({ unlocking: Uint8Array.from(c[1]), lock: Uint8Array.from(c[2]), preimage: null, crypto }); const tj = performance.now() - t
  ok(tp < 3000 && tj < 3000, `${c[0]} — PHP ${tp.toFixed(0)} ms, JS ${tj.toFixed(0)} ms (under 3,000 each)`)
}
await judge(SLOW)

console.log('\n── a host without a capability cannot judge: an error, never a verdict ──')
for (const [what, lock, without] of [
  ['HASH256 without SHA-256', [...push([1, 2, 3]), S(0), W('HASH256'), W('TRUE')], 'sha256'],
  ['ED25519-CHECKSIG without Ed25519', [...push(new Array(64).fill(0)), ...push(new Array(32).fill(0)), ...push([1]), W('ED25519-CHECKSIG')], 'ed25519Verify'],
  ['CHECKSIG without secp256k1', [...push([0x30, 6, 2, 1, 1, 2, 1, 1]), ...push(new Array(33).fill(2)), ...push(DIGEST), W('CHECKSIG')], 'ecdsaVerify'],
]) {
  const { [without]: _, ...less } = crypto
  let thrown = null
  try { await verifyTick({ unlocking: new Uint8Array(0), lock: Uint8Array.from(lock), preimage: null, crypto: less }) } catch (e) { thrown = e }
  ok(thrown instanceof JfHostError, `${what} — ${thrown ? thrown.constructor.name : 'a verdict'}`)
}

// ★ the same two attacks run as one joined script, to show what each rule stops
console.log('\n── the two attacks, run as one joined script ──')
for (const name of ['★ the attack: TRUE EXIT as the unlocking script', '★ the lock jumps back into the unlocking script\'s bytes']) {
  const [what, u, l] = CASES.find(c => c[0] === name)
  const vm = new InterpreterJF()
  let accepted
  try { const st = await vm.run(Uint8Array.from([...u, ...l])); accepted = st.length === 1 && st[0] !== 0n } catch { accepted = false }
  ok(accepted, `joined, "${what.replace('★ ', '')}" is ACCEPTED — verifyTick refuses it`)
}
ok(TICK_LIMITS.maxOps === 500000 && TICK_LIMITS.memSize === 65536 && TICK_MAX_SCRIPT === 500000 && TICK_LIMITS.maxItems === 1000
   && TICK_LIMITS.pushSize === 65536 && TICK_LIMITS.maxSigOps === 100,
   'the limits are JF revision 3\'s: 500,000 instructions, 65,536 bytes of memory and 65,536 of pushes, 500,000-byte scripts, 1,000 items, 100 signature checks')

if (!ecdsa) console.log('  ⚠ secp256k1 (PharLap2) not found beside this repo: the CHECKSIG signature cases did not run')
console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [how a tick is judged]`)
process.exit(fail === 0 ? 0 : 1)
