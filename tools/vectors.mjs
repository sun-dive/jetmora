// © 2026 sun-dive. Apache License 2.0 — see LICENSE.  JETMORA CONFORMANCE VECTORS — the specification itself.
// ⚠ Expected results are HAND-DERIVED from Bitcoin 0.1.3's script.cpp, never computed by our own
// evaluator (that would be circular). `crosscheck.mjs` confirms the BSV-agreeing subset independently.
//
// oracle field:
//   'bsv'    — 0.1.3 and BSV agree; @bsv/sdk can confirm it
//   '013'    — ⚠ 0.1.3 ONLY. BSV differs. @bsv/sdk is NOT an oracle here.
//   'jetmora'— our own decision, no external oracle exists
// ── ⚠⚠⚠ ISOLATED ON PURPOSE — THIS FILE IMPORTS NOTHING ──────────────────────────────────────────────
// The vectors are the ONE thing that crosses the set boundary (gaps §10.9): `BT`, `SV` and `JF` live in
// separate files and are pinned to one answer by this contract alone. ⇒ A contract generated from one
// implementation's tables is not a contract — it moves when that implementation moves.
//
// ⚠ It was worse than a numbering dependency. `push` and `toNum` were imported too, so the vectors'
//   INPUTS were built by the code under test: a bug in `toNum` would encode itself into the vector and
//   the buggy implementation would pass its own exam. The header already promised the expected RESULTS
//   are hand-derived and never computed by our evaluator — this extends that to the scripts.
//
// ★ These constants are FROZEN. They are Bitcoin 0.1.3's numbering, which §5b.1 makes authoritative, and
//   they must never be "kept in sync" with any ops table. If a set disagrees with a number here, the set
//   is what changed. ⇒ `0x7f`–`0x81` are SUBSTR/LEFT/RIGHT; the vectors that use them are oracle=013.
const OP = Object.freeze({
  OP_0:0x00, OP_1NEGATE:0x4f,
  OP_1:0x51, OP_2:0x52, OP_3:0x53, OP_4:0x54, OP_5:0x55, OP_6:0x56, OP_7:0x57, OP_8:0x58, OP_9:0x59,
  OP_16:0x60,
  OP_VER:0x62, OP_IF:0x63, OP_VERIF:0x65, OP_ELSE:0x67, OP_ENDIF:0x68, OP_VERIFY:0x69, OP_RETURN:0x6a,
  OP_TOALTSTACK:0x6b, OP_FROMALTSTACK:0x6c, OP_DEPTH:0x74, OP_DUP:0x76, OP_PICK:0x79, OP_ROLL:0x7a,
  OP_ROT:0x7b, OP_SWAP:0x7c,
  OP_CAT:0x7e, OP_SUBSTR:0x7f, OP_LEFT:0x80, OP_RIGHT:0x81, OP_SIZE:0x82,
  OP_INVERT:0x83, OP_AND:0x84, OP_OR:0x85, OP_XOR:0x86,
  OP_1ADD:0x8b, OP_2MUL:0x8d, OP_2DIV:0x8e, OP_NEGATE:0x8f, OP_ABS:0x90,
  OP_ADD:0x93, OP_SUB:0x94, OP_MUL:0x95, OP_DIV:0x96, OP_MOD:0x97, OP_LSHIFT:0x98, OP_RSHIFT:0x99,
  OP_EQUAL:0x87, OP_NUMEQUAL:0x9c, OP_LESSTHAN:0x9f, OP_MIN:0xa3, OP_WITHIN:0xa5,
  OP_SHA256:0xa8, OP_HASH256:0xaa,
})
/** jetmora's own additions — 0.1.3 leaves 0xb0–0xef empty. Used only by oracle=jetmora vectors. */
const JET = Object.freeze({ OP_SPLIT:0xb0, OP_NUM2BIN:0xb1, OP_BIN2NUM:0xb2 })

/** Push arbitrary bytes, 0.1.3 rules: len<=0x4b direct, else PUSHDATA1/2. */
function push(b) {
  if (b.length <= 0x4b) return [b.length, ...b]
  if (b.length < 0x100) return [0x4c, b.length, ...b]
  if (b.length < 0x10000) return [0x4d, b.length & 0xff, b.length >> 8, ...b]
  throw new Error('PUSHDATA4 not needed in vectors')
}
/** BigInt → script-number bytes: little-endian sign-magnitude, sign in the high bit of the LAST byte. */
function toNum(n) {
  n = BigInt(n)
  if (n === 0n) return []
  const neg = n < 0n
  let v = neg ? -n : n
  const out = []
  while (v > 0n) { out.push(Number(v & 0xffn)); v >>= 8n }
  if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0x00)
  else if (neg) out[out.length - 1] |= 0x80
  return out
}

const N = n => push(toNum(n))
const S = (...parts) => parts.flat()

export const VECTORS = [
  // ── number encoding ────────────────────────────────────────────────────────────────────────
  { id:'num.zero',        oracle:'bsv', script:S(OP.OP_0),                    stack:[''] },
  { id:'num.one',         oracle:'bsv', script:S(OP.OP_1),                    stack:['01'] },
  { id:'num.sixteen',     oracle:'bsv', script:S(OP.OP_16),                   stack:['10'] },
  { id:'num.negone',      oracle:'bsv', script:S(OP.OP_1NEGATE),              stack:['81'] },
  { id:'num.128',         oracle:'bsv', script:S(N(128)),                     stack:['8000'] },
  { id:'num.neg128',      oracle:'bsv', script:S(N(-128)),                    stack:['8080'] },
  // ⚠ negative zero survives as data; only CastToBool treats it as false
  { id:'num.negzero',     oracle:'bsv', script:S(push([0x80])),               stack:['80'] },

  // ── arithmetic ─────────────────────────────────────────────────────────────────────────────
  { id:'add.small',       oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_ADD),        stack:['05'] },
  { id:'sub.negative',    oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_SUB),        stack:['81'] },
  { id:'sub.tozero',      oracle:'bsv', script:S(OP.OP_3, OP.OP_3, OP.OP_SUB),        stack:[''] },
  { id:'mul.small',       oracle:'bsv', script:S(OP.OP_3, OP.OP_4, OP.OP_MUL),        stack:['0c'] },
  { id:'mul.signs',       oracle:'bsv', script:S(N(-7), OP.OP_3, OP.OP_MUL),          stack:['95'] },
  { id:'div.trunc',       oracle:'bsv', script:S(N(7), OP.OP_2, OP.OP_DIV),           stack:['03'] },
  // ⚠ TRUNCATION TOWARD ZERO, not floor — BIGNUM division. -7/2 = -3, NOT -4.
  { id:'div.negtrunc',    oracle:'bsv', script:S(N(-7), OP.OP_2, OP.OP_DIV),          stack:['83'] },
  { id:'mod.sign',        oracle:'bsv', script:S(N(-7), OP.OP_2, OP.OP_MOD),          stack:['81'] },
  { id:'1add',            oracle:'bsv', script:S(OP.OP_5, OP.OP_1ADD),                stack:['06'] },
  { id:'2mul',            oracle:'bsv', script:S(OP.OP_5, OP.OP_2MUL),                stack:['0a'] },
  { id:'2div',            oracle:'bsv', script:S(OP.OP_5, OP.OP_2DIV),                stack:['02'] },
  { id:'negate',          oracle:'bsv', script:S(OP.OP_5, OP.OP_NEGATE),              stack:['85'] },
  { id:'abs.neg',         oracle:'bsv', script:S(N(-5), OP.OP_ABS),                   stack:['05'] },

  // ── ★★ ARBITRARY PRECISION — 0.1.3 has NO 4-byte operand limit (script.cpp:567) ────────────
  { id:'bignum.add',   oracle:'bsv',
    script:S(N(2n**200n), OP.OP_1, OP.OP_ADD),
    stack:[Buffer.from(toNum(2n**200n + 1n)).toString('hex')] },
  { id:'bignum.mul',   oracle:'bsv',
    script:S(N(2n**200n), OP.OP_2, OP.OP_MUL),
    stack:[Buffer.from(toNum(2n**201n)).toString('hex')] },

  // ── ⚠⚠ SHIFTS — 0.1.3 ONLY. BSV's LSHIFT is a BYTEWISE shift; this is a NUMERIC one. ───────
  //    `bn = bn1 << bn2.getulong()` (script.cpp). Same opcode, different meaning.
  { id:'lshift.numeric',  oracle:'013', script:S(OP.OP_1, OP.OP_8, OP.OP_LSHIFT),     stack:['0001'] },
  { id:'rshift.numeric',  oracle:'013', script:S(N(256), OP.OP_8, OP.OP_RSHIFT),      stack:['01'] },
  { id:'lshift.negative', oracle:'013', script:S(OP.OP_1, N(-1), OP.OP_LSHIFT),       error:'negative shift' },

  // ── bitwise — BYTEWISE in 0.1.3 (`vch[i] = ~vch[i]`) ───────────────────────────────────────
  { id:'invert.bytes',    oracle:'bsv', script:S(push([0x0f,0xf0]), OP.OP_INVERT),    stack:['f00f'] },
  { id:'and.bytes',       oracle:'bsv', script:S(push([0xff,0x0f]), push([0x0f,0xff]), OP.OP_AND), stack:['0f0f'] },
  // ★★★ FOUND BY DIFFERENTIAL FUZZING, 24 Aug. 0.1.3 calls MakeSameSize() and ZERO-PADS the shorter to
  //     the longer (script.cpp:26); the result takes the LONGER length. ⚠ BSV REFUSES mismatched sizes,
  //     so these are 013-only. Claude's first implementation truncated to the shorter — a THIRD
  //     behaviour, matching neither. None of the curated vectors exercised unequal lengths.
  { id:'and.padshort',    oracle:'013', script:S(push([0xff,0xff]), push([0x0f]), OP.OP_AND),      stack:['0f00'] },
  { id:'or.padshort',     oracle:'013', script:S(push([0xf0]), push([0x00,0x0f]), OP.OP_OR),       stack:['f00f'] },
  { id:'xor.padshort',    oracle:'013', script:S(push([0xff]), push([0xff,0xff]), OP.OP_XOR),      stack:['00ff'] },
  { id:'or.bytes',        oracle:'bsv', script:S(push([0xf0,0x00]), push([0x0f,0x00]), OP.OP_OR),  stack:['ff00'] },
  { id:'xor.bytes',       oracle:'bsv', script:S(push([0xff,0x00]), push([0x0f,0x00]), OP.OP_XOR), stack:['f000'] },

  // ── ⚠ STRING OPS — 0.1.3 has SUBSTR/LEFT/RIGHT at 0x7f/0x80/0x81. BSV has SPLIT/NUM2BIN/BIN2NUM.
  { id:'cat',             oracle:'bsv', script:S(push([0xaa]), push([0xbb]), OP.OP_CAT), stack:['aabb'] },
  { id:'substr',          oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_1, OP.OP_3, OP.OP_SUBSTR), stack:['020304'] },
  { id:'left',            oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_2, OP.OP_LEFT),  stack:['0102'] },
  { id:'right',           oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_2, OP.OP_RIGHT), stack:['030405'] },
  // ★★ ADDED 4 Sept — found by mutation testing. The only SUBSTR vector was IN RANGE, so an
  //    implementation that checked `end` but extracted by `count` (two expressions for one intent)
  //    silently returned a SHORT READ instead of failing: begin=3 count=4 on 5 bytes gave `0405`.
  //    ⚠ A short read that does not complain is the wrong-answer class this set exists to prevent.
  { id:'substr.overrun',  oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_3, OP.OP_4, OP.OP_SUBSTR), error:'SUBSTR out of range' },
  { id:'size',            oracle:'bsv', script:S(push([1,2,3]), OP.OP_SIZE),           stack:['010203','03'] },

  // ── JETMORA'S OWN DATA OPS at 0xb0–0xb2 ────────────────────────────────────────────────────
  // ⚠ oracle:'jetmora' — these sit at OUR numbers, so no external implementation is an oracle.
  //   BSV has the same NAMES at 0x7f–0x81, which is a different encoding of a similar idea.
  //   ★ Kept ALONGSIDE 0.1.3's SUBSTR/LEFT/RIGHT, not instead of them: SPLIT is cheap for SEQUENTIAL
  //   parsing, SUBSTR for RANDOM ACCESS to one field. Different access patterns, both used.
  { id:'split.mid',       oracle:'jetmora', script:S(push([1,2,3,4,5]), OP.OP_2, JET.OP_SPLIT), stack:['0102','030405'] },
  { id:'split.zero',      oracle:'jetmora', script:S(push([9,8,7]), OP.OP_0, JET.OP_SPLIT),     stack:['','090807'] },
  { id:'split.end',       oracle:'jetmora', script:S(push([9,8,7]), OP.OP_3, JET.OP_SPLIT),     stack:['090807',''] },
  { id:'split.past',      oracle:'jetmora', script:S(push([9,8]), OP.OP_3, JET.OP_SPLIT),       error:'position outside range' },
  { id:'num2bin.pos',     oracle:'jetmora', script:S(OP.OP_5, OP.OP_4, JET.OP_NUM2BIN),         stack:['05000000'] },
  // ⚠ sign lives in the high bit of the LAST byte, not the first — little-endian sign-magnitude
  { id:'num2bin.neg',     oracle:'jetmora', script:S(push([0x85]), OP.OP_4, JET.OP_NUM2BIN),    stack:['05000080'] },
  { id:'num2bin.zero',    oracle:'jetmora', script:S(OP.OP_0, OP.OP_4, JET.OP_NUM2BIN),         stack:['00000000'] },
  { id:'num2bin.toosmall',oracle:'jetmora', script:S(push([0xff,0x00]), OP.OP_1, JET.OP_NUM2BIN), error:'does not fit' },
  { id:'bin2num.strip',   oracle:'jetmora', script:S(push([5,0,0,0]), JET.OP_BIN2NUM),          stack:['05'] },
  { id:'bin2num.neg',     oracle:'jetmora', script:S(push([5,0,0,0x80]), JET.OP_BIN2NUM),       stack:['85'] },
  { id:'bin2num.zero',    oracle:'jetmora', script:S(push([0,0,0,0]), JET.OP_BIN2NUM),          stack:[''] },
  // ★ round trip: a fixed-width field read back is the number it was written from
  { id:'num2bin.roundtrip', oracle:'jetmora',
    script:S(push([0xd2,0x02]), OP.OP_5, JET.OP_NUM2BIN, JET.OP_BIN2NUM),                       stack:['d202'] },

  // ── comparison ─────────────────────────────────────────────────────────────────────────────
  { id:'numequal.true',   oracle:'bsv', script:S(OP.OP_3, OP.OP_3, OP.OP_NUMEQUAL),   stack:['01'] },
  { id:'lessthan',        oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_LESSTHAN),   stack:['01'] },
  { id:'min',             oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_MIN),        stack:['02'] },
  { id:'within.in',       oracle:'bsv', script:S(OP.OP_3, OP.OP_2, OP.OP_5, OP.OP_WITHIN), stack:['01'] },
  { id:'within.out',      oracle:'bsv', script:S(OP.OP_6, OP.OP_2, OP.OP_5, OP.OP_WITHIN), stack:[''] },
  // ★★ ADDED 4 Sept — OP_EQUAL was in NO vector at all, found by mutation testing: an implementation
  //    comparing only LENGTH passed all 75. ⚠ 0.1.3 compares the BYTE VECTORS (`vch1 == vch2`,
  //    script.cpp), so same-length-different-content is the case that separates the two.
  { id:'equal.true',      oracle:'bsv', script:S(push([0xaa,0xbb]), push([0xaa,0xbb]), OP.OP_EQUAL), stack:['01'] },
  { id:'equal.samelen',   oracle:'bsv', script:S(push([0xaa,0xbb]), push([0xaa,0xcc]), OP.OP_EQUAL), stack:[''] },

  // ── stack ──────────────────────────────────────────────────────────────────────────────────
  { id:'dup',             oracle:'bsv', script:S(OP.OP_7, OP.OP_DUP),                 stack:['07','07'] },
  { id:'swap',            oracle:'bsv', script:S(OP.OP_1, OP.OP_2, OP.OP_SWAP),       stack:['02','01'] },
  { id:'rot',             oracle:'bsv', script:S(OP.OP_1, OP.OP_2, OP.OP_3, OP.OP_ROT), stack:['02','03','01'] },
  { id:'pick',            oracle:'bsv', script:S(OP.OP_1, OP.OP_2, OP.OP_3, OP.OP_2, OP.OP_PICK), stack:['01','02','03','01'] },
  { id:'roll',            oracle:'bsv', script:S(OP.OP_1, OP.OP_2, OP.OP_3, OP.OP_2, OP.OP_ROLL), stack:['02','03','01'] },
  { id:'depth',           oracle:'bsv', script:S(OP.OP_1, OP.OP_1, OP.OP_DEPTH),      stack:['01','01','02'] },
  { id:'altstack',        oracle:'bsv', script:S(OP.OP_9, OP.OP_TOALTSTACK, OP.OP_FROMALTSTACK), stack:['09'] },

  // ── control ────────────────────────────────────────────────────────────────────────────────
  { id:'if.taken',        oracle:'bsv', script:S(OP.OP_1, OP.OP_IF, OP.OP_7, OP.OP_ELSE, OP.OP_8, OP.OP_ENDIF), stack:['07'] },
  { id:'if.nottaken',     oracle:'bsv', script:S(OP.OP_0, OP.OP_IF, OP.OP_7, OP.OP_ELSE, OP.OP_8, OP.OP_ENDIF), stack:['08'] },
  // ★★ ADDED 4 Sept — found by mutation testing: making negative zero cast TRUE passed all 75.
  //    ⚠ `num.negzero` proves 0x80 SURVIVES as data; nothing put it through a truth test.
  //    CastToBool scans the bytes and returns false when the only set bit is the sign of the LAST one.
  { id:'negzero.isfalse', oracle:'bsv', script:S(push([0x80]), OP.OP_IF, OP.OP_7, OP.OP_ELSE, OP.OP_8, OP.OP_ENDIF), stack:['08'] },
  { id:'verify.pass',     oracle:'bsv', script:S(OP.OP_1, OP.OP_1, OP.OP_VERIFY),     stack:['01'] },
  { id:'verify.fail',     oracle:'bsv', script:S(OP.OP_0, OP.OP_VERIFY),              error:'VERIFY failed' },
  // ★★★ ALSO FOUND BY FUZZING. 0.1.3's EvalScript does NOT check that OP_IF was balanced — it ends and
  //     returns CastToBool(stack.back()). ⚠ Claude's interpreter failed here, having imported a modern
  //     rule by habit. The unclosed branch simply never executes.
  { id:'if.unbalanced',   oracle:'013', script:S(OP.OP_7, OP.OP_1, OP.OP_IF, OP.OP_8),   stack:['07','08'] },
  { id:'if.unbalanced.f', oracle:'013', script:S(OP.OP_7, OP.OP_0, OP.OP_IF, OP.OP_8),   stack:['07'] },

  // ── ⚠ 0.1.3-ONLY: OP_VER pushes VERSION. Jetmora binds it to the ENTRY (§5.1). ──────────────
  { id:'ver.pushes',      oracle:'jetmora', script:S(OP.OP_VER),
    note:'0.1.3 pushes VERSION=103. Jetmora pushes the ENTRY-BOUND protocol version.' },
  { id:'verif.atleast',   oracle:'jetmora', script:S(N(103), OP.OP_VERIF, OP.OP_1, OP.OP_ELSE, OP.OP_0, OP.OP_ENDIF),
    note:'true iff running version >= 103. Entry-bound in jetmora.' },

  // ── hashes ─────────────────────────────────────────────────────────────────────────────────
  { id:'sha256.empty',    oracle:'bsv', script:S(OP.OP_0, OP.OP_SHA256),
    stack:['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'] },
  { id:'hash256.empty',   oracle:'bsv', script:S(OP.OP_0, OP.OP_HASH256),
    stack:['5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456'] },

  // ── errors ─────────────────────────────────────────────────────────────────────────────────
  { id:'err.underflow',   oracle:'bsv', script:S(OP.OP_ADD),                          error:'stack underflow' },
  // ★★★ CORRECTED 24 Aug — my first vector asserted the modern-BTC behaviour from familiarity and the
  //     cross-check caught it on the FIRST RUN. 0.1.3: `case OP_RETURN: { pc = pend; } break;`
  //     ⇒ it JUMPS TO THE END AND CONTINUES — it does NOT fail. The stack survives.
  //     ⚠ BTC made OP_RETURN an unconditional failure in the 2010 cleanup. **BSV kept 0.1.3's.**
  { id:'return.skipsToEnd', oracle:'bsv', script:S(OP.OP_1, OP.OP_RETURN),            stack:['01'] },
  { id:'return.dropsRest',  oracle:'bsv', script:S(OP.OP_1, OP.OP_RETURN, OP.OP_2),   stack:['01'] },
  { id:'err.div0',        oracle:'013', script:S(OP.OP_1, OP.OP_0, OP.OP_DIV),
    error:'division by zero', note:'⚠ UNVERIFIED — 0.1.3 divides via BIGNUM; confirm the failure mode.' },
]
