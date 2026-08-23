// © 2026 sun-dive. Apache License 2.0 — see LICENSE.  JETMORA CONFORMANCE VECTORS — the specification itself.
// ⚠ Expected results are HAND-DERIVED from Bitcoin 0.1.3's script.cpp, never computed by our own
// evaluator (that would be circular). `crosscheck.mjs` confirms the BSV-agreeing subset independently.
//
// oracle field:
//   'bsv'    — 0.1.3 and BSV agree; @bsv/sdk can confirm it
//   '013'    — ⚠ 0.1.3 ONLY. BSV differs. @bsv/sdk is NOT an oracle here.
//   'jetmora'— our own decision, no external oracle exists
import { OP, push } from './ops.mjs'
import { toNum } from './scriptnum.mjs'

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
  { id:'or.bytes',        oracle:'bsv', script:S(push([0xf0,0x00]), push([0x0f,0x00]), OP.OP_OR),  stack:['ff00'] },
  { id:'xor.bytes',       oracle:'bsv', script:S(push([0xff,0x00]), push([0x0f,0x00]), OP.OP_XOR), stack:['f000'] },

  // ── ⚠ STRING OPS — 0.1.3 has SUBSTR/LEFT/RIGHT at 0x7f/0x80/0x81. BSV has SPLIT/NUM2BIN/BIN2NUM.
  { id:'cat',             oracle:'bsv', script:S(push([0xaa]), push([0xbb]), OP.OP_CAT), stack:['aabb'] },
  { id:'substr',          oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_1, OP.OP_3, OP.OP_SUBSTR), stack:['020304'] },
  { id:'left',            oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_2, OP.OP_LEFT),  stack:['0102'] },
  { id:'right',           oracle:'013', script:S(push([1,2,3,4,5]), OP.OP_2, OP.OP_RIGHT), stack:['030405'] },
  { id:'size',            oracle:'bsv', script:S(push([1,2,3]), OP.OP_SIZE),           stack:['010203','03'] },

  // ── comparison ─────────────────────────────────────────────────────────────────────────────
  { id:'numequal.true',   oracle:'bsv', script:S(OP.OP_3, OP.OP_3, OP.OP_NUMEQUAL),   stack:['01'] },
  { id:'lessthan',        oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_LESSTHAN),   stack:['01'] },
  { id:'min',             oracle:'bsv', script:S(OP.OP_2, OP.OP_3, OP.OP_MIN),        stack:['02'] },
  { id:'within.in',       oracle:'bsv', script:S(OP.OP_3, OP.OP_2, OP.OP_5, OP.OP_WITHIN), stack:['01'] },
  { id:'within.out',      oracle:'bsv', script:S(OP.OP_6, OP.OP_2, OP.OP_5, OP.OP_WITHIN), stack:[''] },

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
  { id:'verify.pass',     oracle:'bsv', script:S(OP.OP_1, OP.OP_1, OP.OP_VERIFY),     stack:['01'] },
  { id:'verify.fail',     oracle:'bsv', script:S(OP.OP_0, OP.OP_VERIFY),              error:'VERIFY failed' },

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
