// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE JETMORA SCRIPT INTERPRETER.
//
// Semantics are Bitcoin 0.1.3's, read from src/script.cpp of github.com/trottier/original-bitcoin
// (MIT), NOT from any later implementation. Where 0.1.3 and modern Bitcoin differ, 0.1.3 wins and the
// difference is noted at the opcode. `vectors/core.json` is the specification; this file must satisfy it.
//
// ⚠ FOUR PLACES THIS DIFFERS FROM WHAT A MODERN READER EXPECTS:
//   · numbers are ARBITRARY PRECISION — no 4-byte cap, no minimal-encoding rule (script.cpp:567)
//   · OP_LSHIFT/OP_RSHIFT are NUMERIC shifts of a bignum, not bytewise shifts of an array
//   · OP_RETURN does NOT fail — it jumps to the end and the stack survives
//   · OP_VER pushes a version; here it is bound to the ENTRY, never to this software (spec §6b)
import { createHash } from 'node:crypto'
import { OP, JET, NAME } from './ops.mjs'
import { toNum, fromNum } from './scriptnum.mjs'

const sha1 = b => [...createHash('sha1').update(Buffer.from(b)).digest()]
const sha256 = b => [...createHash('sha256').update(Buffer.from(b)).digest()]
const ripemd160 = b => [...createHash('ripemd160').update(Buffer.from(b)).digest()]
const hash160 = b => ripemd160(sha256(b))
const hash256 = b => sha256(sha256(b))

class ScriptError extends Error {
  constructor(msg, op) { super(op === undefined ? msg : `${msg} at ${NAME[op] ?? '0x' + op.toString(16)}`); this.op = op }
}
const fail = (m, op) => { throw new ScriptError(m, op) }

/** 0.1.3: `CastToBool` is `CBigNum(vch) != bnZero` — so 0x80 (negative zero) is FALSE. */
const toBool = v => fromNum(v) !== 0n

/**
 * Evaluate a script.
 * @param {number[]} script         raw bytes
 * @param {object}   opts
 * @param {number[][]} opts.stack      initial stack, bottom first
 * @param {number}   opts.version      what OP_VER pushes. ⚠ MUST come from the entry (spec §6b),
 *                                     never from this software's own version.
 * @param {number}   opts.maxOps       refuse runaway scripts. Operator policy, not protocol (spec §4.5).
 * @returns {{ok:boolean, stack:number[][], altStack:number[][], error:string|null, ops:number}}
 */
export function evaluate(script, opts = {}) {
  const stack = (opts.stack ?? []).map(x => [...x])
  const altStack = []
  const vfExec = []           // 0.1.3's conditional stack
  const version = opts.version ?? 103
  const maxOps = opts.maxOps ?? 1_000_000
  // ⚠ OPERATOR POLICY, never a protocol constant (spec §4.5). A ceiling written into the protocol
  //   becomes a number nobody can promise to hold — which is the problem this design exists to escape.
  const maxItemSize = opts.maxItemSize ?? 1_000_000
  let pc = 0, ops = 0

  const need = (n, op) => { if (stack.length < n) fail(`stack underflow: need ${n}, have ${stack.length}`, op) }
  const top = i => stack[stack.length + i]          // top(-1) is the top item
  const popNum = op => { need(1, op); return fromNum(stack.pop()) }
  const pushNum = n => stack.push(toNum(n))

  try {
    while (pc < script.length) {
      if (++ops > maxOps) fail(`exceeded ${maxOps} operations`)
      const fExec = !vfExec.includes(false)
      const opcode = script[pc++]

      // ── push path — 0.1.3 handles this BEFORE the switch (script.cpp:70) ────────────────────
      if (opcode <= OP.OP_PUSHDATA4) {
        let len = 0
        if (opcode < OP.OP_PUSHDATA1) len = opcode
        else if (opcode === OP.OP_PUSHDATA1) { len = script[pc]; pc += 1 }
        else if (opcode === OP.OP_PUSHDATA2) { len = script[pc] | (script[pc + 1] << 8); pc += 2 }
        else { len = script[pc] | (script[pc+1] << 8) | (script[pc+2] << 16) | (script[pc+3] << 24); pc += 4 }
        if (len === undefined || isNaN(len)) fail('truncated pushdata', opcode)
        const data = script.slice(pc, pc + len)
        if (data.length !== len) fail(`truncated push: wanted ${len}, got ${data.length}`, opcode)
        pc += len
        if (fExec) stack.push(data)          // ⚠ only when executing — the push is skipped in a false branch
        continue
      }

      // ── 0.1.3: everything else runs only when executing, EXCEPT the OP_IF…OP_ENDIF family,
      //    which must run unconditionally so that nesting is tracked (script.cpp:72).
      if (!(fExec || (opcode >= OP.OP_IF && opcode <= OP.OP_ENDIF))) continue

      switch (opcode) {
        // ── constants ───────────────────────────────────────────────────────────────────────
        case OP.OP_1NEGATE: pushNum(-1n); break
        case OP.OP_RESERVED: fail('OP_RESERVED', opcode)
        default:
          if (opcode >= OP.OP_1 && opcode <= OP.OP_16) { pushNum(BigInt(opcode - (OP.OP_1 - 1))); break }
          fail('unknown opcode', opcode)                     // 0.1.3: `default: return false`

        // ── control ─────────────────────────────────────────────────────────────────────────
        case OP.OP_NOP: break
        case OP.OP_VER: pushNum(BigInt(version)); break      // ⚠ entry-bound (spec §6b)

        case OP.OP_IF: case OP.OP_NOTIF: case OP.OP_VERIF: case OP.OP_VERNOTIF: {
          let value = false
          if (fExec) {
            need(1, opcode)
            const v = stack.pop()
            value = (opcode === OP.OP_VERIF || opcode === OP.OP_VERNOTIF)
              ? BigInt(version) >= fromNum(v)                // "am I at least version N?"
              : toBool(v)
            if (opcode === OP.OP_NOTIF || opcode === OP.OP_VERNOTIF) value = !value
          }
          vfExec.push(value)
          break
        }
        case OP.OP_ELSE:
          if (!vfExec.length) fail('OP_ELSE without OP_IF', opcode)
          vfExec[vfExec.length - 1] = !vfExec[vfExec.length - 1]
          break
        case OP.OP_ENDIF:
          if (!vfExec.length) fail('OP_ENDIF without OP_IF', opcode)
          vfExec.pop()
          break

        case OP.OP_VERIFY: { need(1, opcode); if (!toBool(stack.pop())) fail('OP_VERIFY failed', opcode); break }
        case OP.OP_RETURN: pc = script.length; break         // ⚠ jumps to the end; does NOT fail

        // ── stack ───────────────────────────────────────────────────────────────────────────
        case OP.OP_TOALTSTACK: need(1, opcode); altStack.push(stack.pop()); break
        case OP.OP_FROMALTSTACK:
          if (!altStack.length) fail('altstack underflow', opcode); stack.push(altStack.pop()); break
        case OP.OP_2DROP: need(2, opcode); stack.length -= 2; break
        case OP.OP_2DUP: need(2, opcode); stack.push([...top(-2)], [...top(-1)]); break
        case OP.OP_3DUP: need(3, opcode); stack.push([...top(-3)], [...top(-2)], [...top(-1)]); break
        case OP.OP_2OVER: need(4, opcode); stack.push([...top(-4)], [...top(-3)]); break
        case OP.OP_2ROT: {
          need(6, opcode); const s = stack.splice(stack.length - 6, 2); stack.push(...s); break
        }
        case OP.OP_2SWAP: {
          need(4, opcode); const s = stack.splice(stack.length - 4, 2); stack.push(...s); break
        }
        case OP.OP_IFDUP: need(1, opcode); if (toBool(top(-1))) stack.push([...top(-1)]); break
        case OP.OP_DEPTH: pushNum(BigInt(stack.length)); break
        case OP.OP_DROP: need(1, opcode); stack.pop(); break
        case OP.OP_DUP: need(1, opcode); stack.push([...top(-1)]); break
        case OP.OP_NIP: need(2, opcode); stack.splice(stack.length - 2, 1); break
        case OP.OP_OVER: need(2, opcode); stack.push([...top(-2)]); break
        case OP.OP_PICK: case OP.OP_ROLL: {
          need(2, opcode)
          const n = Number(popNum(opcode))
          if (n < 0 || n >= stack.length) fail(`${NAME[opcode]} index out of range`, opcode)
          const item = stack[stack.length - 1 - n]
          if (opcode === OP.OP_ROLL) stack.splice(stack.length - 1 - n, 1)
          stack.push([...item])
          break
        }
        case OP.OP_ROT: { need(3, opcode); const [a] = stack.splice(stack.length - 3, 1); stack.push(a); break }
        case OP.OP_SWAP: { need(2, opcode); const [a] = stack.splice(stack.length - 2, 1); stack.push(a); break }
        case OP.OP_TUCK: { need(2, opcode); stack.splice(stack.length - 2, 0, [...top(-1)]); break }

        // ── strings. ⚠ 0.1.3 has SUBSTR/LEFT/RIGHT here, NOT SPLIT/NUM2BIN/BIN2NUM ───────────
        case OP.OP_CAT: { need(2, opcode); const b = stack.pop(), a = stack.pop(); stack.push([...a, ...b]); break }
        case OP.OP_SUBSTR: {
          need(3, opcode)
          const count = Number(popNum(opcode)), begin = Number(popNum(opcode)), s = stack.pop()
          if (begin < 0 || count < 0 || begin + count > s.length) fail('OP_SUBSTR out of range', opcode)
          stack.push(s.slice(begin, begin + count)); break
        }
        case OP.OP_LEFT: case OP.OP_RIGHT: {
          need(2, opcode)
          const n = Number(popNum(opcode)), s = stack.pop()
          if (n < 0 || n > s.length) fail(`${NAME[opcode]} out of range`, opcode)
          stack.push(opcode === OP.OP_LEFT ? s.slice(0, n) : s.slice(n)); break
        }
        case OP.OP_SIZE: need(1, opcode); pushNum(BigInt(top(-1).length)); break

        // ── JETMORA'S OWN DATA OPS (0xb0–0xb2) ──────────────────────────────────────────────
        // ⚠ Semantics defined HERE, not inherited: these sit at our own numbers, so no external
        //   implementation is an oracle for them. Vectors are marked `jetmora` accordingly.
        //   0.1.3's SUBSTR/LEFT/RIGHT remain at 0x7f–0x81 and are kept: SPLIT is cheap for
        //   SEQUENTIAL parsing, SUBSTR is cheap for RANDOM ACCESS. Different jobs, both used.
        case JET.OP_SPLIT: {
          // (data n -- left right)
          need(2, opcode)
          const n = Number(popNum(opcode)), d = stack.pop()
          if (n < 0 || n > d.length) fail(`OP_SPLIT position ${n} outside 0..${d.length}`, opcode)
          stack.push(d.slice(0, n), d.slice(n)); break
        }
        case JET.OP_BIN2NUM: {
          // (bytes -- num) — reinterpret as a script number and re-encode minimally
          need(1, opcode); pushNum(fromNum(stack.pop())); break
        }
        case JET.OP_NUM2BIN: {
          // (num size -- bytes) — fixed-width little-endian, sign in the high bit of the LAST byte
          // ⚠⚠ `size` COMES FROM THE STACK, so this opcode's OUTPUT SIZE DEPENDS ON A VALUE, not on
          //    an input size. That is precisely the static-cost hazard (spec §4.5 / doc §5.2): a
          //    verifier cannot bound the cost before running unless `size` is a script literal.
          //    ⏭ The compiler must emit a literal here. Enforcing that is an OPEN spec item.
          need(2, opcode)
          const size = Number(popNum(opcode))
          const n = fromNum(stack.pop())
          if (size < 0) fail('OP_NUM2BIN negative size', opcode)
          if (size > maxItemSize) fail(`OP_NUM2BIN size ${size} exceeds the operator's item limit`, opcode)
          const min = toNum(n)
          if (min.length > size) fail(`OP_NUM2BIN: ${n} needs ${min.length} bytes, asked for ${size}`, opcode)
          const out = new Array(size).fill(0)
          let neg = false
          if (min.length) {
            const body = [...min]
            neg = (body[body.length - 1] & 0x80) !== 0
            if (neg) body[body.length - 1] &= 0x7f
            for (let i = 0; i < body.length; i++) out[i] = body[i]
          }
          if (size > 0 && neg) out[size - 1] |= 0x80
          stack.push(out); break
        }

        // ── bitwise. ⚠ BYTEWISE in 0.1.3 (`vch[i] = ~vch[i]`) ────────────────────────────────
        case OP.OP_INVERT: { need(1, opcode); const v = stack.pop(); stack.push(v.map(b => (~b) & 0xff)); break }
        // ⚠⚠ 0.1.3 calls MakeSameSize(): it ZERO-PADS THE SHORTER TO THE LONGER (script.cpp:26) and the
        //    result is the LONGER length. It does not truncate, and it does not refuse.
        //    ⇒ BSV REFUSES mismatched sizes. This is a genuine 013-only behaviour, not a shared one.
        case OP.OP_AND: case OP.OP_OR: case OP.OP_XOR: {
          need(2, opcode); const b = stack.pop(), a = stack.pop()
          const n = Math.max(a.length, b.length), out = []
          for (let i = 0; i < n; i++) {
            const x = a[i] ?? 0, y = b[i] ?? 0
            out.push(opcode === OP.OP_AND ? (x & y) : opcode === OP.OP_OR ? (x | y) : (x ^ y))
          }
          stack.push(out); break
        }
        case OP.OP_EQUAL: case OP.OP_EQUALVERIFY: {
          need(2, opcode); const b = stack.pop(), a = stack.pop()
          const eq = a.length === b.length && a.every((x, i) => x === b[i])
          if (opcode === OP.OP_EQUALVERIFY) { if (!eq) fail('OP_EQUALVERIFY failed', opcode) }
          else stack.push(eq ? [1] : [])
          break
        }
        case OP.OP_RESERVED1: case OP.OP_RESERVED2: fail('reserved opcode', opcode)

        // ── arithmetic. ⚠ ARBITRARY PRECISION — no 4-byte cap (script.cpp:567) ───────────────
        case OP.OP_1ADD: pushNum(popNum(opcode) + 1n); break
        case OP.OP_1SUB: pushNum(popNum(opcode) - 1n); break
        case OP.OP_2MUL: pushNum(popNum(opcode) * 2n); break
        case OP.OP_2DIV: pushNum(popNum(opcode) / 2n); break     // BigInt / truncates toward zero
        case OP.OP_NEGATE: pushNum(-popNum(opcode)); break
        case OP.OP_ABS: { const n = popNum(opcode); pushNum(n < 0n ? -n : n); break }
        case OP.OP_NOT: pushNum(popNum(opcode) === 0n ? 1n : 0n); break
        case OP.OP_0NOTEQUAL: pushNum(popNum(opcode) === 0n ? 0n : 1n); break

        case OP.OP_ADD: case OP.OP_SUB: case OP.OP_MUL: case OP.OP_DIV: case OP.OP_MOD:
        case OP.OP_LSHIFT: case OP.OP_RSHIFT: case OP.OP_BOOLAND: case OP.OP_BOOLOR:
        case OP.OP_NUMEQUAL: case OP.OP_NUMEQUALVERIFY: case OP.OP_NUMNOTEQUAL:
        case OP.OP_LESSTHAN: case OP.OP_GREATERTHAN: case OP.OP_LESSTHANOREQUAL:
        case OP.OP_GREATERTHANOREQUAL: case OP.OP_MIN: case OP.OP_MAX: {
          need(2, opcode)
          const bn2 = fromNum(stack.pop()), bn1 = fromNum(stack.pop())
          let r
          switch (opcode) {
            case OP.OP_ADD: r = bn1 + bn2; break
            case OP.OP_SUB: r = bn1 - bn2; break
            case OP.OP_MUL: r = bn1 * bn2; break
            case OP.OP_DIV: if (bn2 === 0n) fail('division by zero', opcode); r = bn1 / bn2; break
            case OP.OP_MOD: if (bn2 === 0n) fail('modulo by zero', opcode); r = bn1 % bn2; break
            // ⚠⚠ NUMERIC shifts — `bn1 << bn2.getulong()`. BSV's are BYTEWISE. Not the same opcode.
            case OP.OP_LSHIFT: if (bn2 < 0n) fail('negative shift', opcode); r = bn1 << bn2; break
            case OP.OP_RSHIFT: if (bn2 < 0n) fail('negative shift', opcode); r = bn1 >> bn2; break
            case OP.OP_BOOLAND: r = (bn1 !== 0n && bn2 !== 0n) ? 1n : 0n; break
            case OP.OP_BOOLOR: r = (bn1 !== 0n || bn2 !== 0n) ? 1n : 0n; break
            case OP.OP_NUMEQUAL: case OP.OP_NUMEQUALVERIFY: r = bn1 === bn2 ? 1n : 0n; break
            case OP.OP_NUMNOTEQUAL: r = bn1 !== bn2 ? 1n : 0n; break
            case OP.OP_LESSTHAN: r = bn1 < bn2 ? 1n : 0n; break
            case OP.OP_GREATERTHAN: r = bn1 > bn2 ? 1n : 0n; break
            case OP.OP_LESSTHANOREQUAL: r = bn1 <= bn2 ? 1n : 0n; break
            case OP.OP_GREATERTHANOREQUAL: r = bn1 >= bn2 ? 1n : 0n; break
            case OP.OP_MIN: r = bn1 < bn2 ? bn1 : bn2; break
            case OP.OP_MAX: r = bn1 > bn2 ? bn1 : bn2; break
          }
          if (opcode === OP.OP_NUMEQUALVERIFY) { if (r !== 1n) fail('OP_NUMEQUALVERIFY failed', opcode) }
          else pushNum(r)
          break
        }
        case OP.OP_WITHIN: {
          need(3, opcode)
          const max = fromNum(stack.pop()), min = fromNum(stack.pop()), x = fromNum(stack.pop())
          pushNum(x >= min && x < max ? 1n : 0n); break
        }

        // ── hashes ──────────────────────────────────────────────────────────────────────────
        case OP.OP_RIPEMD160: need(1, opcode); stack.push(ripemd160(stack.pop())); break
        case OP.OP_SHA1: need(1, opcode); stack.push(sha1(stack.pop())); break
        case OP.OP_SHA256: need(1, opcode); stack.push(sha256(stack.pop())); break
        case OP.OP_HASH160: need(1, opcode); stack.push(hash160(stack.pop())); break
        case OP.OP_HASH256: need(1, opcode); stack.push(hash256(stack.pop())); break
        case OP.OP_CODESEPARATOR: break        // ⏭ affects scriptCode once the preimage exists (spec §5.1)

        // ── signatures ──────────────────────────────────────────────────────────────────────
        case OP.OP_CHECKSIG: case OP.OP_CHECKSIGVERIFY:
        case OP.OP_CHECKMULTISIG: case OP.OP_CHECKMULTISIGVERIFY:
          fail('signature checking not implemented yet — needs the entry preimage (spec §3)', opcode)
      }
    }
    // ⚠ 0.1.3 does NOT check that OP_IF was balanced. EvalScript simply ends and returns
    //   `stack.empty() ? false : CastToBool(stack.back())`. A check here would be a MODERN rule
    //   imported by habit — it was, and the fuzzer caught it. `result` is 0.1.3's own verdict, which
    //   is a different question from whether the script ran without error.
    const result = stack.length ? toBool(stack[stack.length - 1]) : false
    return { ok: true, result, stack, altStack, error: null, ops, unbalanced: vfExec.length > 0 }
  } catch (e) {
    if (!(e instanceof ScriptError)) throw e
    return { ok: false, result: false, stack, altStack, error: e.message, ops, unbalanced: false }
  }
}
