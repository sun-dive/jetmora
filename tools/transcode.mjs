// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// BSV-NUMBERED CHUNKS → JETMORA-NUMBERED CHUNKS.
//
// ⚠⚠ WHY THIS EXISTS, AND WHY IT MUST NOT BE SKIPPED. BSV places SPLIT/NUM2BIN/BIN2NUM at 0x7f/0x80/0x81,
// overwriting 0.1.3's SUBSTR/LEFT/RIGHT. Jetmora keeps 0.1.3's range intact and puts its own ops at
// 0xb0–0xb2. ⇒ The SAME BYTE means a DIFFERENT INSTRUCTION on each rail:
//
//        0x7f   on BSV = OP_SPLIT        on jetmora = OP_SUBSTR
//        0x80   on BSV = OP_NUM2BIN      on jetmora = OP_LEFT
//        0x81   on BSV = OP_BIN2NUM      on jetmora = OP_RIGHT
//
// Run BSV bytes on jetmora without transcoding and they will not error — they will QUIETLY COMPUTE
// SOMETHING ELSE. That is the worst class of bug this project can have, so the mapping is explicit,
// total, and refuses anything it does not recognise.
import { OP, JET, NAME } from './ops.mjs'

/** BSV opcode number → jetmora opcode number. Identity everywhere except these three. */
export const BSV_TO_JET = new Map([
  [0x7f, JET.OP_SPLIT],
  [0x80, JET.OP_NUM2BIN],
  [0x81, JET.OP_BIN2NUM],
])

/** Opcodes BSV does not have, so a jetmora script containing them cannot be run there at all. */
const JET_ONLY = new Set([...Object.values(JET), 0xf010, 0xf011])

/**
 * @param {{op:number,data?:number[]}[]} chunks   as emitted by a BSV-targeted compiler
 * @returns {{op:number,data?:number[]}[]}        jetmora-numbered
 * @throws if a chunk cannot be mapped — never guesses
 */
export function bsvToJetmora(chunks) {
  return chunks.map((c, i) => {
    if (c.op <= OP.OP_PUSHDATA4) return { ...c }              // pushes are identical on both
    if (BSV_TO_JET.has(c.op)) return { ...c, op: BSV_TO_JET.get(c.op) }
    if (JET_ONLY.has(c.op)) throw new Error(`chunk ${i}: 0x${c.op.toString(16)} is jetmora-only and cannot appear in BSV input`)
    if (!(c.op in NAME)) throw new Error(`chunk ${i}: unknown opcode 0x${c.op.toString(16)} — refusing to guess`)
    return { ...c }
  })
}

/** The reverse. ⚠ Throws on anything jetmora-only: those have no BSV equivalent, by design. */
export function jetmoraToBsv(chunks) {
  const back = new Map([...BSV_TO_JET].map(([a, b]) => [b, a]))
  return chunks.map((c, i) => {
    if (c.op <= OP.OP_PUSHDATA4) return { ...c }
    if (back.has(c.op)) return { ...c, op: back.get(c.op) }
    if (c.op >= 0xf000) throw new Error(`chunk ${i}: ${NAME[c.op] ?? 'two-byte opcode'} has no BSV equivalent`)
    if (c.op >= 0xb0 && c.op <= 0xef) throw new Error(`chunk ${i}: 0x${c.op.toString(16)} is jetmora-only`)
    return { ...c }
  })
}

/** Which opcodes in a script make it jetmora-only — i.e. why it cannot be appealed to BSV (doc §2b). */
export function jetmoraOnly(chunks) {
  return chunks.filter(c => c.op >= 0xb0).map(c => NAME[c.op] ?? `0x${c.op.toString(16)}`)
}
