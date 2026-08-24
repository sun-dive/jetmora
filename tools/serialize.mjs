// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// CHUNKS → BYTES. This is the job `@bsv/sdk`'s LockingScript does, and the reason it cannot do it here:
// ⚠ it cannot represent a two-byte opcode. Bounded loops need one, so this had to exist regardless of
// any licence question (doc §5.0).
import { OP, JET, DOUBLE, SINGLEBYTE_END, NAME } from './ops.mjs'

/** @typedef {{op:number, data?:number[]}} Chunk  — the same shape @bsv/sdk calls ScriptChunk. */

const isDouble = op => op >= 0xf000

/** Serialize chunks to script bytes. */
export function serialize(chunks) {
  const out = []
  for (const c of chunks) {
    const { op, data } = c
    if (isDouble(op)) {
      if ((op >> 8) !== SINGLEBYTE_END) throw new Error(`two-byte opcode must be 0xf0xx, got 0x${op.toString(16)}`)
      out.push(SINGLEBYTE_END, op & 0xff)
      if (data) out.push(...data)                  // OP_LOOP carries its count as an immediate
      continue
    }
    if (op > 0xff) throw new Error(`opcode out of range: 0x${op.toString(16)}`)
    if (op <= OP.OP_PUSHDATA4 && data) {           // a push
      if (op < OP.OP_PUSHDATA1) {
        if (data.length !== op) throw new Error(`push length ${data.length} does not match opcode ${op}`)
        out.push(op, ...data)
      } else if (op === OP.OP_PUSHDATA1) out.push(op, data.length, ...data)
      else if (op === OP.OP_PUSHDATA2) out.push(op, data.length & 0xff, data.length >> 8, ...data)
      else out.push(op, data.length & 0xff, (data.length >> 8) & 0xff,
                    (data.length >> 16) & 0xff, (data.length >> 24) & 0xff, ...data)
      continue
    }
    out.push(op)
  }
  return out
}

/** Bytes → chunks. ⚠ Must round-trip exactly: canonical serialization is a hard requirement (spec §3.1). */
export function deserialize(bytes) {
  const chunks = []
  let pc = 0
  while (pc < bytes.length) {
    const b = bytes[pc++]
    if (b === SINGLEBYTE_END) {
      if (pc >= bytes.length) throw new Error('truncated two-byte opcode')
      const op = 0xf000 | bytes[pc++]
      if (op === DOUBLE.OP_LOOP) {
        const data = bytes.slice(pc, pc + 4)
        if (data.length !== 4) throw new Error('truncated OP_LOOP count')
        pc += 4
        chunks.push({ op, data })
      } else chunks.push({ op })
      continue
    }
    if (b <= OP.OP_PUSHDATA4) {
      let len
      if (b < OP.OP_PUSHDATA1) len = b
      else if (b === OP.OP_PUSHDATA1) { len = bytes[pc]; pc += 1 }
      else if (b === OP.OP_PUSHDATA2) { len = bytes[pc] | (bytes[pc+1] << 8); pc += 2 }
      else { len = bytes[pc] | (bytes[pc+1] << 8) | (bytes[pc+2] << 16) | (bytes[pc+3] << 24); pc += 4 }
      const data = bytes.slice(pc, pc + len)
      if (data.length !== len) throw new Error(`truncated push: wanted ${len}, got ${data.length}`)
      pc += len
      chunks.push({ op: b, data })
      continue
    }
    chunks.push({ op: b })
  }
  return chunks
}

/** Human-readable, for diffing two compilations by eye. */
export function disasm(bytes) {
  return deserialize(bytes).map(c =>
    c.data && c.op <= OP.OP_PUSHDATA4
      ? `<${Buffer.from(c.data).toString('hex')}>`
      : (NAME[c.op] ?? `0x${c.op.toString(16)}`) +
        (c.data ? ` ${Buffer.from(c.data).toString('hex')}` : '')
  ).join(' ')
}
