// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ⚠⚠ THE CLAIM UNDER TEST: "an entry IS a transaction" (spec §3). If that is true, the preimage
// computed over an entry must be BYTE-IDENTICAL to the preimage a transaction implementation produces
// from the same field values. If it is not, OP_PUSH_TX will not port, and the covenants do not move.
//
// ⚠ Uses @bsv/sdk to establish BSV preimage compatibility — use on BSV. See NOTICE.
import { preimage } from './preimage.mjs'

const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
let TransactionSignature, LockingScript
try { ({ TransactionSignature, LockingScript } = await import(SDK)) }
catch (e) { console.log(`\nSKIPPED — needs the BSV SDK.\n  ${String(e.message).split('\n')[0]}\n`); process.exit(0) }

const hex = b => Buffer.from(b).toString('hex')
const rev = b => [...b].reverse()

// ⚠ ENDIANNESS TRAP, tested deliberately: a txid is DISPLAYED big-endian and SERIALIZED little-endian.
//   A uniform byte array would hide a mistake here, so this one is deliberately not uniform.
const prevEntry = Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff)
const scriptCode = [0x76, 0xa9, 0x14, ...new Array(20).fill(0xab), 0x88, 0xac]

const CASES = [
  ['one output',      [{ value: 500n, locking: [0x51] }]],
  ['two outputs',     [{ value: 500n, locking: [0x51] }, { value: 0n, locking: [0x52, 0x53] }]],
  ['zero-value only', [{ value: 0n, locking: [0x6a] }]],
  ['long script',     [{ value: 1n, locking: new Array(300).fill(0x51) }]],
]

let pass = 0, fail = 0
console.log('\nPREIMAGE — entry vs transaction, same fields, byte for byte\n')
for (const [name, outputs] of CASES) {
  const entry = {
    version: 2,
    inputs: [{ prevEntry, index: 3, unlocking: [], sequence: 0xfffffffe }],
    outputs, locktime: 0,
  }
  const mine = preimage({ entry, inputIndex: 0, scriptCode, value: 1234n })
  const theirs = TransactionSignature.format({
    // ⚠ the SDK takes the txid as DISPLAY hex and reverses it internally, so reverse ours going in
    sourceTXID: hex(rev(prevEntry)),
    sourceOutputIndex: 3,
    sourceSatoshis: 1234,
    transactionVersion: 2,
    otherInputs: [],
    inputIndex: 0,
    outputs: outputs.map(o => ({ satoshis: Number(o.value), lockingScript: LockingScript.fromHex(hex(o.locking)) })),
    inputSequence: 0xfffffffe,
    subscript: LockingScript.fromHex(hex(scriptCode)),
    lockTime: 0,
    // ⚠⚠ 0x41, NOT 0x01, AND THE REASON IS THE FINDING: on BSV the BIP143 algorithm is SELECTED BY
    //    FORKID. Ask for 0x01 there and you get the LEGACY pre-BIP143 sighash — the whole transaction
    //    serialized with the scriptCode substituted, no hashPrevouts, no hashOutputs, O(n²).
    //    ⇒ BSV's 0x01 and jetmora's 0x01 are DIFFERENT ALGORITHMS behind the same byte. So BSV is not
    //    an oracle for our type byte; it IS an oracle for the LAYOUT, which is what this compares.
    scope: 0x41,
  })
  // identical everywhere except the trailing 4-byte sighash type, which differs BY DESIGN (0x01 vs 0x41)
  const a1 = hex(mine).slice(0, -8), b1 = hex([...theirs]).slice(0, -8)
  const same = a1 === b1
    && hex(mine).slice(-8) === '01000000' && hex([...theirs]).slice(-8) === '41000000'
  console.log(`  ${same ? 'PASS' : 'FAIL'}  ${name.padEnd(16)} ${String(mine.length).padStart(4)} B  ` +
    (same ? 'layout identical; type byte 01 vs 41 by design' : ''))
  if (!same) {
    console.log(`        ours  ${hex(mine)}`)
    console.log(`        bsv   ${hex([...theirs])}`)
    const a = hex(mine), b = hex([...theirs])
    for (let i = 0; i < Math.max(a.length, b.length); i += 2)
      if (a.slice(i, i+2) !== b.slice(i, i+2)) { console.log(`        first difference at byte ${i/2}`); break }
  }
  same ? pass++ : fail++
}
console.log(`\n  ${pass} pass, ${fail} fail\n`)
if (fail) process.exitCode = 1
