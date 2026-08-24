// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// TEST 7 — THE ANCHOR CHAIN, verified OFFLINE.
//
// ★★★ The claim under test is not "a node accepted it". It is that ANCHOR n SPENDS ANCHOR n−1 — that
// the sequence is enforced by proof of work rather than asserted in a payload. A broadcast confirms
// that a miner agreed; running the unlocking script AGAINST the locking script proves WHY they did,
// and does it without a key on the network or a satoshi at risk.
//
// ⚠ Uses a throwaway key generated in-process. It is never printed and never leaves this file.
const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { Transaction, PrivateKey, Script, Spend } = await import(SDK)
const { anchorLock, decodeAnchor, buildAnchor } = await import('./anchor.mjs')

const hex = b => Buffer.from(b).toString('hex')
const rootOf = s => [...Buffer.from(s.padEnd(64, '0').slice(0, 64), 'hex')]
let pass = 0, fail = 0
const check = (ok, label, detail = '') => {
  console.log(`  ${ok ? '✓' : '⚠⚠⚠'} ${label}${detail ? '   ' + detail : ''}`)
  ok ? pass++ : fail++
}

const priv = PrivateKey.fromRandom()
const wif = priv.toWif()                       // ⚠ throwaway, in-process, never printed
const pubHex = priv.toPublicKey().toString()
const p2pkh = new (await import(SDK)).P2PKH()

// ── anchor 1 as it exists on chain: a PushDrop output, plus a P2PKH to fund the next one ───────
const ROOT1 = rootOf('9406cb5e' + 'ab'.repeat(28)), SIZE1 = 264
const prevTx = new Transaction()
prevTx.addOutput({ lockingScript: anchorLock(pubHex, ROOT1, SIZE1), satoshis: 1 })
prevTx.addOutput({ lockingScript: p2pkh.lock(priv.toPublicKey().toHash()), satoshis: 5000 })

const a1lock = prevTx.outputs[0].lockingScript
check(a1lock.toBinary().length === 88, 'anchor lock is 88 bytes', `(${a1lock.toBinary().length})`)
const d1 = decodeAnchor(a1lock.toHex())
check(d1?.root === hex(ROOT1) && d1.treeSize === SIZE1, 'anchor 1 decodes from the script alone',
      `size ${d1?.treeSize}`)

// ── ★★★ anchor 2 SPENDS anchor 1. This code path has never run before. ────────────────────────
const ROOT2 = rootOf('77bb31f0' + 'cd'.repeat(28)), SIZE2 = 1864
let a2 = null, buildErr = ''
try {
  const r = await buildAnchor({
    key: wif, root: ROOT2, treeSize: SIZE2,
    prev: { txid: prevTx.id('hex'), vout: 0, satoshis: 1, sourceTransaction: prevTx },
    funding: { txid: prevTx.id('hex'), vout: 1, satoshis: 5000, sourceTransaction: prevTx },
  })
  a2 = r.tx
  await a2.fee({ computeFee: async t => Math.ceil(t.toBinary().length / 1000 * 100) })
  await a2.sign()
} catch (e) { buildErr = e.message }
check(a2 !== null && !buildErr, '★★★ anchor 2 BUILDS AND SIGNS over the previous anchor', buildErr)
if (!a2) { console.log(`\n  ⚠ ${pass} passed, ${fail} failed`); process.exit(1) }

check(a2.inputs.length === 2, 'anchor 2 has two inputs: the previous anchor, and funding')
// ⚠ read the txid through sourceTransaction: an input built from a full source tx leaves
//   sourceTXID undefined, and asserting on the undefined field passes for the wrong reason
//   whenever both sides are undefined.
const in0 = a2.inputs[0].sourceTransaction?.id('hex') ?? a2.inputs[0].sourceTXID
check(in0 === prevTx.id('hex') && a2.inputs[0].sourceOutputIndex === 0,
      '★ INPUT 0 IS ANCHOR 1\'S OUTPUT — the chain link', in0?.slice(0, 16) + '…')
const d2 = decodeAnchor(a2.outputs[0].lockingScript.toHex())
check(d2?.root === hex(ROOT2) && d2.treeSize === SIZE2, 'anchor 2 commits the NEW root', `size ${d2?.treeSize}`)
check(d2.treeSize > d1.treeSize, 'tree size advances', `${d1.treeSize} \u2192 ${d2.treeSize}`)

// ── ★★★ THE ACTUAL VERIFICATION: does the unlock satisfy the lock? ────────────────────────────
const unlock = a2.inputs[0].unlockingScript
check(unlock.chunks.length === 1, 'unlocking script is JUST the signature',
      `${unlock.toBinary().length} bytes, ${unlock.chunks.length} push`)

const spend = new Spend({
  sourceTXID: prevTx.id('hex'), sourceOutputIndex: 0,
  sourceSatoshis: 1, lockingScript: a1lock,
  transactionVersion: a2.version, otherInputs: [a2.inputs[1]], outputs: a2.outputs,
  inputIndex: 0, unlockingScript: unlock,
  inputSequence: a2.inputs[0].sequence ?? 0xffffffff, lockTime: a2.lockTime,
})
let ok = false, why = ''
try { ok = spend.validate() } catch (e) { why = e.message }
check(ok, '★★★ anchor 2\'s unlock SATISFIES anchor 1\'s lock — script evaluation', why)

// ── and it must FAIL for the wrong key ────────────────────────────────────────────────────────
const wrong = PrivateKey.fromRandom()
const fundingW = new Transaction()
fundingW.addOutput({ lockingScript: anchorLock(wrong.toPublicKey().toString(), ROOT1, SIZE1), satoshis: 1 })
const spendW = new Spend({
  sourceTXID: fundingW.id('hex'), sourceOutputIndex: 0,
  sourceSatoshis: 1, lockingScript: fundingW.outputs[0].lockingScript,
  transactionVersion: a2.version, otherInputs: [a2.inputs[1]], outputs: a2.outputs,
  inputIndex: 0, unlockingScript: unlock,
  inputSequence: 0xffffffff, lockTime: a2.lockTime,
})
let refused = false
try { refused = !spendW.validate() } catch { refused = true }
check(refused, '⚠ a DIFFERENT key\'s anchor refuses the same unlock — not a rubber stamp')

// ── the fee is the policy, not a broadcaster's suggestion ──────────────────────────────────────
const size = a2.toBinary().length
const fee = 5001 - a2.outputs.reduce((s, o) => s + o.satoshis, 0)
const rate = fee / size * 1000
check(rate >= 99 && rate <= 105, 'fee rate is 100 sat/KB', `${size} B, ${fee} sat, ${rate.toFixed(1)} sat/KB`)

console.log(`\n  ${fail === 0 ? '✓' : '⚠'} ${pass} passed, ${fail} failed`)
process.exit(fail === 0 ? 0 : 1)
