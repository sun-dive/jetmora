// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE ANCHOR CHAIN — spec §6, §6.1a.
//
// ★★★ ANCHOR n SPENDS ANCHOR n−1. It does not cite it. A commitment held in data can be forged or
// omitted, and two anchors could both CLAIM the same predecessor; an output can be spent exactly once,
// so the sequence is ENFORCED by proof of work rather than asserted in a payload. ⇒ A log cannot
// equivocate about its own anchors at all: conflicting anchored heads would require a double spend.
//
// ⚠ The output is a PushDrop: the commitment is readable by anyone, and the output stays SPENDABLE so
//   the next anchor can consume it. An OP_RETURN would be readable and unspendable, which is exactly
//   the property that makes the chain impossible.
//
// ⚠ LICENCE: @bsv/sdk is used here to build and broadcast a BSV transaction — use ON BSV. See NOTICE.
import { createHash } from 'node:crypto'

const SDK = process.env.BSV_SDK ?? '@bsv/sdk'
const { Transaction, PrivateKey, P2PKH, Script, OP, LockingScript, UnlockingScript,
        TransactionSignature, Hash } = await import(SDK)

/** ⚠ 100 sat/KB. Never inflated, never taken from a broadcaster's suggestion. */
export const FEE_PER_KB = 100
export const MARKER = [...Buffer.from('JETMORA1')]        // 8 bytes: format marker + version

const hex = b => Buffer.from(b).toString('hex')
const u64be = n => { const o = new Array(8).fill(0); let v = BigInt(n)
  for (let i = 7; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n } return o }

/** Minimal push for a data field, matching Bitcoin's own encoder. */
function pushChunk(data) {
  if (data.length <= 0x4b) return { op: data.length, data }
  if (data.length < 0x100) return { op: OP.OP_PUSHDATA1, data }
  if (data.length < 0x10000) return { op: OP.OP_PUSHDATA2, data }
  return { op: OP.OP_PUSHDATA4, data }
}

/**
 * The anchor output: `<pubkey> OP_CHECKSIG <marker> <root> <size> OP_DROP OP_2DROP`
 * ⚠ Spendable by the log's key, and the commitment is in plain sight for anyone.
 */
export function anchorLock(pubkeyHex, root, treeSize) {
  const pub = [...Buffer.from(pubkeyHex, 'hex')]
  if (root.length !== 32) throw new Error('root must be 32 bytes')
  const fields = [MARKER, root, u64be(treeSize)]
  const chunks = [ { op: pub.length, data: pub }, { op: OP.OP_CHECKSIG }, ...fields.map(pushChunk) ]
  // three fields ⇒ OP_2DROP + OP_DROP
  chunks.push({ op: OP.OP_2DROP }, { op: OP.OP_DROP })
  return new LockingScript(chunks)
}

/** Read a commitment back out of an anchor output. ⇒ Anyone can do this from the chain alone. */
export function decodeAnchor(scriptHex) {
  const chunks = Script.fromHex(scriptHex).chunks
  const fields = chunks.filter(c => c.data && c.data.length).map(c => c.data)
  const marker = fields.find(f => f.length === 8 && hex(f) === hex(MARKER))
  if (!marker) return null
  const root = fields.find(f => f.length === 32)
  const size = fields.find(f => f.length === 8 && hex(f) !== hex(MARKER))
  if (!root || !size) return null
  return { root: hex(root), treeSize: Number(BigInt('0x' + hex(size))) }
}

/**
 * ★★ THE PUSHDROP UNLOCK — the piece that makes an anchor CHAIN rather than a series of unrelated
 * commitments. The public key already sits in the locking script, so the unlocking script is JUST THE
 * SIGNATURE: strictly smaller than a P2PKH unlock, which pushes a key nothing consumes.
 *
 * ⚠ Scope is ALL|FORKID (0x41) — this transaction lives on a proof-of-work chain, so it uses that
 *   chain's rules. Jetmora's own entries use 0x01 with the BIP143 layout (spec §3.0a); the two are
 *   different systems and the byte means different things in each.
 */
export function pushDropUnlock(priv) {
  return {
    sign: async (tx, inputIndex) => {
      const input = tx.inputs[inputIndex]
      const src = input.sourceTransaction?.outputs[input.sourceOutputIndex]
      if (!src) throw new Error('pushDropUnlock: sourceTransaction is required')
      const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID
      const preimage = TransactionSignature.format({
        sourceTXID: input.sourceTXID ?? input.sourceTransaction.id('hex'),
        sourceOutputIndex: input.sourceOutputIndex,
        sourceSatoshis: src.satoshis,
        transactionVersion: tx.version,
        otherInputs: tx.inputs.filter((_, i) => i !== inputIndex),
        inputIndex, outputs: tx.outputs,
        inputSequence: input.sequence ?? 0xffffffff,
        subscript: src.lockingScript,
        lockTime: tx.lockTime, scope,
      })
      const raw = priv.sign(Hash.sha256(preimage))
      const sig = new TransactionSignature(raw.r, raw.s, scope).toChecksigFormat()
      return new UnlockingScript([{ op: sig.length, data: sig }])
    },
    estimateLength: async () => 73,
  }
}

/**
 * Build the next anchor. ⚠ Does NOT broadcast — returns the transaction for inspection.
 * @param prev  null for the first anchor, else { txid, vout, satoshis, lockingScript }
 * @param funding  a P2PKH output to pay the fee from, and to receive change
 */
export async function buildAnchor({ key, root, treeSize, prev, funding, anchorSats = 1 }) {
  const priv = PrivateKey.fromWif(key)
  const pubHex = priv.toPublicKey().toString()
  const tx = new Transaction()

  // ⚠⚠ INPUT 0 IS THE PREVIOUS ANCHOR. Consuming it is what makes the sequence unforgeable — this is
  //    the whole of §6.1a, and it is one line.
  if (prev) {
    tx.addInput({
      sourceTXID: prev.txid, sourceOutputIndex: prev.vout,
      sourceSatoshis: prev.satoshis,
      unlockingScriptTemplate: pushDropUnlock(priv),       // ★ the chain-forming spend
      sequence: 0xffffffff,
    })
  }
  tx.addInput({
    sourceTXID: funding.txid, sourceOutputIndex: funding.vout,
    sourceSatoshis: funding.satoshis,
    unlockingScriptTemplate: new P2PKH().unlock(priv),
    sequence: 0xffffffff,
  })
  tx.addOutput({ lockingScript: anchorLock(pubHex, root, treeSize), satoshis: anchorSats })
  tx.addOutput({ lockingScript: new P2PKH().lock(priv.toPublicKey().toHash()), change: true })
  return { tx, pubHex }
}
