// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ★★ READER IDIOMS FOR THE ANCHOR COVENANT — so a person can actually check it.
//
// ⚠⚠ THE PROBLEM THIS SOLVES, found 25 Aug reading the covenant back. The P2PKH output template is
// two byte literals, and the listing renders them as SCRIPT NUMBERS:
//
//     CAT(CAT(CAT(NUM2BIN(t43, 8), 346650137), t27), -11400)
//
// Both are correct. `346650137` is `19 76 a9 14` and `-11400` is `88 ac`. ⚠ And both are ILLEGIBLE —
// nobody reads a royalty payment out of that. ⇒ The reader exists so a person can CHECK the script,
// and a correct rendering that cannot be read defeats the thing it was built to serve. Same failure
// the runbook already records for shape-matched idioms, arriving from the other direction: there a
// wrong NAME, here no name at all.
//
// ★ `unbasicListing` takes `idioms` as a PARAMETER, so this is fixed here rather than in the
//   compiler's own presets. ⚠ grafverse is not touched, and no bundle is rebuilt.
import { COVENANT_IDIOMS } from '../../grafverse/mint/src/readerPresets.ts'

const push = (d: number[]) => ({ op: d.length, data: d })

/** varint(25) ‖ OP_DUP OP_HASH160 PUSH20 — the front of a standard P2PKH output. */
export const P2PKH_PRE = [0x19, 0x76, 0xa9, 0x14]
/** OP_EQUALVERIFY OP_CHECKSIG — its back. */
export const P2PKH_SUF = [0x88, 0xac]

/**
 * ⚠ `exact` because these are FIXED BYTES, not a shape. The runbook is explicit that only genuinely
 * scope-varying idioms may be shape-matched — a four-byte push of anything else would otherwise be
 * announced as a P2PKH template, and **a wrong name is worse than a stop, because a stop is visible.**
 */
export const ANCHOR_IDIOMS: any[] = [
  ...COVENANT_IDIOMS,
  {
    name: 'P2PKH_PRE',
    chunks: [push(P2PKH_PRE)],
    pops: 0,
    push: 'P2PKH_HEAD',
    exact: true,
  },
  {
    name: 'P2PKH_SUF',
    chunks: [push(P2PKH_SUF)],
    pops: 0,
    push: 'P2PKH_TAIL',
    exact: true,
  },
]
