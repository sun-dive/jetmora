<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE `BT` SET: opcode numbering ───────────────────────────────────────────────────────────────────
// **Bitcoin 0.1.3, complete and unaltered.** From src/script.h of github.com/trottier/original-bitcoin.
//
// ⚠⚠ THIS SET ANSWERS TO `script.cpp`, NOT TO US. It is not "jetmora's set minus three opcodes" — the
// authority runs the other way: 0.1.3 is the original, and jetmora's own set is 0.1.3 PLUS additions.
// ⇒ §5b.1: "Bitcoin 0.1.3's assignments are authoritative in the single-byte space."
//
// ★ THE RULE FOR BUILDING THIS SET: when reading the history, anything that says "changed in",
//   "removed in" or "renumbered in" is OUT OF SCOPE. A version that deleted something is a DIFFERENT
//   SET, not a later revision of this one. This set is one snapshot of one file.
//
// ⚠⚠ WHERE IT DIVERGES FROM BSV — and the whole reason these are separate files:
//   0x7f  SUBSTR   (BSV: SPLIT)
//   0x80  LEFT     (BSV: NUM2BIN)
//   0x81  RIGHT    (BSV: BIN2NUM)
// ⇒ A 2009 script containing 0x7f means SUBSTR. Running it under `SV` gives SPLIT — **not an error, a
//   different answer**, which is worse. That is what this set exists to prevent.
declare(strict_types=1);

const BT_OP = [
  'OP_0'=>0x00, 'OP_PUSHDATA1'=>0x4c, 'OP_PUSHDATA2'=>0x4d, 'OP_PUSHDATA4'=>0x4e, 'OP_1NEGATE'=>0x4f,
  'OP_RESERVED'=>0x50,
  'OP_1'=>0x51,  'OP_2'=>0x52,  'OP_3'=>0x53,  'OP_4'=>0x54,  'OP_5'=>0x55,  'OP_6'=>0x56,
  'OP_7'=>0x57,  'OP_8'=>0x58,  'OP_9'=>0x59,  'OP_10'=>0x5a, 'OP_11'=>0x5b, 'OP_12'=>0x5c,
  'OP_13'=>0x5d, 'OP_14'=>0x5e, 'OP_15'=>0x5f, 'OP_16'=>0x60,
  'OP_NOP'=>0x61, 'OP_VER'=>0x62, 'OP_IF'=>0x63, 'OP_NOTIF'=>0x64, 'OP_VERIF'=>0x65,
  'OP_VERNOTIF'=>0x66, 'OP_ELSE'=>0x67, 'OP_ENDIF'=>0x68, 'OP_VERIFY'=>0x69, 'OP_RETURN'=>0x6a,
  'OP_TOALTSTACK'=>0x6b, 'OP_FROMALTSTACK'=>0x6c, 'OP_2DROP'=>0x6d, 'OP_2DUP'=>0x6e, 'OP_3DUP'=>0x6f,
  'OP_2OVER'=>0x70, 'OP_2ROT'=>0x71, 'OP_2SWAP'=>0x72, 'OP_IFDUP'=>0x73, 'OP_DEPTH'=>0x74,
  'OP_DROP'=>0x75, 'OP_DUP'=>0x76, 'OP_NIP'=>0x77, 'OP_OVER'=>0x78, 'OP_PICK'=>0x79, 'OP_ROLL'=>0x7a,
  'OP_ROT'=>0x7b, 'OP_SWAP'=>0x7c, 'OP_TUCK'=>0x7d,
  'OP_CAT'=>0x7e,
  'OP_SUBSTR'=>0x7f, 'OP_LEFT'=>0x80, 'OP_RIGHT'=>0x81,     // ⚠⚠ NOT SPLIT/NUM2BIN/BIN2NUM
  'OP_SIZE'=>0x82,
  'OP_INVERT'=>0x83, 'OP_AND'=>0x84, 'OP_OR'=>0x85, 'OP_XOR'=>0x86,
  'OP_EQUAL'=>0x87, 'OP_EQUALVERIFY'=>0x88, 'OP_RESERVED1'=>0x89, 'OP_RESERVED2'=>0x8a,
  'OP_1ADD'=>0x8b, 'OP_1SUB'=>0x8c, 'OP_2MUL'=>0x8d, 'OP_2DIV'=>0x8e, 'OP_NEGATE'=>0x8f,
  'OP_ABS'=>0x90, 'OP_NOT'=>0x91, 'OP_0NOTEQUAL'=>0x92,
  'OP_ADD'=>0x93, 'OP_SUB'=>0x94, 'OP_MUL'=>0x95, 'OP_DIV'=>0x96, 'OP_MOD'=>0x97,
  'OP_LSHIFT'=>0x98, 'OP_RSHIFT'=>0x99,                     // ⚠⚠ NUMERIC shifts, not bytewise
  'OP_BOOLAND'=>0x9a, 'OP_BOOLOR'=>0x9b, 'OP_NUMEQUAL'=>0x9c, 'OP_NUMEQUALVERIFY'=>0x9d,
  'OP_NUMNOTEQUAL'=>0x9e, 'OP_LESSTHAN'=>0x9f, 'OP_GREATERTHAN'=>0xa0,
  'OP_LESSTHANOREQUAL'=>0xa1, 'OP_GREATERTHANOREQUAL'=>0xa2,
  'OP_MIN'=>0xa3, 'OP_MAX'=>0xa4, 'OP_WITHIN'=>0xa5,
  'OP_RIPEMD160'=>0xa6, 'OP_SHA1'=>0xa7, 'OP_SHA256'=>0xa8, 'OP_HASH160'=>0xa9, 'OP_HASH256'=>0xaa,
  'OP_CODESEPARATOR'=>0xab, 'OP_CHECKSIG'=>0xac, 'OP_CHECKSIGVERIFY'=>0xad,
  'OP_CHECKMULTISIG'=>0xae, 'OP_CHECKMULTISIGVERIFY'=>0xaf,
];

// ── THE TWO-BYTE SPACE ───────────────────────────────────────────────────────────────────────────────
// ★ 0.1.3 declares OP_SINGLEBYTE_END = 0xf0 and OP_DOUBLEBYTE_BEGIN = 0xf000, and its reader takes the
//   NEXT byte when it sees 0xf0. Satoshi implemented the mechanism and defined NO occupants.
// ⇒ So this set reads the prefix and finds nothing valid behind it. **That is complete, not unfinished.**
//   The occupants (OP_LOOP at 0xf010) belong to jetmora's own set, which declares them.
const BT_SINGLEBYTE_END = 0xf0;

function bt_op_name(int $n): string {
  static $rev = null;
  if ($rev === null) $rev = array_flip(BT_OP);
  return $rev[$n] ?? sprintf('OP_UNKNOWN_%02x', $n);
}
