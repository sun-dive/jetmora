<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// Run the `JF` interpreter against its own tests and report.
//
// ⚠ `JF` has no entry in vectors/core.json yet: that file's oracles are bsv / 013 / jetmora, and a `JF`
//   vector would need a second implementation to be an oracle AGAINST. Until there is one, these are
//   tests, not conformance vectors, and the distinction is worth keeping — a test says "it does what I
//   thought", a vector says "two implementations agree".
//
// ★ The tests that matter most are not the arithmetic. They are the ones that prove the TIER BOUNDARY
//   is enforced rather than declared: a function cannot see the caller's stack, cannot return the wrong
//   number of values, and cannot reach back.
//
//   php server/verify-jf.php           → run
//   php server/verify-jf.php -v        → show each test
declare(strict_types=1);
require_once __DIR__ . '/interpreter-jf.php';

if (!extension_loaded('gmp')) { fwrite(STDERR, "⛔ ext-gmp is required.\n"); exit(2); }

// ⚠ the assembler now lives in jf-asm.php — the wallet needs it too
require_once __DIR__ . '/jf-asm.php';

// ── the tests ────────────────────────────────────────────────────────────────────────────────────────
$T = [];
/** expect the final stack to equal these cell values */
function t(string $id, string $src, array $want, string $defs = ''): void {
  global $T; $T[] = [$id, $defs . jf_asm($src), $want, null];
}
/** expect a throw whose message contains this */
function tf(string $id, string $src, string $msg, string $defs = ''): void {
  global $T; $T[] = [$id, $defs . jf_asm($src), null, $msg];
}
/** expect an ABORT carrying exactly this diagnostic — ⚠ the DIAGNOSTIC, not the message text */
function td(string $id, string $src, string $diag, string $defs = ''): void {
  global $T; $T[] = [$id, $defs . jf_asm($src), null, null, $diag];
}

// literals and cells
t('lit.small',      '0 1 16 -1',            [0, 1, 16, -1]);
t('lit.byte',       '100 -100',             [100, -100]);
t('lit.word',       '30000 -30000',         [30000, -30000]);
t('lit.dword',      '1000000 -1000000',     [1000000, -1000000]);
t('cell.wrap',      '1 63 LSHIFT',          [PHP_INT_MIN]);   // 2^63 WRAPS to the negative, never floats
t('cell.max',       '1 63 LSHIFT 1 -',      [PHP_INT_MAX]);

// stack
t('stack.dup',      '7 DUP',                [7, 7]);
t('stack.swap',     '1 2 SWAP',             [2, 1]);
t('stack.rot',      '1 2 3 ROT',            [2, 3, 1]);
t('stack.nip',      '1 2 NIP',              [2]);
t('stack.tuck',     '1 2 TUCK',             [2, 1, 2]);
t('stack.qdup0',    '0 ?DUP',               [0]);
t('stack.qdup1',    '5 ?DUP',               [5, 5]);
t('stack.pick',     '1 2 3 2 PICK',         [1, 2, 3, 1]);
t('stack.roll',     '1 2 3 2 ROLL',         [2, 3, 1]);
t('stack.depth',    '1 2 3 DEPTH',          [1, 2, 3, 3]);
t('stack.rstack',   '1 2 >R R>',            [1, 2]);
t('stack.2r',       '1 2 2>R 2R>',          [1, 2]);
tf('stack.underflow', 'DUP',                'underflow');

// arithmetic — the ones that separate a real Forth from an approximate one
t('arith.add',      '2 3 +',                [5]);
t('arith.divTrunc', '-7 2 /',               [-3]);              // symmetric, NOT floored
t('arith.modSign',  '-7 2 MOD',             [-1]);              // remainder takes the DIVIDEND's sign
t('arith.divmod',   '-7 2 /MOD',            [-1, -3]);
t('arith.starslash','10 7 3 */',            [23]);              // intermediate stays double width
t('arith.2div',     '-7 2/',                [-4]);              // arithmetic shift: floors
t('arith.absneg',   '-5 ABS -5 NEGATE',     [5, 5]);
t('arith.minmax',   '3 9 MIN 3 9 MAX',      [3, 9]);
// ★ FM/MOD is FLOORED and SM/REM is SYMMETRIC. Collapsing them is the classic Forth bug.
t('arith.fmmod',    '-7 2 FM/MOD',          [1, -4]);
t('arith.smrem',    '-7 2 SM/REM',          [-1, -3]);
tf('arith.div0',    '1 0 /',                'division by zero');

// logic
t('logic.and',      '12 10 AND',            [8]);
t('logic.invert',   '0 INVERT',             [-1]);
t('logic.shift',    '1 8 LSHIFT',           [256]);
t('logic.rshiftLogical', '-1 63 RSHIFT',    [1]);               // LOGICAL, so -1 >> 63 is 1

// comparison — Forth's TRUE is all bits set, not 1
t('cmp.true',       '1 1 =',                [-1]);
t('cmp.false',      '1 2 =',                [0]);
t('cmp.unsigned',   '-1 1 U<',              [0]);               // -1 is huge unsigned
t('cmp.signed',     '-1 1 <',               [-1]);
t('cmp.within',     '5 1 10 WITHIN 10 1 10 WITHIN', [-1, 0]);   // hi is EXCLUSIVE

// memory
t('mem.store',      '1234 64 ! 64 @',       [1234]);
t('mem.cstore',     '65 64 C! 64 C@',       [65]);
t('mem.plusstore',  '10 64 ! 5 64 +! 64 @', [15]);
t('mem.cells',      '3 CELLS 8 CELL+',      [24, 16]);
t('mem.aligned',    '9 ALIGNED',            [16]);
tf('mem.bounds',    '1 1000000 !',          'out of range');

// branches and loops
t('branch.notTaken','1 0BRANCH>skip 99 skip: 7',  [99, 7]);   // nonzero: no branch, 99 runs
t('branch.taken',   '0 0BRANCH>skip 99 skip: 7',  [7]);       // zero: branch, 99 skipped
// : sum ( -- 10 )  0  5 0 DO I + LOOP ;
t('loop.do',        '0 5 0 (DO) top: I + (LOOP)>top', [10]);
t('loop.zeroTrip',  '0 0 (?DO)>done 99 done: 42', [42]);
t('loop.plusloop',  '0 10 0 (DO) top: I + 2 (+LOOP)>top', [20]);
t('loop.leave',     '0 100 0 (DO) top: I + I 3 = 0BRANCH>go LEAVE>out go: (LOOP)>top out: 42', [6, 42]);

// locals — the readability mechanism, and its runtime
// : fee { total rate -- cut }  total rate * 100 / ;
t('locals.fee',     '1000 5 (FRAME)#2 (LOCAL@)#0 (LOCAL@)#1 * 100 / (UNFRAME)', [50]);
t('locals.store',   '1 2 (FRAME)#2 9 (LOCAL!)#0 (LOCAL@)#0 (UNFRAME)', [9]);
tf('locals.noframe','(LOCAL@)#0',           'no frame');

// byte strings — ( c-addr u ) throughout
t('str.push',       '$deadbeef DROP DROP',  []);
t('str.size',       '$deadbeef SIZE',       [65532, 4, 4]);      // scratch grows DOWN from 65536
// ★ SPLIT copies nothing: two spans over the SAME bytes. de ad -> 0xadde, be ef -> 0xefbe.
t('str.split',      '$deadbeef 2 SPLIT BIN2NUM >R BIN2NUM R>', [44510, 61374]);
t('str.bin2num',    '$0100 BIN2NUM',        [1]);                // little-endian
t('str.num2bin',    '258 2 100 NUM2BIN BIN2NUM', [258]);
t('str.cat',        '$aabb $ccdd 100 CAT BIN2NUM', [0xddccbbaa]);
t('str.substr',     '$00112233 1 2 100 SUBSTR BIN2NUM', [0x2211]);
tf('str.substrOver','$0011 0 5 100 SUBSTR', 'out of range');

// crypto
t('crypto.sha256',  '$ 100 SHA256 100 4 BIN2NUM',
  // sha256("") = e3b0c442... → first 4 bytes little-endian = 0x42c4b0e3
  [0x42c4b0e3]);
t('crypto.hash160', '$ 100 HASH160 100 4 BIN2NUM', [0x66a272b4]);

// ── signatures ───────────────────────────────────────────────────────────────────────────────────────
// ⚠ PINNED VECTOR. Minted once with openssl as an ORACLE and checked to verify there before being
//   written down; openssl is NOT a runtime dependency and `server/secp256k1-jf.php` imports nothing.
//   ★ Same discipline the acid test uses: an oracle you disagree with is informative, a dependency you
//   disagree with is a bug you inherit.
const VEC_PUB = '0219b0f59a3a6f44ec2956626e8e6bec3ae57ec4c09e0724099713329460260268';
const VEC_UNC = '0419b0f59a3a6f44ec2956626e8e6bec3ae57ec4c09e07240997133294602602683a571cb658d6b1dc1576'
              . '812adb0166eac290eafacdc23b869c94cd1bd8b38142';
const VEC_SIG = '3045022015fc01dd54c6c52a881f276933dfbecfdee11e704e925324f3e6bf27b07be537022100c36b'
              . 'ffdda4b0e71e0d244a5a89b7e34f8db2b7ca23bf1446fe9ec6d7e8727ea6';
const VEC_DIG = 'd4cc9c8953d2699f1c7b456ade7099c8376b392eb5c0ae8bf1a90887ce3832de';
$flip = fn(string $hex, int $i) => substr($hex, 0, $i) . dechex(hexdec($hex[$i]) ^ 1) . substr($hex, $i + 1);

t('sig.verifies',   '$' . VEC_SIG . ' $' . VEC_PUB . ' $' . VEC_DIG . ' CHECKSIG', [-1]);
t('sig.uncompressed','$' . VEC_SIG . ' $' . VEC_UNC . ' $' . VEC_DIG . ' CHECKSIG', [-1]);
t('sig.badDigest',  '$' . VEC_SIG . ' $' . VEC_PUB . ' $' . $flip(VEC_DIG, 0) . ' CHECKSIG', [0]);
t('sig.tampered',   '$' . $flip(VEC_SIG, 20) . ' $' . VEC_PUB . ' $' . VEC_DIG . ' CHECKSIG', [0]);

// ── ED25519-CHECKSIG, appended at 0xDD. Graded by RFC 8032 §7.1 test vectors 2 and 3. ──────────────
const ED_PUB2 = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';   // TEST 2, msg 72
const ED_SIG2 = '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';
const ED_PUB3 = 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025';   // TEST 3, msg af82
const ED_SIG3 = '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a';
t('ed.verifies2',   '$' . ED_SIG2 . ' $' . ED_PUB2 . ' $72 ED25519-CHECKSIG', [-1]);
t('ed.verifies3',   '$' . ED_SIG3 . ' $' . ED_PUB3 . ' $af82 ED25519-CHECKSIG', [-1]);
t('ed.badMessage',  '$' . ED_SIG3 . ' $' . ED_PUB3 . ' $af83 ED25519-CHECKSIG', [0]);
t('ed.tampered',    '$' . $flip(ED_SIG3, 10) . ' $' . ED_PUB3 . ' $af82 ED25519-CHECKSIG', [0]);
t('ed.wrongKey',    '$' . ED_SIG3 . ' $' . ED_PUB2 . ' $af82 ED25519-CHECKSIG', [0]);
t('ed.keyLength',   '$' . ED_SIG3 . ' $' . ED_PUB3 . '00 $af82 ED25519-CHECKSIG', [0]);      // 33 bytes: failed, not an error
t('ed.notSecp',     '$' . ED_SIG3 . ' $' . ED_PUB3 . ' $af82 CHECKSIG', [0]);                // CHECKSIG stays secp256k1
t('ed.verify',      '$' . ED_SIG3 . ' $' . ED_PUB3 . ' $af82 ED25519-CHECKSIGVERIFY 7', [7]);
tf('ed.verifyFails','$' . ED_SIG3 . ' $' . ED_PUB3 . ' $af83 ED25519-CHECKSIGVERIFY', 'ED25519-CHECKSIGVERIFY failed');
t('sig.wrongKey',   '$' . VEC_SIG . ' $' . $flip(VEC_PUB, 10) . ' $' . VEC_DIG . ' CHECKSIG', [0]);
t('sig.garbageDer', '$30020000 $' . VEC_PUB . ' $' . VEC_DIG . ' CHECKSIG', [0]);
tf('sig.verifyFails','$' . VEC_SIG . ' $' . VEC_PUB . ' $' . $flip(VEC_DIG, 0) . ' CHECKSIGVERIFY',
   'CHECKSIGVERIFY failed');
// ⚠ An off-curve x must be REFUSED, not silently accepted: the square root always returns something,
//   so without the on-curve check a point that is not on the curve verifies against nothing at all.
t('sig.offCurveKey', '$' . VEC_SIG . ' $02' . str_repeat('11', 32) . ' $' . VEC_DIG . ' CHECKSIG', [0]);

// ⛔ NO DUMMY ELEMENT. BTC's off-by-one is a bug `BT` carries for fidelity; reproducing it in a new
//    set would be an amputation in reverse.  ( msg  keys.. n  sigs.. m -- flag )
t('multisig.1of2',  '$' . VEC_DIG . ' $' . VEC_PUB . ' $' . VEC_PUB . ' 2 $' . VEC_SIG . ' 1 CHECKMULTISIG', [-1]);
t('multisig.1of1',  '$' . VEC_DIG . ' $' . VEC_PUB . ' 1 $' . VEC_SIG . ' 1 CHECKMULTISIG', [-1]);
t('multisig.fails', '$' . $flip(VEC_DIG, 0) . ' $' . VEC_PUB . ' 1 $' . VEC_SIG . ' 1 CHECKMULTISIG', [0]);
tf('multisig.moreSigsThanKeys',
   '$' . VEC_DIG . ' $' . VEC_PUB . ' 1 $' . VEC_SIG . ' $' . VEC_SIG . ' 2 CHECKMULTISIG', 'bad key count');

// ── ⛔ THE TIER BOUNDARY. These are the tests the design turns on. ───────────────────────────────────
$D1 = jf_defs([[2, 1, '+']]);                            // 0: ( a b -- sum )
t('invoke.calls',   '10 20 INVOKE#0',        [30], $D1);
t('invoke.leavesRest','9 10 20 INVOKE#0',    [9, 30], $D1);

$D2 = jf_defs([[1, 1, 'DEPTH NIP']]);                    // report the depth it can see
t('invoke.freshStack','7 8 9 INVOKE#0',      [7, 8, 1], $D2);   // ⇒ sees 1, not 3

$D3 = jf_defs([[1, 1, '1 PICK']]);                       // try to reach past the argument
tf('invoke.cannotReach','7 8 INVOKE#0',      'underflow', $D3);

$D4 = jf_defs([[1, 2, 'DROP']]);                         // declares 2 out, produces 0
tf('invoke.arity',  '7 INVOKE#0',            'declared 2 out, produced 0', $D4);

$D5 = jf_defs([[0, 1, 'R>']]);                           // try to unwind into the caller
tf('invoke.freshReturnStack','1 >R INVOKE#0','return stack underflow', $D5);

$D6 = jf_defs([[1, 1, 'DUP']]);
tf('invoke.noSuchDef','1 INVOKE#3',          'no such definition', $D6);

// ── ★★★ THE DECLARED CHANNELS — his call, 7 Sept ────────────────────────────────────────────────────
// EMIT returns its contents; ACCEPT receives from the caller. Both are DECLARED in the DEFS header, so
// both are COUNTED — which is what makes them legal without weakening the arity contract.
//   CORE bank slots:  EMIT 72 · KEY 87 · ACCEPT 45 · TYPE 118 · CR 63 · SPACE 113 · SPACES 114
$E1 = jf_defs([[1, 0, '[CORE:72]', 0, 16]]);              // ( char -- ), out_max 16
t('chan.emitReturns',  '65 INVOKE#0 BIN2NUM',   [65], $E1);          // 'A' comes back as bytes
$E2 = jf_defs([[0, 0, '65 [CORE:72] 66 [CORE:72]', 0, 16]]);
t('chan.emitTwo',      'INVOKE#0 BIN2NUM',      [0x4241], $E2);      // "AB" little-endian
$E3 = jf_defs([[0, 0, '$414243 [CORE:118]', 0, 16]]);     // TYPE ( c-addr u -- )
t('chan.type',         'INVOKE#0 BIN2NUM',      [0x434241], $E3);
$E4 = jf_defs([[0, 0, '65 [CORE:72]', 0, 0]]);            // emits but declared no channel
tf('chan.emitUndeclared','INVOKE#0',            'declared no output channel', $E4);
$E5 = jf_defs([[0, 0, '65 [CORE:72] 66 [CORE:72]', 0, 1]]);
tf('chan.outOverflow', 'INVOKE#0',              'exceeds the declared out_max of 1', $E5);

$I1 = jf_defs([[0, 1, '[CORE:87]', 8, 0]]);               // KEY ( -- char ), in_max 8
t('chan.keyReceives',  '$41 INVOKE#0',          [65], $I1);
$I2 = jf_defs([[0, 1, '100 8 [CORE:45]', 16, 0]]);        // ACCEPT ( c-addr n1 -- n2 )
t('chan.acceptCount',  '$686921 INVOKE#0',      [3], $I2);
$I3 = jf_defs([[0, 1, '100 8 [CORE:45] DROP 100 3 BIN2NUM', 16, 0]]);
t('chan.acceptStores', '$686921 INVOKE#0',      [0x216968], $I3);    // "hi!" landed at addr 100
// ⚠ ACCEPT stops at a newline and CONSUMES it without storing — the part that is easy to get wrong.
$I4 = jf_defs([[0, 1, '100 8 [CORE:45]', 16, 0]]);
t('chan.acceptStopsAtNewline', '$68690a6969 INVOKE#0', [2], $I4);
$I5 = jf_defs([[0, 1, '[CORE:87]', 0, 0]]);
tf('chan.keyUndeclared','INVOKE#0',             'declared no input channel', $I5);
tf('chan.inTooBig',    '$4142 INVOKE#0',        'declared in_max 1',
   jf_defs([[0, 1, '[CORE:87]', 1, 0]]));

// ★★ ROUND TRIP: the caller hands bytes in, the function hands bytes back.
$R1 = jf_defs([[0, 0, '[CORE:87] [CORE:72]', 4, 4]]);     // KEY then EMIT
t('chan.roundTrip',    '$41 INVOKE#0 BIN2NUM',  [65], $R1);

// ⛔ A nested call must not write into its caller's buffer.
$N = jf_defs([[0, 0, '65 [CORE:72]', 0, 4],                          // 0: emits "A"
              [0, 0, '66 [CORE:72] INVOKE#0 DROP DROP', 0, 4]]);     // 1: emits "B", calls 0, drops it
t('chan.nestedIsolated', 'INVOKE#1 BIN2NUM',    [66], $N);           // ⇒ "B" only, never "BA"

// ── ★★ AND THE OUTPUT CHANNEL IS A DIAGNOSTIC CHANNEL (his point, 7 Sept) ───────────────────────────
// "Return values that could for example be sent back to the wallet as an error message even."
//   : check ( n -- ok )   n 10 <  IF  ." too small"  0  ELSE  -1  THEN ;
// ⇒ jetForth gets BOTH the verdict and the reason, and decides what to do with each.
$MSG = '746f6f20736d616c6c';                                          // "too small"
$C1 = jf_defs([[1, 1, '10 < 0BRANCH>ok $' . $MSG . ' [CORE:118] 0 BRANCH>done ok: -1 done:', 0, 32]]);
// ⚠ the returned span is a COPY: the literal inside the function took scratch first, so the address
//   is not the literal's. Reading it through the returned address rather than a magic number is the
//   whole point — a caller never has to know where the function put anything.
// ⚠ 65527, not 65518: the function's own literal now sits in the function's OWN arena, so the
//   caller's scratch is untouched until the returned copy lands. The address is evidence of the
//   memory boundary, which an earlier version of this file did not have.
t('diag.failCarriesReason', '5 INVOKE#0 DROP',   [0, 65527], $C1);    // verdict 0 + an address
t('diag.reasonLength',      '5 INVOKE#0 NIP',    [0, 9], $C1);        // ...and a 9-byte reason
t('diag.passIsSilent',      '20 INVOKE#0 NIP',   [-1, 0], $C1);       // verdict -1, reason empty
// ★ and the reason is READABLE at the address the function handed back: "too small" begins with 't'
t('diag.reasonIsTheText',   '5 INVOKE#0 DROP C@', [0, 116], $C1);

// ── ★★★ ABORT CARRIES THE REASON OUT (his call, 7 Sept) ─────────────────────────────────────────────
// ★ `ABORT` is Forth's own word, promoted to jetForth; `(ABORT")` is what `ABORT"` compiles to.
//   ⚠ A BSV covenant fails with "the top stack element must be true" and nothing else. This one says
//   why, and because the message is bytes the script chose, the reason is part of the proof.
td('abort.bare',        'ABORT',                    '');
td('abort.withReason',  '-1 (ABORT")$' . $MSG,        "too small");
t('abort.flagFalse',    '0 (ABORT")$' . $MSG . ' 7',   [7]);     // not taken, literal skipped
// ⚠ the diagnostic is null for a machine fault: an underflow is not the script speaking
tf('abort.faultIsNotADiagnostic', 'DUP', 'underflow');

// ★★ END TO END: stdForth returns the reason, jetForth decides, the ABORT carries it to the wallet.
//    ( ok c-addr u )  ->  invert ok, keeping the span, then abort if not ok
// ★ jetForth still gets the function's reason as DATA and can branch on it — it simply cannot POST
//   that data outward. The message the wallet sees is a literal the script author wrote.
td('abort.fromStdForth', '5 INVOKE#0 DROP DROP 0= (ABORT")$' . $MSG,  'too small', $C1);
t('abort.passesThrough', '20 INVOKE#0 DROP DROP 0= (ABORT")$' . $MSG . ' 7', [7], $C1);

// ── ⛔⛔⛔ ISOLATION: NOTHING CROSSES THE BOUNDARY EXCEPT WHAT WAS DECLARED (his call, 7 Sept) ────────
// "Nothing involving a key can be passed into or out of a stdForth function. Or out through ABORT."
// ⚠ All three of these were MEASURED LEAKING before they were fixed. They are regression tests.
$Z1 = jf_defs([[0, 1, '200 @']]);                    // a function reading an address it was never given
t('iso.memoryIsFresh',  '123456 200 ! INVOKE#0', [0], $Z1);   // ⇒ 0, not 123456
$Z2 = jf_defs([[0, 0, '999 200 !']]);                // a function scribbling on memory
t('iso.noResidue',      'INVOKE#0 200 @',        [0], $Z2);   // ⇒ the caller's arena is untouched
$Z3 = jf_defs([[0, 2, '100 PREIMAGE']]);             // a function reaching for transaction context
tf('iso.preimageRefused','INVOKE#0',   'covenant-tier only', $Z3);
$Z4 = jf_defs([[0, 2, '100 OUTPUTS-HASH']]);         // ...and the guard is on the whole TX group
tf('iso.txGroupRefused','INVOKE#0',    'covenant-tier only', $Z4);
// ★ The abort message is an INLINE literal, so there is no stack form to post computed bytes through.
//   It is public by construction: it is in the script.
td('iso.abortIsALiteral','-1 (ABORT")$6f6b',      'ok');

// ── ⛔ BANK ESCAPES ──────────────────────────────────────────────────────────────────────────────────
tf('bank.illegalInCovenant', '[FLOATING:3]', 'illegal in jetForth');
// inside a DEFS body it is stdForth, so it is refused BY NAME rather than as a bad byte
$D7 = jf_defs([[0, 1, '[FLOATING:3]']]);
tf('bank.namedRefusal', 'INVOKE#0',          'wordset not implemented: FLOATING', $D7);
$D8 = jf_defs([[0, 1, '[CORE:70]']]);                    // CORE slot 70 is DUP, which is promoted
tf('bank.promotedIllegal', 'INVOKE#0',       'reserved-illegal', $D8);

// ★★★ The CORE bank has NO RUNTIME. Refusing it as "not implemented yet" would be a lie: these are
//     words the COMPILER executes, and bytecode never contains them. The refusal says which kind.
$D9  = jf_defs([[0, 1, '[CORE:30]']]);            // CORE slot 30 is `:`
tf('core.compileTime',  'INVOKE#0', 'compile-time word: the compiler executes it', $D9);
$D10 = jf_defs([[0, 1, '[CORE:72]']]);            // `EMIT`
tf('core.io',           'INVOKE#0', 'declared no output channel', $D10);
// ★ `.` is the honest "not built" case, and it must NOT read like the refusals above.
$D10c = jf_defs([[0, 1, '[CORE:14]']]);           // `.`
tf('core.numberFormatting', 'INVOKE#0', 'NOT BUILT', $D10c);
// ★ ACCEPT is the INPUT side of the same objection, and belongs in the same bucket as EMIT.
$D10b = jf_defs([[0, 1, '[CORE:45]']]);           // `ACCEPT`
tf('core.inputChannel', 'INVOKE#0', 'declared no input channel', $D10b);
$D11 = jf_defs([[0, 1, '[CORE:127]']]);           // `WORD`
tf('core.text',         'INVOKE#0', 'parses source text', $D11);
// ⛔ EVALUATE interprets text at RUNTIME. That is OP_EVAL, and §6 says why it is correctly absent.
$D12 = jf_defs([[0, 1, '[CORE:74]']]);            // `EVALUATE`
tf('core.evaluateIsOpEval', 'INVOKE#0', 'this is OP_EVAL', $D12);

// ── ★★★ THE ORDERING IS DERIVABLE, AND THAT IS A PROPERTY WORTH PINNING ─────────────────────────────
// §10.5e: *"the initial fill is alphabetical."* ⚠ That was true of the BANKS and was NOT true of the
// single-byte set until 7 Sept — nine of fifteen groups were in "natural" order (DUP DROP SWAP OVER
// ROT...), which is my taste baked into the protocol. ⇒ Sorted into TWO alphabetical runs while nothing
// was released. **After a conformance vector or a deployed covenant pins these bytes the rule becomes
// APPEND-ONLY**, and a new word goes at the end however unalphabetical that looks.
// ⚠ ORDER BY CODE, not by the array's key order — the generator EMITS grouped (for the reader) while
//   ASSIGNING alphabetically. Testing the key order tests the comment layout, not the protocol.
// ⇒ 15 Sept, his rule: SECTIONS BY CATEGORY in the declared order, ALPHABETICAL WITHIN each section —
//   a single alphabetical run puts the word a reader wants between unrelated ones. JF_SECTION carries
//   the declared order; the bytes must follow it exactly, section after section, with no gaps.
$byCode = JF_WORD; asort($byCode);
$W = array_keys($byCode);
$promoted = array_values(array_filter($W, fn($w) => isset(JF_PROMOTED[$w])));
$own      = array_values(array_filter($W, fn($w) => !isset(JF_PROMOTED[$w])));
$codesP = array_map(fn($w) => JF_WORD[$w], $promoted);
$codesO = array_map(fn($w) => JF_WORD[$w], $own);
$T[] = ['order.sectionsAlphabeticalWithin', '', null, null, null,
        function () { foreach (JF_SECTION as $name => $ws) { if ($name === 'appended') continue;   // in order of addition
                        $s = $ws; sort($s, SORT_STRING); if ($s !== $ws) return false; } return true; }];
$T[] = ['order.appendedFromDD', '', null, null, null,
        fn() => JF_WORD['ED25519-CHECKSIG'] === 0xdd && JF_WORD['ED25519-CHECKSIGVERIFY'] === 0xde && JF_RESERVED0 === 0xdf];
$T[] = ['order.sectionsInDeclaredOrder', '', null, null, null,
        function () { $expect = []; foreach (JF_SECTION as $ws) foreach ($ws as $w) $expect[] = $w;
                      global $W; return $expect === $W; }];
$T[] = ['order.runsAreContiguous', '', null, null, null,
        fn() => $codesP === range($codesP[0], $codesP[0] + count($codesP) - 1)
             && $codesO === range($codesO[0], $codesO[0] + count($codesO) - 1)];
// ★ the two runs are SEPARATE because a promoted word has a bank slot that is reserved-illegal, and a
//   jetmora word has no bank at all. The numbering shows that difference rather than hiding it.
$T[] = ['order.promotedBeforeOwn', '', null, null, null,
        fn() => max($codesP) < min($codesO)];

// ── run ──────────────────────────────────────────────────────────────────────────────────────────────
$verbose = in_array('-v', $argv, true);
$pass = $fail = 0; $failures = [];

foreach ($T as $case) {
  [$id, $script, $want, $wantErr] = $case;
  $wantDiag = $case[4] ?? null;
  // ⚠ a property case carries a closure instead of a script — it asserts something about the MAP
  if (isset($case[5]) && is_callable($case[5])) {
    if ($case[5]()) { $pass++; if ($verbose) printf("  ✓ %s\n", $id); }
    else { $fail++; $failures[] = [$id, 'property does not hold', '']; }
    continue;
  }
  $vm = new InterpreterJF();
  try {
    $stack = $vm->run($script);
    $got = array_map(fn($g) => gmp_strval($g), $stack);
    if ($wantErr !== null || $wantDiag !== null) {
      $fail++; $failures[] = [$id, 'expected an abort', 'got stack ' . implode(' ', $got)];
    } elseif ($got === array_map('strval', $want)) {
      $pass++; if ($verbose) printf("  ✓ %-28s %s\n", $id, implode(' ', $got));
    } else {
      $fail++; $failures[] = [$id, 'expected ' . implode(' ', array_map('strval', $want)),
                                   'got      ' . implode(' ', $got)];
    }
  } catch (Throwable $e) {
    if ($wantDiag !== null) {
      $d = $e instanceof JfScriptError ? $e->diagnostic : null;
      if ($d === $wantDiag) { $pass++; if ($verbose) printf("  ✓ %-28s (diagnostic: %s)\n", $id, var_export($d, true)); }
      else { $fail++; $failures[] = [$id, 'expected diagnostic ' . var_export($wantDiag, true),
                                          'got      ' . var_export($d, true) . '  (' . $e->getMessage() . ')']; }
    } elseif ($wantErr !== null && str_contains($e->getMessage(), $wantErr)) {
      $pass++; if ($verbose) printf("  ✓ %-28s (refused: %s)\n", $id, $e->getMessage());
    } else {
      $fail++; $failures[] = [$id,
        $wantErr !== null ? "expected error containing '$wantErr'"
                          : 'expected ' . implode(' ', array_map('strval', $want ?? [])),
        'threw    ' . $e->getMessage()];
    }
  }
}

foreach ($failures as [$id, $exp, $got]) printf("  ✗ %-28s\n      %s\n      %s\n", $id, $exp, $got);
printf("\n%s  %d passed, %d failed   [JF · jetForth tier]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
