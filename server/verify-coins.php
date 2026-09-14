<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── UTXO SELECTION ──────────────────────────────────────────────────────────────────────────────────
//
// ⚠⚠ THERE ARE NO PUBLISHED VECTORS FOR COIN SELECTION, and that is a fact about the problem, not a gap
//   in the search: selection is POLICY, not consensus. Two correct wallets legitimately disagree.
//   ⇒ So this suite grades **invariants that must hold whatever the policy is**, plus the specific
//     rules read from ElectrumSV. ★ An invariant is stronger than a vector here: a vector pins one
//     answer, an invariant pins every answer.
//
// ★★★ THE INVARIANT THAT MATTERS MOST — **conservation**: `selected == target + fee + change`, exactly,
//   for every case. ⇒ Any satoshi that is neither spent, paid nor returned has been INVENTED or LOST,
//   and a wallet that does either is broken no matter how plausible its output looks.
declare(strict_types=1);
require_once __DIR__ . '/wallet/bsv/coins.php';

function constant_exists_relay(): bool {
  $r = new ReflectionClass('Coins');
  return array_key_exists('RELAY_DUST', $r->getConstants());
}

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}
function refuses(callable $f, string $needle, string $what): void {
  global $pass, $fail;
  try { $f(); $fail++; printf("  ✗ %s — DID NOT REFUSE\n", $what); }
  catch (Throwable $e) {
    if (str_contains($e->getMessage(), $needle)) $pass++;
    else { $fail++; printf("  ✗ %s — wrong reason: %s\n", $what, $e->getMessage()); }
  }
}
/** a P2PKH-shaped locking script, distinct per seed */
function lock(int $seed): string {
  return "\x76\xa9\x14" . substr(hash('sha256', "s$seed", true), 0, 20) . "\x88\xac";
}
function utxo(int $seed, int $value, ?int $unlocking = null): array {
  $u = ['txid' => hash('sha256', "u$seed$value", true), 'vout' => $seed % 4,
        'value' => $value, 'script' => lock($seed)];
  if ($unlocking !== null) $u['unlockingSize'] = $unlocking;
  return $u;
}

$CHANGE = lock(999);

// ── ★★★ conservation, swept rather than sampled ─────────────────────────────────────────────────────
// How to work #6: sweep the parameter, don't sample it. One lucky case proves nothing here.
echo "── ★★★ conservation across 400 random wallets ──\n";
mt_srand(20260908);
$bad = 0; $withChange = 0; $withoutChange = 0;
for ($t = 0; $t < 400; $t++) {
  $utxos = [];
  for ($i = 0, $n = mt_rand(1, 8); $i < $n; $i++) $utxos[] = utxo($i, mt_rand(1, 500000));
  $outs = [['value' => mt_rand(1, 200000), 'script' => lock(500)]];
  // ⚠ vary the floor: at the 1-satoshi default, change is almost ALWAYS worth creating, so a sweep
  //   that fixed it would never exercise the other branch at all.
  $floor = [1, 546, 20000][$t % 3];
  try { $s = Coins::select($utxos, $outs, $CHANGE, 100, $floor); }
  catch (CoinError) { continue; }                       // insufficient funds is a legitimate outcome
  $s['change'] === null ? $withoutChange++ : $withChange++;
  if ($s['selected'] !== $s['target'] + $s['fee'] + ($s['change'] ?? 0)) $bad++;
}
ok($bad === 0, "★★★ selected == target + fee + change in every case ($bad broke it)");
ok($withChange > 0 && $withoutChange > 0,
   "★ and the sweep reached BOTH branches — $withChange with change, $withoutChange without");

// ── ⚠⚠ the fee covers the SIGNED size, not the unsigned one ─────────────────────────────────────────
echo "\n── ⚠⚠ the fee is for the SIGNED transaction ──\n";
$u = [utxo(1, 100000)];
$o = [['value' => 50000, 'script' => lock(2)]];
$s = Coins::select($u, $o, $CHANGE);
$tx = Coins::build($s, $o, $CHANGE);
ok(strlen($tx->serialize()) < $s['size'],
   '⚠⚠ the UNSIGNED tx is SMALLER than the size we charged for — signatures are not free');
ok($s['size'] - strlen($tx->serialize()) >= 106 * count($s['inputs']),
   '★ the difference is roughly the scriptSig per input (~107 B), which is exactly what gets added');
ok($s['fee'] === Coins::fee($s['size']), 'the fee is computed from the estimated SIGNED size');
ok($s['fee'] > $tx->fee(), '⛔ charging the unsigned size would UNDERPAY — a tx that never confirms');

// ── ⛔ 546 IS NOT IMPOSED ON THE CALLER'S OUTPUTS ────────────────────────────────────────────────────
// ⚠⚠⚠ Every covenant in this project uses 1-satoshi outputs. A selector that refused them would refuse
//   the whole repo. How to work #4.
echo "\n── ⛔ a 1-satoshi covenant output is honoured ──\n";
$one = Coins::select([utxo(3, 100000)], [['value' => 1, 'script' => lock(4)]], $CHANGE);
ok($one['target'] === 1, '★ a 1-satoshi output is accepted, not "corrected" to 546');
ok($one['change'] !== null && $one['change'] > 0, '...and it still gets change');
$many = array_map(fn($i) => ['value' => 1, 'script' => lock($i)], range(10, 19));
$m = Coins::select([utxo(5, 100000)], $many, $CHANGE);
ok($m['target'] === 10, '★ ten 1-satoshi breadcrumbs (PharLap\'s pattern) are honoured');
// ⛔⛔ CORRECTED 8 Sept, his catch: *"546 is really high… the real relay dust level is 1 sat."*
//   ⇒ MEASURED against this project's OWN mainnet history — three CONFIRMED transactions carrying
//     **nine 1-satoshi outputs** between them, at 2,927–5,932 confirmations. They relayed AND were
//     mined. ⚠ 546 is BITCOIN CORE's dust threshold; **BSV removed the dust limit at Genesis (2020)**.
//   ★ The constant was called `RELAY_DUST`, which asserted something false about BSV. A borrowed number
//     under a name that grants it authority is exactly How to work #4's trap, and worse than no
//     constant at all — so it is renamed for its PROVENANCE and kept only to be recognised.
ok(Coins::BTC_LEGACY_DUST === 546 && Coins::MIN_OUTPUT === 1,
   '⚖ 546 is named BTC_LEGACY_DUST — provenance, not authority — and the real floor is 1');
ok(!defined('Coins::RELAY_DUST') && !constant_exists_relay(),
   '⛔ there is no constant called RELAY_DUST any more — the misleading name is GONE, not aliased');
// ⛔ but zero is still refused, because the network refuses it
refuses(fn() => Coins::select([utxo(6, 1000)], [['value' => 0, 'script' => lock(7)]]),
        'refused as dust', '⛔ a 0-value output IS refused — the network refuses it before the script runs');

// ── ★ change below the floor becomes fee ────────────────────────────────────────────────────────────
echo "\n── ★ change below the floor becomes fee ──\n";
// ⚠ Engineered so the leftover is a few satoshis: not worth an output that costs 34 bytes to make.
$tight = Coins::select([utxo(8, 20000)], [['value' => 19980, 'script' => lock(9)]], $CHANGE);
ok($tight['change'] === null, '★ a few satoshis of change is NOT created as an output');
ok($tight['selected'] === $tight['target'] + $tight['fee'],
   '...it went to the FEE, and conservation still holds exactly');
$roomy = Coins::select([utxo(8, 20000)], [['value' => 1000, 'script' => lock(9)]], $CHANGE);
ok($roomy['change'] !== null && $roomy['change'] > 1000, '★ ample change IS created');
// ⚠ and a high threshold suppresses it again — the parameter is real, not decorative
// ⚠ 500 in, minus a ~23 satoshi fee, leaves 477 — below 546 and above 1, so the SAME wallet gives a
//   different answer at each threshold. That contrast is the test; one threshold alone proves nothing.
$lowFloor  = Coins::select([utxo(8, 20000)], [['value' => 19500, 'script' => lock(9)]], $CHANGE, 100, 1);
$highFloor = Coins::select([utxo(8, 20000)], [['value' => 19500, 'script' => lock(9)]], $CHANGE, 100, 546);
ok($lowFloor['change'] !== null && $lowFloor['change'] < 546,
   '★ at the 1-satoshi floor, 477 of change IS created');
ok($highFloor['change'] === null, '⚠ at the 546 floor, the same 477 is suppressed and becomes fee');
ok($highFloor['selected'] === $highFloor['target'] + $highFloor['fee'],
   '...and conservation still holds exactly when it is suppressed');

// ── ★ the privacy rule: a script's coins are spent together ─────────────────────────────────────────
echo "\n── ★ one script's coins are spent together ──\n";
// ⚠⚠ THE DISCRIMINATING CASE, and my first attempt was NOT one — mutation testing found that removing
//   the bucketing entirely still passed it. ⇒ These numbers are chosen so a coin-at-a-time selector
//   provably PARTIALLY spends a script: sorted by value it would take the 30,000 alone and stop,
//   leaving that script's two 1,000-satoshi coins behind and publishing that they are ours.
$shared = [utxo(20, 30000), utxo(20, 1000), utxo(20, 1000)];   // same seed ⇒ ONE locking script
$shared[] = utxo(21, 5000);
$sel = Coins::select($shared, [['value' => 25000, 'script' => lock(22)]], $CHANGE);
$scripts = array_unique(array_column($sel['inputs'], 'script'));
$partial = [];
foreach ($scripts as $sc) {
  $avail = count(array_filter($shared,      fn($x) => $x['script'] === $sc));
  $used  = count(array_filter($sel['inputs'], fn($x) => $x['script'] === $sc));
  if ($avail !== $used) $partial[] = "$used of $avail";
}
ok($partial === [], '★ no chosen script is PARTIALLY spent' . ($partial ? ': ' . implode(', ', $partial) : ''));
// ⚠ and the guard that makes the above non-vacuous: a multi-coin script really was chosen
$multi = max(array_map(fn($sc) => count(array_filter($sel['inputs'], fn($x) => $x['script'] === $sc)),
                       $scripts));
ok($multi > 1, "★★ ...and a multi-coin script WAS selected ($multi coins), so the check is not vacuous");

// ── ⚖ THE ORDERING IS A CHOICE, PINNED SO CHANGING IT IS DELIBERATE ─────────────────────────────────
// ★ Mutation testing reversed the sort and NOTHING failed — correctly, because ordering is POLICY, not
//   correctness: smallest-first (consolidating) satisfies every invariant above just as well.
//   ⇒ But largest-first was chosen on purpose (fewer inputs ⇒ smaller tx ⇒ smaller fee), so it gets a
//     test that says so. A future change should be an argued decision, not an accident.
echo "\n── ⚖ largest-bucket-first, pinned as a CHOICE ──\n";
$mix = [utxo(80, 1000), utxo(81, 900000), utxo(82, 2000)];
$ord = Coins::select($mix, [['value' => 5000, 'script' => lock(83)]], $CHANGE);
ok(count($ord['inputs']) === 1 && $ord['inputs'][0]['value'] === 900000,
   '⚖ the largest bucket is taken first — one input, not three (fewer inputs ⇒ smaller fee)');
ok($ord['fee'] < Coins::fee(3 * Coins::P2PKH_INPUT + 100),
   '★ ...and the fee reflects that, which is the whole reason for the choice');

// ── ⚠ fee rounding, tested directly ─────────────────────────────────────────────────────────────────
// ⚠⚠ Found by mutation testing: nothing distinguished ceil from floor, because every case happened to
//   land on a whole satoshi. A fee rounded DOWN sits below the floor, and the transaction never confirms.
echo "\n── ⚠ the fee rounds UP ──\n";
ok(Coins::fee(225) === 23, '225 bytes at 100 sat/KB = 22.5 ⇒ 23, NOT 22');
ok(Coins::fee(1) === 1,   '⚠ even 1 byte costs 1 satoshi — never 0');
ok(Coins::fee(1000) === 100, 'a whole kilobyte is exactly 100');
ok(Coins::fee(1001) === 101, '...and one byte more costs one satoshi more');

// ── ⚠ the input-count varint is counted ─────────────────────────────────────────────────────────────
// ⚠⚠ Also found by mutation: pinning this to 1 byte changed the fee too little to notice on a large
//   transaction, so nothing caught it. Assert the SIZE arithmetic directly instead of via the fee.
echo "\n── ⚠ the input-count varint grows with the input count ──\n";
$mk = fn(int $n) => array_map(fn($i) => utxo(2000 + $i, 10000), range(1, $n));
$o1 = [['value' => 1000, 'script' => lock(70)]];
$s252 = Coins::select($mk(252), $o1, '', 100);            // no change script ⇒ size is exact
$s253 = Coins::select($mk(253), $o1, '', 100);
ok(count($s252['inputs']) === 1 && count($s253['inputs']) === 1,
   '⚠ only one input is needed, so these two differ ONLY in what was offered');
$exact = 8 + strlen(BsvBytes::varint(1)) + Coins::outputSize(lock(70)) + strlen(BsvBytes::varint(1))
       + Coins::P2PKH_INPUT;
ok($s252['size'] === $exact, "a 1-input, 1-output tx is exactly $exact bytes");
// ★ and the varint really is width-sensitive where it matters
ok(strlen(BsvBytes::varint(252)) === 1 && strlen(BsvBytes::varint(253)) === 3,
   '★ 252 is a 1-byte varint and 253 is 3 — the boundary the size calculation must respect');
$huge = Coins::select($mk(300), [['value' => 2900000, 'script' => lock(71)]], '', 100);
$hand = 8 + strlen(BsvBytes::varint(1)) + Coins::outputSize(lock(71))
      + strlen(BsvBytes::varint(count($huge['inputs']))) + count($huge['inputs']) * Coins::P2PKH_INPUT;
ok($huge['size'] === $hand,
   sprintf('★★ %d inputs ⇒ size %d matches the hand calculation INCLUDING its 3-byte count varint',
           count($huge['inputs']), $hand));

// ── ⚠ a covenant input is not P2PKH-sized ───────────────────────────────────────────────────────────
echo "\n── ⚠ a covenant's unlocking script is much bigger ──\n";
$plain = Coins::select([utxo(30, 500000)], [['value' => 1000, 'script' => lock(31)]], $CHANGE);
$cov   = Coins::select([utxo(30, 500000, 1500)], [['value' => 1000, 'script' => lock(31)]], $CHANGE);
ok($cov['size'] > $plain['size'] + 1300, '★ a 1500-byte unlocking script is charged for');
ok($cov['fee'] > $plain['fee'], '⇒ and it costs more fee — guessing P2PKH here underpays silently');
ok(Coins::inputSize(['unlockingSize' => 1500]) === 32 + 4 + 3 + 1500 + 4,
   '⚠ its length varint is 3 bytes past 252, and that is counted');
ok(Coins::inputSize([]) === 148, 'a P2PKH input is 148 bytes signed');

// ── ⚠ the count varints grow ────────────────────────────────────────────────────────────────────────
echo "\n── ⚠ the input/output count varints grow past 252 ──\n";
$manyU = []; for ($i = 0; $i < 300; $i++) $manyU[] = utxo(1000 + $i, 400);
// ⚠ 300 coins x 400 = 120,000. Asking 60,000 correctly stops at 156 inputs; to cross the
//   252 boundary the target has to actually need them.
$big = Coins::select($manyU, [['value' => 105000, 'script' => lock(40)]], $CHANGE);
ok(count($big['inputs']) > 252, sprintf('%d inputs selected — past the 1-byte varint', count($big['inputs'])));
ok($big['selected'] === $big['target'] + $big['fee'] + ($big['change'] ?? 0),
   '★★ conservation holds with a 3-byte input count too');
$builtBig = Coins::build($big, [['value' => 105000, 'script' => lock(40)]], $CHANGE);
ok(BsvTx::parse($builtBig->hex())->hex() === $builtBig->hex(),
   '...and the built transaction still round-trips through the parser');

// ── ★ the selection builds a real transaction ───────────────────────────────────────────────────────
echo "\n── ★ it builds a transaction the parser accepts ──\n";
$outs = [['value' => 1, 'script' => lock(50)], ['value' => 25000, 'script' => lock(51)]];
$s2   = Coins::select([utxo(52, 90000), utxo(53, 40000)], $outs, $CHANGE);
$t2   = Coins::build($s2, $outs, $CHANGE);
ok(BsvTx::parse($t2->hex())->hex() === $t2->hex(), 'it round-trips');
ok(count($t2->outputs) === count($outs) + ($s2['change'] === null ? 0 : 1), 'change is appended last');
ok(array_sum(array_column($t2->outputs, 'value')) === $s2['selected'] - $s2['fee'],
   '★★★ outputs total exactly what came in, minus the fee — nothing invented, nothing lost');
ok($t2->inputs[0]['script'] === '', '⚠ inputs are UNSIGNED — signing is a separate, later step');

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────
echo "\n── refusals ──\n";
refuses(fn() => Coins::select([utxo(60, 100)], [['value' => 1000000, 'script' => lock(61)]], $CHANGE),
        'insufficient funds', 'insufficient funds is refused, with the arithmetic in the message');
refuses(fn() => Coins::select([], [['value' => 10, 'script' => lock(62)]], $CHANGE),
        'insufficient funds', 'an empty wallet is refused');
refuses(fn() => Coins::select([utxo(63, 0)], [['value' => 1, 'script' => lock(64)]]),
        'positive value', 'a 0-value UTXO is refused');
refuses(fn() => Coins::select([utxo(65, 1000)], [['value' => -1, 'script' => lock(66)]]),
        'cannot be negative', 'a negative output is refused');
// ⚠ just-barely-insufficient is the interesting one: enough for the outputs, NOT for the fee
refuses(fn() => Coins::select([utxo(67, 1000)], [['value' => 1000, 'script' => lock(68)]], $CHANGE),
        'insufficient funds', '⚠ enough for the outputs but NOT the fee is still refused');

// ── ★★★ END TO END: SELECT → BUILD → SIGN → VERIFY ──────────────────────────────────────────────────
//
// ⚠ This is the whole BSV rail in one pass, and the last piece of item 5. Everything before it grades a
//   part; this grades that the parts fit.
echo "\n── ★★★ select → build → sign → verify ──\n";
require_once __DIR__ . '/wallet/bsv/signer.php';
require_once __DIR__ . '/wallet/shared/bip39.php';

$mn   = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
$sgn  = BsvSigner::fromSeed(Bip39::toSeed($mn));
$mine = "\x76\xa9\x14" . hash('ripemd160', hash('sha256', $sgn->publicKey(), true), true) . "\x88\xac";
$wallet = [
  ['txid' => hash('sha256', 'a', true), 'vout' => 0, 'value' => 50000, 'script' => $mine],
  ['txid' => hash('sha256', 'b', true), 'vout' => 1, 'value' => 30000, 'script' => $mine],
];
$outs = [['value' => 1, 'script' => lock(90)], ['value' => 60000, 'script' => lock(91)]];
$sel  = Coins::select($wallet, $outs, $mine);
$tx   = Coins::build($sel, $outs, $mine);
ok(count($sel['inputs']) === 2, 'both coins are needed and both are selected');

$unsignedSize = strlen($tx->serialize());
$sgn->signP2PKH($tx, $sel['inputs']);
ok($tx->inputs[0]['script'] !== '' && $tx->inputs[1]['script'] !== '', 'every input now carries a script');

// ★★★ the check that matters: each signature verifies against the script and amount it was made for
foreach ($sel['inputs'] as $i => $u) {
  $sig = substr($tx->inputs[$i]['script'], 1, ord($tx->inputs[$i]['script'][0]));
  ok(BsvSigner::verifyInput($tx, $i, $u['script'], $u['value'], $sgn->publicKey(), $sig),
     "★★★ input $i's signature verifies against ITS OWN script and amount");
  // ⛔ and it must NOT verify against the other input's amount — proof the amount is really committed
  $other = $sel['inputs'][1 - $i];
  ok(!BsvSigner::verifyInput($tx, $i, $u['script'], $other['value'], $sgn->publicKey(), $sig),
     "⛔ ...and FAILS against the other input's amount — BIP143 really commits the value");
}

// ⚠⚠ THE ESTIMATE MUST NOT HAVE BEEN OPTIMISTIC. This is the whole point of charging for signed size.
$signedSize = strlen($tx->serialize());
ok($signedSize > $unsignedSize, 'signing made it bigger, as the estimate assumed');
ok($signedSize <= $sel['size'],
   sprintf('★★★ the SIGNED size (%d) is within the estimate (%d) — the fee is sufficient, not optimistic',
           $signedSize, $sel['size']));
ok($sel['size'] - $signedSize <= 2 * count($sel['inputs']),
   '★ ...and over-estimates by at most ~2 bytes per input (the DER length varies)');
ok($tx->fee() <= $sel['fee'], 'the fee actually paid covers the real size at 100 sat/KB');
ok(BsvTx::parse($tx->hex())->hex() === $tx->hex(), 'the signed transaction round-trips');
ok(strlen($tx->txid()) === 64, 'and it has a txid');

// ⛔ the alignment guard — the trap this exists to close
echo "\n── ⛔ mis-ordered UTXOs are refused, not signed ──\n";
$tx2 = Coins::build($sel, $outs, $mine);
try { $sgn->signP2PKH($tx2, array_reverse($sel['inputs'])); ok(false, 'reversed UTXOs refused'); }
catch (Throwable $e) {
  ok(str_contains($e->getMessage(), 'outpoints differ'),
     '⛔ reversed UTXOs are REFUSED — signing them gives valid-looking signatures that verify nowhere');
}
try { $sgn->signP2PKH($tx2, [$sel['inputs'][0]]); ok(false, 'wrong count refused'); }
catch (Throwable $e) { ok(str_contains($e->getMessage(), 'for 2 inputs'), 'a short UTXO list is refused'); }

// ⚠ and the two signing rules do not cross
$entrySig = $sgn->signEntry($tx->serialize());
ok(!BsvSigner::verifyInput($tx, 0, $sel['inputs'][0]['script'], $sel['inputs'][0]['value'],
                           $sgn->publicKey(), $entrySig . chr(BsvSighash::ALL_FORKID)),
   '⛔ a jetmora-style signEntry signature does NOT verify as a BSV input — the digests differ');

printf("\n%s  %d passed, %d failed   [UTXO selection · invariants + ElectrumSV policy]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
