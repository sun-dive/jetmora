<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── SPV: MERKLE PROOFS, GRADED AGAINST REAL MAINNET BLOCKS ──────────────────────────────────────────
//
// ★★★ THE GRADE IS CONSENSUS ITSELF. Five real blocks are frozen with every txid and the merkleroot
//   **as the chain recorded it**. ⇒ Rebuilding that root from the txids checks our tree against
//   Bitcoin, not against ourselves — and then EVERY transaction's path is folded back to it, so every
//   position in every block is exercised rather than one lucky index.
//
// ★★ TWO OF THE BLOCKS HAVE ODD TRANSACTION COUNTS (457 and 237). That is not decoration: an odd level
//   is the ONLY way to reach the duplicate-up (`'*'`) case, and an even-sized block can never produce
//   it. A suite made only of even blocks would pass with that case unimplemented.
declare(strict_types=1);
require_once __DIR__ . '/wallet/bsv/spv.php';
require_once __DIR__ . '/merkle.php';

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

$V = json_decode(file_get_contents(__DIR__ . '/wallet/bsv/block-vectors.json'), true);

// ── ★★★ real consensus merkle roots ─────────────────────────────────────────────────────────────────
echo "── ★★★ five real mainnet blocks ──\n";
foreach ($V['blocks'] as $b)
  ok(MerkleProof::rootOf($b['txids']) === $b['merkleRoot'],
     sprintf('block %d (%d tx) — the root we build IS the one consensus recorded', $b['height'], $b['n']));

// ── ★★ every path in every block ────────────────────────────────────────────────────────────────────
echo "\n── ★★ every transaction's path, folded back to the root ──\n";
$total = 0; $bad = 0; $stars = 0; $withStar = 0;
foreach ($V['blocks'] as $b) {
  foreach ($b['txids'] as $i => $txid) {
    $path = MerkleProof::pathFor($b['txids'], $i);
    $s = count(array_filter($path, fn($p) => $p['hash'] === '*'));
    $stars += $s; if ($s > 0) $withStar++;
    if (!MerkleProof::verify(['txId' => $txid, 'merkleRoot' => $b['merkleRoot'], 'path' => $path])) $bad++;
    $total++;
  }
}
ok($bad === 0, "★★★ all $total transaction paths across 5 blocks verify ($bad failed)");
ok($withStar > 0,
   "★★ and $withStar of them contain a duplicate-up '*' ($stars in total) — the case even blocks cannot reach");

// ── ⛔ THE FINDING: skipping '*' FAILS, and it is measured, not asserted ─────────────────────────────
//
// ⚠⚠ `PharLap/src/walletProvider.ts` `tscPath()` does `if (node === '*') { idx = idx >> 1; continue }`
//   — it consumes the level WITHOUT hashing. Its own comment says `'*' = duplicate-up, no sibling`, so
//   the meaning was understood and the handler does not implement it.
//   ⇒ **STRUCTURAL CLAIM (cannot rot):** skipping leaves the working hash untouched, and `H(x‖x) != x`,
//     so any proof containing a `'*'` computes a different root and is rejected.
//   ⇒ **IT FAILS CLOSED**, which is the safe direction: a VALID proof is reported unverified. Annoying,
//     not dangerous — no invalid proof is ever accepted by it.
//   ⚠ **EMPIRICAL, still open:** whether WoC and BananaBlocks actually emit `'*'` in their TSC `nodes`
//     for these positions. That needs checking against a live response and is NOT claimed here.
echo "\n── ⛔ skipping '*' rejects a VALID proof ──\n";
$blk = null;
foreach ($V['blocks'] as $b) if ($b['n'] % 2 === 1) { $blk = $b; break; }
$last = $blk['n'] - 1;
$path = MerkleProof::pathFor($blk['txids'], $last);
ok(count(array_filter($path, fn($p) => $p['hash'] === '*')) > 0,
   sprintf('block %d\'s last tx needs duplicate-up', $blk['height']));
$entry = ['txId' => $blk['txids'][$last], 'merkleRoot' => $blk['merkleRoot'], 'path' => $path];
ok(MerkleProof::verify($entry), '★ pairing the node with ITSELF verifies against consensus');
$skipped = $entry;
$skipped['path'] = array_values(array_filter($path, fn($p) => $p['hash'] !== '*'));
ok(!MerkleProof::verify($skipped),
   '⛔ SKIPPING it rejects the same valid proof — a false negative, and it fails CLOSED');

// ── ⚠ byte order ────────────────────────────────────────────────────────────────────────────────────
echo "\n── ⚠ display order vs natural order ──\n";
$b0 = $V['blocks'][0];
ok(MerkleProof::rootOf(array_map('strrev', $b0['txids'])) !== $b0['merkleRoot'],
   '⚠ reversing the hex characters gives a different root — the trap is real');
ok(MerkleProof::rootOf(array_reverse($b0['txids'])) !== $b0['merkleRoot'],
   '⚠ and so does reordering the transactions — position is committed');

// ── ⛔ Bitcoin's tree is NOT RFC 6962 ────────────────────────────────────────────────────────────────
echo "\n── ⛔ this is NOT server/merkle.php ──\n";
$leaves = array_map(fn($h) => (string)hex2bin($h), array_slice($b0['txids'], 0, 2));
ok(bin2hex(mt_root($leaves)) !== $b0['merkleRoot'],
   '⛔ RFC 6962 over the same leaves gives a DIFFERENT root — the two must never be shared');
// ★ And they cannot be confused by accident: RFC 6962 is FREE FUNCTIONS (`mt_root`), Bitcoin's is a
//   CLASS METHOD (`MerkleProof::rootOf`). Different shapes, not just different names.
ok(function_exists('mt_root') && !method_exists('MerkleProof', 'mt_root'),
   '★ one is a free function, the other a class method — different shapes entirely');
// ⚠ and the reason they differ, asserted: RFC 6962 prefixes leaves with 0x00, Bitcoin does not
ok(mt_leaf_hash('x') !== hash('sha256', hash('sha256', 'x', true), true),
   '⚠ RFC 6962 prefixes a leaf with 0x00 and hashes ONCE; Bitcoin double-hashes raw — CVE-2012-2459');

// ── ★ TSC adapter ───────────────────────────────────────────────────────────────────────────────────
echo "\n── ★ the TSC nodes+index adapter ──\n";
$p = MerkleProof::fromTsc(['aa', 'bb', 'cc'], 5);       // 5 = 101b ⇒ L, R, L
ok(array_column($p, 'position') === ['L', 'R', 'L'],
   '★ the sibling side comes from the index parity at each level (5 ⇒ L,R,L)');
ok(MerkleProof::fromTsc(['aa'], 0)[0]['position'] === 'R', 'an even index puts the sibling on the right');
$withStar = MerkleProof::fromTsc(['aa', '*', 'cc'], 3);
ok($withStar[1]['hash'] === '*',
   "⚠ '*' is CARRIED THROUGH, not dropped — dropping it is the bug measured above");
ok(count($withStar) === 3, '...and the level count is preserved');

// ── ★ proof chains ──────────────────────────────────────────────────────────────────────────────────
echo "\n── ★ proof chains ──\n";
$mk = function (array $b, int $i) { return [
  'txId' => $b['txids'][$i], 'blockHeight' => $b['height'], 'merkleRoot' => $b['merkleRoot'],
  'path' => MerkleProof::pathFor($b['txids'], $i)]; };
$b1 = $V['blocks'][1]; $b2 = $V['blocks'][2];
$chain = ['genesisTxId' => $b2['txids'][0], 'entries' => [$mk($b1, 1), $mk($b2, 0)]];
$headers = [$b1['height'] => ['merkleRoot' => $b1['merkleRoot']],
            $b2['height'] => ['merkleRoot' => $b2['merkleRoot']]];
$r = ProofChain::verify($chain, $headers);
ok($r['valid'], '★ a two-entry chain verifies against its headers: ' . $r['reason']);

// ⚠⚠ A MISSING HEADER IS A FAILURE. The tempting shortcut turns a rate limit into a clean bill of health.
$r = ProofChain::verify($chain, [$b1['height'] => $headers[$b1['height']]]);
ok(!$r['valid'] && str_contains($r['reason'], 'no block header'),
   '⚠⚠ a MISSING header FAILS — it is never treated as "nothing to check"');

// ★★★ the header is the anchor, not the proof's own claim
$lying = $headers; $lying[$b1['height']] = ['merkleRoot' => str_repeat('0', 64)];
$r = ProofChain::verify($chain, $lying);
ok(!$r['valid'] && str_contains($r['reason'], 'mismatch'),
   '★★★ a proof that disagrees with the HEADER is refused — the header is the anchor');

// ⚠ truncating the chain must not hide its origin
$r = ProofChain::verify(['genesisTxId' => $b2['txids'][0], 'entries' => [$mk($b1, 1)]], $headers);
ok(!$r['valid'] && str_contains($r['reason'], 'genesis'),
   '⚠ a chain truncated away from its genesis is refused');
$r = ProofChain::verify(['genesisTxId' => $b2['txids'][0], 'entries' => []], $headers);
ok(!$r['valid'] && str_contains($r['reason'], 'empty'), 'an empty chain is refused');

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────
echo "\n── refusals ──\n";
ok(!MerkleProof::verify(['txId' => 'zz', 'merkleRoot' => $b0['merkleRoot'], 'path' => []]),
   'a malformed txid is refused, not crashed on');
ok(!MerkleProof::verify(['txId' => $b0['txids'][0], 'merkleRoot' => $b0['merkleRoot'],
                         'path' => [['hash' => $b0['txids'][1], 'position' => 'X']]]),
   'an invalid position letter is refused');
refuses(fn() => MerkleProof::rootOf([]), 'at least one transaction', 'an empty block is refused');
refuses(fn() => MerkleProof::pathFor($b0['txids'], 99), 'no transaction at index', 'a bad index is refused');
refuses(fn() => MerkleProof::fromTsc(['aa'], -1), 'cannot be negative', 'a negative index is refused');

// ── ★★★ REAL PROOFS FROM THE REAL SERVICES ─────────────────────────────────────────────────────────
//
// ★ The strongest grade available offline: proofs exactly as BananaBlocks and WhatsOnChain returned
//   them, frozen 8 Sept 2026, folded back to a merkle root that CONSENSUS recorded.
//
// ⚠⚠⚠ AND THEY DISAGREE IN FORMAT, WHICH IS THE WHOLE POINT:
//   | **BananaBlocks** | emits `'*'` for a duplicate-up node |
//   | **WhatsOnChain** | expands it to the explicit hash |
//   ⇒ Both are valid TSC. A verifier must handle BOTH, and one tested against only WoC would ship with
//     the `'*'` case unimplemented and never know.
echo "\n── ★★★ real TSC proofs, from both services ──\n";
$T = json_decode(file_get_contents(__DIR__ . '/wallet/bsv/tsc-vectors.json'), true);
$srcStars = [];
foreach ($T['proofs'] as $pr) {
  $path = MerkleProof::fromTsc($pr['nodes'], $pr['index']);
  ok(MerkleProof::verify(['txId' => $pr['txId'], 'merkleRoot' => $pr['merkleRoot'], 'path' => $path]),
     sprintf('%s idx %d (%d nodes, %d \'*\') — the SERVICE\'s own proof verifies',
             $pr['source'], $pr['index'], count($pr['nodes']), $pr['stars']));
  $srcStars[$pr['source']] = ($srcStars[$pr['source']] ?? 0) + $pr['stars'];
}
ok(($srcStars['banana'] ?? 0) > 0 && ($srcStars['woc'] ?? 0) === 0,
   "★★ the two sources really DO differ — BananaBlocks sent {$srcStars['banana']} '*', WoC sent none");
// ⛔ and the measured consequence, on the source PharLap PREFERS
$banana = null;
foreach ($T['proofs'] as $pr) if ($pr['source'] === 'banana' && $pr['stars'] > 0) $banana = $pr;
$skipped = array_values(array_filter(MerkleProof::fromTsc($banana['nodes'], $banana['index']),
                                     fn($x) => $x['hash'] !== '*'));
ok(!MerkleProof::verify(['txId' => $banana['txId'], 'merkleRoot' => $banana['merkleRoot'], 'path' => $skipped]),
   "⛔ skipping '*' REJECTS this real BananaBlocks proof — measured against live data, not inferred");

printf("\n%s  %d passed, %d failed   [SPV · real mainnet blocks, every path]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
