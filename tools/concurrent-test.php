<?php
// TEST 6 — concurrent appends.
// ⚠ The failure single-threaded tests structurally cannot see: two appenders both read size()=n and
//   both claim seq n. The entries table would catch a duplicate, but the STORED TREE is the thing to
//   worry about — a node written from a half-built sibling set is wrong and stays wrong.
require_once __DIR__ . '/../server/store.php';
$WORKERS = (int)($argv[1] ?? 8);
$EACH    = (int)($argv[2] ?? 25);
$path = sys_get_temp_dir() . '/jetmora-concurrent-' . getmypid() . '.db';
foreach (glob($path . '*') as $f) @unlink($f);
(new LogStore($path));                       // create the schema before the workers race

$startAt = microtime(true) + 1.5;            // ⚠ a common start instant, or they merely queue
$procs = [];
for ($i = 0; $i < $WORKERS; $i++) {
    $cmd = sprintf('php %s %s %d %d %.4f', escapeshellarg(__DIR__.'/concurrent-worker.php'),
                   escapeshellarg($path), $i, $EACH, $startAt);
    $procs[$i] = popen($cmd, 'r');
}
$results = [];
foreach ($procs as $i => $p) { $results[$i] = json_decode(trim(stream_get_contents($p)), true); pclose($p); }

$expected = $WORKERS * $EACH;
$ok = array_sum(array_column($results, 'ok'));
$errs = array_merge(...array_column($results, 'errs'));
$byClass = array_count_values($errs);

echo "  workers $WORKERS × $EACH each   ⇒ attempted $expected\n";
echo "  appends that returned OK       $ok\n";
echo "  appends that raised            " . count($errs) . "\n";
foreach ($byClass as $k => $v) echo "     ⚠ $v × $k\n";

// ── now the checks that matter ──────────────────────────────────────────────────────────────
$store = new LogStore($path);
$size = $store->size();
echo "\n  store->size()                  $size\n";
echo "  " . ($size === $ok ? "✓" : "⚠") . " size equals successful appends\n";

$pdo = new PDO('sqlite:' . $path);
$seqs = $pdo->query('SELECT seq FROM entries ORDER BY seq')->fetchAll(PDO::FETCH_COLUMN);
$dense = true;
foreach ($seqs as $i => $s) if ((int)$s !== $i) { $dense = false; break; }
echo "  " . ($dense ? "✓" : "⚠⚠") . " sequence numbers dense 0..".($size-1)." with no gaps and no duplicates\n";

// ★★★ THE REAL CHECK. Recompute the root from the bodies alone, ignoring every stored node.
//     If any interior node was written from a torn read, this disagrees.
$bodies = $pdo->query('SELECT body FROM entries ORDER BY seq')->fetchAll(PDO::FETCH_COLUMN);
$scratch = mt_root(array_map('strval', $bodies));
$stored  = $store->root();
echo "  " . ($scratch === $stored ? "✓" : "⚠⚠⚠") . " STORED TREE agrees with a from-scratch root\n";
echo "     from scratch  " . bin2hex($scratch) . "\n";
echo "     stored nodes  " . bin2hex($stored) . "\n";

// and every inclusion proof must verify against that root
$bad = 0;
for ($i = 0; $i < $size; $i++) {
    $proof = $store->inclusionProof($i, $size);
    if (!mt_verify_inclusion($i, $size, $bodies[$i], $proof, $stored)) $bad++;
}
echo "  " . ($bad === 0 ? "✓ all $size inclusion proofs verify" : "⚠⚠⚠ $bad of $size inclusion proofs FAILED") . "\n";
foreach (glob($path . '*') as $f) @unlink($f);
