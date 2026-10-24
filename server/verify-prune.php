<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE TIP IS NEVER PRUNED ──────────────────────────────────────────────────────────────────────────
//
// His rule, 17 Oct: "The hash is not sufficient it must be the entire tip and unspent output." Retention
// blanks the bodies BEHIND a thread's newest entry and keeps that entry whole, its unspent output being
// what the next tick spends. A store in a temporary folder, four threads, everything older than the cut:
// one of three entries, one of a single entry, one of a kept state, and one with no tips row, as a thread
// from before tips were kept would be.
//   php server/verify-prune.php
declare(strict_types=1);
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ⚠ One folder per run, removed on every exit: a pass, a failure, a thrown error or an interrupt.
$dir = sys_get_temp_dir() . '/jetmora-prune-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
register_shutdown_function(function () use ($dir) {
  foreach (glob("$dir/*") ?: [] as $f) @unlink($f);
  @rmdir($dir);
});
if (function_exists('pcntl_async_signals')) {
  pcntl_async_signals(true);
  foreach ([SIGINT, SIGTERM, SIGHUP] as $sig) pcntl_signal($sig, fn() => exit(1));
}
$path = "$dir/store.db";
$store = new ThreadStore($path);
$db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$registry = new GenesisRegistry($db);

$thread = fn(string $state): string => $registry->register(['source_hash' => hash('sha256', 'the source', true),
  'script' => "\x51", 'state' => $state, 'authorised' => GenesisRegistry::AUTH_OPEN]);
$tick = function (string $g, string $body) use ($store): void { $store->append($body, $g, $store->tipHashOf($g)); };
$bodies = fn(string $g): array => array_column($store->entriesOf($g), 'body');
$h256 = fn(string $b) => hash('sha256', hash('sha256', $b, true), true);

$kept = random_bytes(16);
$long = $thread(random_bytes(16)); foreach (['first', 'second', 'third, the tip'] as $b) $tick($long, $b);
$one = $thread(random_bytes(16)); $tick($one, 'alone, the tip');
$keep = $thread($kept); foreach (['k1', 'k2'] as $b) $tick($keep, $b);
$old = $thread(random_bytes(16)); foreach (['o1', 'o2', 'o3, the tip'] as $b) $tick($old, $b);
$db->prepare('DELETE FROM tips WHERE genesis = ?')->execute([$old]);       // as an older database would be
$db->exec('UPDATE entries SET ts = ts - 100');                              // all of it older than the cut below

echo "── a prune ──\n";
$n = $store->pruneOlderThan(10, [$kept]);
ok($bodies($long) === ['', '', 'third, the tip'], 'a thread keeps its tip whole; the bodies behind it are pruned');
ok($bodies($one) === ['alone, the tip'], 'a thread of one entry keeps it: it is the tip');
ok($bodies($keep) === ['k1', 'k2'], 'a kept state keeps everything');
ok($bodies($old) === ['', '', 'o3, the tip'], 'a thread with no tips row is given one first, and keeps its tip too');
ok($n === 4, "exactly the bodies behind the tips were pruned ($n)");

echo "\n── the thread ticks on ──\n";
$tip = $bodies($long)[2];
ok($tip !== '' && $store->tipHashOf($long) === $h256($tip), 'the tip the next tick names is HASH256 of the kept body');
$tick($long, 'fourth');                                                     // the next tick names the kept tip
$all = $bodies($long);
ok(end($all) === 'fourth' && $store->tipHashOf($long) === $h256('fourth'), 'and the thread ticks forward from it (spending its output: verify-tip.php)');
$db->exec('UPDATE entries SET ts = ts - 100');
$n2 = $store->pruneOlderThan(10, [$kept]);
ok($bodies($long) === ['', '', '', 'fourth'], 'the old tip is pruned once it is no longer the tip');
ok($n2 === 1, "and only it ($n2)");

printf("\n%s  %d passed · %d failed   [the tip is never pruned]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail ? 1 : 0);
