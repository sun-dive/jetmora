<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE RATE LIMITER, GRADED ACROSS REAL PROCESSES ──────────────────────────────────────────────────
//
// ★★★ THE TEST THIS FILE EXISTS FOR IS THE CROSS-PROCESS ONE, and everything else is secondary.
//   An in-process test of a PHP pacer **passes for free**: one script is one process, so a promise
//   chain, a static, or nothing at all would all look identical. ⇒ The only honest check is to SPAWN
//   CONCURRENT PHP PROCESSES and prove they serialize — which is the exact condition (a busy site) the
//   pacer exists for, and the exact condition a single-process test cannot reach. → How to work #2.
//
// ⚠ NO NETWORK IS USED ANYWHERE HERE. The transport is injected, so 429s, `Retry-After` and slow
//   responses are all produced on demand — a limiter tested only against a live API has not been
//   tested, because the interesting cases are the ones the service will not produce when asked.
declare(strict_types=1);
require_once __DIR__ . '/wallet/bsv/http.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}
$TMP = sys_get_temp_dir() . '/jetmora-http-test-' . getmypid();
@mkdir($TMP, 0777, true);
register_shutdown_function(function () use ($TMP) {
  foreach (glob("$TMP/*") ?: [] as $f) @unlink($f);
  @rmdir($TMP);
});

// ── ★★★ CROSS-PROCESS: concurrent PHP processes must QUEUE ──────────────────────────────────────────
echo "── ★★★ 5 concurrent PHP processes, 3 requests each ──\n";
$stampFile = "$TMP/stamps.txt";
$worker = "$TMP/worker.php";
file_put_contents($worker, '<?php
require_once ' . var_export(__DIR__ . '/wallet/bsv/http.php', true) . ';
[$dir, $stamps, $gap] = [$argv[1], $argv[2], (int)$argv[3]];
$lim = new RateLimiter("test.example", $gap, 30000, $dir);
for ($i = 0; $i < 3; $i++)
  $lim->run(function () use ($stamps) {
    $t = microtime(true);
    usleep(5000);                       // a request takes SOME time; the gap is measured after it
    $h = fopen($stamps, "a"); flock($h, LOCK_EX);
    fwrite($h, sprintf("%.6f %.6f\n", $t, microtime(true)));
    flock($h, LOCK_UN); fclose($h);
  });
');
$GAP = 120;                                       // ms — enough to measure, quick enough to test
$procs = [];
$t0 = microtime(true);
for ($i = 0; $i < 5; $i++)
  $procs[] = proc_open(sprintf('%s %s %s %s %d', PHP_BINARY, escapeshellarg($worker),
                               escapeshellarg($TMP), escapeshellarg($stampFile), $GAP),
                       [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes[$i]);
foreach ($procs as $i => $p) { foreach ($pipes[$i] as $pp) fclose($pp); proc_close($p); }
$elapsed = (microtime(true) - $t0) * 1000;

$rows = array_filter(array_map('trim', file($stampFile) ?: []));
ok(count($rows) === 15, sprintf('all 15 requests ran across 5 processes (%d recorded)', count($rows)));

// ★ sort by start time and check no two STARTS are closer than the gap
$starts = [];
foreach ($rows as $r) { [$s, $e] = array_map('floatval', explode(' ', $r)); $starts[] = [$s, $e]; }
usort($starts, fn($a, $b) => $a[0] <=> $b[0]);
$tooClose = 0; $minGap = INF;
for ($i = 1; $i < count($starts); $i++) {
  // ⚠ measured END-of-previous to START-of-next: that is the gap the limiter actually promises
  $g = ($starts[$i][0] - $starts[$i-1][1]) * 1000;
  $minGap = min($minGap, $g);
  if ($g < $GAP * 0.85) $tooClose++;              // 15% slack for scheduler jitter
}
ok($tooClose === 0,
   sprintf('★★★ NO two requests started within %dms of each other — separate PROCESSES queued (%d violations, tightest %.0fms)',
           $GAP, $tooClose, $minGap));
// ⚠ and no OVERLAP at all: the lock is held across the call, so requests cannot interleave
$overlap = 0;
for ($i = 1; $i < count($starts); $i++) if ($starts[$i][0] < $starts[$i-1][1]) $overlap++;
ok($overlap === 0, '★★ no two requests overlapped in time — the lock is held ACROSS the call, not just the wait');
ok($elapsed >= 14 * $GAP * 0.85,
   sprintf('the wall clock reflects it: %.0fms for 15 paced requests (>= ~%dms)', $elapsed, 14 * $GAP));

// ⛔ THE CONTROL: without the limiter, do the same processes actually burst? If they do not, the test
//   above proves nothing — it would pass on a machine too slow to overlap anyway.
echo "\n── ⛔ the control: unpaced, do they burst? ──\n";
$bare = "$TMP/bare.txt";
$w2 = "$TMP/worker2.php";
file_put_contents($w2, '<?php
[$stamps] = [$argv[1]];
for ($i = 0; $i < 3; $i++) {
  $t = microtime(true); usleep(5000);
  $h = fopen($stamps, "a"); flock($h, LOCK_EX);
  fwrite($h, sprintf("%.6f %.6f\n", $t, microtime(true)));
  flock($h, LOCK_UN); fclose($h);
}');
$procs = []; $pipes = [];
for ($i = 0; $i < 5; $i++)
  $procs[] = proc_open(sprintf('%s %s %s', PHP_BINARY, escapeshellarg($w2), escapeshellarg($bare)),
                       [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes[$i]);
foreach ($procs as $i => $p) { foreach ($pipes[$i] as $pp) fclose($pp); proc_close($p); }
$b = array_filter(array_map('trim', file($bare) ?: []));
$bs = [];
foreach ($b as $r) { [$s, $e] = array_map('floatval', explode(' ', $r)); $bs[] = [$s, $e]; }
usort($bs, fn($x, $y) => $x[0] <=> $y[0]);
$burst = 0;
for ($i = 1; $i < count($bs); $i++) if (($bs[$i][0] - $bs[$i-1][1]) * 1000 < $GAP * 0.85) $burst++;
ok($burst > 0,
   sprintf('⛔ UNPACED, %d of %d pairs burst inside the gap — so the check above is measuring something real',
           $burst, count($bs) - 1));

// ── ⚠ 429 is not an error ───────────────────────────────────────────────────────────────────────────
echo "\n── ⚠ 429 handling ──\n";
$calls = 0;
$http = new BsvHttp(function () use (&$calls) {
  $calls++;
  return $calls <= 2 ? ['status' => 429, 'body' => '', 'headers' => []]
                     : ['status' => 200, 'body' => '{"ok":true}', 'headers' => []];
}, 3, 1);
$r = $http->get('https://api.whatsonchain.com/v1/bsv/main/x');
ok($r['status'] === 200 && $calls === 3, "★ two 429s then success — retried, not thrown ($calls calls)");
ok(json_decode($r['body'], true)['ok'] === true, 'the eventual body comes back intact');

// ⛔ and after the retries are exhausted, the 429 is RETURNED, not thrown as "verification failed"
$always = new BsvHttp(fn() => ['status' => 429, 'body' => '', 'headers' => []], 2, 1);
$r2 = $always->get('https://api.whatsonchain.com/v1/bsv/main/x');
ok($r2['status'] === 429,
   '⛔ a persistent 429 comes back AS 429 — the SDK throws here, which reads as a bad proof');

// ★ Retry-After is honoured — tested in BOTH directions.
// ⚠⚠ Found by mutation testing: my first version used Retry-After: 0.3 and asserted ">= 0.29ms". The
//   DEFAULT backoff is 500ms, which also satisfies that ⇒ ignoring the header passed the test. A value
//   must be chosen that the default CANNOT produce, and checked from both sides.
$waitFor = function (string $after) {
  $seen = []; $n = 0;
  $h = new BsvHttp(function () use (&$n, &$seen, $after) {
    $seen[] = microtime(true); $n++;
    return $n === 1 ? ['status' => 429, 'body' => '', 'headers' => ['retry-after' => $after]]
                    : ['status' => 200, 'body' => 'ok', 'headers' => []];
  }, 3, 1, sys_get_temp_dir());
  $h->get('https://api.whatsonchain.com/v1/bsv/main/y' . $after);
  return (($seen[1] ?? 0) - ($seen[0] ?? 0)) * 1000;
};
$short = $waitFor('0.05');                      // ⚠ 50ms — the 500ms default cannot produce this
ok($short < 250, sprintf('★ Retry-After: 0.05 waited %.0fms — FASTER than the 500ms default', $short));
$long  = $waitFor('0.9');                       // ⚠ 900ms — nor this
ok($long >= 850, sprintf('★ Retry-After: 0.9 waited %.0fms — SLOWER than the default', $long));
ok($long > $short * 3, '★★ the wait TRACKS the header in both directions, so it is really being read');
// ⚠ and a nonsense value falls back rather than crashing
$junk = $waitFor('soon');
ok($junk >= 400 && $junk < 900, sprintf('⚠ a non-numeric Retry-After falls back to the default (%.0fms)', $junk));

// ── ★ per-host queues are independent ───────────────────────────────────────────────────────────────
echo "\n── ★ WoC and BananaBlocks queue separately ──\n";
$order = [];
// ⚠ Its OWN lock directory. Sharing one with the tests above made the FIRST call wait on a stamp they
//   had just written — which is the limiter working correctly, and my measurement spanning both calls.
//   ⇒ Time the SECOND call alone, and start from a clean directory.
$two = new BsvHttp(fn() => ['status' => 200, 'body' => '', 'headers' => []], 3, 300, "$TMP/hosts");
@mkdir("$TMP/hosts", 0777, true);
$two->get('https://api.whatsonchain.com/v1/bsv/main/a');   // primes the WoC slot
$t = microtime(true);
$two->get('https://bananablocks.com/api/v1/b');            // ⚠ different host ⇒ must NOT wait
$span = (microtime(true) - $t) * 1000;
ok($span < 250, sprintf('★ a different host does NOT queue behind WoC (%.0fms)', $span));
$t = microtime(true);
$two->get('https://api.whatsonchain.com/v1/bsv/main/c');   // ⚠ same host ⇒ MUST wait
$same = (microtime(true) - $t) * 1000;
ok($same >= 250, sprintf('⚠ ...but a second call to the SAME host waits (%.0fms)', $same));

// ── ⚠ it fails OPEN, never closed ───────────────────────────────────────────────────────────────────
echo "\n── ⚠ an unwritable lock directory ──\n";
$ro = "$TMP/readonly";
@mkdir($ro, 0500, true);
$lim = new RateLimiter('x.example', 50, 1000, $ro);
$ran = false;
try { $lim->run(function () use (&$ran) { $ran = true; return 1; }); } catch (Throwable) {}
ok($ran, '⚠ pacing is lost but the request still RUNS — a lock file must never take the site down');
@rmdir($ro);

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────
echo "\n── refusals ──\n";
try { (new BsvHttp(fn() => ['status'=>200,'body'=>'','headers'=>[]]))->get('not-a-url');
      ok(false, 'a URL with no host is refused'); }
catch (Throwable $e) { ok(str_contains($e->getMessage(), 'no host'), 'a URL with no host is refused'); }
try { (new BsvHttp(fn() => ['status'=>500,'body'=>'nope','headers'=>[]]))
        ->getJson('https://api.whatsonchain.com/v1/bsv/main/z');
      ok(false, 'a 500 is refused by getJson'); }
catch (Throwable $e) { ok(str_contains($e->getMessage(), 'HTTP 500'), 'getJson refuses a non-2xx, naming the code'); }

printf("\n%s  %d passed, %d failed   [rate-limited HTTP · graded ACROSS PROCESSES, no network]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
