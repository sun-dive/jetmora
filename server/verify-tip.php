<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE TIP IS TICKED ONCE (§4.4) ────────────────────────────────────────────────────────────────────
//
// An entry names the tip it ticks. A second entry naming a tip that is already ticked is INVALID, as a
// spent outpoint is gone on Bitcoin: the operator refuses it (409), and never adjudicates between two
// entries at one sequence, because there is nothing to adjudicate. One writer, one tip, one home.
//   php server/verify-tip.php
declare(strict_types=1);
require_once __DIR__ . '/wallet/jetmora/thread.php';
require_once __DIR__ . '/secp256k1.php';
require_once __DIR__ . '/dispatch.php';
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';
require_once __DIR__ . '/append.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

$path = sys_get_temp_dir() . '/jetmora-tip-' . bin2hex(random_bytes(4)) . '.db';
$db = new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$store = new LogStore($path);
$registry = new GenesisRegistry($db);
$appender = new Appender($store, $registry);

$d   = gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
$pub = Secp256k1::publicKey($d);
$script = "\x76\xa9\x14" . str_repeat("\x33", 20) . "\x88\xac";
$auth = CovenantThread::authorisedHashes([$pub]);
$g = ['source_hash' => hash('sha256', 'the source', true), 'script' => $script, 'state' => "\x00\x01", 'authorised' => $auth];
$id = $registry->register($g);
ok(strlen($id) === 32, 'a thread is registered');

$successor = [['value' => 0, 'locking' => $script]];
$push = fn(string $pre) => "\x4e" . pack('V', strlen($pre)) . $pre;
$tick = fn(string $prev, int $seq, string $salt = '') => CovenantThread::tick($prev, 0, $script, pack('P', 0), [['value' => 0, 'locking' => $script . $salt]], $seq, $push);
$send = function (array $t) use ($appender, $id, $d, $pub) { return $appender->append($id, $t['bytes'], $pub, Secp256k1::sign($d, CovenantThread::appendSighash($t['bytes']))); };
$h256 = fn(string $b) => hash('sha256', hash('sha256', $b, true), true);

echo "── the first tick names the genesis ──\n";
$t1 = $tick($id, 1);
$r1 = $send($t1);
ok($r1->ok, 'the first tick, naming the genesis id, lands');
ok($store->tipHashOf($id) === $h256($t1['bytes']), 'the store now holds HASH256 of that entry as the tip');

echo "\n── the second tick names the first ──\n";
$t2 = $tick($h256($t1['bytes']), 2);
ok($send($t2)->ok, 'a tick naming the first entry lands');

echo "\n── ⛔ a tip ticked twice ──\n";
$t2b = $tick($h256($t1['bytes']), 2, "\x51");        // a different entry, naming the SAME tip the second tick already ticked
ok($t2b['bytes'] !== $t2['bytes'], 'a different entry naming the same tip is built');
$rb = $send($t2b);
ok(!$rb->ok && $rb->status === 409, sprintf('it is refused with 409: "%s"', $rb->error));
ok($store->countOf($id) === 2, 'and nothing was recorded: the thread still has two entries');
$t3wrong = $tick($id, 3);
$rw = $send($t3wrong);
ok(!$rw->ok && $rw->status === 409, 'a tick naming the genesis again (a stale page) is refused too');

echo "\n── the real tip moves on ──\n";
$t3 = $tick($h256($t2['bytes']), 3);
ok($send($t3)->ok && $store->countOf($id) === 3, 'a tick naming the newest entry lands: three entries');

echo "\n── a thread from before tips were kept ──\n";
$db->exec('DELETE FROM tips');                        // as an older database would be
ok($store->tipHashOf($id) === $h256($t3['bytes']), 'the tip is derived from the newest body when no row is kept');
$db->prepare("UPDATE entries SET body = '' WHERE genesis = ?")->execute([$id]);   // every body pruned (§4.5)
ok($store->tipHashOf($id) === null, 'with the newest body pruned the tip is unknowable');
$t4 = $tick(str_repeat("\x42", 32), 4);
ok($send($t4)->ok, 'the next entry is accepted once, whatever it names');
$t5wrong = $tick(str_repeat("\x42", 32), 5);
ok($send($t5wrong)->status === 409, 'and from then on the tip is known again');

@unlink($path); @unlink("$path-wal"); @unlink("$path-shm");
printf("\n%s  %d passed · %d failed   [the tip is ticked once]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail ? 1 : 0);
