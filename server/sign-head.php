<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// SIGN THE HEAD: the operator signs what the thread service holds (spec §5.2), from cron, once the tree has grown.
//
//   php sign-head.php <threads db> <key file>
//
//   key file   the operator's Ed25519 SEED, 32 bytes raw. Made on first run if absent (0600), and its public key
//              printed, so it can be backed up. ⚠ Never in this repository.
//   ⇒ One head per size, never re-signed: HeadStore makes a second head at a size impossible.
//   ⇒ prune_level is the store's own; the service id (log_id in head.php) is 32 zero bytes until this service
//     declares one (legal, and a detector then treats its heads as uncomparable with any other service's).
declare(strict_types=1);
require __DIR__ . '/merkle.php';
require __DIR__ . '/store.php';
require __DIR__ . '/head.php';

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
[$_, $dbPath, $keyPath] = $argv + [null, null, null];
if (!$dbPath || !$keyPath) { fwrite(STDERR, "usage: php sign-head.php <threads db> <key file>\n"); exit(2); }
if (!extension_loaded('sodium')) { fwrite(STDERR, "sodium is required\n"); exit(2); }

if (!is_file($keyPath)) {
    $old = umask(077); file_put_contents($keyPath, random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES)); umask($old);
    $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(file_get_contents($keyPath)));
    echo gmdate('Y-m-d H:i:s'), ' made a new head key: ', bin2hex($pub), "\n";
}
$seed = file_get_contents($keyPath);
if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) { fwrite(STDERR, "the key file is not a 32-byte seed\n"); exit(2); }
$pair = sodium_crypto_sign_seed_keypair($seed);
$pub = sodium_crypto_sign_publickey($pair);

$store = new LogStore($dbPath);
$db = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec('PRAGMA busy_timeout=10000');
$heads = new HeadStore($db);
$n = $store->size();
$latest = $heads->latest();
if ($n === 0 || ($latest !== null && SignedHead::parse($latest['head'])['tree_size'] >= $n)) exit(0);   // nothing new: say nothing

$head = SignedHead::bytes($n, $store->root($n), time(), '', 0, $store->pruneState()['level']);
$sig = sodium_crypto_sign_detached($head, sodium_crypto_sign_secretkey($pair));
$heads->publish($head, $sig, $pub);                 // verifies the signature itself before storing
echo gmdate('Y-m-d H:i:s'), " signed the head at size $n\n";
