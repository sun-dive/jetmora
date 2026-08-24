<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// HOST CAPABILITY PROBE. Answers what a host's PHP can actually do, before anything is built on an
// assumption about it. ⚠ Everything after this in phase 2 depends on the answers.
//
// ⚠⚠ TOKEN-GATED, AND NOT OPTIONAL. This reports server internals; an ungated copy is a disclosure
//    gift to anyone who guesses the filename. Set PROBE_KEY below, call it as ?k=<key>, and
//    ⚠ DELETE THE FILE once you have the answer. It has no other purpose.
declare(strict_types=1);

const PROBE_KEY = 'CHANGE-ME-BEFORE-DEPLOYING';

if (!hash_equals(PROBE_KEY, (string)($_GET['k'] ?? ''))) {
    http_response_code(404);
    exit("Not Found\n");                       // ⚠ 404, not 403 — do not confirm the file exists
}
header('Content-Type: application/json');

$r = ['php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'os' => PHP_OS_FAMILY, 'int_size' => PHP_INT_SIZE];

// ── extensions the log server would use ──────────────────────────────────────────────────────
foreach (['hash','openssl','sqlite3','pdo_sqlite','sodium','gmp','bcmath','curl','json'] as $e)
    $r['ext'][$e] = extension_loaded($e);

// ── ⚠ RUN THE REAL MERKLE CODE ON THIS HOST, do not test a proxy for it ──────────────────────
//    An earlier draft compared against a hash typed from memory. It was wrong, and it reported the
//    HOST as broken. ⇒ Requiring the actual implementation answers the real question — will our code
//    work here — and cannot drift from it.
$r['sha256'] = in_array('sha256', hash_algos(), true);
$r['rfc6962'] = false;
if (is_file(__DIR__ . '/merkle.php')) {
    require_once __DIR__ . '/merkle.php';
    $e = array_map(fn($i) => "entry-$i", range(0, 4));
    $root = mt_root($e);
    $proof = mt_inclusion_proof(3, $e);
    $r['rfc6962'] = bin2hex($root) === '1aa68d3074905a581f84cbbd0f753794904fd80451bc4c13e69d9a53bc59502c'
        && bin2hex($proof[0]) === '049d7dcdb56bcfebd313304c9839f196a3d4b6ef3bdc0b08298f93ac8191f0a8'
        && mt_verify_inclusion(3, 5, $e[3], $proof, $root);
} else {
    $r['rfc6962_note'] = 'merkle.php not deployed alongside this probe — copy both or ignore this line';
}

// ── secp256k1 via openssl — CHECKSIG needs it if sodium is absent ─────────────────────────────
$r['secp256k1'] = false;
if (extension_loaded('openssl')) {
    $curves = openssl_get_curve_names() ?: [];
    $r['secp256k1'] = in_array('secp256k1', $curves, true);
}

// ── ⚠ CAN IT WRITE? An append-only log is not much use otherwise. ────────────────────────────
$dir = __DIR__ . '/_probe_tmp';
$r['write'] = ['dir' => false, 'flock' => false, 'sqlite_file' => false];
if (@mkdir($dir) || is_dir($dir)) {
    $f = $dir . '/t';
    if (@file_put_contents($f, 'x') !== false) {
        $r['write']['dir'] = true;
        $h = @fopen($f, 'c+');
        if ($h) { $r['write']['flock'] = @flock($h, LOCK_EX | LOCK_NB); @flock($h, LOCK_UN); fclose($h); }
    }
    // ⚠ SQLite on shared hosting sometimes cannot lock on a network filesystem — test, do not assume
    if (extension_loaded('pdo_sqlite')) {
        try {
            $db = new PDO('sqlite:' . $dir . '/t.db');
            $db->exec('CREATE TABLE IF NOT EXISTS t(a INTEGER PRIMARY KEY)');
            $db->beginTransaction(); $db->exec('INSERT INTO t(a) VALUES (1)'); $db->commit();
            $r['write']['sqlite_file'] = (int)$db->query('SELECT COUNT(*) FROM t')->fetchColumn() > 0;
            $r['sqlite_version'] = $db->query('SELECT sqlite_version()')->fetchColumn();
            $db = null;
        } catch (Throwable $e) { $r['write']['sqlite_error'] = $e->getMessage(); }
    }
    @array_map('unlink', glob($dir . '/*') ?: []); @rmdir($dir);
}

// ── ⚠ OUTBOUND HTTP — anchoring has to reach a broadcaster ───────────────────────────────────
$r['outbound'] = ['allow_url_fopen' => (bool)ini_get('allow_url_fopen'), 'curl' => extension_loaded('curl')];

// ── limits that bite a merkle tree over a large log ──────────────────────────────────────────
foreach (['memory_limit','max_execution_time','post_max_size','upload_max_filesize','disable_functions']
         as $k) $r['ini'][$k] = ini_get($k);

// ── ⇒ THE VERDICT: can the log server be built here as designed? ─────────────────────────────
$must = $r['ext']['hash'] && $r['sha256'] && $r['rfc6962'] && $r['write']['dir'];
$store = $r['write']['sqlite_file'] ? 'sqlite' : ($r['write']['flock'] ? 'file+flock (fallback)' : 'NONE');
$sig = $r['ext']['sodium'] ? 'sodium' : ($r['secp256k1'] ? 'openssl secp256k1' : 'NONE');
$r['verdict'] = [
    'merkle'    => $must ? 'yes' : 'NO — needs ext/hash, sha256 and a writable directory',
    'storage'   => $store,
    'signature' => $sig,
    'anchoring' => ($r['outbound']['curl'] || $r['outbound']['allow_url_fopen']) ? 'yes' : 'NO outbound HTTP',
    'buildable' => ($must && $store !== 'NONE' && $sig !== 'NONE') ? 'YES' : 'NOT AS DESIGNED',
];
$r['reminder'] = 'DELETE THIS FILE once you have the answer.';

echo json_encode($r, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
