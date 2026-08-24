<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE LOG ENDPOINT — spec §5.3, §4.1. One file, deliberately thin: the store does the work and this
// only translates HTTP to it. ⚠ A log serves PROOFS. It does not adjudicate, does not execute Script,
// and has no opinion about what the entries mean.
//
// ⚠ CORS is open on reads and that is correct: a transparency log's contents are public by
//   construction, and a browser-side verifier is exactly the client this is for. Writes are gated by
//   the append rule's signature, not by origin.
declare(strict_types=1);
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';
require_once __DIR__ . '/append.php';
require_once __DIR__ . '/head.php';

const DB_PATH = __DIR__ . '/data/log.db';       // ⚠ put this OUTSIDE the docroot in a real deployment

function out(array $body, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    echo json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit;
}
$hex = fn(string $b) => bin2hex($b);
$unhex = function (string $h, int $bytes = 0): string {
    if (!preg_match('/^[0-9a-fA-F]*$/', $h) || strlen($h) % 2) out(['error' => 'not hex'], 400);
    $b = hex2bin($h);
    if ($bytes && strlen($b) !== $bytes) out(['error' => "expected $bytes bytes"], 400);
    return $b;
};

if (!is_dir(dirname(DB_PATH))) @mkdir(dirname(DB_PATH), 0700, true);
$db = new PDO('sqlite:' . DB_PATH, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$store = new LogStore(DB_PATH);
$registry = new GenesisRegistry($db);
$heads = new HeadStore($db);

$op = $_GET['op'] ?? '';
$n = $store->size();

switch ($op) {

case 'info':
    $latest = $heads->latest();
    out(['size' => $n, 'root' => $hex($store->root()),
         'head' => $latest ? $hex($latest['head']) : null,
         // ⚠ "witnessed" is not "anchored" and not "confirmed" — see spec §4c
         'state' => 'entries are final on append; anchoring adds objective ordering, not validity']);

case 'head':
    $h = isset($_GET['size']) ? $heads->at((int)$_GET['size']) : $heads->latest();
    if ($h === null) out(['error' => 'no head published'], 404);
    out(['head' => $hex($h['head']), 'signature' => $hex($h['sig']),
         'pubkey' => $hex($h['pubkey']), 'parsed' => array_map(
            fn($v) => is_string($v) ? bin2hex($v) : $v, SignedHead::parse($h['head']))]);

// ── PATH(m, D[n]) ─────────────────────────────────────────────────────────────────────────────
case 'inclusion':
    $leaf = (int)($_GET['leaf'] ?? -1);
    $size = (int)($_GET['size'] ?? $n);
    if ($size < 1 || $size > $n) out(['error' => "size must be 1..$n"], 400);
    if ($leaf < 0 || $leaf >= $size) out(['error' => "leaf must be 0.." . ($size - 1)], 400);
    out(['leaf_index' => $leaf, 'tree_size' => $size,
         'root' => $hex($store->root($size)),
         'proof' => array_map($hex, $store->inclusionProof($leaf, $size))]);

// ── PROOF(m, D[n]) — ★ what no proof-of-work chain provides ──────────────────────────────────
case 'consistency':
    $first = (int)($_GET['first'] ?? 0);
    $second = (int)($_GET['second'] ?? $n);
    if ($first < 1 || $first > $second || $second > $n) out(['error' => "need 1 <= first <= second <= $n"], 400);
    out(['first' => $first, 'second' => $second,
         'first_root' => $hex($store->root($first)), 'second_root' => $hex($store->root($second)),
         'proof' => array_map($hex, $store->consistencyProof($first, $second))]);

case 'entry':
    $seq = (int)($_GET['seq'] ?? -1);
    $body = $seq >= 0 ? $store->entry($seq) : null;
    // ⚠ A pruned log can still PROVE an entry; it cannot PRODUCE one (spec §5c.2). 410, not 404 —
    //   the entry existed and is provable, it is simply no longer held here.
    if ($body === null) out(['error' => 'not held by this log', 'note' => 'may have been pruned — see §5c'], 410);
    out(['seq' => $seq, 'entry' => $hex($body)]);

case 'genesis':
    $g = $registry->get($unhex((string)($_GET['id'] ?? ''), 32));
    if ($g === null) out(['error' => 'unknown genesis'], 404);
    out(['id' => $hex($g['id']), 'source_hash' => $hex($g['source_hash']),
         'script' => $hex($g['script']), 'state' => $hex($g['state']),
         'authorised' => json_decode($g['authorised'], true)]);

// ── the append rule: ONE signature check and nothing else (spec §4.1) ────────────────────────
case 'append':
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') out(['error' => 'POST required'], 405);
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['genesis', 'entry', 'pubkey', 'signature'] as $k)
        if (!isset($in[$k]) || !is_string($in[$k])) out(['error' => "missing $k"], 400);
    // ⏭ the operator's own policy — a price, an account, a rate limit — hooks in here (spec §4.5).
    //    ⚠ The protocol defines no price, no currency and no settlement (§3.4-0b).
    $appender = new Appender($store, $registry, null);
    $r = $appender->append($unhex($in['genesis'], 32), $unhex($in['entry']),
                           $unhex($in['pubkey']), $unhex($in['signature']));
    if (!$r->ok) out(['error' => $r->error], $r->status);
    out(['seq' => $r->seq, 'tree_size' => $store->size(), 'root' => $hex($store->root())], 201);

default:
    out(['log' => 'jetmora', 'spec' => 'https://jetmora.org/spec/log.md',
         'ops' => ['info', 'head', 'inclusion', 'consistency', 'entry', 'genesis', 'append']]);
}
