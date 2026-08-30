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
require_once __DIR__ . '/merkle.php';

// ⚠⚠ THE DATABASE MUST LIVE OUTSIDE THE DOCROOT. Inside one it is web-READABLE as well as
//     web-writable, which hands out the file instead of the proofs.
//   ⇒ Deployment creates a sibling of the docroot ($HOME/jetmora-data); if that directory exists we
//     use it. Locally it does not, so development falls back to ./data and needs no configuration.
define('DB_PATH', (static function (): string {
    $root = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if ($root !== '') {
        $sibling = dirname(rtrim($root, '/')) . '/jetmora-data';
        if (is_dir($sibling)) return $sibling . '/log.db';
    }
    return __DIR__ . '/data/log.db';
})());

function out(array $body, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json');
    header('Access-Control-Allow-Origin: *');
    echo json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit;
}
// ⚠⚠ AN ENDPOINT MUST NEVER ANSWER WITH AN EMPTY BODY. On 30 Aug an uncaught PDOException in the store
//   returned a bare 500, and every client died in `JSON.parse` with nothing to go on — the failure was
//   indistinguishable from a network fault. ⇒ Whatever happens, the answer is JSON.
//   ★ The CLASS is named because it is the whole diagnosis (a PDOException is not a TypeError); the
//   message is not, because messages carry paths and internals.
set_exception_handler(static function (Throwable $e): void {
    // ★ For a PDOException the SQLSTATE and the DRIVER CODE are the whole diagnosis — 5 is BUSY, 8 is
    //   READONLY, 14 is CANTOPEN, 1 is a plain SQL error — and neither carries a path.
    //   ⚠ getCode() is NOT reliable here: it returns an int for driver-level failures, which is why the
    //   first attempt at this printed nothing. `errorInfo` is the property that always has it.
    $kind = $e::class;
    if ($e instanceof PDOException && is_array($e->errorInfo ?? null)) {
        $kind .= ' sqlstate=' . (string)($e->errorInfo[0] ?? '?') . ' driver=' . (string)($e->errorInfo[1] ?? '?');
    }
    out(['error' => 'internal error', 'kind' => $kind], 500);
});
register_shutdown_function(static function (): void {
    $e = error_get_last();
    if ($e !== null && ($e['type'] & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR)) !== 0) {
        if (!headers_sent()) out(['error' => 'internal error', 'kind' => 'fatal'], 500);
    }
});

$hex = fn(string $b) => bin2hex($b);
$unhex = function (string $h, int $bytes = 0): string {
    if (!preg_match('/^[0-9a-fA-F]*$/', $h) || strlen($h) % 2) out(['error' => 'not hex'], 400);
    $b = hex2bin($h);
    if ($bytes && strlen($b) !== $bytes) out(['error' => "expected $bytes bytes"], 400);
    return $b;
};

if (!is_dir(dirname(DB_PATH))) @mkdir(dirname(DB_PATH), 0700, true);
$db = new PDO('sqlite:' . DB_PATH, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec('PRAGMA busy_timeout=10000');  // ⚠ match LogStore's ATTR_TIMEOUT — two connections, one file
$store = new LogStore(DB_PATH);
$registry = new GenesisRegistry($db);
$heads = new HeadStore($db);

$op = $_GET['op'] ?? '';
$n = $store->size();

switch ($op) {

case 'info':
    $latest = $heads->latest();
    out(['size' => $n, 'root' => $hex($store->root()),
         // ⚠ diagnostic: WAL is an optimisation the host may not grant, and knowing which we got
         //   beats guessing. It is not a protocol field.
         'journal_mode' => $store->journalMode,
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
    try {
        out(['leaf_index' => $leaf, 'tree_size' => $size,
             'root' => $hex($store->root($size)),
             'proof' => array_map($hex, $store->inclusionProof($leaf, $size))]);
    } catch (PrunedException $e) {
        // ⚠ absent, not wrong — and recoverable by restoring the bodies under the retained subtree root
        out(['error' => 'pruned', 'note' => $e->getMessage(),
             'prune' => $store->pruneState()], 410);
    }

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
    if ($body === null) out(['error' => 'no such entry'], 404);
    // ⚠⚠ A PRUNED body is an EMPTY STRING, not null — checking only for null returned 200 with an
    //    empty entry, which is the worst of both: it looks like data and is not.
    //    ⇒ 410, not 404: the entry existed and is still provable, it is simply no longer held here.
    if ($body === '') out(['error' => 'pruned — not held by this log',
                           'note' => 'still provable given the body; see spec §5c.2 for where to obtain it'], 410);
    out(['seq' => $seq, 'entry' => $hex($body)]);

case 'genesis':
    $g = $registry->get($unhex((string)($_GET['id'] ?? ''), 32));
    if ($g === null) out(['error' => 'unknown genesis'], 404);
    out(['id' => $hex($g['id']), 'source_hash' => $hex($g['source_hash']),
         'script' => $hex($g['script']), 'state' => $hex($g['state']),
         // ⚠ unpacked for the reader's convenience; the COMMITMENT is the packed bytes, never this.
         'authorised' => GenesisRegistry::unpackAuthorised($g['authorised'])]);

// ── register a genesis (spec §2) ─────────────────────────────────────────────────────────────
// ⚠ Idempotent and never overwriting: re-registering the same genesis returns the same id, and a
//   different authorised key is a DIFFERENT covenant, not an edit. A genesis that could change who
//   may advance it would not be a genesis.
case 'register':
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') out(['error' => 'POST required'], 405);
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['source_hash', 'script', 'state', 'authorised'] as $k)
        if (!isset($in[$k])) out(['error' => "missing $k"], 400);
    // `authorised` is "open", a list of hex public keys (1-of-n), or {threshold, keys} (k-of-n) — §4.2a.
    // ⚠⚠ PACKED, NEVER json_encode: these bytes are hashed into the covenant's IDENTITY, and a JSON
    //    encoder's spacing or key order would change it. Sorting inside makes [a,b] and [b,a] one covenant.
    try { $authPacked = GenesisRegistry::packAuthorised($in['authorised']); }
    catch (InvalidArgumentException $e) { out(['error' => $e->getMessage()], 400); }
    $id = $registry->register([
        'source_hash' => $unhex($in['source_hash'], 32),
        'script'      => $unhex($in['script']),
        'state'       => $unhex($in['state']),
        'authorised'  => $authPacked,
    ]);
    out(['genesis' => $hex($id)], 201);

// ── PORT a covenant from another log — spec §4b ──────────────────────────────────────────────
// ★★★ This is what defeats a censoring operator: state must be continuable ELSEWHERE, or a log that
// refuses your tick freezes the covenant forever and §1 is rebuilt with a new lever.
//
// ⚠⚠ WHAT THIS LOG VERIFIES, AND ONLY THIS (spec §4b.4):
//   1. the inclusion proof validates against the source root
//   2. the source root carries the source operator's signature
//   3. the author signature authorises the continuation
//   ⇒ It does NOT replay the covenant's history. That is a verifier's job, not a log's (§4.1).
case 'port':
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') out(['error' => 'POST required'], 405);
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['genesis_fields','entry','sequence','source_pubkey','source_head','source_head_sig',
              'inclusion_proof','author_pubkey','author_sig'] as $k)
        if (!isset($in[$k])) out(['error' => "missing $k"], 400);

    // the covenant's identity travels with it — a covenant is "descended from genesis G", never
    // "the thing in log A" (spec §4b.1)
    $gf = $in['genesis_fields'];
    $genesisId = $registry->register([
        'source_hash' => $unhex($gf['source_hash'], 32), 'script' => $unhex($gf['script']),
        'state' => $unhex($gf['state']), 'authorised' => json_encode($gf['authorised']),
    ]);

    $entry = $unhex($in['entry']);
    $head  = $unhex($in['source_head']);
    $srcPk = $unhex($in['source_pubkey']);
    // 2. the source operator really published that root
    if (!SignedHead::verify($head, $srcPk, $unhex($in['source_head_sig'])))
        out(['error' => 'source head signature does not verify'], 403);
    $h = SignedHead::parse($head);

    // 1. the entry really was in the source log's tree at that root
    $proof = array_map($unhex, $in['inclusion_proof']);
    if (!mt_verify_inclusion((int)$in['sequence'], $h['tree_size'], $entry, $proof, $h['root']))
        out(['error' => 'inclusion proof does not verify against the source root'], 403);

    // 3. an authorised key asked for this continuation — ⚠ this is what stops ANYONE porting
    //    someone else's covenant, and it is why portable state is safe (spec §3.5)
    $auth = $registry->authorisedFor($genesisId);
    $authorHex = strtolower(bin2hex($unhex($in['author_pubkey'])));
    if ($auth !== 'open' && !in_array($authorHex, array_map('strtolower', $auth ?? []), true))
        out(['error' => 'author is not authorised for this covenant'], 403);
    if (!Appender::verifySignature($entry, $unhex($in['author_pubkey']), $unhex($in['author_sig'])))
        out(['error' => 'author signature does not verify'], 403);

    // ⚠ An ANCHORED source root is final; a merely signed one is portable but CONTESTABLE (§4b.3).
    //   Recorded, not adjudicated — the log has no opinion about which it was.
    $anchored = $h['anchor_root'] !== null && $h['anchor_size'] >= (int)$in['sequence'] + 1;
    $seq = $store->append($entry);
    out(['seq' => $seq, 'genesis' => $hex($genesisId), 'tree_size' => $store->size(),
         'root' => $hex($store->root()), 'source_tree_size' => $h['tree_size'],
         'source_was_anchored' => $anchored,
         'note' => $anchored ? 'ported from an anchored root — final'
                             : 'ported from a signed but unanchored head — portable, contestable (spec §4b.3)'], 201);

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
    // ⚠ `spec` is always the CURRENT document; `spec_version` says which that is, and every superseded
    //    version stays fetchable at its own URL. A specification that can be silently replaced has the
    //    same defect as a log that can.
    out(['log' => 'jetmora',
         'spec' => 'https://jetmora.org/spec/log.md',
         'spec_version' => '0.1.1',
         'spec_versions' => ['0.1.1' => 'https://jetmora.org/spec/log.md',
                             '0.1'   => 'https://jetmora.org/spec/log-v0.1.md'],
         'protocol_version' => 1,   // ⚠ NOT the document version — see spec §6b
         'ops' => ['info', 'head', 'inclusion', 'consistency', 'entry', 'genesis', 'register', 'append', 'port']]);
}
