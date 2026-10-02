<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// THE THREAD SERVICE ENDPOINT — spec §5.3, §4.1. One file, deliberately thin: the store does the work and this
// only translates HTTP to it. ⚠ A thread service serves PROOFS. It does not adjudicate, does not execute Script,
// and has no opinion about what the entries mean.
//
// ⚠ CORS is open on reads and that is correct: a thread service's contents are public by
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
// ⚠ The FILE keeps its first name, log.db: renaming a live database is a change of its own (TODO.md).
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
    // ★ FULL IS NOT BROKEN. The store declines to record and still proves everything it recorded —
    //   "an operator who can only refuse". 507 says exactly that; 500 would say something false.
    if ($e instanceof ThreadStoreFullException)
        out(['error' => 'the thread store is full', 'note' => $e->getMessage(),
             'still_provable' => 'every entry already appended remains readable and provable'], 507);
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

// ── PACKED TRANSPORT (his rule, 19 Sept): bytes on the wire, as on the chain ───────────────────────
//   A wallet talks in the framing the relay already uses: a 4-byte big-endian length before each field
//   or entry. JSON stays for people, tooling and the replay page. The choice is the client's:
//     POST with Content-Type: application/octet-stream  ⇒ the body is packed fields
//     GET  with Accept: application/octet-stream (or &f=bin) ⇒ the answer is packed
//   Errors are always JSON, so no answer is ever an empty body.
$packedIn  = str_starts_with($_SERVER['CONTENT_TYPE'] ?? '', 'application/octet-stream');
$packedOut = str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/octet-stream') || ($_GET['f'] ?? '') === 'bin';
$lp = fn(string $b) => pack('N', strlen($b)) . $b;
/** Split a packed body into its length-prefixed fields; refuses trailing or truncated bytes. */
$fields = function (string $body, int $n): array {
    $out = []; $o = 0;
    for ($i = 0; $i < $n; $i++) {
        if ($o + 4 > strlen($body)) out(['error' => "packed body truncated at field $i"], 400);
        $len = unpack('N', substr($body, $o, 4))[1]; $o += 4;
        if ($o + $len > strlen($body)) out(['error' => "packed body truncated in field $i"], 400);
        $out[] = substr($body, $o, $len); $o += $len;
    }
    if ($o !== strlen($body)) out(['error' => 'packed body has trailing bytes'], 400);
    return $out;
};
function outBytes(string $body, int $status = 200, array $headers = []): never {
    http_response_code($status);
    header('Content-Type: application/octet-stream');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Expose-Headers: X-Tip, X-Count, X-More, X-Seq, X-Tree-Size');
    foreach ($headers as $k => $v) header("$k: $v");
    echo $body;
    exit;
}

if (!is_dir(dirname(DB_PATH))) @mkdir(dirname(DB_PATH), 0700, true);
$db = new PDO('sqlite:' . DB_PATH, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec('PRAGMA busy_timeout=10000');  // ⚠ match ThreadStore's ATTR_TIMEOUT — two connections, one file
$store = new ThreadStore(DB_PATH);
$registry = new GenesisRegistry($db);
$heads = new HeadStore($db);
// ⏭ The operator's own policy (spec §4.5): a price, an account, a rate limit. A file beside this one
//   returning ['register' => fn(): bool, 'append' => fn(string $genesisId, string $hexKey): bool].
//   Not a validity check, and not part of the protocol; absent, everything is admitted.
$policy = is_file(__DIR__ . '/policy.php') ? (require __DIR__ . '/policy.php') : [];
if (!is_array($policy)) $policy = [];

$op = $_GET['op'] ?? '';
$n = $store->size();

switch ($op) {

case 'info':
    $latest = $heads->latest();
    out(['size' => $n, 'root' => $hex($store->root()),
         // ⚠ diagnostic: WAL is an optimisation the host may not grant, and knowing which we got
         //   beats guessing. It is not a protocol field.
         'journal_mode' => $store->journalMode,
         // ⚠ shared hosting. Visible here so it is known LONG before it bites, not discovered at it.
         'bytes' => $store->bytes(), 'capacity_bytes' => ThreadStore::MAX_DB_BYTES,
         // ★ The battery, in entries rather than bytes — measured from this store's own consumption.
         //   ⚠ null until there is enough history for the average to mean anything.
         'charge' => $store->charge(),
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
    if ($body === '') out(['error' => 'pruned — not held by this service',
                           'note' => 'still provable given the body; see spec §5c.2 for where to obtain it'], 410);
    out(['seq' => $seq, 'entry' => $hex($body)]);

// ── one thread, read back — the index per covenant ────────────────────────────────────────────
case 'entries':
    $g = $unhex((string)($_GET['genesis'] ?? ''), 32);
    $after = (int)($_GET['after'] ?? -1);
    $limit = (int)($_GET['limit'] ?? 256);
    $rows = $store->entriesOf($g, $after, $limit);
    $tip = $store->tipOf($g);
    if ($packedOut)   // each entry: 4-byte length ‖ bytes — the relay's framing, so one parser serves both
        outBytes(implode('', array_map(fn($r) => $lp($r['body']), $rows)), 200,
                 ['X-Tip' => $tip ?? -1, 'X-Count' => count($rows), 'X-More' => ($rows !== [] && end($rows)['seq'] < $tip) ? 1 : 0]);
    out(['genesis' => $hex($g), 'after' => $after,
         'entries' => array_map(fn($r) => ['seq' => $r['seq'], 'entry' => $hex($r['body'])], $rows),
         'tip' => $tip, 'more' => $rows !== [] && end($rows)['seq'] < $tip]);

case 'find':
    // Threads by initial state: the way a party finds threads addressed to it by a state it can derive.
    $state = $unhex((string)($_GET['state'] ?? ''));
    if ($state === '' || strlen($state) > 64) out(['error' => 'state is 1..64 bytes'], 400);
    $ids = $store->threadsWithState($state, (int)($_GET['limit'] ?? 256));
    if ($packedOut) outBytes(implode('', $ids), 200, ['X-Count' => count($ids)]);   // 32 bytes each, newest activity first
    out(['state' => $hex($state), 'threads' => array_map($hex, $ids)]);

case 'tip':
    $g = $unhex((string)($_GET['genesis'] ?? ''), 32);
    $tip = $store->tipOf($g); $count = $store->countOf($g);
    if ($packedOut) outBytes(pack('N', $tip ?? 0xFFFFFFFF) . pack('N', $count), 200, ['X-Tip' => $tip ?? -1, 'X-Count' => $count]);
    out(['genesis' => $hex($g), 'tip' => $tip, 'count' => $count]);

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
    if ($packedIn) {
        // ★ The body IS the commitment: LP(source_hash) ‖ LP(script) ‖ LP(state) ‖ LP(authorised). The id is
        //   its double hash, so what the wallet sends is exactly what it hashed — nothing to re-encode.
        [$sh, $sc, $stt, $ap] = $fields(file_get_contents('php://input') ?: '', 4);
        if (strlen($sh) !== 32) out(['error' => 'source_hash must be 32 bytes'], 400);
        if (GenesisRegistry::unpackAuthorised($ap) === null) out(['error' => 'authorised is not a packed set'], 400);
        if (isset($policy['register']) && !$policy['register']()) out(['error' => 'refused by operator policy'], 402);
        $id = $registry->register(['source_hash' => $sh, 'script' => $sc, 'state' => $stt, 'authorised' => $ap]);
        if ($packedOut) outBytes($id, 201);
        out(['genesis' => $hex($id)], 201);
    }
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['source_hash', 'script', 'state'] as $k)
        if (!isset($in[$k])) out(['error' => "missing $k"], 400);
    if (isset($policy['register']) && !$policy['register']()) out(['error' => 'refused by operator policy'], 402);
    // `authorised` is "open", a list of hex public keys (1-of-n), or {threshold, keys} (k-of-n) — §4.2a —
    // packed here as HASHES; or `authorised_packed`, the bytes already packed by a wallet that derived the
    // id itself, so the id it computed and the id registered here are the same bytes hashed.
    // ⚠⚠ PACKED, NEVER json_encode: these bytes are hashed into the covenant's IDENTITY.
    if (isset($in['authorised_packed'])) {
        $authPacked = $unhex((string)$in['authorised_packed']);
        if (GenesisRegistry::unpackAuthorised($authPacked) === null) out(['error' => 'authorised_packed is not a packed set'], 400);
    } elseif (isset($in['authorised'])) {
        try { $authPacked = GenesisRegistry::packAuthorised($in['authorised']); }
        catch (InvalidArgumentException $e) { out(['error' => $e->getMessage()], 400); }
    } else out(['error' => 'missing authorised'], 400);
    $id = $registry->register([
        'source_hash' => $unhex($in['source_hash'], 32),
        'script'      => $unhex($in['script']),
        'state'       => $unhex($in['state']),
        'authorised'  => $authPacked,
    ]);
    out(['genesis' => $hex($id)], 201);

// ── PORT a covenant from another service — spec §4b ──────────────────────────────────────────────
// ★★★ This is what defeats a censoring operator: state must be continuable ELSEWHERE, or a service that
// refuses your tick freezes the covenant forever and §1 is rebuilt with a new lever.
//
// ⚠⚠ WHAT THIS SERVICE VERIFIES, AND ONLY THIS (spec §4b.4):
//   1. the inclusion proof validates against the source root
//   2. the source root carries the source operator's signature
//   3. the author signature authorises the continuation
//   ⇒ It does NOT replay the covenant's history. That is a verifier's job, not a service's (§4.1).
case 'port':
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') out(['error' => 'POST required'], 405);
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['genesis_fields','entry','sequence','source_pubkey','source_head','source_head_sig',
              'inclusion_proof','author_pubkey','author_sig'] as $k)
        if (!isset($in[$k])) out(['error' => "missing $k"], 400);

    // the covenant's identity travels with it — a covenant is "descended from genesis G", never
    // "the thing on service A" (spec §4b.1)
    $gf = $in['genesis_fields'];
    $genesisId = $registry->register([
        'source_hash' => $unhex($gf['source_hash'], 32), 'script' => $unhex($gf['script']),
        'state' => $unhex($gf['state']),
        'authorised' => isset($gf['authorised_packed']) ? $unhex((string)$gf['authorised_packed'])
                                                       : GenesisRegistry::packAuthorised($gf['authorised'] ?? 'open'),
    ]);

    $entry = $unhex($in['entry']);
    $head  = $unhex($in['source_head']);
    $srcPk = $unhex($in['source_pubkey']);
    // 2. the source operator really published that root
    if (!SignedHead::verify($head, $srcPk, $unhex($in['source_head_sig'])))
        out(['error' => 'source head signature does not verify'], 403);
    $h = SignedHead::parse($head);

    // 1. the entry really was in the source service's tree at that root
    $proof = array_map($unhex, $in['inclusion_proof']);
    if (!mt_verify_inclusion((int)$in['sequence'], $h['tree_size'], $entry, $proof, $h['root']))
        out(['error' => 'inclusion proof does not verify against the source root'], 403);

    // 3. an authorised key asked for this continuation — ⚠ this is what stops ANYONE porting
    //    someone else's covenant, and it is why portable state is safe (spec §3.5)
    $auth = $registry->authorisedFor($genesisId);
    if ($auth === null || !GenesisRegistry::isAuthorised($auth, $unhex($in['author_pubkey'])))
        out(['error' => 'author is not authorised for this covenant'], 403);
    if (!Appender::verifySignature($entry, $unhex($in['author_pubkey']), $unhex($in['author_sig'])))
        out(['error' => 'author signature does not verify'], 403);

    // ⚠ An ANCHORED source root is final; a merely signed one is portable but CONTESTABLE (§4b.3).
    //   Recorded, not adjudicated — the service has no opinion about which it was.
    $anchored = $h['anchor_root'] !== null && $h['anchor_size'] >= (int)$in['sequence'] + 1;
    $seq = $store->append($entry, $genesisId);
    out(['seq' => $seq, 'genesis' => $hex($genesisId), 'tree_size' => $store->size(),
         'root' => $hex($store->root()), 'source_tree_size' => $h['tree_size'],
         'source_was_anchored' => $anchored,
         'note' => $anchored ? 'ported from an anchored root — final'
                             : 'ported from a signed but unanchored head — portable, contestable (spec §4b.3)'], 201);

// ── the append rule: ONE signature check and nothing else (spec §4.1) ────────────────────────
case 'append':
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') out(['error' => 'POST required'], 405);
    // ⏭ the operator's own policy — a price, an account, a rate limit — hooks in here (spec §4.5).
    //    ⚠ The protocol defines no price, no currency and no settlement (§3.4-0b).
    $appender = new Appender($store, $registry, $policy['append'] ?? null);
    if ($packedIn) {
        // genesis in the query; body = LP(entry) ‖ LP(pubkey) ‖ LP(signature)
        [$entry, $pk, $sig] = $fields(file_get_contents('php://input') ?: '', 3);
        $r = $appender->append($unhex((string)($_GET['genesis'] ?? ''), 32), $entry, $pk, $sig);
        if (!$r->ok) out(['error' => $r->error], $r->status);
        if ($packedOut) outBytes(pack('N', $r->seq), 201, ['X-Seq' => $r->seq, 'X-Tree-Size' => $store->size()]);
        out(['seq' => $r->seq, 'tree_size' => $store->size(), 'root' => $hex($store->root())], 201);
    }
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($in)) out(['error' => 'body must be JSON'], 400);
    foreach (['genesis', 'entry', 'pubkey', 'signature'] as $k)
        if (!isset($in[$k]) || !is_string($in[$k])) out(['error' => "missing $k"], 400);
    $r = $appender->append($unhex($in['genesis'], 32), $unhex($in['entry']),
                           $unhex($in['pubkey']), $unhex($in['signature']));
    if (!$r->ok) out(['error' => $r->error], $r->status);
    out(['seq' => $r->seq, 'tree_size' => $store->size(), 'root' => $hex($store->root())], 201);

default:
    // ⚠ `spec` is always the CURRENT document; `spec_version` says which that is, and every superseded
    //    version stays fetchable at its own URL. A specification that can be silently replaced has the
    //    same defect as a service that can.
    out(['log' => 'jetmora',
         'spec' => 'https://jetmora.org/spec/log.md',
         'spec_version' => '0.1.1',
         'spec_versions' => ['0.1.1' => 'https://jetmora.org/spec/log.md',
                             '0.1'   => 'https://jetmora.org/spec/log-v0.1.md'],
         'protocol_version' => 1,   // ⚠ NOT the document version — see spec §6b
         'ops' => ['info', 'head', 'inclusion', 'consistency', 'entry', 'entries', 'tip', 'genesis', 'register', 'append', 'port']]);
}
