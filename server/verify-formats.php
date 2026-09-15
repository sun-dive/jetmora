<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── TWO LAYERS, TWO FORMATS, AND THEY MUST NOT BE CONFUSABLE ─────────────────────────────────────────
//
// His design, 31 Aug: **covenant chain = the DESIGN object · log record = the STORAGE object.**
// His call, 7 Sept: *"jetmora does have a real log layer as well as the covenant layer... It is a
// secondary part of the design, not the primary."* — and *"split the two and name them clearly to
// avoid future confusion."*
//
// ⚠⚠⚠ THE REGRESSION TEST AT THE HEART OF THIS FILE is a REAL ENTRY from the first test chain, pinned
//   as hex so it survives that database being deleted. It parsed as a covenant entry for two weeks. It
//   must never parse as one again.
declare(strict_types=1);
require_once __DIR__ . '/covenant-entry.php';
require_once __DIR__ . '/log-record.php';
require_once __DIR__ . '/dispatch.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}
function refuses(callable $f, string $needle, string $what): void {
  try { $f(); ok(false, "$what — DID NOT REFUSE"); }
  catch (Throwable $e) { ok(str_contains($e->getMessage(), $needle), $what . ' — ' . $e->getMessage()); }
}

// ── ⛔⛔⛔ THE ENTRY THAT WAS NEVER A COVENANT ───────────────────────────────────────────────────────
// Seq 1 of the first test chain, verbatim. Parsed to the byte it reads:
//   version 103 · inputs 1 · unlocking 0 BYTES · outputs 1 · locking 24 bytes of STATE · locktime 0
// ⇒ No signature, no OP_PUSH_TX preimage, no proof the transition was permitted. A previous hash, a
//   counter, a value and some state — a LOG ROW, and a perfectly good one. It was called a chain.
const DEAD_CHAIN_ENTRY =
  '6700000001fc913efabc8d9e0d1aec4d2cd97e9ecc5c459c669b60788b44a9aeb0ac707f35'
. '0000000000010000000128bf000000000000180208000000005ed69b2d000000008e891b4200000000bf2800000000';

echo "── ⛔ the first chain's entries must never parse as covenant entries again ──\n";
refuses(fn() => CovenantEntry::decode(hex2bin(DEAD_CHAIN_ENTRY)),
        'no unlocking script', 'a real 84-byte entry from the dead chain is REFUSED');
refuses(fn() => LogRecord::decode(hex2bin(DEAD_CHAIN_ENTRY)),
        'missing the JLR magic', '...and it is not a well-formed log record either');
ok(strlen(hex2bin(DEAD_CHAIN_ENTRY)) === 84, 'it is 84 bytes; a §3-conformant entry needs 181 minimum');

// ── a real covenant entry ───────────────────────────────────────────────────────────────────────────
echo "\n── the covenant entry — the DESIGN object ──\n";
$entry = [
  'version'  => version_build('JF', 2),
  'inputs'   => [['prevEntry' => str_repeat("\x11", 32), 'index' => 0,
                  'unlocking' => "\x47" . str_repeat("\x30", 0x47),   // a signature-shaped push
                  'sequence' => 7]],
  'outputs'  => [['value' => 0, 'locking' => "\x76\xa9\x14" . str_repeat("\x22", 20) . "\x88\xac"]],
  'locktime' => 0,
];
$bytes = CovenantEntry::encode($entry);
$back  = CovenantEntry::decode($bytes);
ok($back['inputs'][0]['unlocking'] === $entry['inputs'][0]['unlocking'], 'round-trips its unlocking script');
ok($back['outputs'][0]['locking']  === $entry['outputs'][0]['locking'],  'round-trips its locking script');
ok($back['version'] === $entry['version'], 'round-trips a FAMILY nVersion, not legacy 103');
ok(strlen($bytes) >= 100, sprintf('it is %d bytes — it carries a script, so it cannot be 84', strlen($bytes)));

echo "\n── ⛔ and the shape that produced the first chain is now unrepresentable ──\n";
$noUnlock = $entry; $noUnlock['inputs'][0]['unlocking'] = '';
refuses(fn() => CovenantEntry::encode($noUnlock), 'NO UNLOCKING SCRIPT', 'encode refuses an empty unlocking script');
$noLock = $entry; $noLock['outputs'][0]['locking'] = '';
refuses(fn() => CovenantEntry::encode($noLock), 'NO LOCKING SCRIPT', 'encode refuses an empty locking script');
refuses(fn() => CovenantEntry::encode(['version'=>1,'inputs'=>[],'outputs'=>[['value'=>0,'locking'=>"\x51"]],'locktime'=>0]),
        'at least one previous entry', 'encode refuses an entry that consumes nothing');
refuses(fn() => CovenantEntry::encode(array_merge($entry, ['locktime' => 1])),
        'nLocktime MUST be 0', 'encode refuses a non-zero locktime (§3)');
// ⚠ canonical serialization: one byte string per entry, or OP_PUSH_TX is not secure
refuses(fn() => CovenantEntry::decode($bytes . "\x00"), 'trailing bytes', 'decode refuses trailing bytes');

// ── the log record ──────────────────────────────────────────────────────────────────────────────────
echo "\n── the log record — the STORAGE object, SECONDARY ──\n";
$cid = LogRecord::chainId(str_repeat("\xaa", 32), str_repeat("\x00", 32));
ok(strlen($cid) === 32, 'chainId = HASH256(genesis ‖ branch); a static covenant has branch = zeroes');
foreach ([LogRecord::KIND_INPUT, LogRecord::KIND_OUTPUT, LogRecord::KIND_ERROR] as $k) {
  $r = LogRecord::encode($cid, str_repeat("\x00", 32), 0, 1757260000, $k, 'payload bytes');
  $d = LogRecord::decode($r);
  ok($d['kind'] === $k && $d['payload'] === 'payload bytes', "round-trips the {$d['kindName']} kind");
}
// ★★ ERRORS LIVE HERE. That is the resolution of §4.3: a refusal is a fact worth keeping, and it is
//    NOT a link in the chain.
$err = LogRecord::decode(LogRecord::encode($cid, str_repeat("\x00",32), 3, 1757260001,
                          LogRecord::KIND_ERROR, 'covenant refused: value below the floor'));
ok($err['kindName'] === 'error', '★ an ERROR is a first-class log record — §4.3 resolved');
refuses(fn() => LogRecord::encode($cid, str_repeat("\x00",32), 0, 0, 0x99, ''), 'input, output or error',
        'refuses an unknown kind');
refuses(fn() => LogRecord::decode(LogRecord::encode($cid, str_repeat("\x00",32),0,0,LogRecord::KIND_INPUT,'x') . 'junk'),
        'trailing or truncated', 'refuses trailing bytes');

// ── ⛔⛔ THE TWO MUST REFUSE EACH OTHER ──────────────────────────────────────────────────────────────
echo "\n── ⛔ the two layers cannot be confused ──\n";
$rec = LogRecord::encode($cid, str_repeat("\x00", 32), 1, 1757260000, LogRecord::KIND_INPUT, 'in');
refuses(fn() => CovenantEntry::decode($rec), '', 'a log record is REFUSED by the covenant decoder');
refuses(fn() => LogRecord::decode($bytes), 'missing the JLR magic',
        'a covenant entry is REFUSED by the log decoder');

// ★★ and the magic can never be a valid nVersion, which is WHY they cannot collide
$asVersion = unpack('V', LogRecord::MAGIC)[1];
try { version_parse($asVersion); ok(false, 'JLR magic must not parse as a version'); }
catch (Throwable $e) { ok(true, sprintf('the JLR magic (0x%08x) is not a legal nVersion — %s',
                                        $asVersion, $e->getMessage())); }

printf("\n%s  %d passed, %d failed   [two layers: covenant entry · log record]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
