<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── CREATING A COVENANT THREAD, AND TICKING IT FORWARD ───────────────────────────────────────────────
//
// ★★★ This is the PRIMARY layer, and it has never been exercised before today. The first test chain
//   built the SECONDARY layer and called it a chain — see `verify-formats.php`, whose regression vector
//   is a real entry from it.
//
// ⚠ The preimage implementation is graded separately, and EXTERNALLY: `server/preimage.php` agrees
//   byte-for-byte with `tools/preimage.mjs` (the independent JS reference) on six input/output shapes.
declare(strict_types=1);
require_once __DIR__ . '/wallet/jetmora/thread.php';
require_once __DIR__ . '/secp256k1.php';
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

// ── creating the thread ─────────────────────────────────────────────────────────────────────────────
echo "── creating a thread (§2: the identity is DERIVED, never asserted) ──\n";
$d   = gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
$pub = Secp256k1::publicKey($d);
$script = "\x76\xa9\x14" . str_repeat("\x33", 20) . "\x88\xac";
$auth = CovenantThread::authorisedHashes([$pub]);
$g = CovenantThread::create(hash('sha256', 'the BASIC source', true), $script, "\x00\x01", $auth);
ok(strlen($g['id']) === 32, 'the genesis id is 32 bytes, SHA256d of the commitment');
$g2 = CovenantThread::create(hash('sha256', 'the BASIC source', true), $script, "\x00\x01", $auth);
ok($g2['id'] === $g['id'], 'identical content gives an identical id — idempotent by §2');
$g3 = CovenantThread::create(hash('sha256', 'the BASIC source', true), $script, "\x00\x02", $auth);
ok($g3['id'] !== $g['id'], '...and differing content is a DIFFERENT chain, never an equivocation');
refuses(fn() => CovenantThread::create('', '', '', $auth), 'no script is not a covenant',
        'a covenant with no script is refused');

// ── ⛔ the authorised set holds HASHES, not keys ─────────────────────────────────────────────────────
echo "\n── ⛔ §4.2a v0x02: the keys are HASHED ──\n";
ok(ord($auth[0]) === CovenantThread::AUTH_V2_HASHES, 'version byte is 0x02');
ok(!str_contains($auth, $pub), '⛔ THE PUBLIC KEY IS NOT IN THE GENESIS — not greppable, not a search key');
ok(str_contains($auth, hash('sha256', $pub, true)), '...its sha256 is');
ok(CovenantThread::isAuthorised($auth, $pub), 'the real key is recognised as authorised');
$other = Secp256k1::publicKey(gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN));
ok(!CovenantThread::isAuthorised($auth, $other), 'another key is not');
// ⚠ k-of-n is the multi-party case, which is why sha256 and not hash160
$keys = array_map(fn() => Secp256k1::publicKey(gmp_import(random_bytes(32),1,GMP_MSW_FIRST|GMP_BIG_ENDIAN)), range(1,5));
$kof = CovenantThread::authorisedHashes($keys, 3);
ok(ord($kof[1]) === 3 && ord($kof[2]) === 5, 'k-of-n packs k and n (3-of-5)');
ok(CovenantThread::isAuthorised($kof, $keys[4]), 'any member of the set is authorised');
$sorted = true; $o = 3; $prev = '';
for ($i = 0; $i < 5; $i++) { $len = ord($kof[$o]); $o++; $h = substr($kof,$o,$len); $o += $len;
  if ($prev !== '' && strcmp($h, $prev) <= 0) $sorted = false; $prev = $h; }
ok($sorted, '⚠ hashes ASCENDING — [a,b] and [b,a] must not be different covenants');
// ★ and it still reads the legacy form, because existing records stay valid
$v1 = "\x01\x01\x01" . chr(strlen($pub)) . $pub;
ok(CovenantThread::isAuthorised($v1, $pub), '★ 0x01 (keys in the clear) still READS — old records stay valid');
ok(CovenantThread::isAuthorised(CovenantThread::AUTH_OPEN, $other), "the literal 'open' authorises anyone");

// ── ticking it forward ──────────────────────────────────────────────────────────────────────────────
echo "\n── ticking the thread forward ──\n";
$tipLocking = $script;
$tipValue   = pack('P', 0);                       // ⚠ §3: value MAY be zero
$successor  = [['value' => 0, 'locking' => "\x76\xa9\x14" . str_repeat("\x44", 20) . "\x88\xac"]];
$seenPreimage = null;
$t = CovenantThread::tick($g['id'], 0, $tipLocking, $tipValue, $successor, 1,
      function (string $pre) use (&$seenPreimage) {
        $seenPreimage = $pre;
        // ★ OP_PUSH_TX: the preimage is PUSHED, and the covenant's CHECKSIG proves it is genuine
        return "\x4e" . pack('V', strlen($pre)) . $pre;
      });
ok($seenPreimage !== null, 'the builder receives the preimage before the unlocking script exists');
ok(strlen($seenPreimage) === 182, sprintf('the preimage is %d bytes (BIP143 layout)', strlen($seenPreimage)));
ok(str_contains($t['bytes'], $seenPreimage), '★ the preimage is carried IN the unlocking script — OP_PUSH_TX');
ok(strlen($t['bytes']) > 181, sprintf('the entry is %d bytes — it carries a script, unlike the old 84', strlen($t['bytes'])));
$rt = CovenantEntry::decode($t['bytes']);
ok($rt['inputs'][0]['sequence'] === 1, '⚠ nSequence IS the tick index (§6.3) — time never comes from a clock');
ok($rt['version'] === version_build('JF', 1), 'the entry names a FAMILY version, not legacy 103');

// ⚠⚠ THE PROPERTY THE WHOLE ORDERING RESTS ON
$t2 = CovenantThread::tick($g['id'], 0, $tipLocking, $tipValue, $successor, 1,
        fn(string $pre) => "\x4e" . pack('V', strlen($pre)) . $pre . str_repeat("\x51", 40));
ok($t2['preimage'] === $t['preimage'],
   '★★★ a DIFFERENT unlocking script gives the SAME preimage — which is why ticking is not circular');
ok($t2['bytes'] !== $t['bytes'], '...while the entry bytes differ, as they must');

echo "\n── ⛔ a tick cannot degenerate into a log row ──\n";
refuses(fn() => CovenantThread::tick($g['id'], 0, $tipLocking, $tipValue, $successor, 1, fn($p) => ''),
        'proves nothing is a LOG RECORD', 'an empty unlocking script is refused');
refuses(fn() => CovenantThread::tick($g['id'], 0, '', $tipValue, $successor, 1, fn($p) => "\x51"),
        'that is a LOG RECORD', 'a tip with no locking script is refused');
refuses(fn() => CovenantThread::tick($g['id'], 0, $tipLocking, $tipValue, [], 1, fn($p) => "\x51"),
        'at least one successor', 'a tick that produces nothing is refused');
refuses(fn() => CovenantThread::tick(str_repeat("\x00", 31), 0, $tipLocking, $tipValue, $successor, 1, fn($p)=>"\x51"),
        'must be 32 bytes', 'a malformed tip reference is refused');

// ── ⚠ the two signatures, and they are not the same thing (§4.0a) ───────────────────────────────────
echo "\n── ⚠ TWO signatures, and a wallet makes BOTH ──\n";
$covSig = Secp256k1::sign($d, hash('sha256', hash('sha256', $t['preimage'], true), true));
ok(Secp256k1::verifyDigest($covSig, $pub, hash('sha256', hash('sha256', $t['preimage'], true), true)),
   'the COVENANT signature is over the PREIMAGE — a verifier’s concern, and the chain must not check it');
$appendSig = Secp256k1::sign($d, CovenantThread::appendSighash($t['bytes']));
ok(Secp256k1::verifyDigest($appendSig, $pub, CovenantThread::appendSighash($t['bytes'])),
   'the APPEND signature is over the ENTRY BYTES — the chain’s only concern (§4.1)');
ok($covSig !== $appendSig, '⛔ they are DIFFERENT signatures over DIFFERENT things — conflating them puts an interpreter in the chain');

printf("\n%s  %d passed, %d failed   [covenant thread: create · tick]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
