<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE SIGNING PATH IS SCHEME-AWARE, AND THE CHAIN'S OWN VERIFIER GRADES IT ─────────────────────────
//
// His call, 8 Sept: *"the wallet's signing path should become scheme-aware — yes that is important."*
//
// ★★★ THE GRADE THAT COUNTS: every signature here is checked with **`Appender::verifySignature`** —
//   the function that actually GATES an append (§4.1). ⇒ Verifying with our own verifier would prove
//   only self-consistency; a signature the CHAIN will not accept does not exist as far as jetmora is
//   concerned, however well-formed it looks.
//
// ⚠⚠ THE DIFFERENCE THIS EXISTS TO GET RIGHT:
//   | ed25519   | signs the MESSAGE — SHA-512 is internal to the scheme |
//   | secp256k1 | signs a 32-byte DIGEST — the caller hashes, and the wrong hash verifies nowhere |
//   ⇒ §4.0a: the append authorisation is *"over the ENTRY BYTES"* for both. **One rule, two mechanics.**
declare(strict_types=1);
require_once __DIR__ . '/append.php';
require_once __DIR__ . '/wallet/jetmora/signer.php';
require_once __DIR__ . '/wallet/bsv/signer.php';
require_once __DIR__ . '/wallet/shared/bip39.php';
require_once __DIR__ . '/wallet/jetmora/thread.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}

$entry = random_bytes(166);                       // an entry-shaped message
$mn    = Bip39::generate();
$seed  = Bip39::toSeed($mn);

// ── the jetmora side: ed25519, from a written-down phrase ────────────────────────────────────────────
echo "── jetmora · ed25519 ──\n";
$j    = JetmoraSigner::fromSeed($seed, "m/44'/0'/0'");
$jPub = $j->publicKey();
$jSig = $j->signEntry($entry);
ok(strlen($jPub) === 32, '★ the public key is 32 bytes RAW — what every live genesis authorises');
ok(strlen($jSig) === 64, 'the signature is 64 bytes');
ok(Appender::verifySignature($entry, $jPub, $jSig),
   "★★★ THE CHAIN'S OWN VERIFIER ACCEPTS IT — not ours, the one that gates an append");
ok(!Appender::verifySignature($entry . 'x', $jPub, $jSig), 'a changed entry is refused');
ok(JetmoraSigner::verify($entry, $jPub, $jSig), '...and our mirror agrees with it');
// ⚠ THE TRAP: pre-hashing for ed25519 gives a well-formed signature the chain refuses.
$wrong = Ed25519Sign::sign(hash('sha256', $entry, true), Slip10Ed25519::derive($seed, "m/44'/0'/0'")['key']);
ok(!Appender::verifySignature($entry, $jPub, $wrong),
   '⛔ pre-hashing for ed25519 produces a VALID-LOOKING signature the chain REFUSES — the trap named');
// ★ deterministic by construction: ed25519 has no k to get wrong
ok($j->signEntry($entry) === $jSig, '★ ed25519 is deterministic by construction — there is no k at all');

// ⚠ what a signer shows of itself, and what the trace of a refused path holds. The phrase's seed, the master node and
//   the signing key, as every run of 4 bytes: raw, in hex, and as a printed trace writes a string (a byte outside
//   ASCII as \xNN).
function traceEscaped(string $s): string {
  $named = ["\n" => '\\n', "\r" => '\\r', "\t" => '\\t', "\f" => '\\f', "\v" => '\\v', '\\' => '\\\\', "\e" => '\\e'];
  $out = '';
  foreach (str_split($s) as $c) $out .= $named[$c] ?? (ord($c) < 32 || ord($c) > 126 ? sprintf('\\x%02X', ord($c)) : $c);
  return $out;
}
/** Every string the arguments of a trace hold, at any depth, counting each SensitiveParameterValue in $hidden. */
function traceStrings(array $args, int &$hidden): array {
  $out = [];
  foreach ($args as $v) {
    if (is_array($v)) array_push($out, ...traceStrings($v, $hidden));
    elseif ($v instanceof SensitiveParameterValue) $hidden++;
    elseif (is_object($v)) $out[] = print_r($v, true);
    elseif (is_scalar($v)) $out[] = (string)$v;
  }
  return $out;
}
$master = Slip10Ed25519::master($seed);
$runs = [];
foreach ([$seed, $master['key'], $master['chain'], Slip10Ed25519::derive($seed, "m/44'/0'/0'")['key']] as $secret)
  for ($i = 0; $i + 4 <= strlen($secret); $i++) { $r = substr($secret, $i, 4); array_push($runs, $r, bin2hex($r), strtoupper(bin2hex($r)), traceEscaped($r)); }
$has = fn(string $text): bool => array_filter($runs, fn($r) => str_contains($text, $r)) !== [];
ob_start(); var_dump($j); $shown = ob_get_clean() . print_r($j, true);
ok(str_contains($shown, bin2hex($jPub)) && !$has($shown), 'var_dump() and print_r() of a signer show its public key, and nothing of its seed');
// the seed is held off the object: no dump of it, and no property of it, holds the seed
ob_start(); debug_zval_dump($j); $zval = ob_get_clean();
$props = '';
foreach ((new ReflectionObject($j))->getProperties() as $p) if (!$p->isStatic()) $props .= var_export($p->getValue($j), true);
$dumps = ['var_export' => var_export($j, true), '(array)' => var_export((array)$j, true), 'get_object_vars' => var_export(get_object_vars($j), true),
          'json_encode' => (string)json_encode($j), 'debug_zval_dump' => $zval, 'its properties by reflection' => $props];
ok(array_filter($dumps, $has) === [] && !(new ReflectionObject($j))->hasProperty('seed'),
   sprintf('%s of a signer: no run of 4 bytes of its seed in any, and it has no seed property', implode(', ', array_keys($dumps))));
/** The class of what $f throws, or 'nothing'. */
$throws = function (callable $f): string { try { $f(); return 'nothing'; } catch (Throwable $e) { return get_class($e); } };
$copy = 'O:13:"JetmoraSigner":1:{s:9:"publicKey";s:32:"' . str_repeat('x', 32) . '";}';
ok($throws(fn() => serialize($j)) === LogicException::class && $throws(fn() => unserialize($copy)) === LogicException::class,
   'serialize() of a signer, and unserialize() of one written by hand, each throw a LogicException');
$twin = clone $j;
ok($twin->publicKey() === $j->publicKey() && $twin->signEntry('a clone') === $j->signEntry('a clone'),
   'a clone signs with the same seed');
$store = (new ReflectionProperty(JetmoraSigner::class, 'seeds'))->getValue();
$before = count($store);
$k = JetmoraSigner::fromSeed($seed, "m/44'/0'/1'"); $with = count($store);
$kSig = $k->signEntry($entry); unset($k); $after = count($store);
ok($with === $before + 1 && $after === $before && Appender::verifySignature($entry, Slip10Ed25519::publicKey(Slip10Ed25519::derive($seed, "m/44'/0'/1'"), false), $kSig),
   "the seed is kept for as long as its signer lives and goes with it: $before held, $with with a second signer, $after once it is gone; the second signs");
// each refusal is made here, at the top level, so that its trace holds the wallet's frames and nothing of this file's.
// A node of the wrong shape is refused before hash_hmac() sees it: an error raised inside a PHP function would print
// that function's arguments, which cannot be marked.
$ignoreArgs = (string)ini_get('zend.exception_ignore_args'); $maxLen = (string)ini_get('zend.exception_string_param_max_len');
ini_set('zend.exception_ignore_args', '0'); ini_set('zend.exception_string_param_max_len', '1000000');
$refusals = [];
try { JetmoraSigner::fromSeed($seed, "m/0"); } catch (Throwable $e) { $refusals[] = $e; }
try { JetmoraSigner::fromSeed($seed, 'm/x'); } catch (Throwable $e) { $refusals[] = $e; }
try { Slip10Ed25519::master(substr($seed, 0, 15)); } catch (Throwable $e) { $refusals[] = $e; }
try { Slip10Ed25519::child($master, 0); } catch (Throwable $e) { $refusals[] = $e; }
$badNodes = [['key' => $master['key']], ['key' => $master['key'], 'chain' => null], ['key' => $master['key'], 'chain' => 7],
             ['key' => [$master['key']], 'chain' => $master['chain']], ['chain' => $master['chain']],
             ['key' => substr($master['key'], 0, 31), 'chain' => $master['chain']], ['key' => $master['key'], 'chain' => $master['chain'] . $master['key']]];
foreach ($badNodes as $node) try { Slip10Ed25519::child($node, Slip10Ed25519::HARDENED); } catch (Throwable $e) { $refusals[] = $e; }
ini_set('zend.exception_ignore_args', $ignoreArgs); ini_set('zend.exception_string_param_max_len', $maxLen);
$hidden = 0; $leaked = 0; $clean = 0;
foreach ($refusals as $e) {
  $hay = [(string)$e]; $h0 = $hidden;
  foreach ($e->getTrace() as $fr) array_push($hay, ...traceStrings($fr['args'] ?? [], $hidden));
  if (array_filter($hay, $has) !== []) $leaked++;
  if ($e instanceof Slip10Error && $hidden > $h0) $clean++;
}
$what = sprintf("a refused path, a short seed, a non-hardened index and %d nodes of the wrong shape (no 'chain', a null or int one, a 'key' that is an array, no 'key', a short 'key', a long 'chain'): %d refusals, %d of them a Slip10Error with a SensitiveParameterValue in its trace, traced with every argument kept; %d with a run of 4 bytes of the seed, a node or the key in a trace argument or the printed exception",
                count($badNodes), count($refusals), $clean, $leaked);
if (PHP_VERSION_ID < 80200 && $ignoreArgs === '1') printf("  - PHP %s has no #[\\SensitiveParameter]; zend.exception_ignore_args = 1 here keeps arguments out of every trace. Not counted as passed: %s\n", PHP_VERSION, $what);
else ok(count($refusals) === 4 + count($badNodes) && $clean === count($refusals) && $leaked === 0, $what);

// ── the BSV side: secp256k1 ─────────────────────────────────────────────────────────────────────────
echo "\n── bsv · secp256k1 ──\n";
$b    = BsvSigner::fromPrivateKey(random_bytes(32));
$bPub = $b->publicKey();
$bSig = $b->signEntry($entry);
ok(strlen($bPub) === 33, 'the public key is 33 bytes compressed');
ok(Appender::verifySignature($entry, $bPub, $bSig),
   "★★★ the chain's verifier accepts it too — the SAME function, the OTHER branch");
ok(!Appender::verifySignature($entry . 'x', $bPub, $bSig), 'a changed entry is refused');
ok(BsvSigner::verify($entry, $bPub, $bSig), '...and our mirror agrees');
// ⚠ THE MIRROR-IMAGE TRAP: signing the raw bytes as if they were a digest.
$bad = Secp256k1::sign(gmp_import(random_bytes(32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN),
                       hash('sha256', hash('sha256', $entry, true), true));
ok(!Appender::verifySignature($entry, $bPub, $bad),
   '⛔ a DOUBLE-hashed digest is refused — the wrong hash verifies nowhere and looks perfect');
ok($b->signEntry($entry) === $bSig, 'RFC 6979 makes it deterministic too — same bytes every time');
$der = Secp256k1::decodeDer($bSig);
$half = hex2bin('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0');   // (n − 1) / 2: 2s <= n
ok($der !== null && strcmp($der[1], $half) <= 0,
   '⚠ lowS defaults ON here — not a protocol rule, but a broadcaster can refuse high-s');

// ── ⛔ the two do not accept each other ──────────────────────────────────────────────────────────────
echo "\n── ⛔ the schemes do not cross ──\n";
ok(!Appender::verifySignature($entry, $jPub, $bSig), 'a secp256k1 signature under an ed25519 key: refused');
ok(!Appender::verifySignature($entry, $bPub, $jSig), 'an ed25519 signature under a secp256k1 key: refused');
ok(!JetmoraSigner::verify($entry, $bPub, $bSig), 'the jetmora verifier refuses a 33-byte key outright');

// ── ★ end to end: a phrase, a thread, a signature the chain accepts ──────────────────────────────────
echo "\n── ★ phrase → key → authorised thread → signature ──\n";
$auth = CovenantThread::authorisedHashes([$jPub]);
ok(CovenantThread::isAuthorised($auth, $jPub),
   '★ a genesis authorises the ed25519 key derived from the phrase (§4.2a v0x02: its sha256)');
ok(!str_contains($auth, $jPub), '⛔ ...and the key itself is not in the genesis');
$g = CovenantThread::create(hash('sha256', 'src', true), "\x51", '', $auth);
ok(strlen($g['id']) === 32, 'the thread exists');
// ⚠ the same phrase on another device reproduces the same key — which is the whole exit story
$again = JetmoraSigner::fromSeed(Bip39::toSeed($mn), "m/44'/0'/0'");
ok($again->publicKey() === $jPub,
   '★★★ the same phrase on another device gives the SAME KEY — the exit story, end to end');
ok(JetmoraSigner::fromSeed(Bip39::toSeed($mn, 'x'), "m/44'/0'/0'")->publicKey() !== $jPub,
   '⚠ ...and a passphrase gives an entirely different wallet');

printf("\n%s  %d passed, %d failed   [scheme-aware signing · graded by the CHAIN's verifier]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
