<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── ONLY THE TIP CAN BE TICKED FORWARD, AND THE SCRIPT DECIDES (§4.4, spec §3.3) ─────────────────────
//
// Only the tip can be ticked forward by spending its output. Once spent, there is no output to spend, and a
// second attempt is rejected (409): the operator never adjudicates between two entries at one sequence,
// because there is nothing to adjudicate. Each tick is judged as a node judges a spend: the output it spends
// must exist, and that output's script, run against the tick, decides. A tick the script refuses is not
// recorded (422), and nor is a tick this host cannot judge (501).
//
// Over HTTP, against a docroot staged by running .cpanel.yml's thread-service lines, so a file the deploy
// leaves out fails here. The thread is the BASIC covenant of basic/test/thread.mjs (signed by the owner,
// value + 1, the same script), compiled by basic/basic-jf.mjs; its ticks are built and signed here. Needs node.
// Signing is not under test: ext/sodium signs, or on a PHP without it ed25519-sign.php, so `php -n -d
// extension=pdo_sqlite` stages a service with neither sodium nor gmp. Ed25519 signing is deterministic, and
// verify-ed25519-sign.php holds the two to the same bytes.
//   php server/verify-tip.php
declare(strict_types=1);

// A writer in the race below: one append through the staged service's own files, at the instant given.
if (($argv[1] ?? '') === 'race-worker') {
  [, , $threads, $dbFile, $gid, $tickHex, $pkHex, $sigHex, $at] = $argv;
  require_once "$threads/append.php";
  $pdo = new PDO('sqlite:' . $dbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
  $pdo->exec('PRAGMA busy_timeout=10000');
  $ap = new Appender(new ThreadStore($dbFile), new GenesisRegistry($pdo));
  while (microtime(true) < (float)$at) usleep(200);
  echo $ap->append(hex2bin($gid), hex2bin($tickHex), hex2bin($pkHex), hex2bin($sigHex))->status;
  exit(0);
}

require_once __DIR__ . '/wallet/jetmora/thread.php';
require_once __DIR__ . '/jf-asm.php';
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';
require_once __DIR__ . '/append.php';
require_once __DIR__ . '/secp256k1.php';
require_once __DIR__ . '/ed25519-sign.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ⚠ One folder per run, removed on every exit, and the server stopped with it: a pass, a failure, a thrown
//   error or an interrupt.
$dir = sys_get_temp_dir() . '/jetmora-tip-' . bin2hex(random_bytes(4));
mkdir($dir, 0700);
$server = null;
register_shutdown_function(function () use ($dir, &$server) {
  if (is_resource($server)) { proc_terminate($server); proc_close($server); }
  $all = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                                       RecursiveIteratorIterator::CHILD_FIRST);
  foreach ($all as $f) $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
  @rmdir($dir);
});
if (function_exists('pcntl_async_signals')) {
  pcntl_async_signals(true);
  foreach ([SIGINT, SIGTERM, SIGHUP] as $sig) pcntl_signal($sig, fn() => exit(1));
}

echo "── the docroot, staged as .cpanel.yml deploys it ──\n";
$repo = dirname(__DIR__);
$home = "$dir/home";
$docroot = "$home/jetmora.org";
mkdir($home, 0700);
// Every deploy line that builds the thread service: what it copies into threads/, and the database folder
// beside the docroot. Run as cPanel runs them, from the repository, with HOME and DEPLOYPATH in the folder.
$lines = [];
foreach (file("$repo/.cpanel.yml", FILE_IGNORE_NEW_LINES) ?: [] as $l)
  if (preg_match('#^\s*-\s+(/bin/(?:mkdir|cp)\s.*)$#', $l, $m)
      && (str_contains($m[1], '$DEPLOYPATH/threads') || str_contains($m[1], '$HOME/jetmora-data')))
    $lines[] = $m[1];
$bad = [];
foreach ($lines as $cmd) {
  $p = proc_open(['/bin/sh', '-c', $cmd], [1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes, $repo,
                 ['HOME' => $home, 'DEPLOYPATH' => "$docroot/", 'PATH' => '/usr/bin:/bin']);
  $err = stream_get_contents($pipes[2]); fclose($pipes[2]);
  if (proc_close($p) !== 0) $bad[] = trim((string)$err) ?: $cmd;
}
ok(count($lines) > 3 && $bad === [] && is_file("$docroot/threads/index.php"),
   sprintf('%d lines of .cpanel.yml stage the thread service%s', count($lines), $bad ? ': ' . implode('; ', $bad) : ''));

// The service and the writers run as this PHP does: under php -n they get -n and the extensions loaded here, so a
// run without gmp stages a host without gmp.
$php = [PHP_BINARY];
if (php_ini_loaded_file() === false) {
  $php[] = '-n';
  foreach (get_loaded_extensions() as $e)
    if (is_file(ini_get('extension_dir') . '/' . strtolower($e) . '.so')) array_push($php, '-d', 'extension=' . strtolower($e));
}
if (in_array('-n', $php, true))
  printf("  - the service runs as %s: %s\n", implode(' ', array_slice($php, 1)),
         extension_loaded('sodium') ? 'with ext/sodium' : 'without ext/sodium, its test signatures made by ed25519-sign.php');
$sock = stream_socket_server('tcp://127.0.0.1:0');
$port = (int)substr((string)strrchr((string)stream_socket_get_name($sock, false), ':'), 1);
fclose($sock);
$server = proc_open([...$php, '-S', "127.0.0.1:$port", '-t', $docroot],
  [0 => ['file', '/dev/null', 'r'], 1 => ['file', "$dir/server.log", 'w'], 2 => ['file', "$dir/server.log", 'a']], $pp);
for ($k = 0, $c = false; $k < 100 && !($c = @fsockopen('127.0.0.1', $port, $en, $es, 0.1)); $k++) usleep(50_000);
if ($c) fclose($c);

/** One request to the staged service. @return array{status:int, body:string, json:mixed} */
function http(string $method, string $query, string $body = '', string $type = 'application/json',
              string $accept = 'application/json'): array
{
  global $port;
  $c = @fsockopen('127.0.0.1', $port, $en, $es, 5);
  if (!$c) return ['status' => 0, 'body' => "no connection: $es", 'json' => null];
  fwrite($c, "$method /threads/?$query HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: $type\r\nAccept: $accept\r\n"
           . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n$body");
  $raw = (string)stream_get_contents($c); fclose($c);
  [$head, $payload] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
  return ['status' => preg_match('#^HTTP/\S+ (\d{3})#', $head, $m) ? (int)$m[1] : 0,
          'body' => $payload, 'json' => json_decode($payload, true)];
}
$info = http('GET', 'op=info');
$dbPath = "$home/jetmora-data/log.db";
ok($info['status'] === 200 && is_file($dbPath), "the service answers ({$info['status']}), its database in jetmora-data beside the docroot");

echo "\n── the thread: the BASIC covenant, compiled ──\n";
// a keypair as libsodium lays it out, seed ‖ public key ‖ public key, and a signature by its 64-byte secret key
$sodium = extension_loaded('sodium');
$keypair = fn(string $seed): string => $sodium ? sodium_crypto_sign_seed_keypair($seed) : $seed . str_repeat(Ed25519Sign::publicKey($seed), 2);
$owner = $keypair(hash('sha256', 'the owner', true));
$other = $keypair(hash('sha256', 'somebody else', true));
$pub = fn(string $kp): string => substr($kp, 64);
$sk  = fn(string $kp): string => substr($kp, 0, 64);
$sign = fn(string $msg, string $kp): string => $sodium ? sodium_crypto_sign_detached($msg, $sk($kp)) : Ed25519Sign::sign($msg, $sk($kp));
$SRC = "VERSION JF 3\nDIM owner\$20";
$ownerHash = hash('ripemd160', hash('sha256', $pub($owner), true), true);
$js = 'const { pathToFileURL } = await import("node:url");'
    . 'const { compileCovenant } = await import(pathToFileURL(process.argv[1]));'
    . 'process.stdout.write(Buffer.from(compileCovenant(process.argv[2], { state: JSON.parse(process.argv[3]) }).bytes).toString("hex"))';
$p = proc_open(['node', '--input-type=module', '-e', $js, '--', "$repo/basic/basic-jf.mjs", $SRC,
                json_encode(['owner' => array_values(unpack('C*', $ownerHash))])],
               [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
$hex = trim((string)stream_get_contents($pipes[1])); $err = trim((string)stream_get_contents($pipes[2]));
fclose($pipes[1]); fclose($pipes[2]); proc_close($p);
$S = preg_match('/^([0-9a-f]{2})+$/', $hex) ? hex2bin($hex) : '';
ok($S !== '' && str_contains($S, $ownerHash), sprintf('the covenant compiles: %d bytes, the owner inside it%s', strlen($S), $S === '' ? " ($err)" : ''));
if ($S === '') { printf("\n⚠  %d passed · %d failed   [nothing to tick without the covenant]\n", $pass, $fail); exit(1); }

$h256 = fn(string $b): string => hash('sha256', hash('sha256', $b, true), true);
$push = fn(string $b): string => chr(strlen($b)) . $b;                // a jetForth direct push: the opcode is the length
$lp   = fn(string $b): string => pack('N', strlen($b)) . $b;
/** The unlocking script the covenant asks for: a signature over the preimage, by $kp, and its key. */
$signs = fn(string $kp): Closure => fn(string $pre): string => $push($sign($h256($pre), $kp)) . $push($pub($kp));
/** Register a thread of $script, its genesis authorising the owner's key (or $keys). Its genesis is its tip until the first tick. */
$thread = function (string $name, string $script, ?array $keys = null) use ($SRC, $owner, $pub): array {
  $r = http('POST', 'op=register', json_encode(['source_hash' => hash('sha256', $SRC), 'script' => bin2hex($script),
                                                'state' => bin2hex($name), 'authorised' => array_map('bin2hex', $keys ?? [$pub($owner)])]));
  $id = hex2bin((string)($r['json']['genesis'] ?? '')) ?: '';
  return ['id' => $id, 'tip' => $id, 'locking' => $script, 'n' => 0];
};
/** A tick spending output 0 of the thread's tip: value n to n + 1 and nSequence n + 1, the same script. */
$tickOf = function (array $t, string $kp, array $o = []) use ($signs): array {
  $n = $t['n'] + ($o['step'] ?? 1);
  return CovenantThread::tick($t['tip'], $o['index'] ?? 0, $t['locking'], pack('P', $t['n']),
                              $o['outputs'] ?? [['value' => $n, 'locking' => $t['locking']]], $o['seq'] ?? $n,
                              $o['unlock'] ?? $signs($kp), $o['version'] ?? null);
};
/** Append over JSON, the append signed by the owner, whose key the genesis authorises. */
$send = fn(array $t, string $bytes): array => http('POST', 'op=append', json_encode([
  'genesis' => bin2hex($t['id']), 'entry' => bin2hex($bytes), 'pubkey' => bin2hex($pub($owner)),
  'signature' => bin2hex($sign($bytes, $owner))]));
/** Send the next correct tick; the thread moves on when it lands. */
$advance = function (array &$t) use ($tickOf, $send, $owner): array {
  $k = $tickOf($t, $owner); $r = $send($t, $k['bytes']);
  if ($r['status'] === 201) { $t['tip'] = $k['hash']; $t['n']++; }
  return [$k, $r];
};
$count = fn(array $t): int => (int)(http('GET', 'op=tip&genesis=' . bin2hex($t['id']))['json']['count'] ?? -1);
$said = fn(array $r): string => "{$r['status']} " . (is_array($r['json']) ? ($r['json']['error'] ?? '') : trim($r['body']));
$store = new ThreadStore($dbPath);
$db = new PDO('sqlite:' . $dbPath, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec('PRAGMA busy_timeout=10000');

echo "\n── a thread, ticked forward ──\n";
$A = $thread('A', $S);
ok(strlen($A['id']) === 32, 'a thread of the covenant is registered');
[$t1, $r] = $advance($A);
ok($r['status'] === 201, 'the first tick spends the genesis output, and lands → ' . $said($r));
ok($store->tipHashOf($A['id']) === $t1['hash'], 'the store now holds HASH256 of that tick as the tip');
[$t2, $r2] = $advance($A);
[$t3, $r3] = $advance($A);
ok($r2['status'] === 201 && $r3['status'] === 201 && $count($A) === 3, 'two more land, each spending the output of the one before: three ticks');

echo "\n── ⛔ only the tip can be ticked forward ──\n";
// the second tick again, its signature in the STR8 push form: other bytes, and as valid
$again = CovenantThread::tick($t1['hash'], 0, $S, pack('P', 1), [['value' => 2, 'locking' => $S]], 2,
  fn(string $pre): string => chr(JF_LIT['STR8']) . chr(64) . $sign($h256($pre), $owner) . $push($pub($owner)));
ok($again['bytes'] !== $t2['bytes'] && CovenantThread::judge($again['entry'], 0, $S, pack('P', 1))['accepted'],
   'a different tick spending the output the second tick spent is built, and its script accepts it');
$r = $send($A, $again['bytes']);
ok($r['status'] === 409, 'once spent, there is no output to spend: the second attempt is rejected → ' . $said($r));
$r = $send($A, $t1['bytes']);
ok($r['status'] === 409, 'and the first tick sent again, as a stale page would, is rejected too → ' . $said($r));
ok($count($A) === 3, 'nothing was recorded: the thread still has three ticks');

echo "\n── ⛔ the script decides: a tick it refuses is not recorded ──\n";
$B = $thread('B', $S);
$r = $send($B, $tickOf($B, $other)['bytes']);
ok($r['status'] === 422 && isset($r['json']['reason']), 'signed for the covenant by somebody else → ' . $said($r) . ': ' . ($r['json']['reason'] ?? '?'));
ok($count($B) === 0, 'nothing was recorded');
$C = $thread('C', $S);
$r = $send($C, $tickOf($C, $owner, ['step' => 2])['bytes']);
ok($r['status'] === 422 && isset($r['json']['reason']), 'a value skipped, 0 → 2 → ' . $said($r));
ok($count($C) === 0, 'nothing was recorded');
$D = $thread('D', $S);
$r = $send($D, $tickOf($D, $owner, ['index' => 1])['bytes']);
ok($r['status'] === 422 && str_contains((string)($r['json']['error'] ?? ''), 'no output 1'), 'a first tick spending output 1 of a genesis that has one output → ' . $said($r));
ok($count($D) === 0, 'nothing was recorded');
$E = $thread('E', $S);
[, $r] = $advance($E);
ok($r['status'] === 201, 'a thread with one tick');
$r = $send($E, $tickOf($E, $owner, ['step' => 2])['bytes']);
ok($r['status'] === 422 && isset($r['json']['reason']), 'its next tick skipping a value, judged against the output in the tip\'s body → ' . $said($r));
$r = $send($E, $tickOf($E, $owner, ['index' => 1])['bytes']);
ok($r['status'] === 422 && str_contains((string)($r['json']['error'] ?? ''), 'no output 1'), 'a tick spending output 1 of a tip that has one output → ' . $said($r));
ok($count($E) === 1, 'nothing was recorded: one tick');

echo "\n── a refusal's reason is the script's own bytes ──\n";
$F = $thread('F', jf_asm('2DROP 1 (ABORT")$ff6e6f'));        // drops the push, then refuses with a reason that is not UTF-8
$tf = $tickOf($F, $owner, ['unlock' => fn(string $pre): string => "\x01\x01"]);
$r = $send($F, $tf['bytes']);
ok($r['status'] === 422 && is_array($r['json']), 'the refusal is JSON that parses → ' . $said($r));
ok(($r['json']['reason_hex'] ?? '') === bin2hex("ABORT: \xffno"), 'reason_hex carries the bytes exactly: ' . ($r['json']['reason_hex'] ?? '?'));
ok(($r['json']['reason'] ?? '') === "ABORT: \u{FFFD}no", 'reason carries the text, the byte that is not UTF-8 substituted');
$packed = http('POST', 'op=append&genesis=' . bin2hex($F['id']),
               $lp($tf['bytes']) . $lp($pub($owner)) . $lp($sign($tf['bytes'], $owner)),
               'application/octet-stream', 'application/octet-stream');
ok($packed['status'] === 422 && ($packed['json']['reason_hex'] ?? '') === bin2hex("ABORT: \xffno"),
   'the packed transport answers the refusal in the same JSON → ' . $said($packed));
ok($count($F) === 0, 'nothing was recorded');

echo "\n── ⛔ no verdict: nothing recorded ──\n";
$G = $thread('G', $S);
$two = ['version' => version_build('JF', 3), 'locktime' => 0, 'outputs' => [['value' => 1, 'locking' => $S]], 'inputs' => [
  ['prevEntry' => $G['id'], 'index' => 0, 'unlocking' => '', 'sequence' => 1],
  ['prevEntry' => str_repeat("\x07", 32), 'index' => 0, 'unlocking' => "\x01\x01", 'sequence' => 1]]];
$two['inputs'][0]['unlocking'] = $signs($owner)(Preimage::build($two, 0, $S, str_repeat("\x00", 8)));
$r = $send($G, CovenantEntry::encode($two));
ok($r['status'] === 501, 'a tick with two inputs, input 0 naming the tip → ' . $said($r));
ok($count($G) === 0, 'nothing was recorded');
$stale = $two;
$stale['inputs'][0]['prevEntry'] = $A['id'];                // A's genesis output, spent by A's first tick
$r = $send($A, CovenantEntry::encode($stale));
ok($r['status'] === 409 && $count($A) === 3, 'the same, input 0 naming an output already spent: rejected as spent, as a node would → ' . $said($r));
foreach ([['ZZ', 1, 'H'], ['JF', 2, 'I'], ['SV', 1, 'J']] as [$family, $revision, $name]) {
  $X = $thread($name, $S);
  $r = $send($X, $tickOf($X, $owner, ['version' => version_build($family, $revision)])['bytes']);
  ok($r['status'] === 501 && $count($X) === 0, "a tick naming $family revision $revision, nothing recorded → " . $said($r));
}
// the tip's body blanked, as ThreadStore::prune can, its tips row kept: the tip is known, its output is not held here
$K = $thread('K', $S);
[, $r] = $advance($K);
$db->prepare("UPDATE entries SET body = '' WHERE genesis = ?")->execute([$K['id']]);
$r = $r['status'] === 201 ? $send($K, $tickOf($K, $owner)['bytes']) : $r;
ok($r['status'] === 501 && $count($K) === 1, 'a tick spending a tip whose body is not held here, nothing recorded → ' . $said($r));
// a tip the store holds that is not a covenant entry: the store takes any bytes, only append.php decodes
$N = $thread('N', $S);
$junk = 'a tip stored without a covenant entry';
$store->append($junk, $N['id'], $N['id']);
$r = $send($N, $tickOf(['tip' => $h256($junk)] + $N, $owner)['bytes']);
ok($r['status'] === 501 && str_contains((string)($r['json']['error'] ?? ''), 'does not decode') && $count($N) === 1,
   'a tick spending a tip held here that does not decode, nothing recorded → ' . $said($r));

echo "\n── the checks before the script are kept ──\n";
$P = $thread('P', $S);
$tp = $tickOf($P, $owner);
$r = http('POST', 'op=append', json_encode(['genesis' => bin2hex($P['id']), 'entry' => bin2hex($tp['bytes']),
  'pubkey' => bin2hex($pub($other)), 'signature' => bin2hex($sign($tp['bytes'], $other))]));
ok($r['status'] === 403, 'appended under a key the genesis does not name → ' . $said($r));
$r = http('POST', 'op=append', json_encode(['genesis' => bin2hex($P['id']), 'entry' => bin2hex($tp['bytes']),
  'pubkey' => bin2hex($pub($owner)), 'signature' => bin2hex($sign('other bytes', $owner))]));
ok($r['status'] === 403, 'an append signature over other bytes → ' . $said($r));
ok($count($P) === 0, 'nothing was recorded');
$d = hash('sha256', 'a secp256k1 key', true);
$Q = $thread('Q', $S, [Secp256k1::publicKey($d)]);
$tq = $tickOf($Q, $owner);                                   // the covenant's own signature is still the owner's
$r = http('POST', 'op=append', json_encode(['genesis' => bin2hex($Q['id']), 'entry' => bin2hex($tq['bytes']),
  'pubkey' => bin2hex(Secp256k1::publicKey($d)), 'signature' => bin2hex(Secp256k1::sign($d, hash('sha256', $tq['bytes'], true)))]));
ok($r['status'] === 201 && $count($Q) === 1, 'appended under a secp256k1 key the genesis names, the script accepting the tick → ' . $said($r));

echo "\n── two writers, one tip: the check inside the write lock ──\n";
// Eight processes send the same first tick at one instant, each through the staged files. Those that pass the
// check before the script is run are stopped by the check inside the write lock: one tick is stored.
$R = $thread('R', $S);
$tr = $tickOf($R, $owner);
$at = sprintf('%.6f', microtime(true) + 0.5);
$ws = []; $wp = [];
for ($i = 0; $i < 8; $i++)
  $ws[$i] = proc_open([...$php, __FILE__, 'race-worker', "$docroot/threads", $dbPath, bin2hex($R['id']), bin2hex($tr['bytes']),
                       bin2hex($pub($owner)), bin2hex($sign($tr['bytes'], $owner)), $at],
                      [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $wp[$i]);
$st = [];
foreach ($ws as $i => $w) {
  $st[] = trim(stream_get_contents($wp[$i][1]) . stream_get_contents($wp[$i][2]));
  fclose($wp[$i][1]); fclose($wp[$i][2]); proc_close($w);
}
$landed = count(array_filter($st, fn($s) => $s === '200'));
$spent = count(array_filter($st, fn($s) => $s === '409'));
ok($landed === 1 && $spent === 7 && $count($R) === 1, "eight at once: $landed lands, $spent rejected as spent, " . $count($R) . ' stored'
   . ($landed === 1 && $spent === 7 ? '' : ' [' . implode(' | ', $st) . ']'));

echo "\n── the tip moves while a tick is judged ──\n";
$M = $thread('M', $S);
$first = $tickOf($M, $owner);
$rival = CovenantThread::tick($M['id'], 0, $S, pack('P', 0), [['value' => 1, 'locking' => $S]], 1,
  fn(string $pre): string => chr(JF_LIT['STR8']) . chr(64) . $sign($h256($pre), $owner) . $push($pub($owner)));
$store->checkTip($M['id'], $M['id']);                        // the rival passes the check before its script runs,
$r = $send($M, $first['bytes']);                             // the first tick lands,
$v = (new ReflectionMethod(Appender::class, 'judge'))->invoke(new Appender($store, new GenesisRegistry($db)), $M['id'], $rival['entry']);
ok($r['status'] === 201 && $v instanceof AppendResult && $v->status === 409,                // and then the rival is judged
   'the output it spends was spent meanwhile: rejected as spent (409), not "no verdict" → ' . ($v?->status ?? 'null') . ' ' . ($v?->error ?? ''));

echo "\n── reads still answer ──\n";
$hexes = array_map('bin2hex', [$t1['bytes'], $t2['bytes'], $t3['bytes']]);
$info = http('GET', 'op=info');
ok($info['status'] === 200 && ($info['json']['size'] ?? 0) >= 4, "info → {$info['status']}, size " . ($info['json']['size'] ?? '?'));
$ent = http('GET', 'op=entries&genesis=' . bin2hex($A['id']));
$rows = $ent['json']['entries'] ?? [];
$last = $rows ? $rows[count($rows) - 1]['seq'] : -1;
ok($ent['status'] === 200 && array_column($rows, 'entry') === $hexes && ($ent['json']['tip'] ?? null) === $last,
   "entries → {$ent['status']}: the three ticks, oldest first");
$seq1 = (int)($rows[0]['seq'] ?? -1);
$one = http('GET', "op=entry&seq=$seq1");
ok($one['status'] === 200 && ($one['json']['entry'] ?? '') === $hexes[0], "entry → {$one['status']}: the first tick");
$tip = http('GET', 'op=tip&genesis=' . bin2hex($A['id']));
ok($tip['status'] === 200 && ($tip['json']['count'] ?? 0) === 3 && ($tip['json']['tip'] ?? null) === $last, "tip → {$tip['status']}");
$gen = http('GET', 'op=genesis&id=' . bin2hex($A['id']));
ok($gen['status'] === 200 && ($gen['json']['script'] ?? '') === bin2hex($S), "genesis → {$gen['status']}: the covenant");

echo "\n── a thread from before tips were kept ──\n";
$forget = fn() => $db->prepare('DELETE FROM tips WHERE genesis = ?')->execute([$A['id']]);   // as an older database would be
$forget();
ok($store->tipHashOf($A['id']) === $t3['hash'], 'the tip is derived from the newest body when no row is kept');
ok($store->recordTips() === 1 && $store->tipHashOf($A['id']) === $t3['hash'], 'recordTips gives it a row from that body');
$forget();
$db->prepare('UPDATE entries SET ts = 1 WHERE genesis = ?')->execute([$A['id']]);            // every tick of it old enough to prune
ok($store->pruneOlderThan(60) === 2, 'pruning blanks the two bodies behind the tip');
ok($store->tipHashOf($A['id']) === $t3['hash'], '★ but first records the tip, so pruning never leaves it unknown');
$bodies = array_column($store->entriesOf($A['id']), 'body');
$kept = (string)end($bodies);
ok($bodies === ['', '', $t3['bytes']], '★ and keeps the tip whole: its unspent output is what the next tick spends');
$out = $kept === '' ? null : CovenantEntry::decode($kept)['outputs'][0];   // the output the next tick spends, read from the kept body
$t4 = $out === null ? null : CovenantThread::tick($h256($kept), 0, $out['locking'], $out['value'],
                                                  [['value' => 4, 'locking' => $out['locking']]], 4, $signs($owner));
$r = $t4 === null ? ['status' => 0, 'body' => 'no kept body', 'json' => null] : $send($A, $t4['bytes']);
ok($r['status'] === 201, 'and the thread ticks on from the kept tip, spending its output → ' . $said($r));

echo "\n── ⛔ a tip that is not known is never ticked ──\n";
$forget();
$db->prepare("UPDATE entries SET body = '' WHERE genesis = ?")->execute([$A['id']]);   // no row, newest body gone
ok($store->tipHashOf($A['id']) === null, 'with no row and the newest body pruned the tip is unknown');
$guess = $send($A, $tickOf(['tip' => str_repeat("\x42", 32), 'n' => 4] + $A, $owner)['bytes']);
ok($guess['status'] === 409, 'a tick naming anything is refused, never accepted once → ' . $said($guess));
ok($count($A) === 4, 'and nothing was recorded');

echo "\n── ⛔ every write path names the tip ──\n";
$threw = null; try { $store->append('a thread entry with no tip named', $A['id']); } catch (TipTickedException $e) { $threw = $e->getMessage(); }
ok($threw !== null, sprintf('the store refuses an entry of a thread that names no tip: "%s"', $threw));
$ported = http('POST', 'op=port', '{}');
ok($ported['status'] === 501 && str_contains((string)($ported['json']['error'] ?? ''), 'moving a thread to this host is not available yet'),
   'port is switched off until moving a thread is designed → ' . $said($ported));

if ($fail) echo "\n── the server's log, last lines ──\n", implode('', array_slice(file("$dir/server.log") ?: [], -12));
printf("\n%s  %d passed · %d failed   [only the tip can be ticked forward, and the script decides]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail ? 1 : 0);
