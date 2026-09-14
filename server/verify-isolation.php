<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE WALLET'S CHAIN BOUNDARY, CHECKED RATHER THAN TRUSTED ─────────────────────────────────────────
//
// His call, 7 Sept: *"The wallet will have two interfaces. One is for jetmora and the other needs to
// talk to BSV. So under the hood but isolated are two sets of code. One for each chain."*
//
// ⚠⚠⚠ WHY THIS IS A TEST AND NOT A CONVENTION. A boundary nobody checks is a boundary that drifts, and
// it drifts most easily in the direction of convenience — one helper, once, because it was right there.
// ⇒ This project has the scar: `page-script-isolation` was earned when the racers' physics went into a
//   file five other pages were built from. The fix was a TEST that pins the copy, not a resolution.
//
// ★★★ AND HERE THE BOUNDARY IS LOAD-BEARING THREE TIMES OVER:
//   1. ⚖ LICENCE — Open BSV v6 clause 2 restricts field of use to the BSV Blockchain. `"derived from"
//      goes murky the moment a helper crosses.` The directory boundary keeps the question ANSWERABLE.
//   2. 💥 BLAST RADIUS — a BSV fix must not be able to reach jetmora.
//   3. ✅ CORRECTNESS — jetmora entries are ed25519, BSV is secp256k1; even HD derivation differs
//      (BIP-32 is secp256k1-specific, ed25519 needs SLIP-0010).
//
// ★ THE RULE: **share what CANNOT disagree; isolate what CAN.**
declare(strict_types=1);

$root = __DIR__ . '/wallet';
$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}
function files(string $dir): array {
  return is_dir($dir) ? array_values(array_filter(glob("$dir/*.php") ?: [], 'is_file')) : [];
}

$jet    = files("$root/jetmora");
$bsv    = files("$root/bsv");
$shared = files("$root/shared");

echo "── the two sets ──\n";
printf("  jetmora %d file(s) · bsv %d file(s) · shared %d file(s)\n",
       count($jet), count($bsv), count($shared));

// ── 1. NEITHER SIDE MAY REQUIRE THE OTHER ───────────────────────────────────────────────────────────
echo "\n── no code crosses the boundary ──\n";
$crossed = [];
foreach ([[$jet, 'bsv', 'jetmora'], [$bsv, 'jetmora', 'bsv']] as [$set, $other, $side]) {
  foreach ($set as $f) {
    $src = file_get_contents($f);
    // ⚠⚠ MATCH THE DIRECTORY NAME ANYWHERE IN THE PATH, not just "wallet/bsv". A crossing is far more
    //   naturally written `__DIR__ . '/../bsv/address.php'` — and an earlier version of this check
    //   looked only for the long form, PASSED a deliberately planted crossing, and would have let the
    //   first real one through. Found by mutation testing, which is the only reason it is right now.
    if (preg_match('#(require|include)(_once)?[^;]*[/\'"]' . $other . '/#', $src))
      $crossed[] = basename($f) . " ($side) requires from $other/";
  }
}
ok($crossed === [], 'neither side requires from the other' . ($crossed ? ': ' . implode('; ', $crossed) : ''));

// ── 2. SHARED MAY NOT DEPEND ON EITHER CHAIN ────────────────────────────────────────────────────────
// ⚠ If it did, it would not be shared — it would be one chain's code with a misleading name.
$leaky = [];
foreach ($shared as $f) {
  $src = file_get_contents($f);
  if (preg_match('#(require|include)(_once)?[^;]*[/\'"](jetmora|bsv)/#', $src)) $leaky[] = basename($f);
}
ok($leaky === [], 'shared/ depends on neither chain' . ($leaky ? ': ' . implode(', ', $leaky) : ''));

// ── 3. NO CLASS FROM ONE SIDE IS NAMED IN THE OTHER ─────────────────────────────────────────────────
// ⚠ A require is the obvious crossing; naming a class is the quiet one, because it works the moment
//   something else happens to have loaded it.
function classesIn(array $fs): array {
  $out = [];
  foreach ($fs as $f)
    if (preg_match_all('/^\s*(?:final\s+)?class\s+(\w+)/m', file_get_contents($f), $m))
      $out = array_merge($out, $m[1]);
  return $out;
}
$jetClasses = classesIn($jet);
$bsvClasses = classesIn($bsv);
foreach ([[$jet, $bsvClasses, 'jetmora', 'BSV'], [$bsv, $jetClasses, 'bsv', 'jetmora']] as
         [$set, $names, $side, $label]) {
  $hits = [];
  foreach ($set as $f) {
    $src = preg_replace('!/\*.*?\*/|//[^\n]*!s', '', file_get_contents($f));   // ignore comments
    foreach ($names as $c) if (preg_match('/\b' . preg_quote($c, '/') . '\s*::/', $src)) $hits[] = "$c in " . basename($f);
  }
  ok($hits === [], "$side/ names no $label class" . ($hits ? ': ' . implode(', ', $hits) : ''));
}

// ── 4. ⚖ THE LICENCE BOUNDARY ───────────────────────────────────────────────────────────────────────
echo "\n── ⚖ licence ──\n";
$sdk = [];
foreach (array_merge($jet, $shared) as $f) {
  $src = preg_replace('!/\*.*?\*/|//[^\n]*!s', '', file_get_contents($f));     // a comment ABOUT it is fine
  if (str_contains($src, 'bsv/sdk')) $sdk[] = basename($f);
}
ok($sdk === [], 'no jetmora or shared file USES @bsv/sdk' . ($sdk ? ': ' . implode(', ', $sdk) : ''));

// ── 5. §2c-i ENFORCED BY ABSENCE ────────────────────────────────────────────────────────────────────
echo "\n── §2c-i ──\n";
require_once "$root/bsv/address.php";
require_once "$root/jetmora/address.php";
ok(!method_exists('Base58Check', 'encode'),
   '⛔ Base58Check has NO encode() — jetmora can read a Bitcoin address, never write one');
ok(method_exists('Base58Check', 'decode'), '...but it can decode one, which §2c needs');
// ★ and the property itself, once more, at the boundary rather than in the address suite
$a = JetAddress::encode(random_bytes(32));
ok(str_starts_with($a, 'j1') && !Base58Check::looksLikeBitcoinAddress($a),
   'a jetmora address starts j1 and does not parse as base58check');

// ── 6. ⛔ A base58check ENCODER NOW EXISTS. It must be unable to emit an ADDRESS. ────────────────────
// ⚠⚠ WIF and xprv need encoding, so `Base58KeyCodec` was added on the BSV side (8 Sept). ⇒ That is the
//   moment §2c-i could have been quietly weakened, so the property is re-checked rather than assumed:
//   the encoder REFUSES the four address version bytes, and the jetmora side cannot reach it at all.
echo "\n── ⛔ the new encoder cannot become an address writer ──\n";
require_once "$root/bsv/bip32.php";
$emitted = [];
foreach ([0x00, 0x05, 0x6f, 0xc4] as $v)
  try { Base58KeyCodec::encode(random_bytes(20), $v); $emitted[] = sprintf('0x%02x', $v); }
  catch (Throwable) { /* refused, as required */ }
ok($emitted === [], '⛔ the key encoder refuses every ADDRESS version byte'
                    . ($emitted ? ': emitted ' . implode(', ', $emitted) : ''));
// ★ and it is on the BSV side, so rule 1 above already forbids jetmora/ from requiring it — asserted
//   here explicitly so the reason survives if that rule is ever loosened.
$reach = [];
foreach ($jet as $f)
  if (str_contains(preg_replace('!/\*.*?\*/|//[^\n]*!s', '', file_get_contents($f)), 'Base58KeyCodec'))
    $reach[] = basename($f);
ok($reach === [], 'no jetmora file names the encoder at all' . ($reach ? ': ' . implode(', ', $reach) : ''));

// ── 7. ⚖ THE SDK-DERIVED VECTORS ARE TEST DATA, AND STAY THAT WAY ───────────────────────────────────
//
// His call, 8 Sept: *"frozen @bsv/sdk vectors can be isolated and still used for testing. It just won't
// exist in any future live code."*
//
// ★★★ AND THE POSITION IS STRONGER THAN "TOLERATED", which is worth writing down so nobody later
//   re-opens it as though it were a compromise:
//   1. **They are OUTPUT, not source.** Nothing was copied from `@bsv/sdk` — it was RUN, and the values
//      it printed were recorded. Running a program does not make its output a derivative of it.
//   2. **The values are FACTS, not authorship.** `phrase → WIF` is fixed by BIP-39 and BIP-32; every
//      conforming implementation prints the same bytes. There is no expressive choice to infringe.
//   3. **Even on a field-of-use reading, this IS the field.** Open BSV v6 clause 2 restricts use to the
//      BSV Blockchain, and these vectors exist solely to prove the BSV side of the wallet matches the
//      live BSV apps. ⛔ The clause bars jetmora — a non-BSV chain — which is why they must not cross.
//   ⇒ So the rule is not "hide them", it is **they are TEST DATA and never ship in live code.**
echo "\n── ⚖ the frozen SDK vectors stay test-only ──\n";
// ⚠⚠ GENERALISED 8 Sept: this named ONE file, so `sdk-signature-vectors.json` — frozen the same day,
//   from the same oracle, under the same reasoning — would have sat completely outside the guard.
//   ⇒ Cover every SDK-derived vector file, and FAIL if the list is empty (there are two today).
$sdkVectors = array_map('basename',
  // ⚠ Match the declared SOURCE, not any mention. `bip143-vectors.json` came from the BIP and only
  //   NAMES the SDK in prose — calling it SDK-derived would be a guard that lies about its own scope.
  array_filter(glob(__DIR__ . '/wallet/bsv/*-vectors.json') ?: [], function ($f) {
    $j = json_decode((string)file_get_contents($f), true);
    return is_array($j) && str_contains((string)($j['source'] ?? ''), '@bsv/sdk');
  }));
ok($sdkVectors !== [], '⚖ found the SDK-derived vector files: ' . (implode(', ', $sdkVectors) ?: 'NONE'));
$readers = [];
foreach ($sdkVectors as $vect) {
  foreach (glob(__DIR__ . '/*.php') ?: [] as $f)
    if (str_contains(file_get_contents($f), $vect)) $readers[] = basename($f);
  foreach (array_merge($jet, $bsv, $shared) as $f)
    if (str_contains(file_get_contents($f), $vect)) $readers[] = basename($f);
}
// ⚠ this file NAMES the string in order to search for it, so it is not itself a reader
$readers = array_values(array_unique(array_diff($readers, ['verify-isolation.php'])));
$nonTest = array_values(array_filter($readers, fn($n) => !str_starts_with($n, 'verify-')));
ok($nonTest === [],
   '⚖ ONLY verify-* files read the SDK-derived vectors — never live code'
   . ($nonTest ? ': ' . implode(', ', $nonTest) : ''));
// ⚠⚠ THE ANTI-VACUOUS GUARD. Without it this whole section passes when the vectors are DELETED, which
//   is the exact shape of failure that let `verify-isolation.php` pass for free once already.
ok($readers !== [],
   '...and at least one other test really does read them, so this is not passing vacuously');
// ⛔ and they must never reach the jetmora side, which is the half clause 2 actually bars
$crossed = [];
foreach ($jet as $f)
  foreach ($sdkVectors as $vect)
    if (str_contains(file_get_contents($f), $vect)) $crossed[] = basename($f);
ok($crossed === [], '⛔ no jetmora file reads them' . ($crossed ? ': ' . implode(', ', $crossed) : ''));

// ── 8. ⛔ THE ROOT FILES — the boundary's blind spot, closed ─────────────────────────────────────────
//
// ⚠⚠⚠ FOUND 8 Sept while answering *"the BSV and jetmora code follow different paths, correct?"*
//   The checks above police `wallet/{jetmora,bsv,shared}`. **`server/` ROOT IS OUTSIDE ALL OF THEM**,
//   and it holds two very different kinds of file:
//   | ✅ **genuinely shared** | `secp256k1.php`, `rfc6979.php` — *a curve cannot disagree*, so sharing is right |
//   | ⛔ **jetmora's ONLY** | `merkle.php`, `preimage.php`, `append.php`, and the rest of the chain |
//   ⇒ Nothing stopped a BSV file from requiring `merkle.php` and silently getting **RFC 6962 instead of
//     Bitcoin's tree** — which would MOSTLY WORK, and disagree exactly on the odd-node duplication and
//     the leaf prefixes. ★ "Share what cannot disagree; isolate what can" was being enforced one
//     directory too narrowly.
echo "\n── ⛔ server/ root: shared vs jetmora-only ──\n";
$SHARED_ROOT = ['secp256k1.php', 'rfc6979.php'];        // ⚠ the ONLY two. Adding to this is a decision.
$rootFiles = array_map('basename', glob(__DIR__ . '/*.php') ?: []);
$jetOnly = array_values(array_diff($rootFiles, $SHARED_ROOT,
             array_filter($rootFiles, fn($n) => str_starts_with($n, 'verify-'))));

$bad = [];
foreach ($bsv as $f) {
  $src = preg_replace('!/\*.*?\*/|//[^\n]*!s', '', file_get_contents($f));   // a mention in prose is fine
  foreach ($jetOnly as $j)
    if (preg_match('#(require|include)(_once)?[^;]*' . preg_quote($j, '#') . '#', $src))
      $bad[] = basename($f) . ' requires ' . $j;
}
ok($bad === [], '⛔ no BSV file requires a jetmora-only root file' . ($bad ? ': ' . implode('; ', $bad) : ''));

// ★ the anti-vacuous guard: the list must actually contain the dangerous ones
foreach (['merkle.php', 'preimage.php', 'append.php'] as $must)
  ok(in_array($must, $jetOnly, true), "★ $must is classed jetmora-only, so the check above can bite");
ok(!in_array('secp256k1.php', $jetOnly, true),
   '✅ ...while secp256k1.php is SHARED — a curve cannot disagree, and both sides legitimately use it');

// ⚠ and the two merkle trees really are different code, not two names for one thing
require_once __DIR__ . '/merkle.php';
require_once __DIR__ . '/wallet/bsv/spv.php';
$two = [bin2hex(hash('sha256', 'a', true)), bin2hex(hash('sha256', 'b', true))];
ok(bin2hex(mt_root([(string)hex2bin($two[0]), (string)hex2bin($two[1])])) !== MerkleProof::rootOf($two),
   '⛔ RFC 6962 and Bitcoin give DIFFERENT roots for the same two leaves — hence two files');

printf("\n%s  %d passed, %d failed   [wallet chain isolation]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
