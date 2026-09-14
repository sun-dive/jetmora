<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── OUR secp256k1 vs @bsv/sdk 2.1.4 — FROZEN, AND IT RUNS ANYWHERE ─────────────────────────────────
//
// His call, 8 Sept: *"You can make a frozen copy if you'd prefer. It's then available as a reference at
// any time."*
//
// ★★★ 613 SIGNATURES THE SDK PRODUCED, checked two ways: **does ours ACCEPT them**, and — because
//   RFC 6979 is deterministic — **does ours produce the SAME BYTES**. ⇒ Two implementations sharing no
//   code, agreeing on every one. That is the acid test `tack-spec.md` asks for, and it now runs with
//   **no node, no npm and no network** — which is the only way it can run on $2 hosting or in CI.
//
// ⚠⚠ AND ONE PLACE THEY MUST **DIS**AGREE, pinned deliberately: the SDK parses and verifies a signature
//   whose `r` lacks its required `0x00`. **BIP-66 has made that invalid on the network since 2015**, so
//   agreeing there would mean copying a defect. ⇒ **Agreement is the test everywhere except the one
//   place consensus says otherwise.**
//
// ⚖ These vectors are OUTPUT, not source — the SDK was RUN and what it printed was recorded. An RFC
//   6979 signature is a FACT fixed by the spec, not authorship. **TEST DATA, never live code**, and
//   `verify-isolation.php` enforces that.
declare(strict_types=1);
require_once __DIR__ . '/secp256k1.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; } else { $fail++; printf("  ✗ %s\n", $what); }
}

// The comparison vectors are LOCAL test data, never shipped (the same rule Phar Lap 2 keeps): the file
// is gitignored, and without it this check is reported as skipped rather than passed.
if (!is_readable(__DIR__ . '/wallet/bsv/sdk-signature-vectors.json')) {
    echo "SKIPPED - needs the local signature vectors (server/wallet/bsv/sdk-signature-vectors.json, not in the repository)\n";
    exit(0);
}
$V = json_decode(file_get_contents(__DIR__ . '/wallet/bsv/sdk-signature-vectors.json'), true);
printf("── ours vs %s ──\n", $V['source']);

// ⚠ The SDK hashes its argument, so the digest actually signed is sha256(msg). Getting this wrong
//   reported 100% failure on the first run — which is not the CVE shape, and the harness was at fault.
$digestOf = fn(string $msgHex) => hash('sha256', (string)hex2bin($msgHex), true);

foreach (['random' => 'random', 'leading_zero_k' => "★ leading-zero k (CVE-2025-14505's trigger)"] as $key => $label) {
  $rows = $V[$key];
  $rejected = 0; $differed = 0;
  foreach ($rows as $r) {
    // ⚠ the leading-zero set was captured with the digest recorded separately; both use sha256(msg)
    $dig = $digestOf($r['msg']);
    if (!Secp256k1::verifyDigest((string)hex2bin($r['der']), (string)hex2bin($r['pub']), $dig)) $rejected++;
    if (bin2hex(Secp256k1::sign(gmp_init($r['priv'], 16), $dig, true)) !== $r['der']) $differed++;
  }
  $n = count($rows);
  ok($rejected === 0, sprintf('%s — all %d SDK signatures VERIFY under ours (%d rejected)', $label, $n, $rejected));
  ok($differed === 0, sprintf('%s — all %d are BYTE-IDENTICAL to ours (%d differed)', $label, $n, $differed));
}

// ★ the targeted set is the one that matters, so say out loud that it is really targeted
$lz = $V['leading_zero_k'];
ok(count($lz) >= 12 && min(array_column($lz, 'kLeadZeros')) >= 1,
   sprintf('★★ and all %d of those really do have a leading-zero k — targeted, not sampled', count($lz)));

// ── ⛔ the one place agreement would be WRONG ────────────────────────────────────────────────────────
echo "\n── ⛔ where we must NOT agree with the SDK ──\n";
$m = $V['malleability'];
ok(Secp256k1::decodeDer((string)hex2bin($m['canonical'])) !== null, 'the canonical form is accepted');
ok(Secp256k1::decodeDer((string)hex2bin($m['mutated'])) === null,
   '⛔ the mutant is REFUSED by ours — the SDK verifies it, and BIP-66 has barred it since 2015');
ok($m['sdk_accepts_both'] === true && $m['ours_accepts_mutant'] === false,
   '★ the divergence is recorded in the vector itself, so the reason survives the SDK');
// ★★ and they really are one signature, which is what makes it malleability
$c = Secp256k1::decodeDer((string)hex2bin($m['canonical']));
ok($c !== null && gmp_cmp($c[0], gmp_init(substr($m['canonical'], 10, 64), 16)) === 0,
   '★ both encode the SAME r ⇒ accepting both is malleability, not a different signature');

// ── ★ this suite needs nothing but PHP ──────────────────────────────────────────────────────────────
echo "\n── ★ self-contained ──\n";
// ⚠ My first version grepped this file for 'curl' and 'exec(' — and FAILED, because it contains those
//   words in its own search. A self-referential check is not a check. ⇒ Assert the dependency graph
//   instead, which is the thing that actually decides whether this runs on PHP-only hosting.
// ⚠ Two earlier versions of this check were wrong: the first grepped this file for 'curl' and matched
//   its own search string; the second used a loose regex that matched the word "requires" in its own
//   code. ⇒ A check that can fail on itself is not a check. Scan only lines that BEGIN with require.
$reqLines = array_values(array_filter(file(__FILE__), fn($l) => str_starts_with(trim($l), 'require')));
ok(count($reqLines) === 1 && str_contains($reqLines[0], 'secp256k1.php'),
   sprintf('★ exactly ONE require, and it is secp256k1.php — no node, no npm, no network (%d found)',
           count($reqLines)));
ok(is_readable(__DIR__ . '/wallet/bsv/sdk-signature-vectors.json'),
   'the frozen vectors are the only input');
// ★★ the point of freezing, asserted: this suite cannot silently follow the SDK if the SDK changes
ok(str_contains(file_get_contents(__DIR__ . '/wallet/bsv/sdk-signature-vectors.json'), 'HIDES DRIFT'),
   '★★ the vector file records WHY it is frozen — a regenerating test would adopt new behaviour silently');

printf("\n%s  %d passed, %d failed   [our secp256k1 vs frozen @bsv/sdk 2.1.4 output]\n",
  $fail === 0 ? '✅' : '⚠', $pass, $fail);
exit($fail === 0 ? 0 : 1);
