<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// DIFFERENTIAL TEST: our secp256k1 against openssl, on the SAME inputs.
//
// ⚠⚠ WHY THIS EXISTS RATHER THAN A FIXED VECTOR FILE. `append.php` verified entry signatures through
// `openssl_verify` and now verifies them through `Secp256k1`. That swap is only safe if the two agree
// on EVERY case, not just on a signature someone chose. A fixed vector proves one point; this sweeps.
//
// ⚠⚠⚠ THE TRAP IT EXISTS TO CATCH, NAMED:
//   `openssl_verify($msg, $sig, $key, OPENSSL_ALGO_SHA256)` HASHES $msg INTERNALLY.
//   `Secp256k1::verifyDigest($sig, $pub, $digest32)` takes the digest ALREADY COMPUTED.
//   ⇒ Swapping one for the other without hashing at the call site fails EVERY existing signature —
//     and getting the direction backwards could make invalid signatures pass. Neither would look like
//     a bug in a green test suite; both are found by running the two side by side.
//
// ⚠ openssl is used HERE ONLY, as an oracle. Nothing in the chain core or `JF` depends on it.
//   ★ Same discipline as the acid test: an oracle you disagree with is informative; a dependency you
//   disagree with is a bug you inherit.
//
//   php server/verify-secp256k1.php            → 200 keypairs
//   php server/verify-secp256k1.php 1000       → more
declare(strict_types=1);
require_once __DIR__ . '/secp256k1.php';

if (!extension_loaded('gmp'))     { fwrite(STDERR, "⛔ ext-gmp required\n"); exit(2); }
if (!extension_loaded('openssl')) { fwrite(STDERR, "⚠ openssl absent — cannot run the oracle\n"); exit(2); }
if (!in_array('secp256k1', openssl_get_curve_names() ?: [], true)) {
  fwrite(STDERR, "⚠ this openssl has no secp256k1 — cannot run the oracle\n"); exit(2);
}

$N = isset($argv[1]) ? max(1, (int)$argv[1]) : 200;
$agree = 0; $disagree = []; $cases = 0;

/** the OLD path, verbatim from append.php before the swap */
function openssl_path(string $msg, string $pubkey, string $sig): bool
{
  $n = strlen($pubkey);
  if ($n !== 33 && $n !== 65) return false;
  $prefix = $n === 33
    ? "\x30\x36\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x22\x00"
    : "\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x42\x00";
  $pem = "-----BEGIN PUBLIC KEY-----\n"
       . chunk_split(base64_encode($prefix . $pubkey), 64, "\n") . "-----END PUBLIC KEY-----\n";
  $key = @openssl_pkey_get_public($pem);
  if ($key === false) return false;
  return openssl_verify($msg, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
}

/** the NEW path, exactly as append.php now calls it */
function ours_path(string $msg, string $pubkey, string $sig): bool
{
  return Secp256k1::verifyDigest($sig, $pubkey, hash('sha256', $msg, true));
}

function compare(string $label, string $msg, string $pub, string $sig): void
{
  global $agree, $disagree, $cases;
  $cases++;
  $a = openssl_path($msg, $pub, $sig);
  $b = ours_path($msg, $pub, $sig);
  if ($a === $b) { $agree++; return; }
  $disagree[] = sprintf('%s — openssl:%s ours:%s  pub=%s sig=%s',
    $label, var_export($a, true), var_export($b, true),
    substr(bin2hex($pub), 0, 16), substr(bin2hex($sig), 0, 16));
}

for ($i = 0; $i < $N; $i++) {
  $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
  $d = openssl_pkey_get_details($k);
  $x = str_pad($d['ec']['x'], 32, "\x00", STR_PAD_LEFT);
  $y = str_pad($d['ec']['y'], 32, "\x00", STR_PAD_LEFT);
  $comp   = chr(2 + (ord($y[31]) & 1)) . $x;
  $uncomp = "\x04" . $x . $y;
  $msg    = random_bytes(1 + random_int(0, 200));
  openssl_sign($msg, $sig, $k, OPENSSL_ALGO_SHA256);

  // ✅ the signature is genuine, both key encodings
  compare('valid/compressed',   $msg, $comp,   $sig);
  compare('valid/uncompressed', $msg, $uncomp, $sig);

  // ⛔ and every way of being wrong — a verifier that only agrees on VALID inputs is not verified
  $bm = $msg;  $bm[0]  = chr(ord($bm[0]) ^ 1);
  compare('tampered message',   $bm,  $comp, $sig);
  $bs = $sig;  $bs[10] = chr(ord($bs[10]) ^ 1);
  compare('tampered signature', $msg, $comp, $bs);
  $bk = $comp; $bk[9]  = chr(ord($bk[9]) ^ 1);
  compare('wrong key',          $msg, $bk,   $sig);
  compare('truncated der',      $msg, $comp, substr($sig, 0, 6));
  compare('empty signature',    $msg, $comp, '');
  compare('garbage der',        $msg, $comp, "\x30\x02\x00\x00");
  // ⚠ a sighash-type byte appended, which is what a Bitcoin signature carries
  compare('trailing byte',      $msg, $comp, $sig . "\x41");
}

foreach ($disagree as $d) echo "  ✗ $d\n";
printf("\n%s  %d of %d cases agree with openssl   (%d keypairs, 9 cases each)\n",
  $disagree ? '⚠' : '✅', $agree, $cases, $N);
exit($disagree ? 1 : 0);
