<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ SLIP-0010 — HD DERIVATION FOR ed25519 ════════════════════════════════════════════════════════════
//
// ★ THE JETMORA SIDE. jetmora entries are signed with ed25519 — every live genesis authorises a 32-byte
//   key — and **BIP-32 is secp256k1-specific**, so it cannot be used here. SLIP-0010 is the standard
//   that generalises HD derivation to other curves, and for ed25519 it is a different algorithm, not a
//   parameter change.
//
// ★★★ HARDENED ONLY, AND THAT IS THE POINT — his requirement, 7 Sept:
//   *"I think it is extremely important that hardened key derivation is used."*
//   ⇒ SLIP-0010 for ed25519 **cannot do non-hardened derivation at all**: *"Public key derivation
//     always fails for ed25519."* ⛔ So this is **ENFORCEMENT BY ABSENCE** — the same pattern as
//     `Base58Check` having no `encode()`. Nobody can weaken it later by choosing the convenient path,
//     because the path does not exist.
//   ★★ WHY IT MATTERS: with NON-hardened derivation, **one leaked child private key plus the parent
//     xpub reconstructs the parent private key.** That is BIP-32's sharpest edge, and it is removed
//     here structurally rather than by discipline.
//   ⚠ WHAT IT COSTS, stated rather than hidden: you cannot hand a third party an xpub and let them
//     generate your future identities. ⇒ Narrow, and there is a workaround (derive a batch, hand over
//     the public keys). On jetmora you do not solicit value by publishing an address for a stranger to
//     pay — a covenant is handed to you — so the pattern this loses is one jetmora does not use.
//
// ⚠⚠ TWO DIFFERENCES FROM BIP-32 THAT LOOK LIKE DETAILS AND ARE NOT:
//   1. **`k_i` is `I_L` DIRECTLY.** No `(IL + kpar) mod n`. ed25519 has no such arithmetic on keys, and
//      doing BIP-32's step here would produce keys that verify fine and match nobody.
//   2. **Every 32-byte string is a valid ed25519 key**, so the retry loop BIP-32 needs does not exist.
//
// ★ One seed → many keys → and each key holds a STRING (his term, 7 Sept: a user's set of threads).
//   ⇒ So a seed phrase does not recover one thread. It recovers **every string you own**, from any site
//     that has them.
declare(strict_types=1);

final class Slip10Error extends RuntimeException {}

final class Slip10Ed25519
{
  /** ⚠ The curve is named IN the HMAC key. Using BIP-32's "Bitcoin seed" here silently derives another
   *  wallet's keys — valid, verifiable, and nobody else's. */
  private const CURVE = 'ed25519 seed';
  public  const HARDENED = 0x80000000;

  /** @return array{key:string,chain:string} the master node from a BIP-39 seed */
  public static function master(string $seed): array
  {
    if (strlen($seed) < 16 || strlen($seed) > 64)
      throw new Slip10Error('a seed is 16 to 64 bytes; BIP-39 produces 64');
    $I = hash_hmac('sha512', $seed, self::CURVE, true);
    // ★ No validity check and none needed: *"for ed25519 every 32-byte sequence (even all zero) is a
    //   valid private key"*, so SLIP-0010's retry loop applies to the other curves, never this one.
    return ['key' => substr($I, 0, 32), 'chain' => substr($I, 32, 32)];
  }

  /**
   * One hardened step.
   * ⛔ REFUSES a non-hardened index — it is not unimplemented, it is IMPOSSIBLE for this curve, and
   *   saying so is more useful than a generic error.
   */
  public static function child(array $node, int $index): array
  {
    if ($index < self::HARDENED)
      throw new Slip10Error(sprintf(
        'index %d is not hardened. ed25519 has NO non-hardened derivation — SLIP-0010: "public key '
      . 'derivation always fails for ed25519". ⇒ Use %d\' (that is %d).',
        $index, $index, $index + self::HARDENED));
    if ($index > 0xffffffff) throw new Slip10Error('index must fit 32 bits');
    // ⚠ The 0x00 prefix is REQUIRED and is not padding: it is what distinguishes this from the
    //   public-key derivation the other curves have, and omitting it derives a different tree.
    $data = "\x00" . $node['key'] . pack('N', $index);
    $I = hash_hmac('sha512', $data, $node['chain'], true);
    // ★★ `k_i` IS `I_L`. ⛔ NOT `(IL + kpar) mod n` — that is BIP-32, and doing it here yields keys
    //    that verify perfectly and match no other wallet.
    return ['key' => substr($I, 0, 32), 'chain' => substr($I, 32, 32)];
  }

  /**
   * Derive down a path: `m`, `m/0'`, `m/44'/0'/0'`. ⚠ Apostrophe or `H` both mean hardened; a bare
   * number is REFUSED rather than silently hardened, because silently hardening would mean two wallets
   * reading one path differently.
   */
  public static function derive(string $seed, string $path): array
  {
    $node = self::master($seed);
    $path = trim($path);
    if ($path === '' || $path === 'm' || $path === 'm/') return $node;
    if (!str_starts_with($path, 'm/')) throw new Slip10Error('a path starts with "m/"');
    foreach (explode('/', substr($path, 2)) as $seg) {
      if ($seg === '') throw new Slip10Error("empty path segment in \"$path\"");
      $hard = str_ends_with($seg, "'") || str_ends_with($seg, 'H') || str_ends_with($seg, 'h');
      $num  = $hard ? substr($seg, 0, -1) : $seg;
      if (!ctype_digit($num)) throw new Slip10Error("not a path index: \"$seg\"");
      if (!$hard) throw new Slip10Error(
        "path segment \"$seg\" is not hardened. ed25519 derivation is hardened-only, and this is "
      . "refused rather than hardened for you — two wallets must not read one path differently.");
      $node = self::child($node, (int)$num + self::HARDENED);
    }
    return $node;
  }

  /**
   * The ed25519 public key for a node: **33 bytes, `0x00` then the point** — SLIP-0010's serialization.
   * ⚠ The leading zero keeps every curve's public key the same width; it is not part of the key.
   * ★ sodium's ed25519 is CONSTANT TIME, which our own PHP secp256k1 cannot be. ⇒ For the signing path
   *   specifically, not owning the code is an ADVANTAGE.
   */
  public static function publicKey(array $node, bool $withPrefix = true): string
  {
    if (!extension_loaded('sodium')) throw new Slip10Error('ext-sodium is required for ed25519');
    $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($node['key']));
    return $withPrefix ? "\x00" . $pub : $pub;
  }

  /** BIP-32's fingerprint rule, over SLIP-0010's 33-byte serialization: first 4 bytes of hash160. */
  public static function fingerprint(array $node): string
  {
    return substr(hash('ripemd160', hash('sha256', self::publicKey($node), true), true), 0, 4);
  }
}
