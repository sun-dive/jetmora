<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ THE JETMORA SIGNER — ed25519 ═════════════════════════════════════════════════════════════════════
//
// ★ jetmora entries are signed with ed25519: **every live genesis authorises a 32-byte key.**
//
// ⚠⚠⚠ THIS FILE IS THE EXACT MIRROR OF `Appender::verifySignature`, and it has to be. That function is
//   what GATES an append (§4.1), so anything it will not accept is a signature that does not exist as
//   far as a chain is concerned. ⇒ The test does not verify with our own verifier — **it verifies with
//   the chain's.**
//
// ⚠⚠ THE DIFFERENCE THAT SILENTLY BREAKS THINGS, named so it cannot be forgotten:
//   | **ed25519**   | signs the MESSAGE. SHA-512 happens INSIDE the scheme |
//   | **secp256k1** | signs a 32-byte DIGEST. The caller must hash, and choosing the wrong hash gives a signature that verifies nowhere |
//   ⇒ §4.0a says the append authorisation is *"over the ENTRY BYTES"* for both. **That is one rule and
//     two mechanics** — which is precisely why the signer must mirror the verifier rather than invent a
//     common interface that hides the difference.
//
// ★★ sodium's ed25519 is CONSTANT TIME, which our own PHP secp256k1 cannot be. ⇒ On the jetmora side,
//   not owning the code is an ADVANTAGE, not a compromise.
declare(strict_types=1);
require_once __DIR__ . '/slip10.php';

final class JetmoraSignerError extends RuntimeException {}

final class JetmoraSigner
{
  /** ⚠ The keypair lives for the life of this object and no longer. Nothing here writes a key. */
  private function __construct(private readonly string $keypair) {}

  /** ★ From a written-down phrase: BIP-39 seed → SLIP-0010 hardened path → an ed25519 key. */
  public static function fromSeed(string $seed, string $path = "m/44'/0'/0'"): self
  {
    if (!extension_loaded('sodium')) throw new JetmoraSignerError('ext-sodium is required for ed25519');
    $node = Slip10Ed25519::derive($seed, $path);
    return new self(sodium_crypto_sign_seed_keypair($node['key']));
  }

  /** ⚠ 32 bytes, RAW — no 0x00 prefix. SLIP-0010's prefix is a serialization detail; a genesis
   *  authorises the bare key, which is why every live one is exactly 32 bytes. */
  public function publicKey(): string
  {
    return sodium_crypto_sign_publickey($this->keypair);
  }

  /**
   * Sign the ENTRY BYTES (§4.0a). ⚠ The message, NOT a digest — ed25519 hashes internally, and
   * pre-hashing here would produce a signature the chain refuses.
   */
  public function signEntry(string $entryBytes): string
  {
    return sodium_crypto_sign_detached($entryBytes, sodium_crypto_sign_secretkey($this->keypair));
  }

  /** The same check `Appender::verifySignature` performs for a 32-byte key. */
  public static function verify(string $entryBytes, string $publicKey, string $sig): bool
  {
    if (strlen($publicKey) !== 32 || strlen($sig) !== 64) return false;
    try { return sodium_crypto_sign_verify_detached($sig, $entryBytes, $publicKey); }
    catch (Throwable) { return false; }
  }
}
