<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
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
// ★★ Keys and signatures are ed25519-sign.php's: no PHP extension, the bytes libsodium's, and the secret path in
//   ref10's constant-time shape. PHP cannot promise constant time; that file says what it does and does not promise.
//
// ⚠ A parameter that holds a seed or a key is marked #[\SensitiveParameter], so that PHP 8.2 and later leave it out of
//   a stack trace, where PHP otherwise keeps each call's arguments (unless zend.exception_ignore_args is on). PHP 8.1
//   ignores the mark and runs the same; there, only that setting keeps the seed out.
// ⚠ The seed is not a property of the signer. It is held in a private static WeakMap keyed by the signer, so that
//   var_dump(), print_r(), var_export(), an (array) cast, get_object_vars() and reflection of the object's properties
//   show the public key and nothing else, and the entry goes when the signer does. A signer is not serialized: that
//   throws a LogicException. A clone signs with the same seed. Reflection of the class's static properties still reaches the map; this
//   keeps the seed out of a dump made by accident, not away from code that goes looking for it.
declare(strict_types=1);
require_once __DIR__ . '/slip10.php';
require_once __DIR__ . '/../../ed25519-sign.php';

final class JetmoraSignerError extends RuntimeException {}

final class JetmoraSigner
{
  /** ⚠ Each signer's seed, for the life of that signer and no longer. Nothing here writes a key. */
  private static ?WeakMap $seeds = null;

  private function __construct(#[\SensitiveParameter] string $seed, private readonly string $publicKey)
  {
    self::$seeds ??= new WeakMap();
    self::$seeds[$this] = $seed;
  }

  /** What var_dump() and print_r() show: the public key, never the seed. */
  public function __debugInfo(): array
  {
    return ['publicKey' => bin2hex($this->publicKey)];
  }

  /** A signer is not meant to be written out: its seed would go with it, or it would come back unable to sign. */
  public function __serialize(): array
  {
    throw new LogicException('a JetmoraSigner is not serialized; keep the phrase, and derive the signer again');
  }

  public function __unserialize(array $data): void
  {
    throw new LogicException('a JetmoraSigner is not serialized; keep the phrase, and derive the signer again');
  }

  /** A copy signs with the same seed: the original's entry, found by the public key both hold, is copied to it. */
  public function __clone()
  {
    foreach (self::$seeds ?? [] as $other => $seed)
      if ($other !== $this && hash_equals($other->publicKey, $this->publicKey)) { self::$seeds[$this] = $seed; return; }
  }

  /** ★ From a written-down phrase: BIP-39 seed → SLIP-0010 hardened path → an ed25519 key. */
  public static function fromSeed(#[\SensitiveParameter] string $seed, string $path = "m/44'/0'/0'"): self
  {
    $node = Slip10Ed25519::derive($seed, $path);
    return new self($node['key'], Ed25519Sign::publicKey($node['key']));
  }

  /** ⚠ 32 bytes, RAW — no 0x00 prefix. SLIP-0010's prefix is a serialization detail; a genesis
   *  authorises the bare key, which is why every live one is exactly 32 bytes. */
  public function publicKey(): string
  {
    return $this->publicKey;
  }

  /**
   * Sign the ENTRY BYTES (§4.0a). ⚠ The message, NOT a digest — ed25519 hashes internally, and
   * pre-hashing here would produce a signature the chain refuses.
   */
  public function signEntry(string $entryBytes): string
  {
    return Ed25519Sign::sign($entryBytes, self::$seeds[$this]);
  }

  /** The same check `Appender::verifySignature` performs for a 32-byte key: our own Ed25519, libsodium's rules. */
  public static function verify(string $entryBytes, string $publicKey, string $sig): bool
  {
    if (strlen($publicKey) !== 32 || strlen($sig) !== 64) return false;
    return Ed25519::verify($sig, $entryBytes, $publicKey);
  }
}
