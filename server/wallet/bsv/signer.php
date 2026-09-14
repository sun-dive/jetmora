<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ THE BSV SIGNER — secp256k1 ═══════════════════════════════════════════════════════════════════════
//
// ⚠⚠⚠ MIRRORS `Appender::verifySignature`'s 33/65-byte branch exactly: **sha256 of the message, then
//   ECDSA over that digest.** ⇒ §4.0a says the append authorisation is over the ENTRY BYTES; ECDSA
//   cannot consume bytes, only a digest, so the hash is explicit HERE rather than hidden in a helper.
//   ⛔ Choosing a different hash — double sha256, say — produces a signature that verifies nowhere and
//     looks perfectly well-formed.
//
// ⚠⚠ THE TIMING CONSTRAINT IS REAL ON THIS SIDE. Our secp256k1 is scalar-blinded, but **PHP cannot be
//   constant time**. ⇒ For anything material, prefer the air-gapped path. The jetmora signer has no
//   such caveat: sodium's ed25519 IS constant time.
//
// ⚠ `lowS` is NOT a protocol rule — 0.1.3 has none and Chronicle removed it — but a BROADCASTER can
//   still refuse a high-s signature, and this project has had a conformant spend refused by exactly
//   that. ⇒ Default ON here, because this side broadcasts.
declare(strict_types=1);
require_once __DIR__ . '/../../secp256k1.php';
require_once __DIR__ . '/bip32.php';
require_once __DIR__ . '/transaction.php';

final class BsvSignerError extends RuntimeException {}

final class BsvSigner
{
  /**
   * ⚠⚠ `$compressed` TRAVELS WITH THE KEY, and that is not a detail: the same private key spends a
   *   DIFFERENT address compressed and uncompressed. ⇒ Importing a WIF and then defaulting to
   *   compressed would hand back an address holding nothing, for a key that is provably yours.
   */
  private function __construct(private readonly GMP $d, private readonly bool $compressed = true) {}

  public static function fromPrivateKey(string $raw32, bool $compressed = true): self
  {
    if (strlen($raw32) !== 32) throw new BsvSignerError('a private key is 32 bytes');
    $d = gmp_import($raw32, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    if (gmp_cmp($d, 1) < 0) throw new BsvSignerError('private key out of range');
    return new self($d, $compressed);
  }

  /** ★ From a written-down phrase. ⚠ BIP-32, not SLIP-0010 — see `bip32.php` for why they differ. */
  public static function fromSeed(string $seed, string $path = "m/44'/236'/0'/0/0"): self
  {
    return self::fromPrivateKey(Bip32::derive($seed, $path)['key']);
  }

  /**
   * ★ From a WIF — his 7 Sept requirement: *"generate a key phrase and WIF"*, so a key can move between
   *   wallets at all.
   * ⛔ NEVER ASK A USER FOR ONE. This exists so a user can import a key THEY produced, on their own
   *   machine, and the standing rule is that a key is never solicited.
   */
  public static function fromWif(string $wif): self
  {
    $d = Wif::decode($wif);
    if ($d === null) throw new BsvSignerError('not a valid WIF — the checksum or the length is wrong');
    return self::fromPrivateKey($d['key'], $d['compressed']);
  }

  /** ⚠ EXPORTS THE PRIVATE KEY. The caller is showing this to its owner and nobody else. */
  public function toWif(): string
  {
    return Wif::encode(str_pad(gmp_export($this->d, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), 32, "\x00",
                               STR_PAD_LEFT), $this->compressed);
  }

  public function publicKey(?bool $compressed = null): string
  {
    return Secp256k1::publicKey($this->d, $compressed ?? $this->compressed);
  }

  /** Sign the ENTRY BYTES. ⚠ The sha256 is the caller-side half of "over the entry bytes". */
  public function signEntry(string $entryBytes, bool $lowS = true): string
  {
    return Secp256k1::sign($this->d, hash('sha256', $entryBytes, true), $lowS);
  }

  /** The same check `Appender::verifySignature` performs for a 33/65-byte key. */
  public static function verify(string $entryBytes, string $publicKey, string $sig): bool
  {
    return Secp256k1::verifyDigest($sig, $publicKey, hash('sha256', $entryBytes, true));
  }

  // ── SIGNING A TRANSACTION ──────────────────────────────────────────────────────────────────────────
  //
  // ⚠⚠⚠ THIS IS A DIFFERENT OPERATION FROM `signEntry`, and confusing them produces a well-formed
  //   signature that verifies nowhere:
  //   | `signEntry` | jetmora · **sha256** of the entry bytes, per §4.0a |
  //   | `signInput` | BSV · **BIP143 preimage → dsha256**, per `BsvSighash` |
  //   ⇒ Both are ECDSA over 32 bytes. Only the 32 bytes differ, and nothing in the output says which
  //     rule produced them.

  /**
   * Sign one input. Returns the DER signature **with the sighash-type byte appended**, which is what a
   * scriptSig actually carries.
   *
   * @param string $scriptCode the LOCKING script of the output being spent
   * @param int    $amount     that output's satoshis
   * ⚠ Both come from the UTXO, never from the transaction — the transaction does not contain them,
   *   which is precisely why BIP143 has to be told.
   */
  public function signInput(BsvTx $tx, int $inputIndex, string $scriptCode, int $amount,
                            int $sighashType = BsvSighash::ALL_FORKID, bool $lowS = true): string
  {
    $digest = BsvSighash::hash($tx, $inputIndex, $scriptCode, $amount, $sighashType);
    // ★ The trailing byte is part of the signature as scripts see it — `verifyDigest` takes
    //   `$allowTrailing` for exactly this, which is why DER stayed STRICT by default.
    return Secp256k1::sign($this->d, $digest, $lowS) . chr($sighashType);
  }

  /** A minimal script data push. ⚠ Only the direct form is needed here: nothing signed is ≥ 76 bytes. */
  private static function push(string $data): string
  {
    $n = strlen($data);
    if ($n === 0 || $n >= 0x4c) throw new BsvSignerError('push size out of the direct range');
    return chr($n) . $data;
  }

  /** The P2PKH unlocking script: `<signature+type> <pubkey>`. */
  public function unlockP2PKH(BsvTx $tx, int $inputIndex, string $scriptCode, int $amount,
                              int $sighashType = BsvSighash::ALL_FORKID): string
  {
    return self::push($this->signInput($tx, $inputIndex, $scriptCode, $amount, $sighashType))
         . self::push($this->publicKey());
  }

  /**
   * Sign every input of a P2PKH transaction IN PLACE.
   *
   * @param array $utxos aligned with `$tx->inputs`, each ['txid','vout','value','script']
   *
   * ⚠⚠⚠ THE ALIGNMENT IS CHECKED, NOT ASSUMED. Handing these in the wrong ORDER signs each input
   *   against another output's script and amount ⇒ **every signature is well-formed and every one is
   *   invalid**, with nothing in the transaction to say so. ⇒ So the outpoints are compared, and a
   *   mismatch is refused rather than signed.
   */
  public function signP2PKH(BsvTx $tx, array $utxos,
                            int $sighashType = BsvSighash::ALL_FORKID): BsvTx
  {
    if (count($utxos) !== count($tx->inputs))
      throw new BsvSignerError(sprintf('%d UTXOs for %d inputs', count($utxos), count($tx->inputs)));
    foreach ($tx->inputs as $i => $in) {
      $u = $utxos[$i];
      if ($u['txid'] !== $in['txid'] || (int)$u['vout'] !== (int)$in['vout'])
        throw new BsvSignerError(sprintf(
          'UTXO %d does not match input %d: the outpoints differ. ⇒ The list is out of order, and '
        . 'signing it would produce valid-looking signatures that verify nowhere.', $i, $i));
      $tx->inputs[$i]['script'] =
        $this->unlockP2PKH($tx, $i, $u['script'], (int)$u['value'], $sighashType);
    }
    return $tx;
  }

  /** Verify one input's signature the way a script would. */
  public static function verifyInput(BsvTx $tx, int $inputIndex, string $scriptCode, int $amount,
                                     string $publicKey, string $sigWithType): bool
  {
    if ($sigWithType === '') return false;
    $type = ord($sigWithType[strlen($sigWithType) - 1]);
    return Secp256k1::verifyDigest(
      $sigWithType, $publicKey,
      BsvSighash::hash($tx, $inputIndex, $scriptCode, $amount, $type),
      true);                                  // ⚠ allowTrailing: the sighash byte follows the DER
  }
}
