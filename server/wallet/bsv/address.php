<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ⚠⚠⚠ THE WALLET IS TWO ISOLATED CODE SETS, ONE PER CHAIN (his call, 7 Sept).
//   `server/wallet/jetmora/` · `server/wallet/bsv/` · `server/wallet/shared/`
//
// ★★★ THE RULE THAT DECIDES WHAT GOES WHERE: **share what CANNOT disagree; isolate what CAN.**
//   A curve cannot disagree by design — secp256k1 is secp256k1 on both chains, so one copy is right
//   and three would be three places for one bug to hide. An ADDRESS FORMAT can disagree. So can a
//   transaction format, and so can a key-derivation path.
//
// ⇒ AND THE ISOLATION IS LOAD-BEARING THREE TIMES OVER, not once:
//   1. ⚖ **LICENCE.** Open BSV v6 clause 2 restricts field of use to the BSV Blockchain, so nothing
//      derived from it may run on jetmora. `own-wallet-sdk-position`: *"the hazard is one codebase
//      mixing them — 'derived from' goes murky the moment a helper crosses."* **The directory boundary
//      is what keeps that question ANSWERABLE.**
//   2. 💥 **BLAST RADIUS.** A BSV fix must not be able to reach jetmora — §10.9 and page-script-isolation.
//   3. ✅ **CORRECTNESS.** They genuinely differ: jetmora entries are ed25519 (every live genesis
//      authorises a 32-byte key); BSV is secp256k1. ⚠ Even HD derivation differs — BIP-32 is
//      secp256k1-specific and ed25519 needs SLIP-0010, a different algorithm.
//
// ── THIS FILE IS THE BSV SIDE ────────────────────────────────────────────────────────────────────────
// ⛔⛔ DECODE ONLY, and that is the enforcement. §2c reads `(chain, address)` published by a creator for
//   an EXTERNAL rail, so jetmora must be able to READ a Bitcoin address. §2c-i forbids it from ever
//   PRODUCING one. ⇒ There is no encode() here and there must never be: **the wrong thing is not
//   discouraged, it is ABSENT.**
declare(strict_types=1);

/**
 * ⛔⛔ DECODE ONLY, ON PURPOSE — there is no encode() and there must never be one.
 *
 * §2c reads `(chain, address)` published by a creator for an EXTERNAL rail, so jetmora must be able to
 * READ a Bitcoin address. §2c-i forbids it from ever PRODUCING one. ⇒ Splitting the direction in the
 * API is the cheapest possible enforcement: the wrong thing is not merely discouraged, it is absent.
 */
final class Base58Check
{
  private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  /** @return array{version:int,payload:string}|null */
  public static function decode(string $s): ?array
  {
    if ($s === '') return null;
    $num = gmp_init(0);
    for ($i = 0, $n = strlen($s); $i < $n; $i++) {
      $p = strpos(self::ALPHABET, $s[$i]);
      if ($p === false) return null;
      $num = gmp_add(gmp_mul($num, 58), $p);
    }
    $bytes = gmp_sign($num) === 0 ? '' : gmp_export($num, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    // ⚠ leading '1's are leading zero BYTES, and they are data — dropping them changes the payload
    $lead = strlen($s) - strlen(ltrim($s, '1'));
    $bytes = str_repeat("\x00", $lead) . $bytes;
    if (strlen($bytes) < 5) return null;
    $body = substr($bytes, 0, -4);
    $sum  = substr($bytes, -4);
    if (substr(hash('sha256', hash('sha256', $body, true), true), 0, 4) !== $sum) return null;
    return ['version' => ord($body[0]), 'payload' => substr($body, 1)];
  }

  /** ⚠ Used to REFUSE: a jetmora address must never satisfy this. */
  public static function looksLikeBitcoinAddress(string $s): bool
  {
    return self::decode($s) !== null;
  }
}
