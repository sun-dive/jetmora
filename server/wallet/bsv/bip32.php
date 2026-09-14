<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ BIP-32 HD DERIVATION · WIF — THE BSV SIDE ════════════════════════════════════════════════════════
//
// ⚠⚠ BIP-32 IS secp256k1-SPECIFIC. The jetmora side uses SLIP-0010 over ed25519, which is a DIFFERENT
//   ALGORITHM, not a parameter change. ⇒ Two files, two chains, and they do not cross.
//
// ★ THE THREE DIFFERENCES FROM SLIP-0010, each of which silently produces another wallet's keys:
//   | HMAC key   | `"Bitcoin seed"`, not `"ed25519 seed"` |
//   | child key  | **`(IL + kpar) mod n`** — NOT `IL` directly |
//   | retry      | if `IL >= n` or the child is zero, **skip that index** — ed25519 never needs this |
//
// ⚠⚠⚠ NON-HARDENED DERIVATION EXISTS HERE, and it is the sharp edge SLIP-0010 removes: **one leaked
//   child private key plus the parent xpub reconstructs the PARENT private key.** ⇒ It is implemented
//   because BIP-32 defines it and the vectors exercise it, but a wallet should prefer hardened paths.
//   ★ On the jetmora side that choice does not exist at all, which is why it is safer there.
declare(strict_types=1);
require_once __DIR__ . '/../../secp256k1.php';

final class Bip32Error extends RuntimeException {}

/**
 * ⛔⛔ BASE58CHECK FOR **KEYS ONLY** — §2c-i survives intact.
 *
 * §2c-i says a jetmora address must never be EMITTED as base58check, and `Base58Check` therefore has
 * no `encode()` and must never have one. WIF and xprv are not addresses, so they need encoding — and
 * this class provides it **while REFUSING the address version bytes outright.**
 * ⇒ So the property is not merely documented: **this encoder physically cannot produce a P2PKH or P2SH
 *   address.** Enforcement by absence, one level finer.
 */
final class Base58KeyCodec
{
  private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  /** ⛔ P2PKH mainnet/testnet and P2SH mainnet/testnet. Never emittable from here. */
  private const ADDRESS_VERSIONS = [0x00, 0x05, 0x6f, 0xc4];

  public static function encode(string $payload, ?int $version = null): string
  {
    if ($version !== null) {
      if (in_array($version, self::ADDRESS_VERSIONS, true))
        throw new Bip32Error(sprintf(
          'version 0x%02x is an ADDRESS version. This encoder emits KEYS only — §2c-i forbids jetmora '
        . 'emitting a base58check address, and that is enforced here rather than remembered.', $version));
      $payload = chr($version) . $payload;
    }
    $body = $payload . substr(hash('sha256', hash('sha256', $payload, true), true), 0, 4);
    $n = gmp_import($body, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $out = '';
    while (gmp_sign($n) > 0) { $out = self::ALPHABET[gmp_intval(gmp_mod($n, 58))] . $out; $n = gmp_div_q($n, 58); }
    return str_repeat('1', strlen($body) - strlen(ltrim($body, "\x00"))) . $out;
  }

  /** @return string|null the payload WITHOUT its checksum, or null if malformed */
  public static function decode(string $s): ?string
  {
    if ($s === '') return null;
    $n = gmp_init(0);
    for ($i = 0, $L = strlen($s); $i < $L; $i++) {
      $p = strpos(self::ALPHABET, $s[$i]);
      if ($p === false) return null;
      $n = gmp_add(gmp_mul($n, 58), $p);
    }
    $b = gmp_sign($n) === 0 ? '' : gmp_export($n, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    $b = str_repeat("\x00", strlen($s) - strlen(ltrim($s, '1'))) . $b;
    if (strlen($b) < 5) return null;
    $body = substr($b, 0, -4);
    if (substr(hash('sha256', hash('sha256', $body, true), true), 0, 4) !== substr($b, -4)) return null;
    return $body;
  }
}

final class Bip32
{
  private const CURVE  = 'Bitcoin seed';
  public  const HARDENED = 0x80000000;
  private const XPRV = "\x04\x88\xad\xe4";       // mainnet private
  private const XPUB = "\x04\x88\xb2\x1e";       // mainnet public

  private static function n(): GMP
  {
    return gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
  }

  /** @return array{key:string,chain:string,depth:int,parentFp:string,index:int} */
  public static function master(string $seed): array
  {
    if (strlen($seed) < 16 || strlen($seed) > 64) throw new Bip32Error('a seed is 16 to 64 bytes');
    $I = hash_hmac('sha512', $seed, self::CURVE, true);
    $k = gmp_import(substr($I, 0, 32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    // ⚠ UNLIKE ed25519: not every 32-byte string is a valid secp256k1 key, so this check is required.
    if (gmp_sign($k) === 0 || gmp_cmp($k, self::n()) >= 0)
      throw new Bip32Error('master key is invalid — astronomically unlikely, and must not be ignored');
    return ['key' => substr($I, 0, 32), 'chain' => substr($I, 32, 32),
            'depth' => 0, 'parentFp' => "\x00\x00\x00\x00", 'index' => 0];
  }

  public static function child(array $node, int $index): array
  {
    $hardened = $index >= self::HARDENED;
    $kpar = gmp_import($node['key'], 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    // ⚠ HARDENED prefixes 0x00 and uses the PRIVATE key; NORMAL uses the compressed PUBLIC key.
    //   Confusing the two derives a different tree that is perfectly valid and nobody else's.
    $data = ($hardened ? "\x00" . $node['key'] : self::publicKey($node)) . pack('N', $index);
    $I = hash_hmac('sha512', $data, $node['chain'], true);
    $IL = gmp_import(substr($I, 0, 32), 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    // ★★ `(IL + kpar) mod n` — NOT `IL`. SLIP-0010's ed25519 takes IL directly; doing that here, or
    //    this there, yields keys that verify perfectly and match no other wallet.
    if (gmp_cmp($IL, self::n()) >= 0) throw new Bip32Error("index $index is invalid; use the next one");
    $ki = gmp_mod(gmp_add($IL, $kpar), self::n());
    if (gmp_sign($ki) === 0) throw new Bip32Error("index $index yields a zero key; use the next one");
    return ['key' => str_pad(gmp_export($ki, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), 32, "\x00", STR_PAD_LEFT),
            'chain' => substr($I, 32, 32), 'depth' => $node['depth'] + 1,
            'parentFp' => self::fingerprint($node), 'index' => $index];
  }

  /** ⚠ A bare number is a NON-HARDENED step here, which BIP-32 permits and the vectors exercise. */
  public static function derive(string $seed, string $path): array
  {
    $node = self::master($seed);
    $path = trim($path);
    if ($path === '' || $path === 'm' || $path === 'm/') return $node;
    if (!str_starts_with($path, 'm/')) throw new Bip32Error('a path starts with "m/"');
    foreach (explode('/', substr($path, 2)) as $seg) {
      if ($seg === '') throw new Bip32Error("empty path segment in \"$path\"");
      $hard = str_ends_with($seg, "'") || str_ends_with($seg, 'H') || str_ends_with($seg, 'h');
      $num  = $hard ? substr($seg, 0, -1) : $seg;
      if (!ctype_digit($num)) throw new Bip32Error("not a path index: \"$seg\"");
      $node = self::child($node, (int)$num + ($hard ? self::HARDENED : 0));
    }
    return $node;
  }

  public static function publicKey(array $node): string
  {
    return Secp256k1::publicKey(gmp_import($node['key'], 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN), true);
  }

  public static function fingerprint(array $node): string
  {
    return substr(hash('ripemd160', hash('sha256', self::publicKey($node), true), true), 0, 4);
  }

  /** 78 bytes then base58check: version ‖ depth ‖ parent fingerprint ‖ index ‖ chain code ‖ key. */
  public static function serialize(array $node, bool $private = true): string
  {
    $body = ($private ? self::XPRV : self::XPUB) . chr($node['depth']) . $node['parentFp']
          . pack('N', $node['index']) . $node['chain']
          . ($private ? "\x00" . $node['key'] : self::publicKey($node));
    if (strlen($body) !== 78) throw new Bip32Error('an extended key is 78 bytes before the checksum');
    return Base58KeyCodec::encode($body);
  }
}

/**
 * WIF — a private key a person can move between wallets.
 * ⚠ The trailing 0x01 means "this key is used COMPRESSED". Omitting it is a different address for the
 *   same key, which is a classic way to lose funds that are provably yours.
 */
final class Wif
{
  private const MAINNET = 0x80;

  public static function encode(string $key32, bool $compressed = true, int $version = self::MAINNET): string
  {
    if (strlen($key32) !== 32) throw new Bip32Error('a private key is 32 bytes');
    return Base58KeyCodec::encode($key32 . ($compressed ? "\x01" : ''), $version);
  }

  /** @return array{key:string,compressed:bool,version:int}|null */
  public static function decode(string $wif): ?array
  {
    $b = Base58KeyCodec::decode($wif);
    if ($b === null || (strlen($b) !== 33 && strlen($b) !== 34)) return null;
    $compressed = strlen($b) === 34;
    if ($compressed && $b[33] !== "\x01") return null;      // ⚠ only 0x01 is a valid suffix
    return ['key' => substr($b, 1, 32), 'compressed' => $compressed, 'version' => ord($b[0])];
  }
}
