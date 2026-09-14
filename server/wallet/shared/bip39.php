<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ BIP-39 — MNEMONIC ⇄ SEED ═════════════════════════════════════════════════════════════════════════
//
// ★ SHARED, and correctly so: **BIP-39 is chain-agnostic.** A mnemonic and its seed are the same on both
//   rails; only the DERIVATION differs (BIP-32 for secp256k1, SLIP-0010 for ed25519). ⇒ "Share what
//   cannot disagree; isolate what can."
//
// ⚠⚠⚠ WHY THIS EXISTS AT ALL, AND IT IS NOT CONVENIENCE.
//   The wallet previously showed a raw 32-byte key as 64 hex characters. **Hex has no checksum**:
//   transpose two characters and you get a DIFFERENT VALID KEY, silently, pointing at threads that do
//   not exist. ⇒ A mnemonic is writable by hand and **checkable** — a mistyped word is caught.
//   ★★ And it is load-bearing for the exit design (7 Sept): *the wallet holder controls the thread, the
//   site holds the backup, swap devices and pull your string back.* **That entire story depends on the
//   key surviving the device change**, and a hex string on paper was the one weak link in it.
//
// ⚠⚠ NFKD NORMALISATION. BIP-39 requires the mnemonic AND passphrase to be NFKD-normalised before
//   PBKDF2. ★ The English wordlist is pure ASCII, where NFKD is the identity — so English mnemonics are
//   unaffected. ⛔ A NON-ASCII PASSPHRASE ON A HOST WITHOUT ext-intl IS REFUSED, never guessed: a
//   silently different seed is a wallet that cannot recover itself anywhere else, and that failure is
//   invisible until the day it matters.
//
// ⚠ The KDF is PBKDF2-HMAC-SHA512 at 2048 iterations — weak by modern standards (Argon2id is the modern
//   answer) but it is what BIP-39 specifies, and changing it breaks compatibility with every wallet in
//   existence. ⇒ A documented trade, not an oversight.
declare(strict_types=1);

final class Bip39Error extends RuntimeException {}

final class Bip39
{
  private const WORDLIST = __DIR__ . '/bip39-english.txt';

  /** @return string[] 2048 words, index 0..2047 */
  public static function words(): array
  {
    static $w = null;
    if ($w !== null) return $w;
    $raw = @file(self::WORDLIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($raw === false) throw new Bip39Error('wordlist missing: ' . self::WORDLIST);
    if (count($raw) !== 2048) throw new Bip39Error('wordlist must be exactly 2048 words');
    return $w = $raw;
  }

  /**
   * ⚠ Valid entropy is 128/160/192/224/256 bits — 12/15/18/21/24 words. Nothing else: the checksum
   *   length is ENT/32, which only works for multiples of 32.
   */
  public static function generate(int $strengthBits = 128): string
  {
    if (!in_array($strengthBits, [128, 160, 192, 224, 256], true))
      throw new Bip39Error('strength must be 128, 160, 192, 224 or 256 bits');
    return self::fromEntropy(random_bytes(intdiv($strengthBits, 8)));
  }

  /** entropy bytes → mnemonic. */
  public static function fromEntropy(string $entropy): string
  {
    $bits = strlen($entropy) * 8;
    if (!in_array($bits, [128, 160, 192, 224, 256], true))
      throw new Bip39Error("entropy must be 16, 20, 24, 28 or 32 bytes; got " . strlen($entropy));
    // ★ THE CHECKSUM: the first ENT/32 bits of sha256(entropy), appended to the entropy bits.
    //   ⇒ It is what makes a mistyped word detectable, which is the whole reason a mnemonic beats hex.
    $csLen = intdiv($bits, 32);
    $bin   = self::toBits($entropy) . substr(self::toBits(hash('sha256', $entropy, true)), 0, $csLen);
    $w = self::words();
    $out = [];
    foreach (str_split($bin, 11) as $chunk) $out[] = $w[bindec($chunk)];
    return implode(' ', $out);
  }

  /**
   * mnemonic → entropy. ⛔ THROWS on a bad checksum or an unknown word — the point of the format.
   * ⚠ Whitespace is collapsed and case is lowered before lookup, because a person typed this.
   */
  public static function toEntropy(string $mnemonic): string
  {
    $parts = preg_split('/\s+/u', trim(self::nfkd($mnemonic, 'mnemonic')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    $n = count($parts);
    if (!in_array($n, [12, 15, 18, 21, 24], true))
      throw new Bip39Error("a mnemonic is 12, 15, 18, 21 or 24 words; got $n");
    $index = array_flip(self::words());
    $bin = '';
    foreach ($parts as $p) {
      $p = mb_strtolower($p, 'UTF-8');
      if (!isset($index[$p])) throw new Bip39Error("not a BIP-39 word: \"$p\"");
      $bin .= str_pad(decbin($index[$p]), 11, '0', STR_PAD_LEFT);
    }
    $entBits = intdiv($n * 11 * 32, 33);
    $entropy = self::fromBits(substr($bin, 0, $entBits));
    $want = substr(self::toBits(hash('sha256', $entropy, true)), 0, $n * 11 - $entBits);
    if (substr($bin, $entBits) !== $want)
      throw new Bip39Error('checksum does not match — a word is wrong or in the wrong place');
    return $entropy;
  }

  public static function isValid(string $mnemonic): bool
  {
    try { self::toEntropy($mnemonic); return true; } catch (Throwable) { return false; }
  }

  /**
   * mnemonic (+ optional passphrase) → 64-byte seed.
   *
   * ⚠⚠ THE SEED DOES NOT DEPEND ON THE MNEMONIC BEING VALID. BIP-39 defines this as PBKDF2 over the
   *   mnemonic STRING, so an invalid mnemonic still yields a seed — which is why a wallet must call
   *   `toEntropy()` to CHECK it, and not infer validity from getting a seed back.
   * ★ The passphrase is a 25th word in effect: a different passphrase is a different wallet, with no
   *   way to tell from the mnemonic that another one exists.
   */
  public static function toSeed(string $mnemonic, string $passphrase = ''): string
  {
    return hash_pbkdf2('sha512', self::nfkd($mnemonic, 'mnemonic'),
                       'mnemonic' . self::nfkd($passphrase, 'passphrase'),
                       2048, 64, true);
  }

  /**
   * ⚠⚠ NFKD, or an explicit refusal. ★ ASCII is unaffected — NFKD is the identity there, so the English
   *   wordlist and ASCII passphrases are exact on any host. ⛔ Non-ASCII without ext-intl THROWS rather
   *   than returning an unnormalised string: a silently different seed is a wallet that cannot recover
   *   itself elsewhere, and nothing would reveal it until the day it mattered.
   */
  public static function nfkd(string $s, string $what = 'text'): string
  {
    if (preg_match('/^[\x20-\x7e]*$/', $s)) return $s;          // pure ASCII: nothing to normalise
    if (class_exists('Normalizer')) {
      $n = \Normalizer::normalize($s, \Normalizer::FORM_KD);
      if ($n !== false) return $n;
    }
    // ★★★ THE FULL-WIDTH FOLD — and it is EXACT, not an approximation.
    //   ⚠⚠ THE REAL FAILURE THIS EXISTS FOR: a CJK input method in full-width mode turns "abandon"
    //     into "ａｂａｎｄｏｎ" — **visually identical, 21 bytes instead of 7, and not in the wordlist.**
    //     A user in Japan, Taiwan or Korea can type a perfect seed phrase and have it rejected, with no
    //     visible reason. That is a real way to lose a wallet.
    //   ★ NFKD maps U+FF01–U+FF5E to U+0021–U+007E and U+3000 to a space, and does nothing to ASCII.
    //     ⇒ So for input made ONLY of ASCII and those forms, this fold IS the NFKD result — which is
    //     why it is safe to do without ext-intl. ⛔ And it is CHECKED: if anything non-ASCII survives
    //     the fold, we refuse exactly as before rather than shipping a half-normalisation.
    $folded = '';
    foreach (preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
      $cp = mb_ord($ch, 'UTF-8');
      if ($cp >= 0xFF01 && $cp <= 0xFF5E)      $folded .= chr($cp - 0xFF01 + 0x21);
      elseif ($cp === 0x3000 || $cp === 0x00A0) $folded .= ' ';
      else                                      $folded .= $ch;
    }
    if (preg_match('/^[\x20-\x7e]*$/', $folded)) return $folded;

    throw new Bip39Error(sprintf(
      'this %s contains characters that are not ASCII and could not be normalised: ext-intl is '
    . 'unavailable on this host. BIP-39 requires NFKD before PBKDF2, and proceeding would produce a '
    . 'seed no other wallet agrees with. ⇒ If you typed a mnemonic with a CJK input method, switch it '
    . 'to half-width and retype; otherwise install ext-intl.', $what));
  }

  private static function toBits(string $bytes): string
  {
    $out = '';
    for ($i = 0, $n = strlen($bytes); $i < $n; $i++)
      $out .= str_pad(decbin(ord($bytes[$i])), 8, '0', STR_PAD_LEFT);
    return $out;
  }

  private static function fromBits(string $bits): string
  {
    if (strlen($bits) % 8 !== 0) throw new Bip39Error('bit string is not a whole number of bytes');
    $out = '';
    foreach (str_split($bits, 8) as $b) $out .= chr(bindec($b));
    return $out;
  }
}
