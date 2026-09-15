<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ THE COVENANT THREAD — creating one, and ticking it forward ═══════════════════════════════════════
//
// ★★★ THIS IS THE PRIMARY LAYER. A covenant chain is *"a tip, ticked forward, only valid links"*.
//   ⛔ The first test chain never built this. It built the SECONDARY layer — `LogRecord` — and called
//   it a chain. Every entry had `unlocking = 0`: no signature, no preimage, nothing enforced. ⇒ See
//   `server/covenant-entry.php`, which now makes that shape unrepresentable.
//
// ⚠⚠ TWO SIGNATURES EXIST AND THEY ARE NOT THE SAME THING (spec §4.0a). A wallet produces BOTH, and
//   confusing them is what puts an interpreter in the chain:
//
//   | the covenant's internal `CHECKSIG` | via `OP_PUSH_TX`, over the entry's PREIMAGE ⇒ proves the STATE TRANSITION is what the program permits. **A verifier's concern. The chain MUST NOT evaluate it** |
//   | the append authorisation          | over the ENTRY BYTES ⇒ proves WHO SUBMITTED this. **The chain's only concern** |
//
// ⚠⚠⚠ AND THE CONSEQUENCE FOR A WALLET, WHICH IS EASY TO MISS: §4.1 says an operator checks only that
//   the entry is well-formed and signed by an authorised key. **It does NOT check the covenant.** So a
//   chain will happily accept an entry whose covenant refuses it — and a verifier will later reject it.
//   ⇒ **Nothing upstream will catch a bad tick. The wallet is the last place it can be caught.**
declare(strict_types=1);
require_once __DIR__ . '/../../covenant-entry.php';
require_once __DIR__ . '/../../preimage.php';

final class ThreadError extends RuntimeException {}

final class CovenantThread
{
  /** §4.2a: `open` is the literal 0x00; a key set is 0x01 (keys) or ★ 0x02 (HASHES — preferred). */
  public const AUTH_OPEN       = "\x00";
  public const AUTH_V1_KEYS    = 0x01;
  public const AUTH_V2_HASHES  = 0x02;

  // ── creating a thread ─────────────────────────────────────────────────────────────────────────────
  /**
   * ★ The genesis identity is NATIVE and DERIVED, never asserted (§2):
   *   `commitment = LP(source_hash) ‖ LP(script) ‖ LP(state) ‖ LP(authorised)`, `id = SHA256d(that)`.
   * ⚠ It is computed by observers from the commitment and MUST NOT be stored inside the thing it
   *   identifies — storing it there is what made the 0.1 formulation impossible (§4bis.0).
   *
   * @param string $sourceHash hash of the covenant's BASIC/Forth SOURCE, canonicalised per §7
   * @param string $script     the compiled locking script
   * @param string $state      the initial state
   * @param string $authorised packed per §4.2a — build it with authorisedHashes()
   * @return array{commitment:string,id:string}
   */
  public static function create(string $sourceHash, string $script, string $state,
                                string $authorised): array
  {
    if ($script === '') throw new ThreadError('a covenant with no script is not a covenant');
    $lp = fn(string $b) => pack('N', strlen($b)) . $b;
    $commitment = $lp($sourceHash) . $lp($script) . $lp($state) . $lp($authorised);
    return ['commitment' => $commitment,
            'id'         => hash('sha256', hash('sha256', $commitment, true), true)];
  }

  /**
   * ★★★ VERSION 0x02 — THE KEYS ARE HASHED, AND THAT IS THE POINT.
   *
   * ⚠⚠ His call, 7 Sept: *"A wallet address or public key should never be seen in the clear... That's
   *   a minable attack vector. Search for the pub key and next to it you're likely to find the private
   *   key in some file somewhere."* ⇒ **A public key is a SEARCH KEY** — a unique, greppable handle
   *   linking an on-chain record to every leaked `.env`, config and backup in the world. A hash breaks
   *   the link, because you cannot grep for `sha256(key)` unless you already hold the key.
   *
   * ★ It costs nothing: an append already supplies the pubkey (§4.1 checks it), so the operator hashes
   *   what it was given and compares. Nothing extra travels.
   * ★★ And it is where the BSV covenants already are: `depot.ts` THROWS unless the owner is a hash.
   *   ⇒ **jetmora storing keys in the clear was a regression from work already shipped.**
   *
   * ⚠ sha256, NOT hash160: §4.2a is k-of-n, which is MULTI-PARTY — exactly where 80-bit collision
   *   resistance is attackable. The BSV covenants use 20 bytes safely because they are single-owner.
   * ⚠ Keys ASCENDING by raw bytes, no duplicates — `[a,b]` and `[b,a]` must not be different covenants.
   *
   * @param string[] $publicKeys raw public keys; only their hashes are stored
   */
  public static function authorisedHashes(array $publicKeys, int $k = 1): string
  {
    $n = count($publicKeys);
    if ($n === 0 || $n > 255) throw new ThreadError('n must be 1..255');
    if ($k < 1 || $k > $n)    throw new ThreadError('k must be 1..n');
    $hashes = array_map(fn(string $pk) => hash('sha256', $pk, true), $publicKeys);
    sort($hashes, SORT_STRING);
    if (count(array_unique($hashes)) !== $n) throw new ThreadError('duplicate key');
    $out = chr(self::AUTH_V2_HASHES) . chr($k) . chr($n);
    foreach ($hashes as $h) $out .= chr(strlen($h)) . $h;
    return $out;
  }

  /** Does this key satisfy a packed `authorised`? ⚠ Reads 0x01 (legacy keys) AND 0x02 (hashes). */
  public static function isAuthorised(string $authorised, string $publicKey): bool
  {
    if ($authorised === self::AUTH_OPEN) return true;
    if (strlen($authorised) < 3) return false;
    $ver = ord($authorised[0]);
    if ($ver !== self::AUTH_V1_KEYS && $ver !== self::AUTH_V2_HASHES) return false;
    $needle = $ver === self::AUTH_V2_HASHES ? hash('sha256', $publicKey, true) : $publicKey;
    $n = ord($authorised[2]); $o = 3;
    for ($i = 0; $i < $n; $i++) {
      if ($o >= strlen($authorised)) return false;
      $len = ord($authorised[$o]); $o++;
      if ($o + $len > strlen($authorised)) return false;
      // ⚠ hash_equals, not ===: this compares attacker-supplied bytes against a stored value
      if (hash_equals(substr($authorised, $o, $len), $needle)) return true;
      $o += $len;
    }
    return false;
  }

  // ── ticking it forward ────────────────────────────────────────────────────────────────────────────
  /**
   * Build the entry that spends the current tip and produces its successor.
   *
   * ★★★ THE ORDER MATTERS AND IS NOT ARBITRARY. The preimage covers the PREVIOUS tip's locking script,
   *   never this entry's unlocking script — so it can be computed BEFORE the unlocking script exists.
   *   ⇒ That is what makes ticking possible rather than circular, and it is why `OP_PUSH_TX` works.
   *
   * ⚠ `$sequence` IS THE TICK INDEX (§6.3). **Time in a covenant MUST derive from this and MUST NOT
   *   derive from any clock.** The log's timestamp is a separate thing, is a record rather than proof,
   *   and a script cannot reach it.
   *
   * @param callable $buildUnlocking fn(string $preimage): string — the caller assembles the unlocking
   *        script from the preimage (`OP_PUSH_TX`) plus whatever the covenant needs. ⚠ It MUST return
   *        something: an empty unlocking script is what made the first chain a log.
   * @return array{entry:array,bytes:string,hash:string,preimage:string}
   */
  public static function tick(string $prevEntryHash, int $prevIndex, string $prevLocking,
                              string $prevValue, array $outputs, int $sequence,
                              callable $buildUnlocking, ?int $version = null): array
  {
    if (strlen($prevEntryHash) !== 32) throw new ThreadError('the tip reference must be 32 bytes');
    if ($prevLocking === '')
      throw new ThreadError('the tip has no locking script — that is a LOG RECORD, not a covenant tip');
    if (strlen($prevValue) !== 8) throw new ThreadError('value must be 8 raw bytes');
    if (!$outputs) throw new ThreadError('a tick must produce at least one successor');

    // 1. the skeleton. The unlocking script is not needed yet and is not part of the preimage.
    $skeleton = [
      'version'  => $version ?? version_build('JF', 2),
      'inputs'   => [['prevEntry' => $prevEntryHash, 'index' => $prevIndex,
                      'unlocking' => '', 'sequence' => $sequence]],
      'outputs'  => $outputs,
      'locktime' => 0,
    ];

    // 2. the preimage over it — this is what OP_PUSH_TX proves
    $pre = Preimage::build($skeleton, 0, $prevLocking, $prevValue);

    // 3. the caller builds the unlocking script from it
    $unlocking = $buildUnlocking($pre);
    if (!is_string($unlocking) || $unlocking === '')
      throw new ThreadError(
        'the unlocking script is empty — an entry that proves nothing is a LOG RECORD, not a tick');

    // 4. and only now is the entry complete. ⚠ Filling it in does NOT change the preimage.
    $entry = $skeleton;
    $entry['inputs'][0]['unlocking'] = $unlocking;
    $bytes = CovenantEntry::encode($entry);
    return ['entry' => $entry, 'bytes' => $bytes,
            'hash' => CovenantEntry::hash($bytes), 'preimage' => $pre];
  }

  /**
   * ⚠ The APPEND AUTHORISATION — the second signature, over the ENTRY BYTES.
   * ⛔ NOT the covenant's `CHECKSIG`, which is over the PREIMAGE and lives inside the unlocking script.
   * ★ This is the only one the chain checks (§4.1), and the only one it is allowed to check.
   */
  public static function appendSighash(string $entryBytes): string
  {
    return hash('sha256', $entryBytes, true);
  }
}
