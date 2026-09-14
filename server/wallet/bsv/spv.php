<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ SPV — MERKLE PROOFS AND PROOF CHAINS ═════════════════════════════════════════════════════════════
//
// ⚖ **Ported from `PharLap/src/tokenProtocol.ts`, which is sun-dive's OWN code** — its only `@bsv/sdk`
//   import was `Hash` (sha256, native in PHP). Nothing here derives from the SDK's `MerklePath`.
//
// ⛔⛔⛔ THIS IS **BITCOIN'S** MERKLE TREE. `server/merkle.php` IS NOT, AND THEY MUST NEVER BE SHARED.
//   `merkle.php` is **RFC 6962** for jetmora's own §5.1 roots, and it differs exactly where it bites:
//   | | Bitcoin (here) | RFC 6962 (`merkle.php`) |
//   |---|---|---|
//   | odd node | **duplicates the last one** ⇒ two different tx lists can share a root (CVE-2012-2459) | promotes it — no duplication |
//   | leaves vs nodes | hashed **identically** ⇒ an internal node can pose as a leaf | `0x00` / `0x01` prefixes forbid it |
//   ⇒ Using one for the other **mostly works**, which is the worst possible failure mode. Two files.
//
// ⚠⚠ BYTE ORDER IS THE CLASSIC TRAP, and it is silent. A txid or merkle root as a person reads it is
//   **REVERSED** (display order); the tree is computed in natural order. ⇒ Reverse on the way in, and
//   reverse the computed root on the way back out. Getting this wrong produces a valid-looking hash
//   that matches nothing.
//
// ★★★ THE DISCIPLINE THAT MATTERS, and it is already right in the reference: a proof is checked against
//   the BLOCK HEADER's merkle root, **never against the `target` the proof reports about itself.**
//   A proof that vouches for itself proves nothing. → `walletProvider.ts:556`
//
// ⚠ SCOPE, and it is DELIBERATE — his call, 8 Sept: *"there is no need to do full chain walks and the
//   end result is identical."* ⇒ Headers are SUPPLIED by the caller. There is no header chain, no
//   chainwork comparison, no proof-of-work validation, and `BlockHeader` carrying only height and
//   merkle root is **sufficient by design, not an omission.** The security comes from asking more than
//   one independent source (BananaBlocks and WoC), not from re-hashing one source's headers.
//   → [[spv-level-is-deliberate]]
declare(strict_types=1);

final class SpvError extends RuntimeException {}

final class MerkleProof
{
  /** ⚠ Bitcoin's tree: SHA-256 twice, at every level. */
  private static function dsha256(string $b): string
  {
    return hash('sha256', hash('sha256', $b, true), true);
  }

  /** display hex (reversed) → natural byte order */
  private static function fromDisplay(string $hex): string
  {
    if (strlen($hex) !== 64 || !ctype_xdigit($hex))
      throw new SpvError("not a 32-byte hex hash: \"$hex\"");
    return strrev((string)hex2bin($hex));
  }

  private static function toDisplay(string $raw): string { return bin2hex(strrev($raw)); }

  /**
   * Verify one proof: fold `txId` up through `path` and compare with `merkleRoot`.
   *
   * @param array $entry ['txId'=>hex, 'merkleRoot'=>hex, 'path'=>[['hash'=>hex,'position'=>'L'|'R'],…]]
   *   ⚠ `position` is the SIBLING's side. 'R' means the sibling is on the right, so the working hash
   *     goes first. Swapping them yields a different root that is just as well-formed.
   *   ★ A `hash` of `'*'` means **duplicate-up**: this node has no sibling, so Bitcoin pairs it with
   *     ITSELF. ⛔ Skipping the level instead leaves the working hash untouched, and `H(x‖x) != x`, so
   *     every proof containing one would fail. See `verify-spv.php`, which measures exactly that.
   */
  public static function verify(array $entry): bool
  {
    try { $current = self::fromDisplay((string)$entry['txId']); }
    catch (SpvError) { return false; }

    foreach ($entry['path'] ?? [] as $node) {
      $h   = (string)($node['hash'] ?? '');
      $pos = (string)($node['position'] ?? '');
      if ($h === '*') {                        // ★ no sibling ⇒ pair with itself
        $current = self::dsha256($current . $current);
        continue;
      }
      if ($pos !== 'L' && $pos !== 'R') return false;
      try { $sib = self::fromDisplay($h); } catch (SpvError) { return false; }
      $current = self::dsha256($pos === 'R' ? $current . $sib : $sib . $current);
    }

    try { $want = (string)$entry['merkleRoot']; }
    catch (Throwable) { return false; }
    return hash_equals(self::toDisplay($current), strtolower($want));
  }

  /**
   * TSC `nodes` + the transaction's `index` → an L/R path.
   * ⚠ The position comes from the INDEX's parity at each level, and the index halves as you climb.
   * ★ `'*'` is carried through rather than dropped, so `verify()` can pair the node with itself.
   */
  public static function fromTsc(array $nodes, int $index): array
  {
    if ($index < 0) throw new SpvError('a transaction index cannot be negative');
    $path = [];
    $idx  = $index;
    foreach ($nodes as $n) {
      $n = (string)$n;
      $path[] = ['hash' => $n, 'position' => ($idx % 2 === 0) ? 'R' : 'L'];
      $idx >>= 1;
    }
    return $path;
  }

  /**
   * ★ Build a block's merkle root from every txid, for checking a whole block rather than one proof.
   * ⚠ This is where Bitcoin duplicates the last node on an odd count — the CVE-2012-2459 shape — and
   *   it is reproduced faithfully because the goal is to agree with Bitcoin, not to improve on it.
   */
  public static function rootOf(array $txidsDisplay): string
  {
    if ($txidsDisplay === []) throw new SpvError('a block has at least one transaction');
    $level = array_map([self::class, 'fromDisplay'], $txidsDisplay);
    while (count($level) > 1) {
      $next = [];
      for ($i = 0; $i < count($level); $i += 2) {
        $l = $level[$i];
        $r = $level[$i + 1] ?? $l;             // ⚠ odd count ⇒ the last node pairs with ITSELF
        $next[] = self::dsha256($l . $r);
      }
      $level = $next;
    }
    return self::toDisplay($level[0]);
  }

  /** The proof path for one index in a block, in the same shape `verify()` consumes. */
  public static function pathFor(array $txidsDisplay, int $index): array
  {
    $level = array_map([self::class, 'fromDisplay'], $txidsDisplay);
    if (!isset($level[$index])) throw new SpvError("no transaction at index $index");
    $path = [];
    $idx  = $index;
    while (count($level) > 1) {
      $sibling = $idx ^ 1;
      // ★ no sibling at this level ⇒ '*', which means "pair with yourself"
      $path[] = isset($level[$sibling])
        ? ['hash' => self::toDisplay($level[$sibling]), 'position' => ($idx % 2 === 0) ? 'R' : 'L']
        : ['hash' => '*', 'position' => 'R'];
      $next = [];
      for ($i = 0; $i < count($level); $i += 2)
        $next[] = self::dsha256($level[$i] . ($level[$i + 1] ?? $level[$i]));
      $level = $next;
      $idx >>= 1;
    }
    return $path;
  }
}

final class ProofChain
{
  /**
   * Verify a chain of proofs against caller-supplied headers.
   *
   * @param array $chain   ['genesisTxId'=>hex, 'entries'=>[MerkleProofEntry,…]] — newest first
   * @param array $headers height => ['merkleRoot'=>hex]
   * @return array{valid:bool,reason:string}
   *
   * ⚠⚠ A MISSING HEADER IS A FAILURE, NOT A PASS. The tempting shortcut — skip entries whose header we
   *   could not fetch — turns a rate limit or a network blip into a clean bill of health.
   */
  public static function verify(array $chain, array $headers): array
  {
    $entries = $chain['entries'] ?? [];
    if ($entries === []) return ['valid' => false, 'reason' => 'proof chain is empty'];

    foreach ($entries as $e) {
      $id = substr((string)($e['txId'] ?? ''), 0, 12);
      if (!MerkleProof::verify($e))
        return ['valid' => false, 'reason' => "merkle proof invalid for tx $id…"];
      $h = (int)($e['blockHeight'] ?? -1);
      if (!isset($headers[$h]))
        return ['valid' => false, 'reason' => "no block header for height $h"];
      // ★★★ ANCHOR TO THE HEADER, never to the proof's own claim about itself.
      if (strtolower((string)$headers[$h]['merkleRoot']) !== strtolower((string)$e['merkleRoot']))
        return ['valid' => false, 'reason' => "merkle root mismatch at height $h"];
    }

    // ⚠ The OLDEST entry must be the genesis, or a chain could be truncated to hide its origin.
    $oldest = $entries[count($entries) - 1];
    if (($oldest['txId'] ?? null) !== ($chain['genesisTxId'] ?? false))
      return ['valid' => false, 'reason' => 'oldest proof entry does not match the genesis tx'];

    return ['valid' => true, 'reason' => 'verified against the supplied headers'];
  }
}
