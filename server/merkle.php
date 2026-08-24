<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// RFC 6962 MERKLE TREE — spec §5.1. The server half of tools/merkle.mjs.
//
// ⚠⚠ NOT Bitcoin's tree. Bitcoin duplicates the final node on an odd count, so two different entry
// lists can share a root (CVE-2012-2459), and it hashes leaves and internal nodes identically, so an
// internal node can be passed off as a leaf. RFC 6962 forecloses both with the 0x00 / 0x01 prefixes.
//
// ⚠ Needs only ext/hash, which is always present. No SQLite, no sodium, no bignum.
// ⚠ All values are RAW BINARY STRINGS, never hex. Mixing the two is the obvious way to get a tree that
//   looks right and agrees with nothing.

declare(strict_types=1);

function mt_leaf_hash(string $entry): string { return hash('sha256', "\x00" . $entry, true); }
function mt_node_hash(string $l, string $r): string { return hash('sha256', "\x01" . $l . $r, true); }
function mt_empty_root(): string { return hash('sha256', '', true); }

/** ⚠ k = the largest power of two STRICTLY LESS than n. This defines the shape of the whole tree. */
function mt_split_point(int $n): int {
    if ($n < 2) throw new InvalidArgumentException('split point needs n >= 2');
    $k = 1;
    while ($k * 2 < $n) $k *= 2;
    return $k;
}

/** MTH(D[n]) */
function mt_root(array $entries): string {
    $n = count($entries);
    if ($n === 0) return mt_empty_root();
    if ($n === 1) return mt_leaf_hash($entries[0]);
    $k = mt_split_point($n);
    return mt_node_hash(mt_root(array_slice($entries, 0, $k)), mt_root(array_slice($entries, $k)));
}

/** PATH(m, D[n]) — built BOTTOM-UP, and it must be consumed bottom-up. */
function mt_inclusion_proof(int $m, array $entries): array {
    $n = count($entries);
    if ($m < 0 || $m >= $n) throw new InvalidArgumentException("index $m outside 0.." . ($n - 1));
    if ($n === 1) return [];
    $k = mt_split_point($n);
    return $m < $k
        ? array_merge(mt_inclusion_proof($m, array_slice($entries, 0, $k)), [mt_root(array_slice($entries, $k))])
        : array_merge(mt_inclusion_proof($m - $k, array_slice($entries, $k)), [mt_root(array_slice($entries, 0, $k))]);
}

/**
 * ⚠⚠ MIRRORS THE CONSTRUCTION rather than reasoning about the order. A verifier that walks the path
 *    top-down agrees for particular tree sizes only — in the JS twin that scored 203 of 820, which
 *    reads as a working implementation with an edge case rather than as a wrong one.
 */
function mt_verify_inclusion(int $m, int $n, string $leaf, array $path, string $expected): bool {
    if ($m < 0 || $m >= $n || $n < 1) return false;
    $pos = 0; $failed = false;
    $walk = function (int $m, int $size) use (&$walk, &$pos, &$failed, $path, $leaf): ?string {
        if ($size === 1) return mt_leaf_hash($leaf);
        $k = mt_split_point($size);
        $h = $m < $k ? $walk($m, $k) : $walk($m - $k, $size - $k);
        if ($h === null || $pos >= count($path)) { $failed = true; $pos++; return null; }
        $sib = $path[$pos++];
        return $m < $k ? mt_node_hash($h, $sib) : mt_node_hash($sib, $h);
    };
    $h = $walk($m, $n);
    return !$failed && $h !== null && $pos === count($path) && hash_equals($expected, $h);
}

/** PROOF(m, D[n]) — the tree of size m is a prefix of the tree of size n. */
function mt_consistency_proof(int $m, array $entries): array {
    $n = count($entries);
    if ($m < 1 || $m > $n) throw new InvalidArgumentException("m must be 1..$n");
    if ($m === $n) return [];
    return mt_sub_proof($m, $entries, true);
}
function mt_sub_proof(int $m, array $entries, bool $b): array {
    $n = count($entries);
    if ($m === $n) return $b ? [] : [mt_root($entries)];
    $k = mt_split_point($n);
    return $m <= $k
        ? array_merge(mt_sub_proof($m, array_slice($entries, 0, $k), $b), [mt_root(array_slice($entries, $k))])
        : array_merge(mt_sub_proof($m - $k, array_slice($entries, $k), false), [mt_root(array_slice($entries, 0, $k))]);
}

function mt_verify_consistency(int $m, int $n, string $old, string $new, array $proof): bool {
    if ($m === $n) return count($proof) === 0 && hash_equals($old, $new);
    if ($m < 1 || $m > $n) return false;
    $p = $proof;
    $fn = $m - 1; $sn = $n - 1;
    while ($fn & 1) { $fn >>= 1; $sn >>= 1; }
    // ⚠ when m is an exact power of two the old root is NOT carried in the proof — it IS the old root
    if ($fn !== 0) { if (!$p) return false; $fr = $sr = array_shift($p); }
    else { $fr = $sr = $old; }
    while ($sn !== 0) {
        if (($fn & 1) || $fn === $sn) {
            if (!$p) return false;
            $s = array_shift($p);
            $fr = mt_node_hash($s, $fr); $sr = mt_node_hash($s, $sr);
            while (!($fn & 1) && $fn !== 0) { $fn >>= 1; $sn >>= 1; }
        } else {
            if (!$p) return false;
            $sr = mt_node_hash($sr, array_shift($p));
        }
        $fn >>= 1; $sn >>= 1;
    }
    return count($p) === 0 && hash_equals($old, $fr) && hash_equals($new, $sr);
}
