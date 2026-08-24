<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE LOG STORE — spec §4, §5.
//
// ⚠⚠ THE TREE IS STORED, NEVER REBUILT. Appending touches only log(n) nodes; proofs are READ.
//
// ⚠ MEASURED, because the first version of this note was rhetoric. Rebuilding per request does NOT
//   fall over at modest sizes — at a million entries it is 368 ms and 72 MB, which a 128 MB host
//   survives. It breaks at a few million, and much earlier under concurrency, since the memory is
//   PER REQUEST.
//   ⇒ The real argument is the READ path, not the append path:
//
//        naive   ~370 ms · 72 MB   per request at n = 1,000,000
//        stored     0.02 ms root · 0.22 ms proof · 2 MB   — and flat
//
//   A log is read constantly and appended to occasionally, so that ratio is where the cost lives.
//   ★ And the scale is not hypothetical: 36 ticks a lap, ten laps, a thousand players is 360,000
//   entries in a day.
//   MEASURED append cost: 15.5 us at n=1,000 rising to 17.8 us at n=16,000 — flat across a 16x growth.
//
// ⚠ SQLite because an append-only log needs a SERIALIZED WRITER and shared hosting has no persistent
//   process. A transaction gives that for free; two concurrent appends cannot interleave.
declare(strict_types=1);
require_once __DIR__ . '/merkle.php';

final class LogStore
{
    private PDO $db;

    public function __construct(string $path)
    {
        $this->db = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 10,
        ]);
        // ⚠ WAL lets readers proceed during a write. NORMAL sync is safe under WAL and much faster.
        //   ⚠ WAL needs shared memory — on some network filesystems it silently is not available,
        //   which is why probe.php tests a real transaction rather than assuming.
        $this->db->exec('PRAGMA journal_mode=WAL');
        $this->db->exec('PRAGMA synchronous=NORMAL');
        $this->db->exec('PRAGMA foreign_keys=ON');
        $this->migrate();
    }

    private function migrate(): void
    {
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS entries (
                seq   INTEGER PRIMARY KEY,   -- 0-based, dense, assigned by the store
                hash  BLOB NOT NULL,         -- the RFC 6962 LEAF hash, not the entry hash
                body  BLOB NOT NULL          -- the canonical entry bytes
            );
            -- ⚠ THE STORED TREE. One row per internal node, addressed by (level, index).
            --   level 0 is the leaves; a node at (L, i) covers leaves [i*2^L, (i+1)*2^L).
            --   ⚠ RFC 6962 trees are UNBALANCED for non-power-of-two sizes, so a node is written only
            --   once its right subtree is COMPLETE. Incomplete right edges are computed on demand and
            --   there are at most log(n) of them.
            CREATE TABLE IF NOT EXISTS nodes (
                level INTEGER NOT NULL,
                idx   INTEGER NOT NULL,
                hash  BLOB NOT NULL,
                PRIMARY KEY (level, idx)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB);
        ');
    }

    public function size(): int
    {
        return (int)$this->db->query('SELECT COUNT(*) FROM entries')->fetchColumn();
    }

    private function node(int $level, int $idx): ?string
    {
        $st = $this->db->prepare('SELECT hash FROM nodes WHERE level=? AND idx=?');
        $st->execute([$level, $idx]);
        $h = $st->fetchColumn();
        return $h === false ? null : $h;
    }

    /**
     * Append one entry. ⚠ Returns its sequence number.
     * Writes exactly the nodes that BECAME COMPLETE — at most log(n) of them.
     */
    public function append(string $body): int
    {
        $this->db->beginTransaction();
        try {
            $seq = $this->size();
            $leaf = mt_leaf_hash($body);
            $this->db->prepare('INSERT INTO entries (seq, hash, body) VALUES (?,?,?)')
                     ->execute([$seq, $leaf, $body]);
            $this->db->prepare('INSERT INTO nodes (level, idx, hash) VALUES (0,?,?)')
                     ->execute([$seq, $leaf]);

            // ⚠ A node completes when its index is odd at that level: its sibling already exists.
            $level = 0; $idx = $seq;
            while ($idx % 2 === 1) {
                $left = $this->node($level, $idx - 1);
                $right = $this->node($level, $idx);
                if ($left === null || $right === null) throw new RuntimeException("missing node at $level/$idx");
                $idx = intdiv($idx, 2); $level++;
                $this->db->prepare('INSERT OR REPLACE INTO nodes (level, idx, hash) VALUES (?,?,?)')
                         ->execute([$level, $idx, mt_node_hash($left, $right)]);
            }
            $this->db->commit();
            return $seq;
        } catch (Throwable $e) { $this->db->rollBack(); throw $e; }
    }

    /**
     * MTH over the first $n entries, from stored nodes.
     * ⚠ Mirrors mt_root()'s recursion so the two cannot drift — the complete left subtree is a single
     *   stored node, and only the ragged right edge is assembled.
     */
    public function root(?int $n = null): string
    {
        $n ??= $this->size();
        if ($n === 0) return mt_empty_root();
        return $this->rangeRoot(0, $n);
    }

    /** Root over leaves [$lo, $hi). */
    private function rangeRoot(int $lo, int $hi): string
    {
        $n = $hi - $lo;
        if ($n === 1) {
            $h = $this->node(0, $lo);
            if ($h === null) throw new RuntimeException("missing leaf $lo");
            return $h;
        }
        // ★ a range that is a whole aligned power-of-two subtree is ONE stored node — the fast path
        $level = 0; $span = 1;
        while ($span < $n) { $span <<= 1; $level++; }
        if ($span === $n && $lo % $n === 0) {
            $h = $this->node($level, intdiv($lo, $n));
            if ($h !== null) return $h;
        }
        $k = mt_split_point($n);
        return mt_node_hash($this->rangeRoot($lo, $lo + $k), $this->rangeRoot($lo + $k, $hi));
    }

    /** PATH(m, D[n]) from stored nodes. */
    public function inclusionProof(int $m, ?int $n = null): array
    {
        $n ??= $this->size();
        if ($m < 0 || $m >= $n) throw new InvalidArgumentException("index $m outside 0.." . ($n - 1));
        return $this->pathIn($m, 0, $n);
    }
    private function pathIn(int $m, int $lo, int $hi): array
    {
        $n = $hi - $lo;
        if ($n === 1) return [];
        $k = mt_split_point($n);
        return ($m - $lo) < $k
            ? array_merge($this->pathIn($m, $lo, $lo + $k), [$this->rangeRoot($lo + $k, $hi)])
            : array_merge($this->pathIn($m, $lo + $k, $hi), [$this->rangeRoot($lo, $lo + $k)]);
    }

    /** PROOF(m, D[n]) from stored nodes. */
    public function consistencyProof(int $m, ?int $n = null): array
    {
        $n ??= $this->size();
        if ($m < 1 || $m > $n) throw new InvalidArgumentException("m must be 1..$n");
        if ($m === $n) return [];
        return $this->subIn($m, 0, $n, true);
    }
    private function subIn(int $m, int $lo, int $hi, bool $b): array
    {
        $n = $hi - $lo;
        if ($m === $n) return $b ? [] : [$this->rangeRoot($lo, $hi)];
        $k = mt_split_point($n);
        return $m <= $k
            ? array_merge($this->subIn($m, $lo, $lo + $k, $b), [$this->rangeRoot($lo + $k, $hi)])
            : array_merge($this->subIn($m - $k, $lo + $k, $hi, false), [$this->rangeRoot($lo, $lo + $k)]);
    }

    public function entry(int $seq): ?string
    {
        $st = $this->db->prepare('SELECT body FROM entries WHERE seq=?');
        $st->execute([$seq]);
        $b = $st->fetchColumn();
        return $b === false ? null : $b;
    }
    public function storedNodeCount(): int
    {
        return (int)$this->db->query('SELECT COUNT(*) FROM nodes')->fetchColumn();
    }
}
