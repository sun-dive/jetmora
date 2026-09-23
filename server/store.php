<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
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

/** ⚠ Distinct from a generic failure: the data is not wrong, it is ABSENT and recoverable (§5c.2). */
class PrunedException extends RuntimeException {}

/** ⚠ The log is FULL, not broken. Everything already recorded stays readable and provable. */
class LogFullException extends RuntimeException {}
/** A second entry naming a tip that is already ticked (§4.4): invalid, never adjudicated. */
final class TipTickedException extends RuntimeException {}

final class LogStore
{
    /**
     * ⚠⚠ SHARED HOSTING, SO THE LOG HAS A CEILING — 100 MB, about 293,000 entries at a measured 341
     *   bytes each (body + tree nodes + index), or roughly 3,250 races.
     *
     * ★ Reaching it is not a failure mode, it is THE failure mode we want: the log declines to record
     *   and can still prove everything it already recorded. *An operator who can only refuse.*
     * ⚠ This is NOT a defence against abuse — appending is free by design (§6c.1) and a log that
     *   throttled strangers would be solving the wrong problem. It exists so that filling this log
     *   cannot fill the ACCOUNT, which hosts other things that have nothing to do with jetmora.
     */
    public const MAX_DB_BYTES = 100 * 1024 * 1024;

    private PDO $db;
    private string $path;
    /** The journal mode actually in force — "wal" where the host allows it, otherwise the fallback. */
    public string $journalMode = 'unknown';

    public function __construct(string $path)
    {
        $this->path = $path;
        $this->db = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT => 10,
        ]);
        // ⚠ WAL lets readers proceed during a write. NORMAL sync is safe under WAL and much faster.
        //   ⚠ WAL needs shared memory — on some network filesystems it silently is not available,
        //   which is why probe.php tests a real transaction rather than assuming.
        // ⚠⚠ ANTICIPATED ABOVE AND THEN ASSUMED ANYWAY — which is what actually happened: appends
        //   returned 500 with an empty body on the first host they met (30 Aug), while registers, which
        //   never touch this connection, worked. ⇒ WAL is an OPTIMISATION; failing to get it must cost
        //   speed, never correctness. `journalMode` records what we ended up with, so nobody has to guess.
        try { $this->db->exec('PRAGMA journal_mode=WAL'); }
        catch (Throwable) { /* stays in the default rollback journal — slower, still correct */ }
        $this->journalMode = (string)($this->db->query('PRAGMA journal_mode')->fetchColumn() ?: 'unknown');
        // ⚠ NORMAL sync is only safe under WAL. Without it, fall back to FULL rather than keep the speed.
        $this->db->exec('PRAGMA synchronous=' . (strtolower($this->journalMode) === 'wal' ? 'NORMAL' : 'FULL'));
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
        // ★ The index per covenant (the reference, §2): which thread an entry advances, so a thread is
        //   read back with one query instead of a scan. Added as a column so an older file migrates.
        $cols = array_column($this->db->query('PRAGMA table_info(entries)')->fetchAll(PDO::FETCH_ASSOC), 'name');
        if (!in_array('genesis', $cols, true)) $this->db->exec('ALTER TABLE entries ADD COLUMN genesis BLOB');
        // ⚠ When the operator RECEIVED the entry: a record for retention policy (§4.5), never a protocol
        //   field and never read by a covenant (§6.3). Absent on rows from before the column existed.
        if (!in_array('ts', $cols, true)) $this->db->exec('ALTER TABLE entries ADD COLUMN ts INTEGER');
        $this->db->exec('CREATE INDEX IF NOT EXISTS entries_genesis ON entries (genesis, seq)');
        // ★ THE TIP of every thread (§4.4, his ruling 23 Sept): HASH256 of its newest entry, which is what the next
        //   entry's input names. Kept as a row so it survives body pruning (§4.5) and costs one lookup.
        $this->db->exec('CREATE TABLE IF NOT EXISTS tips (genesis BLOB PRIMARY KEY, seq INTEGER NOT NULL, hash BLOB NOT NULL) WITHOUT ROWID');
    }
    /** The tip a new entry must name: HASH256 of the thread's newest entry, the genesis id itself when it has none,
     *  or null when it cannot be known (a thread from before tips were kept, its newest body pruned). */
    public function tipHashOf(string $genesis): ?string
    {
        $st = $this->db->prepare('SELECT hash FROM tips WHERE genesis=?'); $st->execute([$genesis]);
        $h = $st->fetchColumn();
        if ($h !== false && $h !== null) return $h;
        $st = $this->db->prepare('SELECT body FROM entries WHERE genesis=? ORDER BY seq DESC LIMIT 1'); $st->execute([$genesis]);
        $body = $st->fetchColumn();
        if ($body === false || $body === null) return $genesis;              // no entry yet: the first tick names the genesis
        return $body === '' ? null : hash('sha256', hash('sha256', $body, true), true);   // pruned: unknowable, once
    }

    /** The entries of one thread, oldest first, after a sequence number. @return array<array{seq:int, body:string}> */
    public function entriesOf(string $genesis, int $after = -1, int $limit = 256): array
    {
        $st = $this->db->prepare('SELECT seq, body FROM entries WHERE genesis=? AND seq>? ORDER BY seq LIMIT ?');
        $st->execute([$genesis, $after, max(1, min(256, $limit))]);
        return array_map(fn($r) => ['seq' => (int)$r['seq'], 'body' => $r['body']], $st->fetchAll(PDO::FETCH_ASSOC));
    }
    /**
     * ★ RETENTION (spec §5c, an operator's policy): discard the BODIES of entries received more than
     *   $seconds ago whose genesis STATE is not one of $keepStates. The leaf hashes stay, so the tree and
     *   every proof still stand; a pruned body reads as '' (log.php answers 410 for it). Returns rows pruned.
     */
    public function pruneOlderThan(int $seconds, array $keepStates = []): int
    {
        $cut = time() - $seconds;
        // ⚠ Compare states as HEX text: a bound PHP string is TEXT to SQLite and never equals a BLOB column.
        $keep = array_map(fn($b) => strtoupper(bin2hex($b)), $keepStates) ?: ['-'];
        $sql = 'UPDATE entries SET body = \'\' WHERE ts IS NOT NULL AND ts < ? AND length(body) > 0'
             . ' AND genesis IN (SELECT id FROM genesis WHERE hex(state) NOT IN (' . implode(',', array_fill(0, count($keep), '?')) . '))';
        $st = $this->db->prepare($sql);
        $st->execute([$cut, ...$keep]);
        return $st->rowCount();
    }
    /**
     * The threads whose genesis STATE is $state and which still hold an unpruned entry, newest activity
     * first. A state a party derives from something public (a number, a topic) is how another party finds
     * threads addressed to it without knowing who wrote them. @return string[] genesis ids
     */
    public function threadsWithState(string $state, int $limit = 256): array
    {
        $st = $this->db->prepare('SELECT e.genesis, MAX(e.ts) AS t FROM entries e JOIN genesis g ON g.id = e.genesis'
            . ' WHERE hex(g.state) = ? AND length(e.body) > 0 GROUP BY e.genesis ORDER BY t DESC LIMIT ?');
        $st->execute([strtoupper(bin2hex($state)), max(1, min(256, $limit))]);
        return array_map(fn($r) => $r['genesis'], $st->fetchAll(PDO::FETCH_ASSOC));
    }
    /** The newest sequence number of a thread, or null if it has none. */
    public function tipOf(string $genesis): ?int
    {
        $st = $this->db->prepare('SELECT MAX(seq) FROM entries WHERE genesis=?');
        $st->execute([$genesis]);
        $v = $st->fetchColumn();
        return $v === null || $v === false ? null : (int)$v;
    }
    public function countOf(string $genesis): int
    {
        $st = $this->db->prepare('SELECT COUNT(*) FROM entries WHERE genesis=?');
        $st->execute([$genesis]);
        return (int)$st->fetchColumn();
    }

    /**
     * ★★★ THE BATTERY, IN THE ONLY UNIT THAT MEANS ANYTHING HERE.
     *
     * A BRC-226 battery bounds SATOSHIS — how much an agent may spend before it is refuelled. This log
     * has no satoshis, so what it bounds is ENTRIES, and what that buys is RACES. Same mechanism, the
     * resource swapped. ⇒ Bytes are the implementation; entries are the charge.
     *
     * ⚠ MEASURED, NEVER ASSUMED: the cost per entry is taken from this log's own consumption so far, so
     *   it self-corrects as the shape of the entries changes. A hardcoded constant would drift silently,
     *   and the whole point of a fuel gauge is that it is not a guess.
     * ⚠ Returns null below a floor — with a handful of entries the average is dominated by the schema
     *   and page overhead, and a confident wrong number is worse than an honest absence.
     *
     * @return array{bytes_per_entry:int, entries_remaining:int}|null
     */
    public function charge(): ?array
    {
        $n = $this->size();
        if ($n < 32) return null;
        $per = max(1, intdiv($this->bytes(), $n));
        return ['bytes_per_entry' => $per,
                'entries_remaining' => max(0, intdiv(self::MAX_DB_BYTES - $this->bytes(), $per))];
    }

    /** Bytes on disk. ⚠ Under WAL the newest writes are in -wal, so counting the .db alone under-reads. */
    public function bytes(): int
    {
        clearstatcache();                                   // ⚠ filesize() is cached; stale here is wrong
        $t = 0;
        foreach (['', '-wal'] as $suffix)
            if (is_file($this->path . $suffix)) $t += (int)filesize($this->path . $suffix);
        return $t;
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
     * BEGIN IMMEDIATE — see the note in append(). Every writing transaction must use this.
     *
     * ⚠⚠ AND SO MUST ITS COMMIT AND ITS ROLLBACK. Do NOT mix `exec('BEGIN IMMEDIATE')` with PDO's
     *   `commit()` / `rollBack()` / `inTransaction()`: those track PDO's OWN flag, which a manual BEGIN
     *   never sets. Whether that matters is VERSION-DEPENDENT — PHP 8.5's PDO_SQLITE answers
     *   `inTransaction()` from SQLite's autocommit state and forgives the mix, and 8.1 does not.
     *   ⇒ MEASURED 30 Aug: every append on a PHP 8.1 host died in `commit()` with
     *   "There is no active transaction" — a PDOException carrying NO errorInfo, which is what a
     *   transaction-state error looks like and is how it was finally identified. It passed locally on
     *   8.5 throughout, 264/264. ★ A green test on a path the host does not take.
     */
    private function begin(): void  { $this->db->exec('BEGIN IMMEDIATE'); }
    private function commit(): void { $this->db->exec('COMMIT'); }
    private function rollback(): void { try { $this->db->exec('ROLLBACK'); } catch (Throwable) {} }

    /**
     * Append one entry. ⚠ Returns its sequence number.
     * Writes exactly the nodes that BECAME COMPLETE — at most log(n) of them.
     */
    public function append(string $body, ?string $genesis = null, ?string $prev = null): int
    {
        // ⚠⚠ BEGIN IMMEDIATE, NOT beginTransaction(). PDO issues a plain BEGIN, which is DEFERRED:
        //    the write lock is not taken until the first INSERT, but size() is READ before it. Under
        //    WAL, if another appender commits in that gap, SQLite returns SQLITE_BUSY_SNAPSHOT — and
        //    busy_timeout CANNOT retry that one, because retrying a stale snapshot cannot help.
        //    ⇒ Measured 25 Aug: 8 concurrent appenders, 183 of 200 appends lost to 'database is
        //    locked'. IMMEDIATE takes the write lock up front so busy_timeout can actually wait.
        //    ★ The tree was never corrupted either way — seq is a PRIMARY KEY, so the race could only
        //    ever refuse, not corrupt. This is an availability fix, not an integrity one.
        // ⚠ Checked BEFORE the write lock: refusing early costs nothing, and refusing late holds a lock
        //   while doing it. ⇒ The overshoot is one entry, which is 341 bytes.
        if ($this->bytes() >= self::MAX_DB_BYTES)
            throw new LogFullException('log is at its storage ceiling: ' . self::MAX_DB_BYTES . ' bytes');
        $this->begin();
        try {
            // ⚠ INSIDE the write lock: the tip is ticked by this entry, and no other entry may tick the same tip
            //   (§4.4). Checked before the lock, two writers could both pass and both land.
            if ($genesis !== null && $prev !== null) {
                $tip = $this->tipHashOf($genesis);
                if ($tip !== null && $tip !== $prev) throw new TipTickedException('tip already ticked: the entry does not name the thread\'s tip');
            }
            $seq = $this->size();
            $leaf = mt_leaf_hash($body);
            $this->db->prepare('INSERT INTO entries (seq, hash, body, genesis, ts) VALUES (?,?,?,?,?)')
                     ->execute([$seq, $leaf, $body, $genesis, time()]);
            $this->db->prepare('INSERT INTO nodes (level, idx, hash) VALUES (0,?,?)')
                     ->execute([$seq, $leaf]);
            if ($genesis !== null) $this->db->prepare('INSERT OR REPLACE INTO tips (genesis, seq, hash) VALUES (?,?,?)')
                                            ->execute([$genesis, $seq, hash('sha256', hash('sha256', $body, true), true)]);

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
            $this->commit();
            return $seq;
        } catch (Throwable $e) {
            // ⚠⚠ NEVER LET THE ROLLBACK EAT THE DIAGNOSIS. A rollback that throws replaces the original
            //   exception, and you then debug the mask. ⇒ rollback() swallows its own failure only.
            $this->rollback();
            throw $e;
        }
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
            // ⚠ PRUNED. The leaf is gone and cannot be recomputed without the body (§5c.2). Say so
            //   plainly rather than returning something wrong.
            if ($h === null) throw new PrunedException("leaf $lo has been pruned — fetch the body and restore it");
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
    /**
     * ★★ PRUNE — spec §5c. Discard entry bodies below $upTo, and tree nodes below $level for the
     * ranges they cover. Keeps subtree roots at $level, so K = 2^$level entries share one node.
     *
     * ⚠⚠ THE CALLER MUST HAVE ANCHORED $upTo FIRST (§6.2a). Between broadcast and depth a
     *    reorganisation can remove the anchor, and bodies discarded against a commitment that no
     *    longer exists cannot be recovered. This method cannot check that and does not try.
     *
     * ⚠ A node is removed only if the range it covers lies ENTIRELY below $upTo. A node straddling
     *   the boundary is still needed by the unpruned side.
     * @return array{bodies:int,nodes:int} what was discarded
     */
    public function prune(int $level, int $upTo): array
    {
        if ($level < 1) throw new InvalidArgumentException('prune level must be >= 1');
        if ($upTo < 0 || $upTo > $this->size()) throw new InvalidArgumentException('upTo outside the log');
        $this->begin();
        try {
            $b = $this->db->prepare('UPDATE entries SET body = X\'\' WHERE seq < ? AND length(body) > 0');
            $b->execute([$upTo]);
            $bodies = $b->rowCount();
            // levels 0..level-1: a node at (L,i) covers [i*2^L, (i+1)*2^L)
            $nodes = 0;
            for ($L = 0; $L < $level; $L++) {
                $span = 1 << $L;
                $maxIdx = intdiv($upTo, $span);          // ⚠ strictly-below: idx*span + span <= upTo
                $st = $this->db->prepare('DELETE FROM nodes WHERE level = ? AND idx < ?');
                $st->execute([$L, $maxIdx]);
                $nodes += $st->rowCount();
            }
            $this->db->prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (\'prune_level\', ?)')->execute([(string)$level]);
            $this->db->prepare('INSERT OR REPLACE INTO meta (k,v) VALUES (\'pruned_to\', ?)')->execute([(string)$upTo]);
            $this->commit();
            return ['bodies' => $bodies, 'nodes' => $nodes];
        } catch (Throwable $e) { $this->rollback(); throw $e; }
    }

    public function pruneState(): array
    {
        $g = fn(string $k) => (int)($this->db->query("SELECT v FROM meta WHERE k='$k'")->fetchColumn() ?: 0);
        return ['level' => $g('prune_level'), 'to' => $g('pruned_to')];
    }

    /** ⚠ Restore bodies fetched back from wherever they were offloaded, so a proof can be rebuilt. */
    public function restore(int $seq, string $body): void
    {
        // ★ the leaf hash is the check: a body that does not hash to the stored leaf is not the body
        $st = $this->db->prepare('SELECT hash FROM entries WHERE seq=?');
        $st->execute([$seq]);
        $leaf = $st->fetchColumn();
        if ($leaf === false) throw new RuntimeException("no entry at $seq");
        if (!hash_equals($leaf, mt_leaf_hash($body)))
            throw new RuntimeException("restored body for $seq does not match its leaf hash");
        $this->db->prepare('UPDATE entries SET body=? WHERE seq=?')->execute([$body, $seq]);
        // and put its leaf node back so proofs can be recomputed
        $this->db->prepare('INSERT OR REPLACE INTO nodes (level,idx,hash) VALUES (0,?,?)')->execute([$seq, $leaf]);
    }

    public function storedNodeCount(): int
    {
        return (int)$this->db->query('SELECT COUNT(*) FROM nodes')->fetchColumn();
    }
}
