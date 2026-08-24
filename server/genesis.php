<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// GENESIS REGISTRY — spec §2. ⏭ PROPOSED, not settled: §2's serialization is still an open item, and
// this is the smallest thing that lets the append rule work. Marked so it is revised deliberately.
//
// A covenant is "the thing descended from genesis G", never "the thing in log L". The registry answers
// exactly one question the append endpoint needs: ⇒ WHICH KEY MAY ADVANCE COVENANT G?
declare(strict_types=1);

final class GenesisRegistry
{
    public function __construct(private PDO $db) { $this->migrate(); }

    private function migrate(): void
    {
        // ⚠ `authorised` is a JSON array of hex public keys, or the literal string "open" (spec §4.2).
        //   ⚠ It is IMMUTABLE once written: a genesis that could change who may advance it would not
        //   be a genesis. There is deliberately no UPDATE path.
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS genesis (
                id          BLOB PRIMARY KEY,   -- sha256d of the commitment bytes
                commitment  BLOB NOT NULL,      -- the canonical bytes, whatever §2 settles on
                source_hash BLOB NOT NULL,      -- H(AST) of the BASIC source (spec §7)
                script      BLOB NOT NULL,
                state       BLOB NOT NULL,      -- the initial state
                authorised  TEXT NOT NULL,      -- JSON: ["<hex pubkey>", ...] or "open"
                anchor_txid BLOB                -- ⏭ the proof-of-work timestamp (spec §4d), if known
            ) WITHOUT ROWID;
        ');
    }

    /** ⏭ PROPOSED commitment layout. Canonical by construction: fixed order, length-prefixed, no options. */
    public static function commitmentBytes(array $g): string
    {
        $lp = fn(string $b) => pack('N', strlen($b)) . $b;      // 4-byte big-endian length prefix
        return $lp($g['source_hash']) . $lp($g['script']) . $lp($g['state']) . $lp($g['authorised']);
    }
    public static function idOf(array $g): string
    {
        return hash('sha256', hash('sha256', self::commitmentBytes($g), true), true);
    }

    /** @return string the genesis id */
    public function register(array $g): string
    {
        foreach (['source_hash','script','state','authorised'] as $k)
            if (!isset($g[$k])) throw new InvalidArgumentException("genesis missing $k");
        $id = self::idOf($g);
        // ⚠ INSERT OR IGNORE, never REPLACE. Re-registering the same genesis is harmless and idempotent;
        //   overwriting one would silently change who may advance a live covenant.
        $st = $this->db->prepare('INSERT OR IGNORE INTO genesis
            (id, commitment, source_hash, script, state, authorised, anchor_txid) VALUES (?,?,?,?,?,?,?)');
        $st->execute([$id, self::commitmentBytes($g), $g['source_hash'], $g['script'], $g['state'],
                      $g['authorised'], $g['anchor_txid'] ?? null]);
        return $id;
    }

    public function get(string $id): ?array
    {
        $st = $this->db->prepare('SELECT * FROM genesis WHERE id=?');
        $st->execute([$id]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * ⇒ THE ONLY QUESTION THE APPEND RULE ASKS (spec §4.1, §4.2).
     * @return string[]|'open'|null  hex public keys, the literal 'open', or null if unknown
     */
    public function authorisedFor(string $id): array|string|null
    {
        $row = $this->get($id);
        if ($row === null) return null;
        $a = json_decode($row['authorised'], true);
        return $a === 'open' ? 'open' : (is_array($a) ? $a : null);
    }
}
