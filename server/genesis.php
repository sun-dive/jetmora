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

    /**
     * ⚠⚠ AUTHORISED IS PACKED, NEVER JSON — spec §2, §4.2a.
     *
     * It was `json_encode($auth)` until 30 Aug, and that put a JSON encoder's whitespace and key order
     * inside the bytes a covenant's IDENTITY is hashed from. ⇒ ON CHAIN IS ALWAYS PACKED BYTES. The rule
     * was already written down; this field was the one place that broke it.
     *
     *   open       0x00
     *   threshold  0x01 ‖ k ‖ n ‖ (len ‖ key) × n      keys ASCENDING by raw bytes, no duplicates
     *
     * ★ Sorting is not tidiness — it is what makes the encoding canonical. Before this, `[a,b]` and
     *   `[b,a]` were DIFFERENT COVENANTS. Now they are the same one, which is what anybody meant.
     * ★ And a bare list is simply k=1, so a 1-of-n set has exactly ONE encoding, never two.
     */
    public static function packAuthorised(mixed $auth): string
    {
        if ($auth === 'open') return "\x00";
        if (!is_array($auth)) throw new InvalidArgumentException('authorised must be a list or "open"');

        if (array_is_list($auth)) { $k = 1; $keys = $auth; }
        else {
            $k = $auth['threshold'] ?? null; $keys = $auth['keys'] ?? null;
            if (!is_int($k) || !is_array($keys) || !array_is_list($keys))
                throw new InvalidArgumentException('authorised object must be {threshold:int, keys:[…]}');
        }

        $raw = [];
        foreach ($keys as $hex) {
            if (!is_string($hex) || !preg_match('/^[0-9a-fA-F]+$/', $hex) || strlen($hex) % 2)
                throw new InvalidArgumentException('authorised key is not hex');
            $b = hex2bin(strtolower($hex));
            // ⚠ 32 ⇒ Ed25519 · 33/65 ⇒ secp256k1. Anything else is not a key we can ever verify against.
            if (!in_array(strlen($b), [32, 33, 65], true))
                throw new InvalidArgumentException('authorised key must be 32, 33 or 65 bytes');
            $raw[] = $b;
        }
        sort($raw, SORT_STRING);                                   // ★ canonical order
        if (count(array_unique($raw, SORT_STRING)) !== count($raw))
            throw new InvalidArgumentException('duplicate key in authorised');

        $n = count($raw);
        if ($n < 1 || $n > 255)  throw new InvalidArgumentException('authorised needs 1..255 keys');
        if ($k < 1 || $k > $n)   throw new InvalidArgumentException('threshold must be 1..n');

        $out = "\x01" . chr($k) . chr($n);
        foreach ($raw as $b) $out .= chr(strlen($b)) . $b;
        return $out;
    }

    /** @return array{k:int, keys:string[]}|'open'|null  keys as lowercase hex */
    public static function unpackAuthorised(string $b): array|string|null
    {
        if ($b === "\x00") return 'open';
        if (strlen($b) < 3 || $b[0] !== "\x01") return null;
        $k = ord($b[1]); $n = ord($b[2]); $o = 3; $keys = [];
        for ($i = 0; $i < $n; $i++) {
            if ($o >= strlen($b)) return null;
            $len = ord($b[$o]); $o++;
            if ($o + $len > strlen($b)) return null;
            $keys[] = bin2hex(substr($b, $o, $len)); $o += $len;
        }
        if ($o !== strlen($b)) return null;                        // ⚠ trailing bytes are not canonical
        return ['k' => $k, 'keys' => $keys];
    }

    /** Canonical by construction: fixed order, length-prefixed, no options, no JSON. */
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
        // ⚠ Stored PACKED since 30 Aug. A row written before that is not readable here and is treated as
        //   unknown rather than guessed at — the alternative is a JSON fallback whose bytes never matched
        //   the id anyway. Only throwaway test genesis records existed at the change.
        return self::unpackAuthorised($row['authorised']);
    }
}
