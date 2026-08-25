<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// SIGNED TREE HEAD — spec §5.2. ⏭ PROPOSED, not settled.
//
// ⚠ A head is the operator SIGNING what it holds. That is the middle rung of §4c: witnessed (the log
//   has it, final immediately) → SIGNED (publicly committed, so equivocation becomes provable) →
//   anchored (dated by proof of work, cannot be walked back).
//   ⇒ It is NOT a confirmation of anything. The entries were already final when they were appended.
//
// ⚠⚠ ONCE PUBLISHED, A HEAD IS IMMUTABLE (spec §5.2). Two heads signed at the same size with different
//    roots are the operator's own evidence of equivocation — which is the whole security model. An
//    implementation that re-signs a size has destroyed it.
declare(strict_types=1);
require_once __DIR__ . '/merkle.php';

final class SignedHead
{
    public const VERSION = 1;
    /** ⚠ 122 bytes since 25 Aug — `log_id` was added. Nothing had shipped, so the format was free. */
    public const SIZE = 122;

    /**
     * ⚠ CANONICAL: fixed field order, fixed widths, no optional fields. A head with two encodings
     *   could be signed as one thing and read as another.
     *
     *   version      1 byte
     *   log_id      32 bytes — ★★★ HASH256(genesis ‖ branch): WHICH HISTORY THIS HEAD IS FOR.
     *                ⚠⚠ Added 25 Aug, and the reason is that WITHOUT IT THE EQUIVOCATION DETECTOR
     *                CANNOT WORK. One operator key runs many branches, so two heads signed by that
     *                key at one tree size with different roots are either a LIE or a FORK — and
     *                nothing in the bytes said which. §4bis.4 asked the detector to take
     *                (genesis, branch, key); a caller cannot supply what the heads do not carry.
     *                ★ A reader checks it against the chain: the branch's anchor covenant carries
     *                `genesis` and `branch` in its PushDrop state, so hash them and compare.
     *   tree_size    8 bytes big-endian
     *   root        32 bytes
     *   timestamp    8 bytes big-endian, unix seconds — ⚠ THE OPERATOR'S CLOCK, and a CLAIM, not a fact.
     *                Anyone may compare it against the anchor; nothing depends on it being honest.
     *   anchor_root 32 bytes — the last ANCHORED root, or 32 zero bytes if none yet
     *   anchor_size  8 bytes big-endian — the tree size at that anchored root
     *   prune_level  1 byte  — ⚠ PER LOG, his call. Retention granularity as a LEVEL: the operator
     *                keeps subtree roots at this level for pruned regions, so K = 2^level.
     *                0 means nothing is pruned. ⇒ Held in the HEAD rather than in a policy document
     *                because a client verifying an OLD proof needs the value that applied THEN, and
     *                heads are immutable and never discarded (§5c.1) — so the answer is always there.
     */
    public static function bytes(int $size, string $root, int $ts, string $anchorRoot = '', int $anchorSize = 0, int $pruneLevel = 0, string $logId = ''): string
    {
        if (strlen($root) !== 32) throw new InvalidArgumentException('root must be 32 bytes');
        /* ⚠ 32 zero bytes means "this log has not declared its identity" — legal, and a detector
           MUST treat two such heads as UNCOMPARABLE rather than as the same branch. */
        $logId = $logId === '' ? str_repeat("\x00", 32) : $logId;
        if (strlen($logId) !== 32) throw new InvalidArgumentException('log id must be 32 bytes');
        $anchorRoot = $anchorRoot === '' ? str_repeat("\x00", 32) : $anchorRoot;
        if (strlen($anchorRoot) !== 32) throw new InvalidArgumentException('anchor root must be 32 bytes');
        if ($pruneLevel < 0 || $pruneLevel > 63) throw new InvalidArgumentException('prune level out of range');
        return chr(self::VERSION) . $logId . pack('J', $size) . $root . pack('J', $ts)
             . $anchorRoot . pack('J', $anchorSize) . chr($pruneLevel);
    }

    public static function parse(string $b): array
    {
        if (strlen($b) !== self::SIZE) throw new InvalidArgumentException('a head is exactly ' . self::SIZE . ' bytes');
        $v = ord($b[0]);
        if ($v !== self::VERSION) throw new InvalidArgumentException("unknown head version $v");
        $logId = substr($b, 1, 32);
        $anchorRoot = substr($b, 81, 32);
        return [
            'version'     => $v,
            /* ⚠ null means the log has not declared which history this is. A detector MUST treat two
               such heads as UNCOMPARABLE — not as the same branch. */
            'log_id'      => $logId === str_repeat("\x00", 32) ? null : $logId,
            'tree_size'   => unpack('J', substr($b, 33, 8))[1],
            'root'        => substr($b, 41, 32),
            'timestamp'   => unpack('J', substr($b, 73, 8))[1],
            'anchor_root' => $anchorRoot === str_repeat("\x00", 32) ? null : $anchorRoot,
            'anchor_size' => unpack('J', substr($b, 113, 8))[1],
            'prune_level' => ord($b[121]),
            'prune_k'     => ord($b[121]) === 0 ? 0 : 1 << ord($b[121]),
        ];
    }

    /** ⚠ Key length selects the scheme, as with the append rule: 32 ⇒ Ed25519, 33/65 ⇒ secp256k1. */
    public static function verify(string $head, string $pubkey, string $sig): bool
    {
        require_once __DIR__ . '/append.php';
        return Appender::verifySignature($head, $pubkey, $sig);
    }
}

final class HeadStore
{
    public function __construct(private PDO $db) {
        // ⚠ tree_size is the PRIMARY KEY, deliberately. It makes re-signing a size impossible by
        //   construction rather than by discipline — the operator cannot quietly replace a head.
        $this->db->exec('CREATE TABLE IF NOT EXISTS heads (
            tree_size INTEGER PRIMARY KEY, head BLOB NOT NULL, sig BLOB NOT NULL, pubkey BLOB NOT NULL
        ) WITHOUT ROWID;');
    }

    /** @throws RuntimeException if a head already exists at this size — see the note above. */
    public function publish(string $head, string $sig, string $pubkey): void
    {
        $p = SignedHead::parse($head);
        if (!SignedHead::verify($head, $pubkey, $sig)) throw new RuntimeException('head signature does not verify');
        $st = $this->db->prepare('INSERT INTO heads (tree_size, head, sig, pubkey) VALUES (?,?,?,?)');
        try { $st->execute([$p['tree_size'], $head, $sig, $pubkey]); }
        catch (PDOException $e) {
            throw new RuntimeException("a head is already published at size {$p['tree_size']} — heads are immutable (spec §5.2)");
        }
    }

    public function latest(): ?array
    {
        $r = $this->db->query('SELECT head, sig, pubkey FROM heads ORDER BY tree_size DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }
    public function at(int $size): ?array
    {
        $st = $this->db->prepare('SELECT head, sig, pubkey FROM heads WHERE tree_size=?');
        $st->execute([$size]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }
}
