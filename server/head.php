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

    /**
     * ⚠ CANONICAL: fixed field order, fixed widths, no optional fields. A head with two encodings
     *   could be signed as one thing and read as another.
     *
     *   version      1 byte
     *   tree_size    8 bytes big-endian
     *   root        32 bytes
     *   timestamp    8 bytes big-endian, unix seconds — ⚠ THE OPERATOR'S CLOCK, and a CLAIM, not a fact.
     *                Anyone may compare it against the anchor; nothing depends on it being honest.
     *   anchor_root 32 bytes — the last ANCHORED root, or 32 zero bytes if none yet
     *   anchor_size  8 bytes big-endian — the tree size at that anchored root
     */
    public static function bytes(int $size, string $root, int $ts, string $anchorRoot = '', int $anchorSize = 0): string
    {
        if (strlen($root) !== 32) throw new InvalidArgumentException('root must be 32 bytes');
        $anchorRoot = $anchorRoot === '' ? str_repeat("\x00", 32) : $anchorRoot;
        if (strlen($anchorRoot) !== 32) throw new InvalidArgumentException('anchor root must be 32 bytes');
        return chr(self::VERSION) . pack('J', $size) . $root . pack('J', $ts) . $anchorRoot . pack('J', $anchorSize);
    }

    public static function parse(string $b): array
    {
        if (strlen($b) !== 89) throw new InvalidArgumentException('a head is exactly 89 bytes');
        $v = ord($b[0]);
        if ($v !== self::VERSION) throw new InvalidArgumentException("unknown head version $v");
        $anchorRoot = substr($b, 49, 32);
        return [
            'version'     => $v,
            'tree_size'   => unpack('J', substr($b, 1, 8))[1],
            'root'        => substr($b, 9, 32),
            'timestamp'   => unpack('J', substr($b, 41, 8))[1],
            'anchor_root' => $anchorRoot === str_repeat("\x00", 32) ? null : $anchorRoot,
            'anchor_size' => unpack('J', substr($b, 81, 8))[1],
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
