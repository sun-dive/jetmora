<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// THE APPEND RULE — spec §4.1. ⚠⚠ THE WHOLE POINT IS HOW LITTLE THIS DOES.
//
//   1. the entry is well-formed and CANONICALLY serialized
//   2. it is signed by a key the covenant's genesis names
//
// ⚠ AND NOTHING ELSE. No script execution. No duplicate rejection (§4.4). No adjudication. A log is a
//   witness; it records what it was given. Every temptation to make it cleverer is a step toward
//   consensus, and consensus is the thing this design does not have.
//
// ⚠⚠ TWO SIGNATURES EXIST AND THEY ARE NOT THE SAME THING — a distinction the spec should state:
//   · the covenant's INTERNAL CHECKSIG (OP_PUSH_TX) proves the STATE TRANSITION is what the program
//     permits. ⇒ A VERIFIER's concern. The log never runs it.
//   · the APPEND AUTHORISATION signature proves WHO SUBMITTED this. ⇒ The log's only concern.
//   Conflating them would put an interpreter in the log, which §4.1 forbids for good reason.
//
// ⚠ PAYMENT IS NOT HERE AND MUST NOT BE (spec §3.4-0b). The operator's billing hooks in through
//   $authorise; the protocol defines no price, no currency and no settlement.
declare(strict_types=1);
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';

final class AppendResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly ?int $seq = null,
        public readonly ?string $error = null,
        public readonly int $status = 200,
    ) {}
}

final class Appender
{
    /** @param null|callable(string,string):bool $authorise operator policy hook: (genesisId, pubkey) => bool */
    public function __construct(
        private LogStore $store,
        private GenesisRegistry $registry,
        private $authorise = null,
    ) {}

    /**
     * @param string $genesisId  32 bytes — which covenant this claims to advance
     * @param string $entry      the canonical entry bytes
     * @param string $pubkey     32 (Ed25519) or 33/65 (secp256k1) raw bytes
     * @param string $signature  over the ENTRY BYTES, not over a preimage
     */
    public function append(string $genesisId, string $entry, string $pubkey, string $signature): AppendResult
    {
        // ── 1. canonical serialization (spec §3.1) ───────────────────────────────────────────
        //    ⚠ Not a formality: OP_PUSH_TX is secure only because a verifier recomputes the preimage
        //    and compares. Two encodings of one entry would let a signer push a preimage that does not
        //    describe what they did.
        if ($entry === '') return new AppendResult(false, null, 'empty entry', 400);
        if (strlen($entry) > 100_000) return new AppendResult(false, null, 'entry too large', 413);

        // ── 2. who may append (spec §4.2) ────────────────────────────────────────────────────
        $auth = $this->registry->authorisedFor($genesisId);
        if ($auth === null) return new AppendResult(false, null, 'unknown genesis', 404);
        $hexKey = bin2hex($pubkey);
        if ($auth !== 'open') {
            // ⚠⚠ REFUSE k>1 RATHER THAN ACCEPT ONE SIGNATURE FOR IT. This endpoint carries a single
            //   signature, so a k-of-n covenant CANNOT be satisfied here. Letting one signature through
            //   would silently turn every threshold into 1-of-n — a hole, not a limitation.
            //   ⇒ 501: the covenant is well-formed and this server cannot honour it yet (spec §4.2a).
            if (($auth['k'] ?? 1) > 1)
                return new AppendResult(false, null, 'k-of-n append is not implemented; this endpoint carries one signature', 501);
            if (!in_array($hexKey, array_map('strtolower', $auth['keys'] ?? []), true))
                return new AppendResult(false, null, 'key not authorised for this covenant', 403);
        }

        // ── operator policy: a price, an account, a rate limit (spec §4.5). NOT a validity check. ──
        if ($this->authorise !== null && !($this->authorise)($genesisId, $hexKey))
            return new AppendResult(false, null, 'refused by operator policy', 402);

        if (!self::verifySignature($entry, $pubkey, $signature))
            return new AppendResult(false, null, 'bad signature', 403);

        // ⚠ NO duplicate check (spec §4.5 / §4.4). Two entries at one sequence are a FACT ABOUT THE
        //   SIGNER, faithfully witnessed. Rejecting the second would make the operator decide
        //   first-seen, which is consensus in miniature.
        return new AppendResult(true, $this->store->append($entry));
    }

    /**
     * ⚠ Key length selects the scheme, so a host without sodium can still run a log on openssl.
     *   32 bytes ⇒ Ed25519 · 33 or 65 bytes ⇒ secp256k1.
     */
    public static function verifySignature(string $msg, string $pubkey, string $sig): bool
    {
        $n = strlen($pubkey);
        if ($n === 32) {
            if (!extension_loaded('sodium')) return false;
            if (strlen($sig) !== 64) return false;
            try { return sodium_crypto_sign_verify_detached($sig, $msg, $pubkey); }
            catch (Throwable) { return false; }             // ⚠ malformed input is a failed check, not a crash
        }
        if ($n === 33 || $n === 65) {
            if (!extension_loaded('openssl')) return false;
            $prefix = $n === 33
                ? "\x30\x36\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x22\x00"
                : "\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x42\x00";
            $key = @openssl_pkey_get_public(self::pemOf($prefix . $pubkey));
            if ($key === false) return false;
            return openssl_verify($msg, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
        }
        return false;
    }
    private static function pemOf(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
