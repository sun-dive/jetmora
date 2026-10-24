<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// THE APPEND RULE: spec §4.1, §3.3. ⚠⚠ THE WHOLE POINT IS HOW LITTLE THIS DOES.
//
//   1. the entry is well-formed and CANONICALLY serialized
//   2. it is signed by a key the covenant's genesis names
//   3. it names the thread's tip: a second entry naming a tip already ticked is invalid (§4.4), not a
//      rival to choose between
//   4. it spends an output of that tip that exists, and that output's locking script, run against the tick,
//      accepts it (§3.3). A tick the script refuses is not recorded (his ruling, 23 Oct).
//
// ⚠ AND NOTHING ELSE. Steps 1 and 2 are what this host admits; from step 3 on, no rule is the service's own
//   and nothing is adjudicated: every refusal is the script's verdict or what a node refuses with a spend.
//   A thread service is a witness; it records what the script accepts. That is consensus of a kind: between
//   the parties to a thread, who need not trust each other, because each can run the same script and reach
//   the same verdict. It is not a global consensus among strangers who care nothing for the tick. A rule
//   here that is not in the script would end it: the parties could no longer check the service's answer.
//
// ⚠⚠ TWO SIGNATURES EXIST AND THEY ARE NOT THE SAME THING — a distinction the spec should state:
//   · the covenant's INTERNAL CHECKSIG (OP_PUSH_TX) proves the STATE TRANSITION is what the program
//     permits. ⇒ It runs inside the script, at step 4.
//   · the APPEND AUTHORISATION signature proves WHO SUBMITTED this. ⇒ Step 2.
//   Neither stands in for the other: a good append signature does not make a transition permitted.
//
// ⚠ PAYMENT IS NOT HERE AND MUST NOT BE (spec §3.4-0b). The operator's billing hooks in through
//   $authorise; the protocol defines no price, no currency and no settlement.
declare(strict_types=1);
require_once __DIR__ . '/secp256k1.php';
require_once __DIR__ . '/store.php';
require_once __DIR__ . '/genesis.php';
require_once __DIR__ . '/covenant-entry.php';

final class AppendResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly ?int $seq = null,
        public readonly ?string $error = null,
        public readonly int $status = 200,
        /** When the script refused the tick: its reason, as the interpreter gave it. Bytes, not always UTF-8. */
        public readonly ?string $reason = null,
    ) {}
}

final class Appender
{
    /** @param null|callable(string,string):bool $authorise operator policy hook: (genesisId, pubkey) => bool */
    public function __construct(
        private ThreadStore $store,
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
        //    describe what they did. ⇒ Decode, re-encode, require the same bytes. The decoder also
        //    refuses the shape the first test chain had (no unlocking script): a log tick is not a
        //    covenant tick, and this service records covenant ticks.
        if ($entry === '') return new AppendResult(false, null, 'empty entry', 400);
        if (strlen($entry) > 100_000) return new AppendResult(false, null, 'entry too large', 413);
        try { $canonical = CovenantEntry::encode(CovenantEntry::decode($entry)) === $entry; }
        catch (CovenantEntryError $e) { return new AppendResult(false, null, 'not a covenant entry: ' . $e->getMessage(), 400); }
        if (!$canonical) return new AppendResult(false, null, 'entry is not canonically serialized', 400);

        // ── 2. who may append (spec §4.2) ────────────────────────────────────────────────────
        $auth = $this->registry->authorisedFor($genesisId);
        if ($auth === null) return new AppendResult(false, null, 'unknown genesis', 404);
        $hexKey = bin2hex($pubkey);
        if ($auth !== GenesisRegistry::AUTH_OPEN) {
            // ⚠⚠ REFUSE k>1 RATHER THAN ACCEPT ONE SIGNATURE FOR IT. This endpoint carries a single
            //   signature, so a k-of-n covenant CANNOT be satisfied here. Letting one signature through
            //   would silently turn every threshold into 1-of-n — a hole, not a limitation.
            //   ⇒ 501: the covenant is well-formed and this server cannot honour it yet (spec §4.2a).
            $set = GenesisRegistry::unpackAuthorised($auth);
            if (($set['k'] ?? 1) > 1)
                return new AppendResult(false, null, 'k-of-n append is not implemented; this endpoint carries one signature', 501);
            if (!GenesisRegistry::isAuthorised($auth, $pubkey))
                return new AppendResult(false, null, 'key not authorised for this covenant', 403);
        }

        // ── operator policy: a price, an account, a rate limit (spec §4.5). NOT a validity check. ──
        if ($this->authorise !== null && !($this->authorise)($genesisId, $hexKey))
            return new AppendResult(false, null, 'refused by operator policy', 402);

        if (!self::verifySignature($entry, $pubkey, $signature))
            return new AppendResult(false, null, 'bad signature', 403);

        // ── 3. the tip (spec §4.4, his ruling 23 Sept) ─────────────────────────────────────────
        //    An entry TICKS the tip it names (input 0). A tip ticked twice is impossible by design, as a
        //    spent outpoint is gone on Bitcoin: the second entry is not a competing valid entry to be
        //    adjudicated, it is invalid. One writer, one tip, one home: no ordering rule, no global consensus.
        //    The check runs before the script, so a stale tick is refused without running it, and again
        //    inside the store's write lock, so two writers cannot both pass.
        $tick = CovenantEntry::decode($entry);
        $prev = $tick['inputs'][0]['prevEntry'];
        try { $this->store->checkTip($genesisId, $prev); }
        catch (TipTickedException $e) { return new AppendResult(false, null, $e->getMessage(), 409); }
        // ⏭ A tick spending several outputs needs each input judged. This host judges input 0 only, so it
        //   gives no verdict rather than judge one input of several (spec §3.3).
        if (count($tick['inputs']) > 1)
            return new AppendResult(false, null, 'not built yet: this host judges input 0 only', 501);

        // ── 4. the script decides (spec §3.3, his ruling 23 Oct) ─────────────────────────────────────
        $refused = $this->judge($genesisId, $tick);
        if ($refused !== null) return $refused;

        try { return new AppendResult(true, $this->store->append($entry, $genesisId, $prev)); }
        catch (TipTickedException $e) { return new AppendResult(false, null, $e->getMessage(), 409); }
    }

    /**
     * Judge input 0 of a tick that names the thread's tip, as a node judges a spend: the output it spends must
     * exist, and that output's locking script, run against the tick, decides. Returns null when the script
     * accepts it; otherwise the refusal (422), or why this host gives no verdict (501). Nothing is stored either way.
     */
    private function judge(string $genesisId, array $tick): ?AppendResult
    {
        // ⚠ The judge's files load here and nowhere else: a host missing one can break appends, never reads.
        require_once __DIR__ . '/wallet/jetmora/thread.php';
        $in = $tick['inputs'][0];
        $tipSeq = $this->store->tipOf($genesisId);
        if ($tipSeq === null && $in['prevEntry'] === $genesisId) {
            // The first tick spends the genesis. It has one output: the genesis script, with a value of zero.
            $outputs = [['locking' => $this->registry->get($genesisId)['script'], 'value' => str_repeat("\x00", 8)]];
        } else {
            // A later tick spends an output of the tip, read from the tip's body (kept whole: store.php).
            $body = $tipSeq === null ? null : $this->store->entry($tipSeq);
            if ($body === null || $body === '')
                return new AppendResult(false, null, 'no verdict: the output this tick spends is not held here', 501);
            if (CovenantEntry::hash($body) !== $in['prevEntry']) {
                // The tip moved after the check in append(): another tick spent this output first.
                try { $this->store->checkTip($genesisId, $in['prevEntry']); }
                catch (TipTickedException $e) { return new AppendResult(false, null, $e->getMessage(), 409); }
                return new AppendResult(false, null, 'no verdict: the output this tick spends is not held here', 501);
            }
            try { $outputs = CovenantEntry::decode($body)['outputs']; }
            catch (CovenantEntryError) { return new AppendResult(false, null, 'no verdict: the tip held here does not decode', 501); }
        }
        // A node refuses a spend of an output that was never made.
        $spent = $outputs[$in['index']] ?? null;
        if ($spent === null)
            return new AppendResult(false, null, "the tip has no output {$in['index']} to spend", 422);

        // ⚠ No verdict is not a refusal: a host without the interpreter the tick names, or a library it needs,
        //   says so and records nothing, so no tick is refused here and accepted on another host.
        try { $v = CovenantThread::judge($tick, 0, $spent['locking'], $spent['value']); }
        catch (VersionError | JfHostError $e) { return new AppendResult(false, null, 'no verdict: ' . $e->getMessage(), 501); }
        if ($v['accepted']) return null;
        return new AppendResult(false, null, 'the script refused this tick', 422,
                                $v['error'] ?? 'the script did not end with exactly one non-zero item');
    }

    /**
     * ⚠ Key length selects the scheme: 32 bytes ⇒ Ed25519 · 33 or 65 bytes ⇒ secp256k1.
     *
     * ⚠⚠ secp256k1 WAS verified through `openssl_verify` and is now verified by `Secp256k1`, which
     * depends on nothing. ⇒ Two reasons, and the second is the bigger one:
     *   1. The chain core must give the same answer on every host forever. A system crypto library is
     *      the wrong thing for that to rest on — it varies by build, and its absence silently turned
     *      every secp256k1 signature into a REFUSAL rather than an error.
     *   2. ⚖ A dependency you have to argue about is an attack surface even when the argument is
     *      sound. Removing it is cheaper than winning it.
     *
     * ⚠⚠⚠ THE TRAP IN THIS SWAP, AND IT WAS MEASURED, NOT GUESSED:
     *   `openssl_verify(..., OPENSSL_ALGO_SHA256)` HASHES the message internally; `verifyDigest` takes
     *   the digest already computed. Hence the explicit `hash('sha256', ...)` below — without it every
     *   existing signature fails, and with the direction reversed invalid ones could pass.
     *   ⇒ `server/verify-secp256k1.php` sweeps 200 keypairs x 9 cases against openssl as an ORACLE and
     *     requires total agreement. It caught a real divergence on the first run: our DER parser
     *     tolerated a trailing byte that openssl refused.
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
            // ⚠ STRICT DER: a chain entry signature carries no sighash-type byte, so nothing may follow
            //   the sequence. That leniency belongs to Bitcoin signatures and is opt-in, not default.
            return Secp256k1::verifyDigest($sig, $pubkey, hash('sha256', $msg, true));
        }
        return false;
    }
}
