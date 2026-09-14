<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ UTXO SELECTION ═══════════════════════════════════════════════════════════════════════════════════
//
// ⚖⚖ **POLICY READ FROM ElectrumSV; NOTHING IMPORTED, NOTHING COPIED.** What crossed is a handful of
//   *facts about how coin selection behaves*, which are not anybody's expression.
//   ⚠⚠ **A LICENCE CLAIM I GOT WRONG, CORRECTED 8 Sept:** an earlier version of this comment said that
//   tree is "Open BSV licensed today". **It is not — ElectrumSV relicensed Open BSV → MIT in January
//   2024.** I read that from the LICENCE of a **1.3.15 tarball dated March 2023**, which predates the
//   change. ⇒ The conclusion (read, do not import) was his standing policy anyway and does not move —
//   but asserting someone else's licence from a stale copy is exactly the error this file warns about.
//   → [[own-wallet-sdk-position]]
//
// ★★★ THE FOUR RULES WORTH TAKING, and one number worth REFUSING:
//   | ✅ **the fee is circular** | it depends on the SIZE, which depends on which coins you picked ⇒ solved by iterating, never by one pass |
//   | ✅ **change below the floor becomes fee** | creating an output nobody will ever spend is worse than paying the miner |
//   | ✅ **spend a script's coins together** | partially spending an address publishes that the rest are yours anyway, so the privacy was already gone |
//   | ✅ **the floor applies to CHANGE ONLY** | ⇒ ElectrumSV never second-guesses the caller's own outputs, and neither does this |
//   | ⛔ **546 as a threshold** | ⚠ **BTC's number.** BSV dropped the dust limit at Genesis — see below |
//
// ⛔⛔⛔ WHY 546 IS **NOT** THE DEFAULT HERE, AND THIS IS NOT A DETAIL.
//   ElectrumSV hard-codes `dust_threshold = 546`. **Every covenant in this project uses 1-satoshi
//   outputs** — `satoshis: 1` in PharLap's breadcrumbs, editionBuilder's notify output, racerTx's
//   payees, and *"1-sat covenant/token outputs kept on chain"* in editionBuilder's own comment.
//   ⇒ A selector that imposed 546 would refuse or mangle **every transaction this repo builds.**
//   ⛔⛔ AND 546 IS NOT BSV RELAY POLICY EITHER — an earlier draft of this comment said it was, and
//     that was still wrong. **It is BITCOIN CORE's** dust threshold (`dustRelayFee` 3000 sat/kB over a
//     P2PKH output). ⚠⚠ **BSV REMOVED THE DUST LIMIT AT GENESIS (Feb 2020).**
//     ✅ **MEASURED 8 Sept 2026 against this project's OWN mainnet history:** three CONFIRMED
//     transactions carry **nine 1-satoshi outputs** between them, at **2,927–5,932 confirmations**.
//     ⇒ They relayed AND were mined. **There is no 546 floor on this chain to respect.**
//   ★ So `BTC_LEGACY_DUST` is kept ONLY so a reader recognises the number and does not re-import it.
//     The caller may still pass a higher threshold to avoid tiny change — that is a PREFERENCE, not a
//     network rule, and it is **never imposed on an output the caller asked for.**
//   → [[covenant-min-1-sat]] · How to work #4: *never add a restriction the system doesn't require.*
//
// ⚠⚠ THE SILENT FAILURE THIS FILE EXISTS TO PREVENT: **estimating the fee from the UNSIGNED size.**
//   An unsigned input carries an empty script; the signed one carries ~107 bytes. ⇒ The transaction is
//   well-formed, under-paid, and **simply never confirms** — with nothing in it to say why.
declare(strict_types=1);
require_once __DIR__ . '/transaction.php';

final class CoinError extends RuntimeException {}

final class Coins
{
  /**
   * ⛔⛔⛔ **THIS IS BTC's NUMBER AND IT DOES NOT APPLY TO BSV.** Named for its PROVENANCE, not for any
   * authority it has here — an earlier version of this file called it `RELAY_DUST`, which asserted
   * something false about BSV and is exactly the kind of borrowed restriction How to work #4 forbids.
   *
   * ★ 546 is Bitcoin Core's dust threshold (dustRelayFee 3000 sat/kB over a P2PKH output). ElectrumSV
   * hard-codes it. **BSV REMOVED THE DUST LIMIT AT GENESIS (Feb 2020).**
   * ✅ MEASURED 8 Sept 2026 against this project's OWN mainnet history: three confirmed transactions
   * carry **nine 1-satoshi outputs** between them, at 2,927–5,932 confirmations. ⇒ They relayed AND
   * were mined. **The real floor is 1, not 546.**
   * ⇒ Kept ONLY so a future reader recognises the number and does not re-import it as a rule.
   */
  public const BTC_LEGACY_DUST = 546;
  /**
   * ★★ THE ACTUAL FLOOR. A covenant output is 1 satoshi and must never be 0 — a zero-value output is
   * refused as dust before the script is evaluated at all. → [[covenant-min-1-sat]]
   */
  public const MIN_OUTPUT = 1;
  public const SAT_PER_KB = 100;                       // ★ official rate; never ARC's suggestion

  /** A signed P2PKH input: 32 txid + 4 vout + 1 varint + 107 scriptSig + 4 sequence. */
  public const P2PKH_INPUT  = 148;
  /** 8 value + 1 varint + 25 script. */
  public const P2PKH_OUTPUT = 34;

  /**
   * The size an input will occupy ONCE SIGNED.
   * ⚠⚠ `unlockingSize` is the caller's business for anything that is not P2PKH — a covenant's unlocking
   *   script can be hundreds of bytes, and guessing P2PKH for one under-pays the fee silently.
   */
  public static function inputSize(array $utxo): int
  {
    if (isset($utxo['unlockingSize'])) {
      $u = (int)$utxo['unlockingSize'];
      if ($u < 0) throw new CoinError('an unlocking script cannot have negative size');
      return 32 + 4 + strlen(BsvBytes::varint($u)) + $u + 4;
    }
    return self::P2PKH_INPUT;
  }

  public static function outputSize(string $script): int
  {
    return 8 + strlen(BsvBytes::varint(strlen($script))) + strlen($script);
  }

  /** ⚠ Rounded UP. A fee below the floor is a transaction that never confirms. */
  public static function fee(int $sizeBytes, int $satPerKb = self::SAT_PER_KB): int
  {
    return (int)ceil($sizeBytes * $satPerKb / 1000);
  }

  /**
   * Choose coins to fund `$outputs`.
   *
   * @param array $utxos    each ['txid'=>wire-order 32B, 'vout'=>int, 'value'=>int, 'script'=>string,
   *                              optionally 'unlockingSize'=>int]
   * @param array $outputs  each ['value'=>int, 'script'=>string] — ★ TAKEN AS GIVEN. A 1-satoshi
   *                        covenant output is not this function's business to question.
   * @param int   $dustThreshold applies ONLY to the change output we might create.
   * @return array{inputs:array,change:?int,fee:int,size:int,selected:int,target:int}
   */
  public static function select(array $utxos, array $outputs, string $changeScript = '',
                                int $satPerKb = self::SAT_PER_KB,
                                int $dustThreshold = self::MIN_OUTPUT): array
  {
    $target = 0;
    foreach ($outputs as $o) {
      if ($o['value'] < 0)                throw new CoinError('an output value cannot be negative');
      if ($o['value'] === 0)              throw new CoinError(
        'a 0-value output is refused as dust before the script is evaluated at all — use 1 satoshi');
      $target += $o['value'];
    }
    // ⚠ base size: version(4) + locktime(4) + both counts, and the counts GROW past 252 items
    $base = 8 + strlen(BsvBytes::varint(count($outputs)));
    foreach ($outputs as $o) $base += self::outputSize($o['script']);

    // ★ THE PRIVACY RULE, read from ElectrumSV: a script's coins are spent TOGETHER. Partially
    //   spending one publishes that the remainder is yours, so splitting buys nothing.
    $buckets = [];
    foreach ($utxos as $u) {
      if (($u['value'] ?? 0) <= 0) throw new CoinError('a UTXO must carry a positive value');
      $buckets[$u['script']][] = $u;
    }
    // ⚠ Largest bucket first: fewer inputs ⇒ a smaller transaction ⇒ a smaller fee. The cost is that
    //   small coins linger; consolidating them is a deliberate act, not something to do by surprise.
    $ordered = array_values($buckets);
    usort($ordered, fn($a, $b) => array_sum(array_column($b, 'value'))
                                <=> array_sum(array_column($a, 'value')));

    $chosen = []; $sum = 0; $size = $base + 1;      // +1 = the input-count varint, for now
    foreach ($ordered as $bucket) {
      foreach ($bucket as $u) { $chosen[] = $u; $sum += $u['value']; $size += self::inputSize($u); }
      // ⚠⚠ THE CIRCULARITY, resolved by re-asking after every bucket rather than assuming: the fee we
      //   must cover depends on the size we have only just changed.
      $size = $base + strlen(BsvBytes::varint(count($chosen)));
      foreach ($chosen as $c) $size += self::inputSize($c);
      if ($sum >= $target + self::fee($size, $satPerKb)) break;
    }

    $fee = self::fee($size, $satPerKb);
    if ($sum < $target + $fee)
      throw new CoinError(sprintf(
        'insufficient funds: %d satoshis available, %d needed (%d to spend + %d fee at %d sat/KB)',
        $sum, $target + $fee, $target, $fee, $satPerKb));

    // ── change ──────────────────────────────────────────────────────────────────────────────────────
    // ★ Adding a change output makes the transaction BIGGER, so it costs more fee — which can leave
    //   less change than the output is worth. ⇒ Ask with the output included, then decide.
    $change = null;
    if ($changeScript !== '') {
      $withChange = $size + self::outputSize($changeScript);
      // ⚠ the output COUNT varint can roll over to 3 bytes when change is the 253rd output
      $withChange += strlen(BsvBytes::varint(count($outputs) + 1))
                   - strlen(BsvBytes::varint(count($outputs)));
      $feeWith = self::fee($withChange, $satPerKb);
      $left    = $sum - $target - $feeWith;
      if ($left >= $dustThreshold && $left >= self::MIN_OUTPUT) {
        $change = $left; $fee = $feeWith; $size = $withChange;
      }
      // ⛔ else: the change is not worth its own output ⇒ it becomes fee. Creating an output nobody
      //   will ever profitably spend is worse than paying the miner, and it bloats the UTXO set.
      else { $fee = $sum - $target; }
    } else {
      $fee = $sum - $target;                      // ★ no change script ⇒ everything left is the fee
    }

    return ['inputs' => $chosen, 'change' => $change, 'fee' => $fee,
            'size' => $size, 'selected' => $sum, 'target' => $target];
  }

  /** Build the unsigned transaction a selection describes. ⚠ Change is appended LAST. */
  public static function build(array $sel, array $outputs, string $changeScript = '',
                               int $locktime = 0): BsvTx
  {
    $tx = new BsvTx(1, [], [], $locktime);
    foreach ($sel['inputs'] as $u)
      $tx->inputs[] = ['txid' => $u['txid'], 'vout' => $u['vout'],
                       'script' => '', 'sequence' => 0xffffffff];
    foreach ($outputs as $o) $tx->outputs[] = ['value' => $o['value'], 'script' => $o['script']];
    if ($sel['change'] !== null) $tx->outputs[] = ['value' => $sel['change'], 'script' => $changeScript];
    return $tx;
  }
}
