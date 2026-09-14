<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ══ THE JETMORA WALLET — a local frontend ════════════════════════════════════════════════════════════
//
// ★★★ HIS ARCHITECTURE, 7 Sept: **the browser provides the interface, not the signing mechanism.**
//   *"Web forms work and will continue to always work, browsers change and will continue to change."*
//   ⇒ No JavaScript. Plain `<form method=post>`. Works with JS off, on any browser, for the next thirty
//     years, and degrades to `curl` for free.
//
// ⚠⚠⚠ THE KEY IS SUPPLIED PER OPERATION AND IS NEVER PERSISTED. Nothing here writes a private key to
//   disk, to a session, or to a cookie. ⇒ Threads are stored; **keys are not, ever.**
//   ⚠ It lives in process memory for the duration of one request. On a shared host that is a real
//     exposure — see the constant-time note in `secp256k1.php`. **This is a LOCAL tool.**
//
// ⚠ THE UI SITS ABOVE BOTH CHAIN SETS, not inside either: the wallet has two interfaces (jetmora and
//   BSV) and `server/wallet/jetmora/` · `server/wallet/bsv/` must not reach across. This file may talk
//   to both; they may not talk to each other.
//
//   Run it:  php -S 127.0.0.1:8080 -t server/wallet server/wallet/wallet.php
//   Then:    http://127.0.0.1:8080/
declare(strict_types=1);
require_once __DIR__ . '/../secp256k1.php';
require_once __DIR__ . '/../covenant-entry.php';
require_once __DIR__ . '/../preimage.php';
require_once __DIR__ . '/../interpreter-jf.php';
require_once __DIR__ . '/../jf-asm.php';
require_once __DIR__ . '/../dispatch.php';
require_once __DIR__ . '/jetmora/thread.php';
require_once __DIR__ . '/jetmora/address.php';
require_once __DIR__ . '/jetmora/signer.php';        // ★ ed25519 — jetmora's scheme
require_once __DIR__ . '/shared/bip39.php';
require_once __DIR__ . '/../append.php';             // ⚠ the CHAIN's verifier, to check our own work

// ── the covenant this wallet mints: a counter that may only increment ────────────────────────────────
// ⚠ The state is the OUTPUT VALUE — §3's "application-defined quantity". The script never changes, so
//   it needs no self-modification, and the successor must carry the SAME script with value + 1.
const COUNTER_SRC = <<<'ASM'
  1000 PREIMAGE  DUP 8 !
  2DUP 8 @ 52 - 8 2000 SUBSTR BIN2NUM 16 !
  2DUP 8 @ 40 - 32 2100 SUBSTR 2DROP
  2DUP 105 8 @ 157 - 2200 SUBSTR 24 ! DROP
  16 @ 1+ 8 3000 NUM2BIN 2DROP
  24 @ 3008 C!
  2200 3009 24 @ MOVE
  3000 24 @ 9 + 4000 HASH256
  4000 32 2100 32 BYTES=
  NIP NIP
ASM;

/** ★ One hardened path for now. SLIP-0010 is hardened-only, so every segment carries a `'`. */
const PATH = "m/44'/0'/0'";

const STORE = __DIR__ . '/../data/wallet.db';

/**
 * ★★★ THE SITE KEEPS A COPY, AND IT MUST — his call, 7 Sept. That is not custody creeping back in:
 *   **it is the BACKUP.** Without it, a lost device loses your threads.
 *   | ⛔ custody | the site is the ONLY holder |
 *   | ✅ backup  | the site holds a copy, YOU hold one too, and either restores the other |
 *
 * ⚠ SQLite, not JSON — *"a .json is not very scalable storage"*. A thread list grows without bound and
 *   a whole-file rewrite per tick does not.
 *
 * ⚠⚠ THREADS ONLY. **There is no key column in this schema and there must never be one.** The lookup
 *   index is `auth_hash` = sha256 of the authorised public key — which the genesis already holds
 *   (§4.2a v0x02), so ★ **the hashed authorised set doubles as the recovery index**: present your
 *   PUBLIC key, the site hashes it, and returns every thread that authorises it. No account, no login,
 *   nothing stored about you, and no leak — the key is public once used.
 */
function db(): PDO {
  static $db = null;
  if ($db) return $db;
  @mkdir(dirname(STORE), 0777, true);
  $db = new PDO('sqlite:' . STORE);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->exec('PRAGMA journal_mode=WAL');
  $db->exec('CREATE TABLE IF NOT EXISTS threads (
               genesis   TEXT PRIMARY KEY,
               label     TEXT NOT NULL DEFAULT \'\',  -- initial STATE, and part of the identity
               auth_hash TEXT NOT NULL,   -- sha256(pubkey): the RECOVERY INDEX, never the key
               auth      TEXT NOT NULL,
               address   TEXT NOT NULL,
               tip       TEXT NOT NULL,
               value     INTEGER NOT NULL,
               ticks     INTEGER NOT NULL,
               last_size INTEGER,
               created   TEXT NOT NULL,
               updated   TEXT NOT NULL)');
  $db->exec('CREATE INDEX IF NOT EXISTS threads_auth ON threads(auth_hash)');
  return $db;
}
/** @return array<string,array> keyed by genesis; all of them, or only those a key authorises */
function load_threads(?string $authHash = null): array {
  $q = $authHash === null
     ? db()->query('SELECT * FROM threads ORDER BY created')
     : (function() use ($authHash) { $s = db()->prepare(
         'SELECT * FROM threads WHERE auth_hash = ? ORDER BY created'); $s->execute([$authHash]); return $s; })();
  $out = [];
  foreach ($q as $r) $out[$r['genesis']] = $r;
  return $out;
}
function put_thread(array $t): void {
  $s = db()->prepare('INSERT INTO threads
      (genesis,label,auth_hash,auth,address,tip,value,ticks,last_size,created,updated)
      VALUES (:genesis,:label,:auth_hash,:auth,:address,:tip,:value,:ticks,:last_size,:created,:updated)
      ON CONFLICT(genesis) DO UPDATE SET
        tip=:tip, value=:value, ticks=:ticks, last_size=:last_size, updated=:updated');
  $s->execute($t);
}
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function hexOf(string $b): string { return bin2hex($b); }

/** Run the covenant over a tick's preimage. ★ This is the verdict nothing upstream will give you. */
function covenant_verdict(string $script, string $preimage): array {
  $vm = new InterpreterJF();
  $vm->setPreimage($preimage);
  try {
    $stack = $vm->run($script);
    if (count($stack) !== 1) return [false, 'the covenant left ' . count($stack) . ' items, expected 1'];
    return [gmp_sign($stack[0]) !== 0, gmp_sign($stack[0]) !== 0 ? 'accepted' : 'REFUSED by the covenant'];
  } catch (JfScriptError $e) {
    return [false, 'covenant error: ' . $e->getMessage()];
  }
}

$script  = jf_asm(COUNTER_SRC);
$threads = load_threads();
$notice = null; $error = null; $reveal = null;
$action = $_POST['action'] ?? '';

try {
  // ── generate a key. ⚠ SHOWN ONCE, STORED NOWHERE. ────────────────────────────────────────────────
  // ★★★ A SEED PHRASE, not 64 hex characters. Hex has no checksum: transpose two and you get a
  //   DIFFERENT VALID KEY, silently. A mnemonic is writable by hand and a mistyped word is CAUGHT.
  //   ⇒ And it is what makes the exit story real: the same phrase on another device is the same key.
  if ($action === 'keygen') {
    $mnemonic = Bip39::generate(128);                            // 12 words
    $signer   = JetmoraSigner::fromSeed(Bip39::toSeed($mnemonic), PATH);
    $pub      = $signer->publicKey();
    $reveal = ['mnemonic' => $mnemonic, 'pub' => bin2hex($pub),
               'addr' => JetAddress::encode(hash('sha256', $pub, true))];
    $notice = 'Seed phrase generated. ⚠ Written down once, stored nowhere — copy it now.';
  }

  // ── mint a covenant thread ────────────────────────────────────────────────────────────────────────
  if ($action === 'mint') {
    $pub = @hex2bin(trim($_POST['pubkey'] ?? ''));
    // ⚠ 32 = ed25519 (jetmora's own), 33/65 = secp256k1. The CHAIN accepts both and dispatches on
    //   length, so the wallet accepts both too rather than narrowing what the protocol allows.
    if ($pub === false || !in_array(strlen($pub), [32, 33, 65], true))
      throw new RuntimeException('a public key is 32 bytes (ed25519) or 33/65 (secp256k1), as hex');
    $auth = CovenantThread::authorisedHashes([$pub]);          // ★ §4.2a v0x02 — HASHES, not keys
    // ★★★ ONE KEY, MANY THREADS — his correction, 7 Sept. `commitment = LP(source_hash) ‖ LP(script) ‖
    //   LP(state) ‖ LP(authorised)`, so **a different initial state is a different thread on the same
    //   key.** A user's set of threads is a STRING; a site holds hundreds of strings, one per user.
    //   ⚠ Without this the wallet could only ever mint ONE thread per key, which is a limit of the demo
    //     and was never a property of the design.
    $label = substr(trim($_POST['label'] ?? ''), 0, 64);
    $g = CovenantThread::create(hash('sha256', COUNTER_SRC, true), $script, $label, $auth);
    $id = hexOf($g['id']);
    if (isset($threads[$id])) throw new RuntimeException('that covenant already exists — §2 is idempotent');
    put_thread(['genesis' => $id, 'label' => $label, 'auth_hash' => hash('sha256', $pub), 'auth' => hexOf($auth),
                'address' => JetAddress::encode(hash('sha256', $pub, true)), 'tip' => $id,
                'value' => 0, 'ticks' => 0, 'last_size' => null,
                'created' => date('c'), 'updated' => date('c')]);
    $threads = load_threads();
    $notice = "Covenant minted. Genesis {$id}";
  }

  // ── tick it forward ───────────────────────────────────────────────────────────────────────────────
  if ($action === 'tick') {
    $id = $_POST['id'] ?? '';
    if (!isset($threads[$id])) throw new RuntimeException('unknown thread');
    $t = $threads[$id];
    // ⚠ THE PHRASE IS SUPPLIED PER OPERATION AND NEVER PERSISTED — same rule as the raw key it replaces.
    $mnemonic = trim($_POST['mnemonic'] ?? '');
    if (!Bip39::isValid($mnemonic))
      throw new RuntimeException('that is not a valid seed phrase — a wrong or transposed word is '
        . 'caught by the checksum, which is the whole reason a phrase beats hex');
    $signer = JetmoraSigner::fromSeed(Bip39::toSeed($mnemonic), PATH);
    $pub    = $signer->publicKey();
    if (!CovenantThread::isAuthorised(hex2bin($t['auth']), $pub))
      throw new RuntimeException('that key is not authorised for this covenant');

    $newValue = (int)$t['value'] + (int)($_POST['step'] ?? 1);
    $tick = CovenantThread::tick(
      hex2bin($t['tip']), 0, $script, pack('P', (int)$t['value']),
      [['value' => $newValue, 'locking' => $script]], (int)$t['ticks'] + 1,
      fn(string $pre) => chr(JF_SMALL0 + 1)     // ⚠ JF's PREIMAGE is native: no OP_PUSH_TX needed
    );

    // ★★★ THE COVENANT DECIDES. §4.1: an operator checks only well-formedness and authorisation, so
    //   nothing upstream will catch a bad tick. The wallet is the last place it can be caught.
    [$okc, $why] = covenant_verdict($script, $tick['preimage']);
    if (!$okc) throw new RuntimeException("the covenant refused this tick — {$why}");

    // ⚠ TWO SIGNATURES (§4.0a). The append one is over the ENTRY BYTES and is all a chain may check.
    // ★★★ SCHEME-AWARE: ed25519 signs the MESSAGE (SHA-512 is internal). Pre-hashing here would give a
    //   valid-looking signature the chain REFUSES — see verify-signers.php, where that trap is a test.
    $appendSig = $signer->signEntry($tick['bytes']);
    // ⚠ CHECKED WITH THE CHAIN'S OWN VERIFIER, not ours: a signature it will not accept does not exist.
    if (!Appender::verifySignature($tick['bytes'], $pub, $appendSig))
      throw new RuntimeException('the append signature does not verify against the chain rule');
    put_thread(['genesis' => $id, 'label' => $t['label'], 'auth_hash' => $t['auth_hash'], 'auth' => $t['auth'],
                'address' => $t['address'], 'tip' => hexOf($tick['hash']), 'value' => $newValue,
                'ticks' => (int)$t['ticks'] + 1, 'last_size' => strlen($tick['bytes']),
                'created' => $t['created'], 'updated' => date('c')]);
    $threads = load_threads();
    $notice = "Ticked to {$newValue}. The covenant accepted it, and the entry is "
            . strlen($tick['bytes']) . " bytes.";
    unset($mnemonic, $signer);                    // ⚠ out of scope immediately; never written anywhere
  }

  // ── ★ RECOVER: a new device pulls its threads back from the site's copy ─────────────────────────
  //   ⚠ Present your PUBLIC key. The site hashes it and looks up `auth_hash`. Nothing is proved and
  //     nothing needs to be: the thread is public data, and only your PRIVATE key can advance it.
  if ($action === 'recover') {
    $pub = @hex2bin(trim($_POST['pubkey'] ?? ''));
    if ($pub === false || !in_array(strlen($pub), [32, 33, 65], true))
      throw new RuntimeException('a public key is 32 bytes (ed25519) or 33/65 (secp256k1), as hex');
    $found = load_threads(hash('sha256', $pub));
    $threads = $found;
    $notice = $found
      ? count($found) . ' thread(s) recovered for that key — this is what a new device pulls back.'
      : 'No threads on this site authorise that key.';
  }

  if ($action === 'forget') { db()->exec('DELETE FROM threads'); $threads = []; $notice = 'Threads cleared.'; }
} catch (Throwable $e) { $error = $e->getMessage(); }

?><!doctype html><meta charset="utf-8">
<title>jetmora wallet — local</title>
<style>
:root{--bg:#0f1115;--fg:#e8eaf0;--soft:#a8b0c0;--faint:#6b7488;--card:#171a21;--line:#232833;
      --ok:#7fd1b9;--warn:#ffd479;--bad:#ff8a7a;--acc:#9db4ff}
*{box-sizing:border-box}
body{margin:0;padding:26px 20px 60px;background:var(--bg);color:var(--fg);
     font:14px/1.55 -apple-system,"Segoe UI",system-ui,sans-serif;max-width:980px;margin-inline:auto}
h1{font-size:23px;margin:0 0 2px;letter-spacing:-.02em}
.sub{color:var(--soft);font-size:13px;margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin:0 0 16px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);margin:0 0 12px}
label{display:block;font-size:12px;color:var(--soft);margin:0 0 4px}
input[type=text]{width:100%;padding:8px 10px;background:#0c0e13;border:1px solid var(--line);
     border-radius:5px;color:var(--fg);font:12.5px ui-monospace,Menlo,monospace}
input[type=number]{width:90px;padding:8px 10px;background:#0c0e13;border:1px solid var(--line);
     border-radius:5px;color:var(--fg);font:12.5px ui-monospace,monospace}
button{padding:8px 16px;background:var(--acc);color:#0f1115;border:0;border-radius:5px;
     font:600 13px system-ui;cursor:pointer;margin-top:10px}
button.ghost{background:transparent;color:var(--faint);border:1px solid var(--line)}
.msg{padding:10px 14px;border-radius:6px;margin:0 0 16px;font-size:13px}
.msg.ok{background:#12261f;color:var(--ok);border:1px solid #1d4437}
.msg.bad{background:#2a1614;color:var(--bad);border:1px solid #4a2320}
.msg.warn{background:#2a2312;color:var(--warn);border:1px solid #4a3d1d}
code{font:12px ui-monospace,Menlo,monospace;color:var(--acc);word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--faint);font:600 10.5px/1 ui-monospace,monospace;text-transform:uppercase;
   letter-spacing:.05em;padding:0 8px 8px 0;border-bottom:1px solid var(--line)}
td{padding:9px 8px 9px 0;border-bottom:1px solid #1a1e27;font:12px ui-monospace,monospace;vertical-align:top}
.dim{color:var(--faint)} .big{font-size:17px;color:var(--ok);font-weight:600}
.note{color:var(--faint);font-size:12px;margin-top:10px}
form.inline{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap}
form.inline > div{flex:1;min-width:260px}
</style>

<h1>jetmora wallet</h1>
<p class="sub">Local. The browser is the form; PHP does the signing.</p>

<div class="msg warn">
  ⚠ <b>Your seed phrase is never stored.</b> It is typed in per operation, used to sign, and goes out of
  scope when the request ends — nothing is written to disk, a session or a cookie. Threads are saved;
  keys are not. ⛔ This is a local tool: on a shared host, signing is timeable and memory is readable.
</div>

<?php if ($notice): ?><div class="msg ok"><?= h($notice) ?></div><?php endif; ?>
<?php if ($error):  ?><div class="msg bad">⛔ <?= h($error) ?></div><?php endif; ?>

<?php if ($reveal): ?>
<div class="card">
  <h2>Your seed phrase — written down once</h2>
  <p style="font-size:16px;line-height:1.9"><code style="color:var(--ok)"><?= h($reveal['mnemonic']) ?></code></p>
  <p><span class="dim">public key (ed25519)</span><br><code><?= h($reveal['pub']) ?></code></p>
  <p><span class="dim">jetmora address</span><br><code><?= h($reveal['addr']) ?></code></p>
  <p class="note">★ <b>Twelve words, not 64 hex characters.</b> Hex has no checksum — transpose two and
  you get a different valid key, silently. A <b>mistyped or transposed word is caught</b>.
  ⇒ Write it down: the same phrase on another device is the same key, and that is the whole recovery
  story. ⚠ A passphrase would make an entirely different wallet.</p>
  <p class="note">⚠ The address carries <b>sha256 of the key</b>, never the key: a public key is a
  greppable search handle. And it is bech32m, so no Bitcoin wallet will accept it (§2c-i).</p>
</div>
<?php endif; ?>

<div class="card">
  <h2>1 · a seed phrase</h2>
  <form method="post"><input type="hidden" name="action" value="keygen">
    <button>Generate a seed phrase</button>
    <span class="note">BIP-39 · SLIP-0010 <b>hardened-only</b> · ed25519, which is jetmora&rsquo;s scheme.</span>
  </form>
</div>

<div class="card">
  <h2>2 · mint a covenant</h2>
  <p class="note" style="margin-top:0">A counter that <b>may only increment</b>. The state is the output
  value; the script never changes, so the successor must carry the same script with value + 1.
  <?= strlen($script) ?> bytes of jetForth.</p>
  <form method="post" class="inline"><input type="hidden" name="action" value="mint">
    <div><label>your public key (hex)</label><input type="text" name="pubkey" placeholder="ed25519, 64 hex characters" required></div>
    <div style="max-width:220px"><label>initial state — a label</label><input type="text" name="label" placeholder="counter A"></div>
    <button>Mint</button>
  </form>
  <p class="note">⚠ The genesis stores <b>sha256 of your key</b> (§4.2a v0x02), not the key.
  ★ <b>One key, many threads:</b> the initial state is part of the commitment, so a different label is a
  different thread. Your set of threads is a <b>string</b>.</p>
</div>

<div class="card">
  <h2>3 · recover on a new device</h2>
  <p class="note" style="margin-top:0">★ <b>The site keeps a copy, and it must</b> &mdash; that is the
  <b>backup</b>, not custody. Swap devices, restore your key from its seed, and pull your threads back
  from any site that has them.</p>
  <form method="post" class="inline"><input type="hidden" name="action" value="recover">
    <div><label>your public key (hex)</label><input type="text" name="pubkey" placeholder="ed25519, 64 hex characters" required></div>
    <button>Find my threads</button>
  </form>
  <p class="note">⚠ Your <b>public</b> key, and nothing is proved: a thread is public data and only your
  <b>private</b> key can advance it. ★ The genesis already stores sha256 of your key (§4.2a v0x02), so
  <b>the authorised set doubles as the lookup index</b> &mdash; no account, no login, nothing stored
  about you.</p>
</div>

<div class="card">
  <h2>4 · your string — every thread on this key</h2>
  <?php if (!$threads): ?>
    <p class="dim">No threads yet. Mint one above.</p>
  <?php else: ?>
  <table>
    <tr><th>genesis</th><th>value</th><th>ticks</th><th>tip</th><th>advance</th></tr>
    <?php foreach ($threads as $id => $t): ?>
    <tr>
      <td><?= $t['label'] !== '' ? '<b>'.h($t['label']).'</b><br>' : '' ?><?= h(substr($id,0,16)) ?>…
          <br><span class="dim"><?= h($t['address'] ?? '') ?></span></td>
      <td class="big"><?= (int)$t['value'] ?></td>
      <td><?= (int)$t['ticks'] ?>
        <?php if (!empty($t['last_size'])): ?><br><span class="dim"><?= (int)$t['last_size'] ?> B entry</span><?php endif; ?></td>
      <td><?= h(substr($t['tip'],0,16)) ?>…</td>
      <td>
        <form method="post">
          <input type="hidden" name="action" value="tick">
          <input type="hidden" name="id" value="<?= h($id) ?>">
          <label>seed phrase — used once, never stored</label>
          <input type="text" name="mnemonic" placeholder="twelve words" required>
          <label style="margin-top:6px">step</label>
          <input type="number" name="step" value="1">
          <button>Tick forward</button>
          <p class="note">⚠ Try a step other than 1 — <b>the covenant will refuse it</b>, and that
          refusal comes from the program, not from this page.</p>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
  <form method="post" style="margin-top:14px"><input type="hidden" name="action" value="forget">
    <button class="ghost">Clear threads</button></form>
  <?php endif; ?>
</div>

<p class="note">
★ Every tick runs the covenant before signing. §4.1 says an operator checks only that an entry is
well-formed and authorised — <b>it does not check the covenant</b> — so nothing upstream would catch a
bad tick. This page is the last place it can be caught, which is why the verdict is shown.
</p>
