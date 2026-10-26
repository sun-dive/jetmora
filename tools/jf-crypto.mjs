// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// ── THE CRYPTO A JF TICK IS JUDGED WITH, THE SAME IN A PAGE AND IN NODE ─────────────────────────────────────────────
//
// tools/interpreter-jf.mjs takes its crypto from the caller, so that one interpreter serves a page and a test. This is
// the object to give it, and what tools/thread.mjs's judge gives it unless told otherwise. Every function is ours,
// synchronous, and imports nothing of node's or of a browser's, and each gives the answer the thread service's PHP
// gives (server/interpreter-jf.php):
//
//   sha256(bytes), sha1(bytes), ripemd160(bytes) → Uint8Array   PHP's hash()                tools/sha256.mjs, sha1.mjs, ripemd160.mjs
//   ed25519Verify(sig, pub, msg) → boolean                      ed25519.php, libsodium 1.0.22's rules   tools/ed25519.mjs
//   ecdsaVerify(sig, pub, digest32) → boolean                   secp256k1.php's verifyDigest            tools/secp256k1.mjs
//
// ⛔ Never a browser's own. WebCrypto's digest is async and has no RIPEMD-160, it has no secp256k1, and its Ed25519
//   accepts small-order keys that libsodium, and so every host, refuses: a tick judged by it could pass in a page and
//   be refused by the host.
// ⚠ ecdsaVerify takes the DIGEST: JF's CHECKSIG names an explicit 32-byte digest, and the interpreter has already
//   refused a signature that is not strict DER. tools/ecdsa.mjs is a different contract (the raw preimage, hashed for
//   the caller through node:crypto) and serves the SV interpreter; it is not for a page.
// tools/verify-judge.mjs grades each function against node:crypto and the PHP.
import { sha256 } from './sha256.mjs'
import { sha1 } from './sha1.mjs'
import { ripemd160 } from './ripemd160.mjs'
import { verify as ed25519 } from './ed25519.mjs'
import { verifyDigest } from './secp256k1.mjs'

export const jfCrypto = Object.freeze({
  sha256: b => Uint8Array.from(sha256(b)),
  sha1,
  ripemd160,
  ed25519Verify: (sig, pub, msg) => ed25519(sig, msg, pub),
  ecdsaVerify: (sig, pub, digest32) => verifyDigest(sig, pub, digest32),
})
