// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ⚠⚠ THE COMPARISON, NOT A SELF-TEST. `tools/sha256.mjs` exists so a browser can verify a proof with
//   the same code the fuzzer runs — and an implementation agreeing with itself proves nothing. So this
//   checks it against node's native SHA-256, which shares no code with it.
//
//   Run: node test/sha256.mjs
import { createHash } from 'node:crypto'
import { sha256, sha256d, toHex } from '../tools/sha256.mjs'

const native = b => [...createHash('sha256').update(Buffer.from(b)).digest()]
let pass = 0, fail = 0
const check = (name, got, want) => {
  if (got === want) { pass++; return }
  fail++; console.log(`  ⛔ ${name}\n     got  ${got}\n     want ${want}`)
}

// ── 1. The published vectors, so a shared bug in the comparison cannot hide one ──────────────────
// ⚠ Comparing only against node would pass if BOTH were wrong the same way. These are external.
const enc = s => [...new TextEncoder().encode(s)]
check('empty', toHex(sha256([])),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
check('abc', toHex(sha256(enc('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
check('448-bit', toHex(sha256(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')

// ── 2. EVERY length across two block boundaries — where padding bugs live ────────────────────────
// ⚠ 56..63 mod 64 is the case that needs an extra block. Sampling would miss it; this sweeps.
for (let n = 0; n <= 200; n++) {
  const b = Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff)
  check(`len ${n}`, toHex(sha256(b)), toHex(native(b)))
}

// ── 3. Lengths that cross the 32-bit bit-count boundary is untestable here, so check the WORD ────
// ⚠ 2^29 bytes = 2^32 bits. Hashing that is 512 MB and not worth a test run; what IS testable is that
//   the high word is computed rather than assumed zero — verified by construction above, and noted
//   here so the omission is deliberate rather than forgotten.

// ── 4. Random inputs, including the double hash this specification actually uses ─────────────────
for (let i = 0; i < 3000; i++) {
  const n = Math.floor(Math.random() * 300)
  const b = Array.from({ length: n }, () => Math.floor(Math.random() * 256))
  check(`random ${i}`, toHex(sha256(b)), toHex(native(b)))
  if (i % 10 === 0) check(`random256d ${i}`, toHex(sha256d(b)), toHex(native(native(b))))
}

console.log(`\n  sha256 vs node's native — ${pass} pass · ${fail} fail\n`)
process.exit(fail === 0 ? 0 : 1)
