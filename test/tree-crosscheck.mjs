// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ⚠⚠ THE COMPARISON — two implementations agreeing with THEMSELVES proves nothing.
//
// This is stronger than it looks, because NOTHING is shared across the boundary:
//
//   JS side   our own SHA-256 (tools/sha256.mjs)  →  our tree (tools/merkle.mjs)
//   PHP side  native SHA-256                      →  the PHP tree (server/merkle.php)
//
// ⇒ Two independent hash implementations under two independent tree implementations. A bug would have
//   to occur identically in both to survive, and they share not one line.
//
//   Run: php server/emit-vectors.php | node test/tree-crosscheck.mjs
//   (or just: node test/tree-crosscheck.mjs — it will run the PHP side itself)
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import * as M from '../tools/merkle.mjs'
import { toHex } from '../tools/sha256.mjs'

// ⚠ isTTY is FALSE whenever there is no terminal — a CI job, a tool harness — not only when something
//   is piped in. Keying on it alone reads an empty stdin and dies in JSON.parse with no clue why.
//   ⇒ Take stdin only if it actually contained something; otherwise run the PHP side ourselves.
const repo = new URL('..', import.meta.url).pathname
let json = ''
try { if (!process.stdin.isTTY) json = readFileSync(0, 'utf8') } catch { /* nothing on stdin */ }
if (json.trim() === '')
  json = execSync('php server/emit-vectors.php', { cwd: repo, maxBuffer: 1 << 28 }).toString()

// ⚠ The SAME leaf construction as emit-vectors.php — chr(i & 0xff) ‖ chr(i >> 8) ‖ 'e'. If this drifts
//   the test compares two different trees and passes for the wrong reason.
const leaves = n => Array.from({ length: n }, (_, i) => [i & 0xff, (i >> 8) & 0xff, 0x65])

let pass = 0, fail = 0
const check = (name, got, want) => {
  if (got === want) { pass++; return }
  fail++; console.log(`  ⛔ ${name}\n     js  ${got}\n     php ${want}`)
}

for (const rec of JSON.parse(json)) {
  const e = leaves(rec.n)
  check(`root n=${rec.n}`, toHex(M.root(e)), rec.root)
  for (const [m, proof] of Object.entries(rec.inclusion))
    check(`inclusion ${m}/${rec.n}`, M.inclusionProof(+m, e).map(toHex).join(','), proof.join(','))
  for (const [m, proof] of Object.entries(rec.consistency))
    check(`consistency ${m}→${rec.n}`, M.consistencyProof(+m, e).map(toHex).join(','), proof.join(','))
}

console.log(`\n  JS tree (our SHA-256) vs PHP tree (native SHA-256) — ${pass} pass · ${fail} fail\n`)
process.exit(fail === 0 ? 0 : 1)
