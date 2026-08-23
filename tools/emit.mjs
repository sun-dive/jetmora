// © 2026 sun-dive. Apache License 2.0 — see LICENSE. Emit vectors/core.json with the O(1) comparison hash of §2b.
//   H(result) = sha256( for each stack item: varint(len) ‖ bytes )
// ⚠ CANONICAL BY CONSTRUCTION: one byte string per stack, no optional fields (doc §4c.3).
import { writeFileSync } from 'node:fs'
import { VECTORS } from './vectors.mjs'
import { stackHash } from './hash.mjs'
const out = {
  spec: 'jetmora-conformance', version: 1,
  basis: 'Bitcoin 0.1.3 (MIT) — github.com/trottier/original-bitcoin src/script.cpp',
  note: 'Expected results are hand-derived from the 0.1.3 source. oracle=bsv can be confirmed by an ' +
        'independent BSV interpreter; oracle=013 CANNOT (BSV differs); oracle=jetmora is our own decision.',
  vectors: VECTORS.map(v => ({
    id: v.id, oracle: v.oracle,
    script: Buffer.from(v.script).toString('hex'),
    ...(v.stack ? { stack: v.stack, result_hash: stackHash(v.stack) } : {}),
    ...(v.error ? { error: v.error } : {}),
    ...(v.note ? { note: v.note } : {}),
  })),
}
writeFileSync(new URL('../vectors/core.json', import.meta.url), JSON.stringify(out, null, 2) + '\n')
console.log(`wrote ${out.vectors.length} vectors`)
const withHash = out.vectors.filter(v => v.result_hash).length
console.log(`  ${withHash} with result hashes, ${out.vectors.length - withHash} error/undecided`)
