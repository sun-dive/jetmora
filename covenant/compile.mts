// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
// ⚠ USES the grafverse BASIC compiler; never edits it, and never rebuilds any bundle a page loads.
import { compileState, BASIC_VERSION } from '../../grafverse/mint/src/basic.ts'
import { LockingScript } from '../../grafverse/mint/node_modules/@bsv/sdk/dist/esm/mod.js'
import { anchorSrc, ANCHOR_STACK } from './anchorSrc.mjs'

const len = (ops: any) => new LockingScript(ops as any).toBinary().length
console.log('  BASIC_VERSION', BASIC_VERSION, '\n')
for (const N of [1, 2, 3, 5]) {
  try {
    const r: any = compileState(anchorSrc(N), { stack: [...ANCHOR_STACK], consts: {} })
    console.log(`  N=${N}  peel ${String(len(r.peel)).padStart(4)} · body ${String(len(r.body)).padStart(4)}` +
                ` · rebuild ${String(len(r.rebuild)).padStart(4)}  ⇒ TOTAL ${len(r.ops)} B  (${r.ops.length} ops)`)
  } catch (e: any) { console.log(`  N=${N}  ⚠ ${e.message}`) }
}
