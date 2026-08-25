import { buildAnchorLock } from './anchorFrame.mts'
const payees = (n: number) => Object.fromEntries(
  Array.from({ length: n }, (_, i) => ['p' + 'abcdefgh'[i], Array(20).fill(i + 1)]))
for (const N of [1, 3, 5]) {
  const lock = buildAnchorLock({
    levels: N, owner: Array(20).fill(7), creator: Array(20).fill(0xc1),
    state: { genesis: Array(32).fill(9), depth: 0, treesize: 0, royalty: 1, forkable: 1, ...payees(N) },
  })
  const b = lock.toBinary().length
  console.log(`  N=${N}  lock ${b} B   ⇒ ~${(b / 1000 * 100).toFixed(1)} sat of the anchor's fee`)
}
