import { compileState } from '../../grafverse/mint/src/basic.ts'
import { unbasicListing } from '../../grafverse/mint/src/unbasic.ts'
import { COVENANT_IDIOMS } from '../../grafverse/mint/src/readerPresets.ts'
import { anchorSrc, ANCHOR_STACK } from './anchorSrc.mjs'
const r: any = compileState(anchorSrc(2), { stack: [...ANCHOR_STACK], consts: {} })
console.log(unbasicListing(r.ops, { stack: [...ANCHOR_STACK, 'scriptCode'], idioms: COVENANT_IDIOMS }))
