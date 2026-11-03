// © 2026 sun-dive — Apache License 2.0.
//
// BASIC → jetForth: does a compiled program compute what it says, in BOTH jetmora interpreters?
//   node basic/test/basic-jf.mjs
// The programs are grafverse/mint/test/basic.ts's, with jetForth's answers where jetForth differs: a
// comparison is -1, the words on bytes and numbers are typed, and loops are loops. Every program runs in
// the JavaScript interpreter here and the PHP one (tools/jf-run.php), and the two must leave the same
// stack or raise the same refusal. Then every program is read back, and the reading compiles to the
// same bytes; its listing's offsets are where the engine lets a jump land, and every branch lands on one.
// Covenants with INPUT are compiled, refused and read back here; their ticks are judged in basic/test/thread.mjs.
// Last, this compiler is proved against 0.7 as it was released, read from git, by results: the same values from every
// program, and the same verdict from every covenant on the same ticks.
import { execFileSync } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileBasic, compileCovenant, covenantFrame, varintSize, JF_NVERSION, JF_REVISION, DECLARATION, BASIC_JF_VERSION } from '../basic-jf.mjs'
import { unbasic, disassemble, jfListing } from '../unbasic-jf.mjs'
import { InterpreterJF, TICK_LIMITS, PUSH_BASE } from '../../tools/interpreter-jf.mjs'
import { JF_LIT, JF_WORD, JF_PUSH_MAX } from '../../tools/ops-jf.mjs'
import { declaredVersion, tick, judge, jfCrypto } from '../../tools/thread.mjs'
import { basicUnlock, ed25519Signer } from '../../tools/thread-writer.mjs'
import { preimage } from '../../tools/preimage.mjs'
import { verify as ed25519 } from '../../tools/ed25519.mjs'     // libsodium 1.0.22's rules, as server/ed25519.php's

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '../..')
const hex = b => Buffer.from(b).toString('hex')
const h = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const crypto = { sha256: h('sha256'), sha1: h('sha1'), ripemd160: h('ripemd160'), ed25519Verify: (s, p, m) => ed25519(s, m, p) }
let pass = 0, fail = 0
const ok = (c, what) => { c ? pass++ : fail++; console.log(`  ${c ? '✓' : '✗'} ${what}`) }
const S = 2n ** 32n
/** Every program names its version first. */
const V = `VERSION JF ${JF_REVISION}\n`

/** What the unlocking script pushes, for a test: a number as LIT64, bytes as a direct push. */
const pushes = inputs => inputs.flatMap(v => {
  if (typeof v === 'string') { const d = [...Buffer.from(v, 'hex')]; return [d.length, ...d] }
  let u = BigInt(v); if (u < 0n) u += 1n << 64n
  const o = [JF_LIT.LIT64]; for (let k = 0; k < 8; k++) { o.push(Number(u & 0xffn)); u >>= 8n } return o
})

// ── the programs ─────────────────────────────────────────────────────────────────────────────────────
/** @type {{name:string, src:string, env:object, inputs:any[], want:any, covenant?:boolean, bytes?:Uint8Array, script?:Uint8Array}[]} */
const progs = []
/** want: an array of the left values (bigint, or a hex string for bytes), or 'refused'. */
const prog = (name, src, env, inputs, want) => progs.push({ name, src: V + src, env, inputs, want })

// 1. arithmetic, precedence and parentheses
{
  const env = { stack: ['a', 'b'], leave: ['x'] }
  prog('a + b * 2', 'x = a + b * 2', env, [3, 4], [11n])
  prog('(a + b) * 2', 'x = (a + b) * 2', env, [3, 4], [14n])
  prog('a - b - 1 is left-associative', 'x = a - b - 1', env, [10, 3], [6n])
  prog('a * b / 2', 'x = a * b / 2', env, [7, 6], [21n])
  prog('/ truncates toward zero', 'x = 0 - a / b', env, [7, 2], [-3n])
  prog('0 - a', 'x = 0 - a', env, [5, 0], [-5n])
  prog('unary minus', 'x = -a + b', env, [5, 2], [-3n])
  prog('MIN and MAX', 'x = MIN(a, b) + MAX(a, b)', env, [4, 9], [13n])
  prog('ABS', 'x = ABS(0 - a)', env, [6, 0], [6n])
  prog('a 64-bit cell wraps', 'x = a * b', env, [2n ** 62n, 4], [0n])
}

// 2. a line of a car's physics, against a reference in BigInt
{
  const consts = { G0: 3, GV: 2 ** 30, FE: 1000, TM: 16, DRAG: 2 ** 28, SLIP: 1000 }
  const SRC = `
    REM  one press of the accelerator
    grip   = (tyr * G0 + FMUL(v, GV)) * slip / SLIP
    demand = eng * FE * throttle / TM
    force  = 0
    IF demand > grip THEN force = grip ELSE force = demand
    nv = v + FDIV(force, mass) - FMUL(v, DRAG)
  `
  const fm = (x, y) => x * y / S, fd = (x, y) => x * S / y
  for (const [v, tyr, slip, eng, th] of [[0n, 10n, 1000n, 14n, 8n], [2n * S, 10n, 1000n, 14n, 8n], [4n * S, 2n, 600n, 20n, 16n],
    [S, 6n, 1800n, 8n, 3n], [7n * S / 2n, 10n, 1000n, 24n, 12n], [0n, 1n, 400n, 1n, 0n]]) {
    const mass = 900n + eng * 20n + tyr * 5n
    const grip = (tyr * 3n + fm(v, 2n ** 30n)) * slip / 1000n
    const demand = eng * 1000n * th / 16n
    const force = demand > grip ? grip : demand
    prog(`the car, v ${v} tyr ${tyr}`, SRC, { stack: ['v', 'tyr', 'slip', 'eng', 'throttle', 'mass'], consts, leave: ['nv'] },
      [v, tyr, slip, eng, th, mass], [v + fd(force, mass) - fm(v, 2n ** 28n)])
  }
}

// 3. IF — no stack to balance, so a variable assigned in one arm is simply assigned
{
  const env = { stack: ['a', 'b', 'p', 'q'], leave: ['r'] }
  const SRC = 'IF a > b THEN p = 1 ELSE q = 2\n r = p * 10 + q'
  prog('IF: the THEN path', SRC, env, [5, 3, 7, 9], [19n])
  prog('IF: the ELSE path', SRC, env, [3, 5, 7, 9], [72n])
  prog('IF nested', 'IF a > b THEN IF a > 100 THEN p = 1 ELSE p = 2\n r = p', env, [5, 3, 0, 0], [2n])
  prog('IF with no ELSE, not taken', 'IF a > b THEN p = 1\n r = p', env, [3, 5, 7, 0], [7n])
  prog('a block IF', 'IF a > b THEN\n p = 1\nELSE\n p = 2\nEND IF\nr = p', env, [5, 3, 0, 0], [1n])
  prog('ENDIF as one word', 'IF a > b THEN\n p = 1\nELSE\n p = 2\nENDIF\nr = p', env, [3, 5, 0, 0], [2n])
  prog('a FOR inside a block IF', 'IF a > b THEN\n FOR i = 1 TO 3\n  p = p + i\n NEXT i\nEND IF\nr = p', env, [5, 3, 0, 0], [6n])
}

// 4. FOR … NEXT — a loop, never unrolled
{
  const env = { stack: ['s'], leave: ['s'] }
  prog('a plain count', 'FOR i = 1 TO 5\n s = s + i\n NEXT i', env, [0], [15n])
  prog('the counter in the body', 'FOR i = 1 TO 4\n s = s + i * i\n NEXT', env, [0], [30n])
  prog('STEP', 'FOR i = 0 TO 10 STEP 2\n s = s + i\n NEXT i', env, [0], [30n])
  prog('STEP counts down', 'FOR i = 10 TO 1 STEP -3\n s = s + i\n NEXT i', env, [0], [22n])
  prog('nested loops', 'FOR i = 1 TO 3\n FOR j = 1 TO 3\n s = s + i * j\n NEXT j\n NEXT i', env, [0], [36n])
  prog('an IF inside the body', 'FOR i = 1 TO 6\n IF i > 3 THEN s = s + i\n NEXT i', env, [0], [15n])
  prog('zero trips run the body no times', 'FOR i = 1 TO 0\n s = s + 999\n NEXT i', env, [7], [7n])
  prog('a single-line FOR', 'FOR i = 1 TO 3 : s = s + i : NEXT i', env, [0], [6n])
  const env2 = { stack: ['s', 'n'], leave: ['s'] }
  prog('★ a bound known only when the script runs', 'FOR i = 1 TO n\n s = s + i\n NEXT i', env2, [0, 100], [5050n])
  prog('★ a STEP known only when it runs, counting up', 'FOR i = 1 TO 10 STEP n\n s = s + i\n NEXT i', env2, [0, 3], [22n])
  prog('★ …and counting down', 'FOR i = 10 TO 1 STEP n\n s = s + i\n NEXT i', env2, [0, -4], [18n])
  prog('★ TO is worked out once, before the loop', 'FOR i = 1 TO n\n n = n + 1\n s = s + 1\n NEXT i', env2, [0, 4], [4n])
  prog('★ the counter after the loop', 'FOR i = 1 TO 4\n s = s + 1\n NEXT i\n s = i', env, [0], [5n])
  prog('★ a thousand trips cost one body', 'FOR i = 1 TO 1000\n s = s + i\n NEXT i', env, [0], [500500n])
}

// 5. the machine's own words
{
  const env = { stack: ['a', 'b'], leave: ['x'] }
  prog('VERIFY passes and leaves nothing behind', 'VERIFY a > 0\nx = a + b', env, [3, 4], [7n])
  prog('VERIFY fails: the program is refused', 'VERIFY a > 10\nx = a + b', env, [3, 4], 'refused')
  /* VERIFY is one comparison and one abort: every comparison, NOT and a plain number, each on both sides of where it holds */
  const HOLDS = { '=': (a, b) => a === b, '<>': (a, b) => a !== b, '<': (a, b) => a < b, '>': (a, b) => a > b,
                  '<=': (a, b) => a <= b, '>=': (a, b) => a >= b }
  for (const [op, f] of Object.entries(HOLDS)) for (const a of [-1n, 0n, 1n, 2n]) {
    prog(`VERIFY a ${op} b, ${a} and 1`, `VERIFY a ${op} b\nx = a`, env, [a, 1], f(a, 1n) ? [a] : 'refused')
  }
  for (const a of [-1n, 0n, 1n]) prog(`VERIFY NOT(a), ${a}`, 'VERIFY NOT(a)\nx = a', env, [a, 0], a === 0n ? [a] : 'refused')
  for (const a of [-1n, 0n, 5n]) prog(`VERIFY a, ${a}`, 'VERIFY a\nx = a', env, [a, 0], a !== 0n ? [a] : 'refused')
  prog('MOD', 'x = MOD(a, b)', env, [17, 5], [2n])
  prog('WITHIN is [lo, hi), and true is -1', 'x = WITHIN(a, 0, 10) + WITHIN(b, 0, 10)', env, [5, 20], [-1n])
  prog('NOT: 0 becomes -1', 'x = NOT(a) + NOT(b)', env, [0, 7], [-1n])
  prog('ISTRUE', 'x = ISTRUE(a) + ISTRUE(b)', env, [0, 9], [-1n])
  prog('a comparison is -1', 'x = a < b', env, [1, 2], [-1n])
  prog('<= and >=', 'x = (a <= b) + (a >= b) + (a <= a)', env, [1, 2], [-2n])
  prog('AND and OR are both-non-zero and either-non-zero', 'x = (a AND b) + (a OR 0) + (0 AND b)', env, [2, 1], [-2n])
  prog('NEGATE and ABS', 'x = ABS(NEGATE(a))', env, [6, 0], [6n])
  prog('BITAND, BITOR, BITXOR work on numbers', 'x = BITAND(a, b) * 100 + BITOR(a, b) * 10 + BITXOR(a, b)', env, [12, 10], [8n * 100n + 14n * 10n + 6n])
  prog('LSHIFT and RSHIFT', 'x = LSHIFT(a, 4) + RSHIFT(b, 1)', env, [3, 10], [53n])
  prog('INVERT', 'x = INVERT(a)', env, [0, 0], [-1n])
  prog('SIZE gives back ONE value', 'f = NUM2BIN(a, 4)\nl, r = SPLIT(f, 1)\nx = SIZE(l) * 10 + SIZE(r)', env, [0, 0], [13n])
  prog('NUM2BIN and BIN2NUM', 'x = BIN2NUM(NUM2BIN(a, 8)) - a', env, [123456789, 0], [0n])
  prog('SAMEBYTES is bytes: a padded zero is not a one-byte zero', 'f = NUM2BIN(0, 4)\nz = NUM2BIN(0, 1)\nx = SAMEBYTES(f, z)', env, [0, 0], [0n])
  prog('…while as NUMBERS the two are equal', 'f = NUM2BIN(0, 4)\nx = BIN2NUM(f) = 0', env, [0, 0], [-1n])
  prog('SPLIT then CAT gives back what went in', 'f = NUM2BIN(a, 6)\nl, r = SPLIT(f, 2)\nx = SAMEBYTES(CAT(l, r), f)', env, [123456, 0], [-1n])
  prog('a hex literal is bytes', 'x = BIN2NUM(&Hdeadbeef)', env, [0, 0], [0xefbeadden])
  prog('literals compared and joined', 'x = SAMEBYTES(&H0102, &H0102) + SIZE(CAT(&H0102, &H03))', env, [0, 0], [2n])
  prog('a byte string made before a loop and read inside it', 'h = HASH256(&H01)\nx = 0\nFOR i = 1 TO 3\n x = x + SIZE(h)\nNEXT i', env, [0, 0], [96n])
  prog('★ a swap inside a loop: what a variable can hold is everything it may be given on any trip',
    `p = &H01\nq = &H${'ab'.repeat(40)}\nt = p\nFOR i = 1 TO 2\n t = p\n p = q\n q = t\nNEXT i\nc = CAT(t, &H03)\nd = HASH256(&H04)\nx = SAMEBYTES(c, CAT(&H${'ab'.repeat(40)}, &H03))`, env, [0, 0], [-1n])
  prog('SPLIT inside a loop: no bytes are made, so no place is rewritten', 'bs = &H0102030405\nx = 0\nFOR i = 1 TO 4\n l, bs = SPLIT(bs, 1)\n x = x + BIN2NUM(l)\nNEXT i', env, [0, 0], [10n])
  prog('a byte string from the unlocking script', 'x = SIZE(k) + BIN2NUM(k)', { stack: ['k$'], leave: ['x'] }, ['0201'], [258n + 2n])
  const v = Buffer.from('jetmora'), d = hex(v)
  const want = (alg, n) => hex(h(alg)(alg === 'sha256' && n === 'HASH256' ? h('sha256')(v) : n === 'HASH160' ? h('sha256')(v) : v))
  prog('HASH256', `x = HASH256(&H${d})`, env, [0, 0], [want('sha256', 'HASH256')])
  prog('SHA256', `x = SHA256(&H${d})`, env, [0, 0], [hex(h('sha256')(v))])
  prog('HASH160', `x = HASH160(&H${d})`, env, [0, 0], [want('ripemd160', 'HASH160')])
  prog('RIPEMD160', `x = RIPEMD160(&H${d})`, env, [0, 0], [hex(h('ripemd160')(v))])
  prog('SHA1', `x = SHA1(&H${d})`, env, [0, 0], [hex(h('sha1')(v))])
  prog('a byte string left on the stack', 'x = CAT(&H01, NUM2BIN(a, 2))', env, [0x0302, 0], ['010203'])
}

// 5a. the scratch: bytes a word makes for its statement, used from the scratch's start again by the next one
{
  const env = { stack: ['a', 'b'], leave: ['x'] }
  const n4 = v => Uint8Array.of(v, 0, 0, 0), cat = (...p) => Uint8Array.from(p.flatMap(b => [...b]))
  const TWO = 'x = SAMEBYTES(SHA256(CAT(NUM2BIN(a, 4), NUM2BIN(b, 4))), SHA256(CAT(NUM2BIN(b, 4), NUM2BIN(a, 4))))'
  prog('two hashes alive in one statement, unequal', TWO, env, [3, 5], [0n])
  prog('two hashes alive in one statement, equal', TWO, env, [7, 7], [-1n])
  prog('a hash written over the hash it hashes', 'x = SAMEBYTES(SHA256(SHA256(NUM2BIN(a, 4))), HASH256(NUM2BIN(a, 4)))', env, [9, 0], [-1n])
  prog('a hash kept, past the scratch the next statement fills',
    'h = SHA256(NUM2BIN(a, 4))\nVERIFY SIZE(CAT(CAT(NUM2BIN(b, 8), NUM2BIN(b, 8)), CAT(NUM2BIN(b, 8), NUM2BIN(b, 8)))) = 32\n' +
    'x = SAMEBYTES(h, SHA256(NUM2BIN(a, 4)))', env, [2, 6], [-1n])
  prog('SPLIT keeps what it splits', 'l, r = SPLIT(SHA256(NUM2BIN(a, 4)), 4)\nz = SHA256(NUM2BIN(b, 4))\n' +
    'x = SAMEBYTES(CAT(l, r), SHA256(NUM2BIN(a, 4))) + SIZE(z)', env, [4, 8], [31n])
  prog('hashes inside hashes, left on the stack', 'x = SHA256(CAT(SHA256(NUM2BIN(a, 4)), HASH160(NUM2BIN(b, 4))))', env, [1, 2],
    [hex(h('sha256')(cat(h('sha256')(n4(1)), h('ripemd160')(h('sha256')(n4(2))))))])
}

// 5b. a program that ends with an IF and leaves nothing
prog('an IF with no ELSE at the very end', 'p = 0\nIF a > b THEN p = 1', { stack: ['a', 'b'] }, [3, 4], [])

// 6. `^` is a multiply loop: JF revision 3 has no power word
{
  const env = { stack: ['a', 'b'], leave: ['x'] }
  prog('2 ^ 8', 'x = 2 ^ 8', env, [0, 0], [256n])
  prog('★ an exponent known only when it runs', 'x = a ^ b', env, [3, 4], [81n])
  prog('★ 2 ^ k inside a FOR', 's = 0\nFOR k = 0 TO 3\n s = s + 2 ^ k\nNEXT k\nx = s', env, [0, 0], [15n])
  prog('right-associative: 2 ^ 3 ^ 2 is 2 ^ 9', 'x = 2 ^ 3 ^ 2', env, [0, 0], [512n])
  prog('binds tighter than *', 'x = 2 * 3 ^ 2', env, [0, 0], [18n])
  prog('anything ^ 0 is 1, and so is 0 ^ 0', 'x = a ^ 0 + 0 ^ 0', env, [7, 0], [2n])
  prog('a negative base', 'x = -2 ^ 3', env, [0, 0], [-8n])
  prog('it wraps at 64 bits, as * does', 'x = 3 ^ 41', env, [0, 0], [BigInt.asIntN(64, 3n ** 41n)])
  prog('2 ^ 64 wraps to 0', 'x = 2 ^ 64', env, [0, 0], [0n])
  prog('★ a negative exponent is refused when it runs', 'x = a ^ b', env, [2, -1], 'refused')
}

// 7. line numbers are labels
prog('a numbered program', '10 x = a + b\n20 x = x * 2', { stack: ['a', 'b'], leave: ['x'] }, [3, 4], [14n])
prog('a numbered FOR loop', '10 FOR i = 1 TO 3\n20 x = x + i\n30 NEXT i', { stack: ['x'], leave: ['x'] }, [0], [6n])

// 7b. INPUT is a statement only where a name follows it: a variable may still be named input
prog('a variable named input', 'input = a + b\nx = input * 2', { stack: ['a', 'b'], leave: ['x'] }, [3, 4], [14n])
prog('…and one half of a SPLIT', 'input, rest = SPLIT(NUM2BIN(a, 2), 1)\nx = BIN2NUM(input) + BIN2NUM(rest)', { stack: ['a'], leave: ['x'] }, [0x0302], [5n])

// 8. the machine stops a loop that does not end
prog('★ a loop past the operation budget is refused by the interpreter', 'FOR i = 1 TO 1000000000\n s = s + 1\nNEXT i', { stack: ['s'], leave: ['s'] }, [0], 'refused')

// ── compile, and run each in both interpreters ───────────────────────────────────────────────────────
console.log('\nBASIC → jetForth — every program, in both interpreters\n')
for (const p of progs) {
  p.c = compileBasic(p.src, p.env)
  /* The inputs are pushed straight after the lock's declaration: VER is valid only as a lock's first instruction. */
  const d = DECLARATION.length
  p.script = Uint8Array.from([...p.c.bytes.slice(0, d), ...pushes(p.inputs), ...p.c.bytes.slice(d)])
}
const php = execFileSync('php', [join(ROOT, 'tools/jf-run.php'), '0'],
  { input: JSON.stringify(progs.map(p => ({ script: hex(p.script), preimage: null }))), maxBuffer: 1 << 28 })
  .toString().trim().split('\n').map(l => JSON.parse(l))
let agree = 0, right = 0
for (const [k, p] of progs.entries()) {
  const vm = new InterpreterJF({ crypto })
  let js, got
  try {
    const stack = await vm.run(p.script)
    js = { stack: stack.map(String) }
    got = []; let s = 0
    for (const _ of p.c.leave) {
      const isBytes = typeof p.want !== 'string' && typeof p.want[got.length] === 'string'
      if (isBytes) { const [a, u] = [stack[s], stack[s + 1]]; got.push(hex(vm.read(a, u))); s += 2 }
      else { got.push(stack[s]); s += 1 }
    }
  } catch (e) { js = { error: hex(Buffer.from(e.message)) }; got = 'refused' }
  const same = JSON.stringify(js) === JSON.stringify(php[k].stack ? { stack: php[k].stack } : { error: php[k].error })
  const correct = JSON.stringify(got, (_, v) => typeof v === 'bigint' ? String(v) : v)
    === JSON.stringify(p.want, (_, v) => typeof v === 'bigint' ? String(v) : v)
  if (same) agree++; if (correct) right++
  if (!same || !correct || process.env.V) {
    console.log(`  ${same && correct ? '·' : '✗'} ${p.name} — ${p.c.bytes.length} B` +
      (correct ? '' : `\n      want ${JSON.stringify(p.want, (_, v) => String(v))}, got ${JSON.stringify(got, (_, v) => String(v))}`) +
      (same ? '' : `\n      JS ${JSON.stringify(js)}\n      PHP ${JSON.stringify(php[k])}`))
  }
}
ok(right === progs.length, `★★ ${right}/${progs.length} programs compute what they say`)
ok(agree === progs.length, `★★ the JavaScript and PHP interpreters leave the same stack, or raise the same refusal, on all ${agree}/${progs.length}`)
{
  const why = start => Buffer.from(php[progs.findIndex(p => p.name.startsWith(start))].error ?? '', 'hex').toString()
  ok(why('★ a loop past') === 'op budget exhausted', '…and the endless loop is stopped by the op budget')
}

// ── refusals, by name ────────────────────────────────────────────────────────────────────────────────
console.log('\n── and it refuses what it cannot do, by name ──')
const badRaw = (src, env = {}) => { try { compileBasic(src, env); return '' } catch (e) { return e.message } }
const bad = (src, env) => badRaw(V + src, env)
const refusals = [
  ['an unknown variable', 'x = notAThing + 1', {}, 'notAThing'],
  ['a variable that exists only inside a branch', 'IF a > 1 THEN zz = 1 ELSE zz = 2', { stack: ['a'] }, 'zz'],
  ['a word with the wrong number of arguments', 'x = FMUL(1)', {}, 'FMUL'],
  ['a word that does not exist', 'x = WOBBLE(1, 2)', {}, 'WOBBLE'],
  ['a FOR with no NEXT', 'FOR i = 1 TO 3\n s = s + 1', { stack: ['s'] }, 'NEXT'],
  ['a NEXT that closes a different loop', 'FOR i = 1 TO 3\n s = s + 1\n NEXT j', { stack: ['s'] }, 'NEXT j'],
  ['a NEXT with no FOR', 's = s + 1\n NEXT i', { stack: ['s'] }, 'no FOR'],
  ['a FOR inside a line-scoped IF arm', 'IF s > 1 THEN FOR i = 1 TO 3\n s = s + 1\n NEXT i', { stack: ['s'] }, 'line-scoped'],
  ['a nested loop on the same counter', 'FOR i = 1 TO 3\nFOR i = 1 TO 2\nNEXT i\nNEXT i', {}, 'already open'],
  ['a GOTO target after THEN', 'IF a > b THEN 100', { stack: ['a', 'b'] }, 'cannot start'],
  ['an odd number of hex digits', 'x = &Habc', {}, 'even number'],
  ['SPLIT with one name', 'x = SPLIT(&H0102, 1)', {}, 'two names'],
  ['a block IF never closed', 'IF a > b THEN\n p = 1', { stack: ['a', 'b', 'p'] }, 'END IF'],
  ['arithmetic on bytes', 'x = &H01 + 1', {}, 'BIN2NUM'],
  ['SAMEBYTES on numbers', 'x = SAMEBYTES(1, 2)', {}, 'NUM2BIN'],
  ['= on bytes', 'x = &H01 = &H01', {}, 'numbers'],
  ['a variable changing kind', 'x = 1\nx = &H01', {}, 'one kind'],
  ['assigning a constant', 'K = 1', { consts: { K: 2 } }, 'constant'],
  ['DIM outside a covenant', 'DIM v%5\nv = 1', {}, 'compileCovenant'],
  ['★ a byte literal inside a FOR: it would be copied into the push space on every trip', 'x = 0\nFOR i = 1 TO 3\n x = x + SIZE(&H01)\nNEXT i', {}, 'byte literal'],
  ['★ CAT inside a FOR: its place would be rewritten on every trip', 'b = &H01\nFOR i = 1 TO 3\n b = CAT(b, b)\nNEXT i', {}, 'every trip'],
  ['★ a hash inside a FOR, the same', 'b = &H01\nFOR i = 1 TO 3\n b = HASH256(b)\nNEXT i', {}, 'every trip'],
  ['NUM2BIN with a width known only when it runs', 'b = NUM2BIN(5, w)', { stack: ['w'] }, 'width'],
  ['★ NUM2BIN with a negative width', 'b = &H00\nIF 1 = 0 THEN\n b = NUM2BIN(5, 0 - 32)\nEND IF', {}, '0 to 65536'],
  ['CAT of bytes whose length is not known', 'b = CAT(k, k)', { stack: ['k$'] }, 'not known'],
  ['CHECKSIG, until its BASIC form is decided', 'x = CHECKSIG(&H01, &H02)', {}, 'digest'],
]
for (const [what, src, env, needle] of refusals) {
  const m = bad(src, env)
  ok(m.includes(needle), `${what}${m ? '' : ' — NOT refused'}`)
}
const VERSION_REFUSALS = [
  ['a program that does not name its version', 'x = 1', 'names its version first'],
  ['a version this compiler does not emit', 'VERSION JF 2\nx = 1', 'emits JF revision 3'],
  ['another instruction set', 'VERSION SV 1\nx = 1', 'emits JF revision 3'],
  ['VERSION said twice', 'VERSION JF 3\nx = 1\nVERSION JF 3', 'said once'],
  ['VERSION inside an IF', 'VERSION JF 3\nx = 1\nIF x THEN VERSION JF 3', 'said once'],
]
for (const [what, src, needle] of VERSION_REFUSALS) {
  const m = badRaw(src)
  ok(m.includes(needle), `${what}${m ? '' : ' — NOT refused'}`)
}
ok(badRaw('REM  a counter\n10 VERSION JF 3\n20 x = 1') === '', 'a REM and a line number may come before it')

// ── THE HARD RULE ────────────────────────────────────────────────────────────────────────────────────
console.log('\n── THE HARD RULE — the script says what the program says ──')
const words = (src, env = {}) => disassemble(compileBasic(V + src, env).bytes).map(x => x.name)
const arith = (src, env) => words(src, env).filter(n => ['+', '-', '*', '/'].includes(n)).length
ok(arith('x = 2 * 3 + 4') === 2, '`x = 2 * 3 + 4` emits a multiply and an add — not the number 10')
ok(arith('x = K * 3 + 4', { consts: { K: 2 } }) === 2, 'a named constant is substituted, and the arithmetic around it still emits')
ok(arith('a = 2\nb = a * 2\nc = b * 2\nd = c * 2') === 3, '…and through a chain of assignments, every step emits')
ok(words('a = 15\nVERIFY a > 10').includes('>'), 'a comparison of two known values is still checked when it runs')
ok(words('x = 2 ^ 8').filter(n => n === '*').length === 1 && words('x = 2 ^ 8').includes('(?DO)'),
  '★ `x = 2 ^ 8` emits its multiply loop — nothing is folded, not even `^`')
{
  const nums = disassemble(compileBasic(V + 'x = 2 ^ 8').bytes).filter(x => x.name === 'NUM').map(x => x.value)
  ok(nums.includes(2n) && nums.includes(8n) && !nums.includes(256n), '…the script holds 2 and 8, and never 256')
}
ok(words('s = 0\nFOR i = 1 TO 4\ns = s + i * 3\nNEXT i').filter(n => n === '*').length === 1,
  '★ a FOR is a loop: its body is in the script once, however many times it runs')
{
  const one = compileBasic(V + 'FOR i = 1 TO 1\ns = s + i\nNEXT i', { stack: ['s'] }).bytes.length
  const many = compileBasic(V + 'FOR i = 1 TO 45000\ns = s + i\nNEXT i', { stack: ['s'] }).bytes.length
  ok(many - one === 4, `★ 1 trip ${one} B, 45,000 trips ${many} B — the 4 bytes are the wider literal; the body is there once`)
}

// ── the same language, written two ways ──
const same = (a, b, env) => hex(compileBasic(V + a, env).bytes) === hex(compileBasic(V + b, env).bytes)
ok(same('x = a + b\nx = x * 2', '10 x = a + b\n20 x = x * 2', { stack: ['a', 'b'] }), 'line numbers are labels: byte-identical')
ok(hex(compileBasic('VERSION JF 3\nx = 1').bytes).startsWith('d103004a46')
   && hex(compileBasic('VERSION JF 3\nx = 1').bytes) === hex(compileBasic('REM  x\n10 VERSION JF 3\n20 x = 1').bytes),
   'the VERSION line is the lock\'s declaration, VER JF 3, D1 03 00 4A 46: a REM and a line number before it change nothing')
ok(same('IF a > b THEN p = 1 ELSE p = 2', 'IF a > b THEN\n p = 1\nELSE\n p = 2\nEND IF', { stack: ['a', 'b', 'p'] }),
  'a line IF and a block IF are byte-identical')

// ── the version ──────────────────────────────────────────────────────────────────────────────────────
console.log('\n── the version the script declares, and an entry must name ──')
const reg = JSON.parse(execFileSync('php', ['-r',
  `require '${join(ROOT, 'server/dispatch.php')}'; echo json_encode(['jf' => $GLOBALS['JETMORA_SETS']['JF']['revisions'], 'v' => version_build('JF', ${JF_REVISION})]);`]).toString())
ok(reg.v === JF_NVERSION, `nVersion 0x${JF_NVERSION.toString(16)} is version_build('JF', ${JF_REVISION})`)
ok(reg.jf.includes(JF_REVISION), `…and dispatch.php serves JF revision ${JF_REVISION}`)
ok(progs.every(p => p.c.nVersion === JF_NVERSION) && compileCovenant(V + 'DIM owner$20\nx = 1', { state: { owner: new Array(20).fill(1) } }).nVersion === JF_NVERSION,
  'every compiled program carries it')
{
  const all = [...progs.map(p => p.c.bytes), compileCovenant(V + 'DIM owner$20\nx = 1', { state: { owner: new Array(20).fill(1) } }).bytes]
  ok(DECLARATION[0] === JF_WORD.VER && all.every(b => hex(b.slice(0, 5)) === 'd103004a46' && declaredVersion(b) === JF_NVERSION),
    `★ and declares it: every one, ${all.length}/${all.length} with a covenant, starts with VER JF 3, which tools/thread.mjs's declaredVersion reads as 0x${JF_NVERSION.toString(16)}`)
}

// ── read back ────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── every program read back, and the reading compiled again ──')
let read = 0, round = 0
for (const p of progs) {
  const r = unbasic(p.c.bytes, { stack: p.c.inputs })
  if (r.stoppedAt) { console.log(`  ✗ ${p.name}: ${r.stoppedAt}`); continue }
  read++
  let again = ''
  try { again = hex(compileBasic(r.lines.join('\n'), { stack: r.stack, consts: {}, leave: r.leave }).bytes) } catch (e) { again = e.message }
  if (again === hex(p.c.bytes)) round++
  else console.log(`  ✗ ${p.name}: reads as\n${r.lines.map(l => '      ' + l).join('\n')}`)
}
ok(read === progs.length, `the reader reads all ${read}/${progs.length} to the end`)
ok(round === progs.length, `★★ and every reading compiles back to the SAME BYTES (${round}/${progs.length})`)
{
  const b = compileBasic(V + 'x = 1', { leave: ['x'] }).bytes
  ok(unbasic(b).lines[0] === 'VERSION JF 3' && jfListing(b).split('\n')[0].trim() === '0  VER JF 3',
    'the declaration reads back as the VERSION line, and lists as VER JF 3')
  const none = unbasic(b.slice(5)), other = unbasic(Uint8Array.from([JF_WORD.VER, 2, 0, 0x4a, 0x46, ...b.slice(5)]))
  ok(none.lines.length === 0 && /declares no version/.test(none.stoppedAt ?? ''), `a script that declares no version is not read: ${none.stoppedAt}`)
  ok(other.lines.length === 0 && /declares JF 2/.test(other.stoppedAt ?? ''), `nor one that declares another: ${other.stoppedAt}`)
}

// ── INPUT ────────────────────────────────────────────────────────────────────────────────────────────
console.log('\n── INPUT: what a covenant\'s tick carries after the signature and the key ──')
const OWN = new Array(20).fill(0xab)
/** The code thread's covenant: each release carries its code, and the successor holds its SHA-256 */
const RELEASE = 'DIM owner$20\nDIM rev%2\nDIM code$32\nINPUT bundle$, r%\ncode = SHA256(bundle)\nrev = r'
const INPUTS = [
  [RELEASE, { owner: OWN, rev: 3, code: new Array(32).fill(0) }],
  ['DIM owner$20\nDIM n%2\nINPUT t$4, k%2, m%\nn = SIZE(t) + k + m', { owner: OWN, n: 0 }],
  ['INPUT a$, b$40\nDIM owner$20\nINPUT c%3\nVERIFY SIZE(a) = 4\nVERIFY c < 9', { owner: OWN }],
  ['DIM owner$20\nDIM h$32\nINPUT p$32, q$\nIF SIZE(q) > 0 THEN\n h = HASH256(CAT(p, h))\nEND IF', { owner: OWN, h: new Array(32).fill(1) }],
  ['DIM owner$20\nDIM n%8\nINPUT k%8\nn = k', { owner: OWN, n: 1 }],
  ['DIM owner$20\nINPUT big$1000\nVERIFY SIZE(big) = 1000', { owner: OWN }],
  ['DIM owner$20\nINPUT input$\nVERIFY SIZE(input) > 0', { owner: OWN }],
]
{
  const cov = (text, state, env = {}) => compileCovenant(V + text, { state, ...env })
  const c = cov(...INPUTS[0])
  ok(JSON.stringify(c.inputs) === JSON.stringify([{ name: 'bundle', width: null, bytes: true }, { name: 'r', width: 8, bytes: false }]),
    `the release covenant compiles, ${c.bytes.length} B: INPUT bundle$, r% is bytes of any length, then a number of at most 8 bytes`)
  const st = INPUTS[0][1], b = text => hex(cov(text, st).bytes)
  ok(b(RELEASE) === b(RELEASE.replace('r%', 'r%8')), '`r%` is `r%8`: a number with no width is at most a cell')
  ok(b(RELEASE) === b('INPUT bundle$, r%\n' + RELEASE.replace('INPUT bundle$, r%\n', ''))
     && b(RELEASE) === b(RELEASE.replace('INPUT bundle$, r%', 'INPUT bundle$\nINPUT r%')),
    'INPUT before the DIMs, or as two lines: the same bytes. The declarations are laid out fields first, then inputs, in order')
  ok(c.pushed === cov(RELEASE.replace('r%', 'r%2'), st).pushed + 6 && c.pushed === cov(RELEASE.replace('bundle$', 'bundle$100'), st).pushed - 100,
    `the push space counts an input at its width, and one of any length not at all, its length being the tick's: ${c.pushed} B`)
  let compiled = 0, read = 0
  for (const [text, state] of INPUTS) {
    let k
    try { k = cov(text, state); compiled++ } catch (e) { console.log(`  ✗ ${text.split('\n').join(' · ')}: ${e.message}`); continue }
    for (const opts of [{ names: k.names }, {}]) {
      const u = unbasic(k.bytes, opts)
      let again = ''
      try { again = hex(compileCovenant(u.lines.join('\n'), { state: u.state }).bytes) } catch (e) { again = e.message }
      if (!u.stoppedAt && u.lines.some(l => l.startsWith('INPUT ')) && again === hex(k.bytes)) read++
      else console.log(`  ✗ ${text.split('\n').join(' · ')}: read back, ${u.stoppedAt ?? 'it compiles to different bytes'}\n${u.lines.map(l => '      ' + l).join('\n')}`)
    }
  }
  ok(compiled === INPUTS.length, `every INPUT covenant here compiles (${compiled}/${INPUTS.length})`)
  ok(read === 2 * INPUTS.length, `★★ and each one is read back with its INPUT line, named and unnamed, and the reading compiles to the SAME BYTES (${read}/${2 * INPUTS.length})`)
  const u = unbasic(c.bytes, { names: c.names })
  ok(u.lines.includes('INPUT bundle$, r%8') && JSON.stringify(u.inputs) === JSON.stringify(c.inputs), `the release covenant reads back as ${u.lines.find(l => l.startsWith('INPUT'))}`)
  /* A lock the compiler does not write: DIM owner$20 and one input r, the frame laid down for a width INPUT does not
     have, at the lock's own length */
  const unwritten = x => {
    const layout = [{ name: 'owner', width: 20, bytes: true }], given = [{ name: 'r', ...x }]
    const head = [...DECLARATION, 20, ...new Array(20).fill(0)]
    for (let k = 0, L = 0; k < 8; k++) {
      const { frame, rebuild } = covenantFrame(layout, L, [], given)
      if (head.length + frame.length + rebuild.length === L) return Uint8Array.from([...head, ...frame, ...rebuild])
      L = head.length + frame.length + rebuild.length
    }
  }
  ok(hex(unwritten({ width: 7, bytes: false })) === hex(cov('DIM owner$20\nINPUT r%7', { owner: new Array(20).fill(0) }).bytes),
    'a lock laid down this way for INPUT r%7 is the compiler\'s, byte for byte')
  const odd = [{ width: 9, bytes: false }, { width: 0, bytes: false }, { width: 0, bytes: true }, { width: 65537, bytes: true }].map(x => unbasic(unwritten(x)))
  ok(odd.every(r => r.covenant && r.stoppedAt?.startsWith('in0') && !r.lines.some(l => l.startsWith('INPUT'))),
    `laid down for %9, %0, $0 and $65537, widths INPUT does not have: read as a covenant, stopped at that input, and no INPUT line given that would not compile (${odd.map(r => r.stoppedAt ?? r.lines.find(l => l.startsWith('INPUT'))).join(' · ')})`)
  const badCov = (text, env = {}) => { try { cov(text, { owner: OWN, n: 1 }, env); return '' } catch (e) { return e.message } }
  for (const [what, text, needle, env] of [
    ['INPUT after a statement that runs', 'DIM owner$20\nx = 1\nINPUT k$', 'every INPUT comes before'],
    ['INPUT inside an IF arm', 'DIM owner$20\nDIM n%1\nIF n > 0 THEN INPUT k$', 'cannot sit inside an IF'],
    ['INPUT inside a block IF', 'DIM owner$20\nDIM n%1\nIF n > 0 THEN\n INPUT k$\nEND IF', 'every INPUT comes before'],
    ['INPUT inside a FOR', 'DIM owner$20\nFOR i = 1 TO 2\n INPUT k$\nNEXT i', 'every INPUT comes before'],
    ['a name INPUT gives twice', 'DIM owner$20\nINPUT k$, k%2', 'named twice by INPUT'],
    ['INPUT naming a DIM field', 'DIM owner$20\nINPUT owner$20', 'a DIM field and an INPUT'],
    ['a DIM naming an earlier INPUT', 'DIM owner$20\nINPUT n%2\nDIM n%2', 'a DIM field and an INPUT'],
    ['an INPUT with no sigil', 'DIM owner$20\nINPUT k\nx = 1', 'needs a sigil'],
    ['a comma and no name after it', 'DIM owner$20\nINPUT k$,\nx = 1', 'INPUT wants a name'],
    ['a number wider than a cell', 'DIM owner$20\nINPUT k%9', 'from 1 to 8'],
    ['bytes of width 0', 'DIM owner$20\nINPUT k$0', 'from 1 to 65536'],
    ['a width that is not whole', 'DIM owner$20\nINPUT k%2.5', 'from 1 to 8'],
    ['a compile-time constant as an INPUT', 'DIM owner$20\nINPUT K%2', 'compile-time constant', { consts: { K: 1 } }],
    ['inputs past the push space', 'DIM owner$20\nINPUT a$40000, b$40000', 'the push space has 65536'],
    ['bytes of any length where their length must be known', 'DIM owner$20\nINPUT k$\nx = CAT(k, k)', 'not known'],
  ]) {
    const m = badCov(text, env)
    ok(m.includes(needle), `${what}${m ? '' : ': NOT refused'}`)
  }
  const m = bad('INPUT k$\nx = 1')
  ok(m.includes('a covenant has DIM owner$20'), `INPUT in a program, which no tick runs: ${m || 'NOT refused'}`)
}

// ── where a jump lands ───────────────────────────────────────────────────────────────────────────────
/* A jump lands on the start of an instruction, as GOTO lands on a line (his call, 27 Oct). The listing and the engine
   take each instruction at the same length, and every branch this compiler writes lands on a start, or on the end. */
console.log('\n── where a jump lands: on the start of an instruction, in every program and covenant ──')
{
  const own = new Array(20).fill(0xab)
  const covenants = [['DIM owner$20', { owner: own }], ['DIM owner$20\nDIM n%4\nn = n + 1', { owner: own, n: 7 }],
    ['DIM owner$20\nDIM n%4\nDIM tag$3\nIF n > 3 THEN\n tag = &H010203\nELSE\n IF n = 0 THEN n = 9\nEND IF\nn = n + 2 ^ 3', { owner: own, n: 9, tag: [7, 8, 9] }],
    ['DIM owner$20\nDIM h$32\nh = HASH256(CAT(h, owner))', { owner: own, h: new Array(32).fill(1) }], ...INPUTS]
  const all = [...progs.flatMap(p => [p.c.bytes, p.script]), ...covenants.map(([text, state]) => compileCovenant(V + text, { state }).bytes)]
  const JUMPS = new Set(['BRANCH', '0BRANCH', '(?DO)', '(LOOP)', '(+LOOP)', 'LEAVE', 'CALL'])
  let same = 0, jumps = 0, landed = 0
  for (const b of all) {
    const ins = disassemble(b), starts = InterpreterJF.instructionStarts(b), listed = new Uint8Array(b.length)
    for (const x of ins) listed[x.at] = 1
    if (hex(listed) === hex(starts)) same++
    for (const x of ins.filter(x => JUMPS.has(x.name))) { jumps++; if (x.arg === b.length || starts[x.arg] === 1) landed++ }
  }
  ok(same === all.length, `★ the listing's offsets are the engine's instruction starts, in ${same}/${all.length} programs and covenants`)
  ok(landed === jumps && jumps > 0, `★ and every branch the compiler writes lands on one, or on the end: ${landed}/${jumps}`)
}

// ── a released compiler, read from git ─────────────────────────────────────────────────────────────
/** basic-jf.mjs as it was at a revision, importing that revision's opcode table; null when git does not have it */
async function released(rev) {
  const show = path => {
    try { return execFileSync('git', ['-C', ROOT, 'show', `${rev}:${path}`], { stdio: ['ignore', 'pipe', 'ignore'] }).toString() } catch { return null }
  }
  const src = show('basic/basic-jf.mjs'), ops = show('tools/ops-jf.mjs')
  if (src === null || ops === null) return null
  const url = s => `data:text/javascript;base64,${Buffer.from(s).toString('base64')}`
  return import(url(src.replace("'../tools/ops-jf.mjs'", `'${url(ops)}'`) + '\nexport { buildCovenant, covenantLayout, parseProgram, writes }\n'))
}
// covenants: the threads basic/test/thread.mjs ticks, the page's, and a field of every width a push holds, read or written
const COVENANTS = [
  ['DIM owner$20', { owner: OWN }],
  ['DIM owner$20\nDIM n%4\nn = n + 1', { owner: OWN, n: 7 }],
  [`DIM owner$20\nowner = &H${'cd'.repeat(20)}`, { owner: OWN }],
  ['DIM owner$20\nowner = &H0102', { owner: OWN }],
  ['DIM owner$20\nDIM n%8\nn = n + 1', { owner: OWN, n: 2n ** 63n - 2n }],
  ['DIM owner$20\nDIM n%4\nIF n > 3 THEN n = n + 1', { owner: OWN, n: 2 }],
  ['DIM owner$20\nDIM n%4\nDIM tag$3\nIF n > 3 THEN\n tag = &H010203\nELSE\n IF n = 0 THEN n = 9\nEND IF\nn = n + 2 ^ 3', { owner: OWN, n: 9, tag: [7, 8, 9] }],
  ['DIM owner$20\nDIM n%4\nx = n * 2\nVERIFY x > 0', { owner: OWN, n: 3 }],
  ['DIM owner$20\nDIM h$32\nh = HASH256(CAT(h, owner))', { owner: OWN, h: new Array(32).fill(1) }],
  ...Array.from({ length: JF_PUSH_MAX }, (_, k) => [`DIM owner$20\nDIM tag$${k + 1}`, { owner: OWN, tag: new Array(k + 1).fill(7) }]),
  ...Array.from({ length: JF_PUSH_MAX }, (_, k) => [`DIM owner$20\nDIM tag$${k + 1}\ntag = &H${'cd'.repeat(k + 1)}`, { owner: OWN, tag: new Array(k + 1).fill(7) }]),
]
// ── a field wider than a direct push ─────────────────────────────────────────────────────────────────
/* A $ field is one push in the head, as Code.push lays it down: a direct push to 72 bytes, STR8 to 255, STR16 past that.
   The rebuild writes the same push, so a field of any width the interpreter's memory holds can be written and kept. */
console.log('\n── a field wider than a direct push ──')
const WIDE = [73, 255, 256, 1200]
const wideCov = (w, written) => V + `DIM owner$20\nDIM tag$${w}` + (written ? `\nINPUT t$${w}\ntag = t` : '')
{
  let forms = 0, back = 0
  for (const w of WIDE) for (const written of [false, true]) {
    const c = compileCovenant(wideCov(w, written), { state: { owner: OWN, tag: new Array(w).fill(7) } })
    const head = [...c.bytes.slice(26, 26 + (w <= 0xff ? 2 : 3))]
    if (JSON.stringify(head) === JSON.stringify(w <= 0xff ? [JF_LIT.STR8, w] : [JF_LIT.STR16, w & 0xff, w >> 8])) forms++
    const r = unbasic(c.bytes)
    let again = ''
    try { again = hex(compileCovenant(r.lines.join('\n'), { state: r.state }).bytes) } catch (e) { again = e.message }
    if (!r.stoppedAt && again === hex(c.bytes)) back++
  }
  ok(forms === WIDE.length * 2, `tag$73 and tag$255 are one STR8 push in the head, tag$256 and tag$1200 one STR16, written or not (${forms}/${WIDE.length * 2})`)
  ok(back === WIDE.length * 2, `and each reads back to BASIC that compiles to the same bytes (${back}/${WIDE.length * 2})`)
  const past = (w, written) => { try { compileCovenant(wideCov(w, written), { state: { owner: OWN, tag: new Array(w).fill(7) } }); return '' } catch (e) { return e.message } }
  ok(past(65187, false) === '' && /needs \d+ bytes of memory, and the interpreter has 65536/.test(past(65188, false)),
     'the interpreter\'s memory bounds a field never written: 65,187 bytes, the preimage holding the script; past it the compiler says so')
  ok(past(32710, true) === '' && /pushes \d+ bytes, and the push space has 65536/.test(past(32711, true)),
     'the push space bounds one written from an INPUT: 32,710 bytes, pushed in the head and by the tick; past it the compiler says so')
  ok(/from 1 to 65535/.test(past(65536, false)), `DIM tag$65536 is refused: one push holds at most 65535 bytes`)
}

// ── a program checks a signature ─────────────────────────────────────────────────────────────────────
/* ED25519SIG(sig, pub, msg), the word the frame checks the owner's signature with, is a program's too: Ed25519 over the
   message as given, -1 or 0. Each program runs in both interpreters and reads back, as the ones above do. */
console.log('\n── a program checks a signature: ED25519SIG ──')
const keyOf = s => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), h('sha256')(Buffer.from(s))]), format: 'der', type: 'pkcs8' })
const pubOf = k => hex(createPublicKey(k).export({ format: 'der', type: 'spki' }).subarray(12))
const sigOf = (k, m) => hex(sign(null, Buffer.from(m, 'hex'), k))
const AUTHOR = keyOf('an author'), SOMEONE = keyOf('somebody else')
const MSG = hex(Buffer.from('a comment, as its author wrote it')), PUB = pubOf(AUTHOR), SIG = sigOf(AUTHOR, MSG)
/** Programs that check a signature: 0.6 compiles none of them, so they are kept apart from `progs`. */
const SIGNED = []
{
  const env = { stack: ['s$', 'p$', 'm$'], leave: ['x'] }, CHECK = 'x = ED25519SIG(s, p, m)'
  const one = (name, src, inputs, want, e = env) => SIGNED.push({ name, src: V + src, env: e, inputs, want })
  const flip = s => (parseInt(s.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0') + s.slice(2)
  one('signed by the key given: -1', CHECK, [SIG, PUB, MSG], [-1n])
  one('the message changed after signing: 0', CHECK, [SIG, PUB, flip(MSG)], [0n])
  one('the signature with one bit changed: 0', CHECK, [flip(SIG), PUB, MSG], [0n])
  one('signed by somebody else: 0', CHECK, [sigOf(SOMEONE, MSG), PUB, MSG], [0n])
  one('a key of 31 bytes: 0, a failed check and not an error', CHECK, [SIG, PUB.slice(2), MSG], [0n])
  one('a signature of 63 bytes: 0', CHECK, [SIG.slice(2), PUB, MSG], [0n])
  one('an empty message, signed: -1', CHECK, [sigOf(AUTHOR, ''), PUB, ''], [-1n])
  one('a message the program makes: signed over the SHA-256 of the bytes given', 'x = ED25519SIG(s, p, SHA256(m))',
    [sigOf(AUTHOR, hex(h('sha256')(Buffer.from(MSG, 'hex')))), PUB, MSG], [-1n])
  one('as numbers: two that pass and one that does not', 'x = ED25519SIG(s, p, m) + ED25519SIG(s, p, m) + ED25519SIG(s, p, SHA256(m))', [SIG, PUB, MSG], [-2n])
  one('VERIFY ED25519SIG passes and leaves nothing behind', 'VERIFY ED25519SIG(s, p, m)\nx = 1', [SIG, PUB, MSG], [1n])
  one('VERIFY ED25519SIG refuses a signature by somebody else', 'VERIFY ED25519SIG(s, p, m)\nx = 1', [sigOf(SOMEONE, MSG), PUB, MSG], 'refused')
  const LOOP = 'x = 0\nFOR i = 1 TO n\n x = x + ED25519SIG(s, p, m)\nNEXT i', env4 = { stack: ['s$', 'p$', 'm$', 'n'], leave: ['x'] }
  one('★ in a FOR, 100 checks, the most JF revision 3 makes in a run', LOOP, [SIG, PUB, MSG, 100], [-100n], env4)
  one('★ …and the 101st is refused by the interpreter, not the compiler', LOOP, [SIG, PUB, MSG, 101], 'refused', env4)
}
/** Covenants whose program checks a signature: an author's, over the text a tick carries. Their ticks are in basic/test/thread.mjs. */
const SIGNED_COVENANTS = [
  ['DIM owner$20\nDIM by$32\nDIM said$32\nINPUT asig$64, apub$32, text$\nVERIFY ED25519SIG(asig, apub, text)\nby = apub\nsaid = SHA256(text)',
    { owner: OWN, by: new Array(32).fill(0), said: new Array(32).fill(0) }],
  ['DIM owner$20\nINPUT asig$64, apub$32, text$, n%2\nFOR i = 1 TO n\n VERIFY ED25519SIG(asig, apub, text)\nNEXT i', { owner: OWN }],
]
{
  for (const p of SIGNED) {
    p.c = compileBasic(p.src, p.env)
    const d = DECLARATION.length
    p.script = Uint8Array.from([...p.c.bytes.slice(0, d), ...pushes(p.inputs), ...p.c.bytes.slice(d)])
  }
  const php = execFileSync('php', [join(ROOT, 'tools/jf-run.php'), '0'],
    { input: JSON.stringify(SIGNED.map(p => ({ script: hex(p.script), preimage: null }))), maxBuffer: 1 << 28 })
    .toString().trim().split('\n').map(l => JSON.parse(l))
  const big = (_, v) => typeof v === 'bigint' ? String(v) : v
  let agree = 0, right = 0, back = 0
  for (const [k, p] of SIGNED.entries()) {
    const vm = new InterpreterJF({ crypto })
    let js, got
    try {
      const stack = await vm.run(p.script)
      js = { stack: stack.map(String) }; got = stack.slice(0, p.c.leave.length)
    } catch (e) { js = { error: hex(Buffer.from(e.message)) }; got = 'refused' }
    const same = JSON.stringify(js) === JSON.stringify(php[k].stack ? { stack: php[k].stack } : { error: php[k].error })
    const correct = JSON.stringify(got, big) === JSON.stringify(p.want, big)
    const r = unbasic(p.c.bytes, { stack: p.c.inputs })
    let again = r.stoppedAt ?? ''
    if (!r.stoppedAt) { try { again = hex(compileBasic(r.lines.join('\n'), { stack: r.stack, consts: {}, leave: r.leave }).bytes) } catch (e) { again = e.message } }
    if (same) agree++; if (correct) right++; if (again === hex(p.c.bytes)) back++
    if (!same || !correct || again !== hex(p.c.bytes) || process.env.V) {
      console.log(`  ${same && correct ? '·' : '✗'} ${p.name}: ${p.c.bytes.length} B` +
        (correct ? '' : `\n      want ${JSON.stringify(p.want, big)}, got ${JSON.stringify(got, big)}`) +
        (same ? '' : `\n      JS ${JSON.stringify(js)}\n      PHP ${JSON.stringify(php[k])}`) +
        (again === hex(p.c.bytes) ? '' : `\n      reads as\n${r.lines.map(l => '      ' + l).join('\n')}`))
    }
  }
  ok(right === SIGNED.length, `★★ ${right}/${SIGNED.length} programs that check a signature compute what they say`)
  ok(agree === SIGNED.length, `★ the JavaScript and PHP interpreters leave the same stack, or raise the same refusal, on all ${agree}/${SIGNED.length}`)
  const why = start => Buffer.from(php[SIGNED.findIndex(p => p.name.startsWith(start))].error ?? '', 'hex').toString()
  ok(/signature check limit exceeded/.test(why('★ …and the 101st')), `…the 101st check: ${why('★ …and the 101st') || 'NOT refused'}`)
  ok(back === SIGNED.length, `★ and each reads back, ED25519SIG and all, to BASIC that compiles to the same bytes (${back}/${SIGNED.length})`)
  let read = 0
  for (const [text, state] of SIGNED_COVENANTS) {
    const c = compileCovenant(V + text, { state })
    for (const opts of [{ names: c.names }, {}]) {
      const u = unbasic(c.bytes, opts)
      let again = ''
      try { again = hex(compileCovenant(u.lines.join('\n'), { state: u.state }).bytes) } catch (e) { again = e.message }
      if (!u.stoppedAt && u.lines.some(l => l.includes('ED25519SIG(')) && again === hex(c.bytes)) read++
      else console.log(`  ✗ ${text.split('\n').join(' · ')}: read back, ${u.stoppedAt ?? 'it compiles to different bytes'}\n${u.lines.map(l => '      ' + l).join('\n')}`)
    }
  }
  ok(read === 2 * SIGNED_COVENANTS.length, `★ a covenant whose program checks an author's signature compiles and reads back, named and unnamed, to the same bytes (${read}/${2 * SIGNED_COVENANTS.length})`)
}
/** The frame's own words stay its own; ED25519SIG takes three byte strings. */
const SIGNED_REFUSALS = [
  ['PREIMAGE is still the frame\'s alone', 'x = SIZE(PREIMAGE())', {}, 'no such word: PREIMAGE'],
  ['and so is DEPTH', 'x = DEPTH()', {}, 'no such word: DEPTH'],
]
for (const [what, src, env, needle] of [...SIGNED_REFUSALS,
  ['ED25519SIG with two arguments', 'x = ED25519SIG(&H01, &H02)', {}, 'takes 3 argument(s)'],
  ['ED25519SIG given a number', 'x = ED25519SIG(1, &H02, &H03)', {}, 'works on bytes'],
]) {
  const m = bad(src, env)
  ok(m.includes(needle), `${what}${m ? '' : ': NOT refused'}`)
}

// ── against 0.7, by results ──────────────────────────────────────────────────────────────────────────
/* Rule 3: a new version, proved against the old one, by results and not by bytes: this version writes other code, and
   it must mean the same. 0.7 is read from git as it was released. Every program both compile leaves the same values;
   every program 0.7 refuses, this version refuses in the same words; and every covenant here gives the same verdict on
   the same ticks, built for each version's own script: its next tick, with the state 0.7's own program writes (its
   fields read from 0.7's memory after a run), a next state that is not that one, the tick signed by another key, and
   the value moved by 2, and nSequence not the next number. Each tick is judged by CovenantThread::judge (tools/judge-run.php) and judge() of
   tools/thread.mjs, which must agree. */
const REV07 = '64eb708'
console.log(`\n── compiler ${BASIC_JF_VERSION} against 0.7, as released (${REV07}, from git), by results ──`)
const B7 = await released(REV07)
if (B7 === null) console.log(`  - no 0.7 to prove against: revision ${REV07} is not in this repository. The comparison is skipped, never counted as passed.`)
else {
  ok(B7.BASIC_JF_VERSION === '0.7', '0.7 loads beside this compiler, on its own opcode table')
  /** What a compiled program leaves, read as the run above reads it: its values, or why it was refused */
  const resultOf = async (bytes, p, leave) => {
    const d = DECLARATION.length, vm = new InterpreterJF({ crypto })
    try {
      const stack = await vm.run(Uint8Array.from([...bytes.slice(0, d), ...pushes(p.inputs), ...bytes.slice(d)]))
      const got = []; let s = 0
      for (const _ of leave) {
        if (typeof p.want !== 'string' && typeof p.want[got.length] === 'string') { got.push(hex(vm.read(stack[s], stack[s + 1]))); s += 2 }
        else { got.push(String(stack[s])); s += 1 }
      }
      return JSON.stringify(got)
    } catch (e) { return `refused: ${e.message}` }
  }
  let plain = 0
  for (const p of progs) {
    const c7 = B7.compileBasic(p.src, p.env), r7 = await resultOf(c7.bytes, p, c7.leave), r8 = await resultOf(p.c.bytes, p, p.c.leave)
    if (r7 === r8) plain++
    else console.log(`  ✗ ${p.name}\n      0.7 ${r7}\n      ${BASIC_JF_VERSION} ${r8}`)
  }
  ok(plain === progs.length, `★★ every program here, ${plain}/${progs.length}: the same values from 0.7's script and from this version's`)
  const refused = [...refusals.map(([, src, env]) => [V + src, env]), ...SIGNED_REFUSALS.map(([, src, env]) => [V + src, env]),
                   ...VERSION_REFUSALS.map(([, src]) => [src, {}])]
  let words = 0
  for (const [src, env] of refused) {
    let m7 = ''
    try { B7.compileBasic(src, env) } catch (e) { m7 = e.message }
    if (m7 !== '' && m7 === badRaw(src, env)) words++
  }
  ok(words === refused.length, `every program 0.7 refuses here, PREIMAGE and DEPTH among them, ${BASIC_JF_VERSION} refuses in the same words (${words}/${refused.length})`)

  // ── covenants: the same ticks, judged the same ──
  const newKey = async () => ed25519Signer(await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']))
  const OWNER = await newKey(), OTHER = await newKey(), ownerHash = [...h('ripemd160')(h('sha256')(OWNER.publicKey))]
  const VALUE = 5n, TIP = new Uint8Array(32).fill(0x7e)
  const le64 = v => hex(Uint8Array.from({ length: 8 }, (_, k) => Number((v >> BigInt(8 * k)) & 0xffn)))
  /** What a tick carries for a covenant's INPUT line: bytes of its width, 4 when any length; a number, 3 */
  const inputsFor = c => c.inputs.map(x => x.bytes ? new Uint8Array(x.width ?? 4).fill(0x61) : 3)
  const tickFor = (lock, next, inputs, { key = OWNER, step = 1n, sequence = Number(VALUE + step) } = {}) =>
    tick(TIP, 0, lock, VALUE, [{ value: VALUE + step, locking: next }], sequence, basicUnlock(key, inputs))
  /** The state 0.7's program writes on its next tick: its fields, read from 0.7's memory after a run on a tick whose
      successor is the tip's own script, which the run checks only at its end */
  async function nextState(c, inputs) {
    const t = await tickFor(c.bytes, c.bytes, inputs)
    const vm = new InterpreterJF({ ...TICK_LIMITS, crypto: jfCrypto })
    vm.setPreimage(Uint8Array.from(preimage({ entry: t.entry, inputIndex: 0, scriptCode: c.bytes, value: VALUE })))
    Object.assign(vm, { ds: [], rs: [], frames: [], chan: [], opCount: 0, depth: 0, frameCells: 0, held: 0, sigOps: 0, mem: null,
                        pmem: new Uint8Array(0), plen: 0, pbase: PUSH_BASE, mbase: 0 })
    try {
      await vm.exec(t.entry.inputs[0].unlocking, 0, true)
      Object.assign(vm, { rs: [], frames: [], depth: 0, frameCells: 0 })
      await vm.exec(c.bytes, vm.codeStart(c.bytes), true)
    } catch {}
    const addr = Object.fromEntries(Object.entries(c.names).map(([a, n]) => [n, BigInt(a)]))
    return Object.fromEntries(c.layout.map(f => [f.name, f.bytes ? [...vm.read(vm.fetch(addr[f.name] + 8n), vm.fetch(addr[f.name]))] : vm.fetch(addr[f.name])]))
  }
  const wide = WIDE.flatMap(w => [false, true].map(written => [wideCov(w, written).slice(V.length), { owner: OWN, tag: new Array(w).fill(7) }]))
  const all = [...COVENANTS, ...INPUTS, ...wide], built = []
  const compiles = (B, src, state) => { try { return B.compileCovenant(src, { state }).bytes } catch { return null } }
  for (const [text, state] of all) {
    const src = V + text, S0 = { ...state, owner: ownerHash }, c7 = B7.compileCovenant(src, { state: S0 }), inputs = inputsFor(c7)
    let S1 = await nextState(c7, inputs), next = true
    /* a program that writes a field at another width than its DIM can never tick: its next state does not compile */
    if (compiles(B7, src, S1) === null) { S1 = S0; next = false }
    const wrong = { ...S1, owner: S1.owner.map((b, k) => k === 0 ? b ^ 1 : b) }
    const cases = [['its next tick', S1, {}, next], ['a next state not the one its program writes', wrong, {}, false],
                   ['signed by another key', S1, { key: OTHER }, false], ['the value moved by 2', S1, { step: 2n }, false],
                   ['nSequence not the next number', S1, { sequence: Number(VALUE) + 3 }, false]]
    for (const [B, version] of [[B7, '0.7'], [{ compileCovenant }, BASIC_JF_VERSION]]) {
      const lock = B.compileCovenant(src, { state: S0 }).bytes
      for (const [what, S, opts, want] of cases) {
        built.push({ text, version, what, want, lock, t: await tickFor(lock, B.compileCovenant(src, { state: S }).bytes, inputs, opts) })
      }
    }
  }
  const php = JSON.parse(execFileSync('php', [join(ROOT, 'tools/judge-run.php'), 'judge'], { maxBuffer: 1 << 28,
    input: JSON.stringify(built.map(b => ({ entry: hex(b.t.bytes), input: 0, lock: hex(b.lock), value: le64(VALUE) }))) }).toString())
  let judged = 0, accepted = 0
  for (const [k, b] of built.entries()) {
    const js = (await judge(b.t.entry, 0, b.lock, VALUE)).accepted === true, ph = php[k].accepted === true
    if (js === ph && ph === b.want) { judged++; if (ph) accepted++ }
    else console.log(`  ✗ ${b.text.split('\n').join(' · ')} [${b.version}] ${b.what}: PHP ${ph}, JS ${js}, want ${b.want}`)
  }
  ok(judged === built.length, `★★ every covenant here, ${all.length} of them, the INPUT and wide-field ones among them: its next tick, a next state ` +
    `not the one its program writes, another key, the value moved by 2 and nSequence not the next number, each judged by both judges, under 0.7 and under ${BASIC_JF_VERSION} ` +
    `(${judged}/${built.length}, ${accepted} accepted)`)
}


console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [BASIC → jetForth]`)
process.exit(fail === 0 ? 0 : 1)
