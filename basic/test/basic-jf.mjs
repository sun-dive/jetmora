// © 2026 sun-dive — Apache License 2.0.
//
// BASIC → jetForth: does a compiled program compute what it says, in BOTH jetmora interpreters?
//   node basic/test/basic-jf.mjs
// The programs are grafverse/mint/test/basic.ts's, with jetForth's answers where jetForth differs: a
// comparison is -1, the words on bytes and numbers are typed, and loops are loops. Every program runs in
// the JavaScript interpreter here and the PHP one (tools/jf-run.php), and the two must leave the same
// stack or raise the same refusal. Then every program is read back, and the reading compiles to the
// same bytes.
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { compileBasic, compileCovenant, JF_NVERSION, JF_REVISION } from '../basic-jf.mjs'
import { unbasic, disassemble } from '../unbasic-jf.mjs'
import { InterpreterJF } from '../../tools/interpreter-jf.mjs'
import { JF_LIT } from '../../tools/ops-jf.mjs'

const HERE = dirname(fileURLToPath(import.meta.url)), ROOT = join(HERE, '../..')
const hex = b => Buffer.from(b).toString('hex')
const h = alg => b => Uint8Array.from(createHash(alg).update(b).digest())
const crypto = { sha256: h('sha256'), sha1: h('sha1'), ripemd160: h('ripemd160') }
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
  prog('one literal used twice is stored once', 'x = SAMEBYTES(&H0102, &H0102) + SIZE(CAT(&H0102, &H03))', env, [0, 0], [2n])
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

// 8. the heap stops at the literals, and the machine stops a loop that does not
prog('★ bytes that would reach the literals are refused', `L = &H${'ab'.repeat(64)}\nFOR i = 1 TO 100000\n y = CAT(L, L)\nNEXT i`, {}, [], 'refused')
prog('★ bytes past the end of memory are refused', 'x = &H01\nFOR i = 1 TO 100\n x = CAT(x, x)\nNEXT i', {}, [], 'refused')
prog('★ a loop past the operation budget is refused by the interpreter', 'FOR i = 1 TO 1000000000\n s = s + 1\nNEXT i', { stack: ['s'], leave: ['s'] }, [0], 'refused')

// ── compile, and run each in both interpreters ───────────────────────────────────────────────────────
console.log('\nBASIC → jetForth — every program, in both interpreters\n')
for (const p of progs) {
  p.c = compileBasic(p.src, p.env)
  p.script = Uint8Array.from([...pushes(p.inputs), ...p.c.bytes])
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
      if (isBytes) { const [a, u] = [stack[s], stack[s + 1]]; got.push(hex(vm.mem.slice(Number(a), Number(a + u)))); s += 2 }
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
  ok(why('★ bytes that would reach') === 'ABORT', '…heap blocks reaching the literals: refused by the compiled floor check')
  ok(why('★ bytes past the end').startsWith('memory out of range'), '…a block past the end of memory: refused by the interpreter\'s own bound')
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
  ['DIM, until jetmora\'s state is decided', 'DIM v%5\nv = 1', {}, 'state'],
  ['CHECKSIG, until its BASIC form is decided', 'x = CHECKSIG(&H01, &H02)', {}, 'digest'],
]
for (const [what, src, env, needle] of refusals) {
  const m = bad(src, env)
  ok(m.includes(needle), `${what}${m ? '' : ' — NOT refused'}`)
}
for (const [what, src, needle] of [
  ['a program that does not name its version', 'x = 1', 'names its version first'],
  ['a version this compiler does not emit', 'VERSION JF 2\nx = 1', 'emits JF revision 3'],
  ['another instruction set', 'VERSION SV 1\nx = 1', 'emits JF revision 3'],
  ['VERSION said twice', 'VERSION JF 3\nx = 1\nVERSION JF 3', 'said once'],
  ['VERSION inside an IF', 'VERSION JF 3\nx = 1\nIF x THEN VERSION JF 3', 'said once'],
]) {
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
ok(hex(compileBasic('VERSION JF 3\nx = 1').bytes) === hex(compileBasic('REM  x\n10 VERSION JF 3\n20 x = 1').bytes), 'the VERSION line emits nothing: it names the revision the bytes are in')
ok(same('IF a > b THEN p = 1 ELSE p = 2', 'IF a > b THEN\n p = 1\nELSE\n p = 2\nEND IF', { stack: ['a', 'b', 'p'] }),
  'a line IF and a block IF are byte-identical')

// ── the version ──────────────────────────────────────────────────────────────────────────────────────
console.log('\n── the version an entry must name ──')
const reg = JSON.parse(execFileSync('php', ['-r',
  `require '${join(ROOT, 'server/dispatch.php')}'; echo json_encode(['jf' => $GLOBALS['JETMORA_SETS']['JF']['revisions'], 'v' => version_build('JF', ${JF_REVISION})]);`]).toString())
ok(reg.v === JF_NVERSION, `nVersion 0x${JF_NVERSION.toString(16)} is version_build('JF', ${JF_REVISION})`)
ok(reg.jf.includes(JF_REVISION), `…and dispatch.php serves JF revision ${JF_REVISION}`)
ok(progs.every(p => p.c.nVersion === JF_NVERSION) && compileCovenant(V + 'x = 1').nVersion === JF_NVERSION,
  'every compiled program carries it')

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

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed, ${fail} failed   [BASIC → jetForth]`)
process.exit(fail === 0 ? 0 : 1)
