#!/usr/bin/env python3
"""
THE CANONICAL `JF` OPCODE MAP. One implementation, two consumers.

  tools/gen-ops-jf.py        → server/ops-jf.php   (what the interpreter runs)
  ~/Documents/gen-jf-wordmap.py → the human table   (what we read)

⚠⚠ Both import THIS. A second copy of the assignment logic is how the table and
   the interpreter drift apart, and the conformance vectors would not catch it —
   they pin behaviour, not numbering.

THE SCHEME (design notes §10.5e–§10.5j):
  jetForth  one byte  — data pushes, runtime primitives, all crypto. CONTROLS the covenant.
  stdForth  two bytes — the complete Forth 2012 vocabulary, one bank per wordset.
  A word promoted to jetForth has ONLY that encoding; its bank slot is reserved-illegal,
  because jetmora proves execution by hashing the bytecode and two encodings of one
  program would mean two hashes.
"""
import collections, os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'forth2012.tsv')

# ── jetForth: the hot set ───────────────────────────────────────────────────
# The rule: a word is single-byte iff A COMPILED COVENANT EXECUTES IT. Everything
# that parses text, compiles, or mutates the dictionary is a compiling word — it
# never appears in bytecode, so a bank costs it nothing.
HOT = {
 'stack': ['DUP', 'DROP', 'SWAP', 'OVER', 'ROT', '?DUP', 'NIP', 'TUCK', 'DEPTH',
           'PICK', 'ROLL', '2DUP', '2DROP', '2SWAP', '2OVER',
           '>R', 'R>', 'R@', '2>R', '2R>', '2R@'],
 'arithmetic': ['+', '-', '*', '/', 'MOD', '/MOD', '*/', '*/MOD', '1+', '1-',
                '2*', '2/', 'ABS', 'NEGATE', 'MIN', 'MAX',
                'FM/MOD', 'SM/REM', 'UM*', 'UM/MOD', 'M*', 'S>D'],
 'logic': ['AND', 'OR', 'XOR', 'INVERT', 'LSHIFT', 'RSHIFT'],
 'compare': ['=', '<>', '<', '>', 'U<', 'U>', '0=', '0<>', '0<', '0>', 'WITHIN'],
 'constant': ['TRUE', 'FALSE', 'BL'],
 'memory': ['@', '!', 'C@', 'C!', '+!', '2@', '2!', 'MOVE', 'FILL', 'ERASE',
            'CELLS', 'CELL+', 'CHARS', 'CHAR+', 'ALIGNED'],
 'loop runtime': ['I', 'J', 'UNLOOP', 'LEAVE', 'EXIT', 'EXECUTE'],
 # ★ `ABORT` is Forth CORE and is PROMOTED: a covenant refusing is the commonest thing it does, and
 #   it must be able to say why. Its two-byte form is therefore reserved-illegal, like every promoted
 #   word. `ABORT"` itself stays in the bank — it is a COMPILING word that emits `(ABORT")`.
 'abort': ['ABORT'],
}
# bytecode-only primitives — NOT Forth words. IF/THEN/DO/LOOP are compiling words
# that EMIT these; these are what actually appears in a compiled covenant.
BRANCH = ['BRANCH', '0BRANCH', '(DO)', '(?DO)', '(LOOP)', '(+LOOP)', 'CALL', 'RET']
# the ONE word that crosses into stdForth. stdForth has no word that reaches back.
INVOKE = ['INVOKE']
# named locals are the readability mechanism (§10.5h), so their runtime lives here.
# `{:` and `LOCALS|` are COMPILING words (bank) and never appear in bytecode.
LOCALS = ['(FRAME)', '(LOCAL@)', '(LOCAL!)', '(UNFRAME)']
# `ABORT"` compiles to this. ⚠ NOT a Forth word — it is the runtime half, as BRANCH is for IF.
#   ( flag c-addr u -- )   abort carrying the message when the flag is true.
ABORTS = ['(ABORT")']

CRYPTO = ['CHECKMULTISIG', 'CHECKMULTISIGVERIFY', 'CHECKSIG', 'CHECKSIGVERIFY',
          'HASH160', 'HASH256', 'RIPEMD160', 'SHA1', 'SHA256']
TX = ['LOCKTIME', 'NSEQUENCE', 'OUTPOINT', 'OUTPUTS-HASH', 'PREIMAGE',
      'PREVOUTS-HASH', 'SCRIPTCODE', 'SEQUENCES-HASH', 'TXVALUE', 'TXVERSION',
      'VER', 'VERIF', 'VERNOTIF']
# ⚠⚠ `BYTES=` WAS MISSING UNTIL 7 SEPT, and only writing a REAL COVENANT found it.
#   A covenant's core operation is comparing a computed hash against one taken from the preimage.
#   `=` compares CELLS; `BIN2NUM` on a 32-byte hash truncates to 64 bits. ⇒ There was NO WAY TO
#   COMPARE TWO HASHES — which is the one thing every covenant must do.
#   ★ Bitcoin has OP_EQUAL for exactly this. Forth's own `COMPARE` is STRING-wordset (optional, banked),
#   and a covenant cannot depend on an optional wordset for its central operation.
#   ⚠ Constant time by construction: it must not leak where two hashes first differ.
BYTES = ['BIN2NUM', 'BYTES=', 'CAT', 'LEFT', 'NUM2BIN', 'RIGHT', 'SIZE', 'SPLIT', 'SUBSTR']

# ★ APPENDED after the sectioned fill was pinned (15 Sept, revision 2). In order of addition, from
#   0xDD upward, never sorted and never moved: an insert would renumber everything above it.
#   ED25519-CHECKSIG ( a-sig u-sig a-pub u-pub a-msg u-msg -- flag ): Ed25519 over the message as given
#   (the scheme hashes internally, so no digest word precedes it). 32-byte key, 64-byte signature;
#   any other length is a failed check, never an error. CHECKSIG itself stays secp256k1: a word that
#   mirrors a Bitcoin opcode keeps Bitcoin's meaning, and another scheme is another word.
APPENDED = ['ED25519-CHECKSIG', 'ED25519-CHECKSIGVERIFY']

LITFORMS = [('LIT8',   'next 1 byte, signed  -> integer'),
            ('LIT16',  'next 2 bytes, signed -> integer'),
            ('LIT32',  'next 4 bytes, signed -> integer'),
            ('LIT64',  'next 8 bytes, signed -> integer'),
            ('LITBIG', 'varint length, then sign-magnitude bytes -> bignum'),
            ('STR8',   'next 1 byte = length, then that many bytes'),
            ('STR16',  'next 2 bytes = length, then that many bytes'),
            ('STR32',  'next 4 bytes = length, then that many bytes')]

# ⚠ MEASURED, not chosen by habit. Bitcoin has OP_1..OP_16 because N-of-M multisig needed them;
#   `JF` does multisig differently and its common small constants are sizes (0 1 2 4 8). Meanwhile a
#   DER signature is 70-73 bytes and an uncompressed key is 65 — the two most frequent pushes in any
#   covenant. ⇒ Spending 8 slots on 9..16 to make every signature cost an extra byte is backwards.
#   Trimming them buys push 0..72, which covers hash160, sha256, both key forms AND signatures, at
#   exactly the same reserve. A constant 9..16 still works; it costs LIT8, two bytes.
SMALL_INTS = list(range(0, 9)) + [-1]
N_PUSH = 73        # 0x00..0x48 — direct push of 0..72 bytes
ESC0 = 0xF0        # 16 escapes: 13 wordsets, 2 free, 0xFF = plane escape
PLANE = 0xFF

FORTH_OPTIONAL = ['BLOCK', 'DOUBLE', 'EXCEPTION', 'FACILITY', 'FILE', 'FLOATING',
                  'LOCAL', 'MEMORY', 'SEARCH', 'STRING', 'TOOLS', 'XCHAR']
BANKS = ['CORE'] + FORTH_OPTIONAL          # 0xF0 .. 0xFC


# ── why the CORE bank has no runtime ─────────────────────────────────────────
# ⚠⚠ MEASURED 7 Sept, and it changed the build plan. Of the 98 CORE words left in
# the bank after promotion, ZERO are runtime data operations. Every one compiles,
# parses text, formats output, or is a system word. ⇒ THE 84 PROMOTED WORDS ARE
# THE COMPLETE RUNTIME CORE, and the promotion rule split it exactly.
#
# ★ So the CORE bank is an ENCODING RESERVATION, not unimplemented work: the
#   numbers exist so the map stays complete and derivable from the standard, and
#   the interpreter refuses each one saying WHICH KIND of word it is.
# ⛔ `EVALUATE` is the exception worth naming separately: it interprets text at
#   runtime, which is `OP_EVAL`. Design notes §6 sets out why OP_EVAL is correctly
#   absent, and that reasoning does not stop applying because the spelling changed.
CORE_KIND = {}
for _w in """: ; :NONAME CREATE DOES> POSTPONE IMMEDIATE LITERAL [ ] ['] [CHAR] [COMPILE]
 IF ELSE THEN DO ?DO LOOP +LOOP BEGIN UNTIL WHILE REPEAT AGAIN CASE OF ENDOF ENDCASE RECURSE
 VARIABLE CONSTANT VALUE DEFER MARKER BUFFER: TO IS ACTION-OF DEFER@ DEFER! COMPILE,
 ALLOT , C, ALIGN HERE UNUSED >BODY PAD ( \\""".split():
    CORE_KIND[_w] = 'compile-time'
for _w in """WORD PARSE PARSE-NAME SOURCE SOURCE-ID >IN REFILL ACCEPT FIND \' S" C" ."
 S\\" SAVE-INPUT RESTORE-INPUT >NUMBER COUNT CHAR""".split():
    CORE_KIND[_w] = 'text interpretation'
# ★★★ THE DECLARED CHANNELS (his call, 7 Sept). These RUN inside a stdForth function whose DEFS
#   header declares in_max / out_max — `EMIT` returns its contents, `ACCEPT` receives from the caller.
#   ⇒ Refused only where no channel is declared, which is a contract fact, not a capability one.
for _w in 'EMIT CR SPACE SPACES TYPE'.split():
    CORE_KIND[_w] = 'output channel'
for _w in 'KEY ACCEPT'.split():
    CORE_KIND[_w] = 'input channel'
# ⚠ These are genuinely NOT BUILT, and saying so is different from the refusals above: they need
#   `BASE` as live state plus pictured numeric output. Honest work outstanding.
for _w in '. U. .R U.R .( <# # #S #> HOLD HOLDS SIGN BASE DECIMAL HEX'.split():
    CORE_KIND[_w] = 'number formatting'
for _w in 'QUIT ENVIRONMENT? STATE'.split():
    CORE_KIND[_w] = 'system'
# ⚠ `ABORT"` is a COMPILING word: it emits `(ABORT")` plus the inline string, exactly as `IF` emits a
#   branch. `ABORT` itself is promoted to jetForth and so is not in this table at all.
CORE_KIND['ABORT"'] = 'compile-time'
CORE_KIND['EVALUATE'] = 'runtime text interpretation — this is OP_EVAL'


def load(src=SRC):
    """Forth 2012's alphabetical index → {wordset: [words]}, duplicates collapsed.

    A name listed under several wordsets is ONE word whose semantics a later set
    extends (ABORT in CORE and EXCEPTION EXT, S" in CORE and FILE, ...). It gets
    ONE slot, in the earliest set.
    """
    rows = [l.rstrip('\n').split('\t') for l in open(src) if l.strip()]
    listed = collections.defaultdict(list)
    for n, w in rows:
        listed[n].append(w)
    prio = {'CORE': 0, 'CORE EXT': 1}
    home = {n: sorted(ws, key=lambda w: (prio.get(w, 2), w))[0] for n, ws in listed.items()}
    sets = collections.defaultdict(list)
    for n, w in home.items():
        sets[w].append(n)
    for w in sets:
        sets[w].sort()                       # alphabetical FIRST FILL — derivable by anyone
    dups = {n: ws for n, ws in listed.items() if len(ws) > 1}
    return dict(sets), dups, set(home)


def assign(src=SRC):
    """The complete map. Raises if it does not fit, rather than quietly shrinking the reserve."""
    sets, dups, allnames = load(src)

    hot = [w for g in HOT.values() for w in g]
    bogus = [w for w in hot if w not in allnames]
    if bogus:
        raise SystemExit(f'⛔ not Forth 2012 words: {bogus}')
    if len(set(hot)) != len(hot):
        raise SystemExit('⛔ duplicate in the hot list: '
                         f'{[w for w, c in collections.Counter(hot).items() if c > 1]}')
    jm = set(BRANCH + INVOKE + LOCALS + ABORTS + CRYPTO + TX + BYTES + APPENDED)
    clash = jm & allnames
    if clash:
        raise SystemExit(f'⛔ jetmora word collides with a Forth name: {sorted(clash)}')

    # ★★★ SECTIONS BY CATEGORY, ALPHABETICAL WITHIN EACH — his rule, 15 Sept: a single alphabetical run
    #   is inferior for a person looking through the list, because the word they want sits between
    #   unrelated ones. The section order is the declared order below, so the bytes are still DERIVABLE:
    #   anyone holding this file and the standard regenerates the same numbers.
    # ⇒ Two runs kept: promoted Forth words first (each has a bank slot that is RESERVED-ILLEGAL),
    #   then jetmora's own (no bank at all), so that difference stays visible in the numbering.
    # ⚠ Renumbered 15 Sept while nothing permanent pins these bytes (no JF conformance vector, no
    #   chain entry; foen's threads keep no chain behind the tip and redeploy with it). After a
    #   conformance vector or a deployed covenant pins them, the rule becomes APPEND-ONLY: a new word
    #   goes at 0xDD upward, whatever its category.
    SECTIONS = [(name, sorted(g)) for name, g in HOT.items()] + [
        ('branch', sorted(BRANCH)), ('tier boundary', sorted(INVOKE)), ('locals runtime', sorted(LOCALS)),
        ('abort runtime', sorted(ABORTS)), ('crypto', sorted(CRYPTO)), ('transaction', sorted(TX)),
        ('byte strings', sorted(BYTES)),
        ('appended', list(APPENDED))]          # ⚠ in order of addition, never sorted
    words = [w for _, ws in SECTIONS for w in ws]
    n_lit = len(SMALL_INTS) + len(LITFORMS)
    # ⚠⚠ THE RESERVE IS THE REMAINDER, NEVER A RANGE. Letting the push range absorb
    #    the slack is exactly how 0.1.3 ended up with no room to append.
    reserve = 256 - (256 - ESC0) - N_PUSH - n_lit - len(words)
    if reserve < 16:
        raise SystemExit(f'⛔ only {reserve} single-byte slots left in reserve')

    code, at = {}, N_PUSH
    for i in SMALL_INTS:
        code[f'#{i}'] = at; at += 1
    for w, _ in LITFORMS:
        code[w] = at; at += 1
    for w in words:
        code[w] = at; at += 1
    assert at + reserve == ESC0, (at, reserve)

    banks = {}                                # escape byte -> (wordset, [words in slot order])
    for i, w in enumerate(BANKS):
        banks[ESC0 + i] = (w, sets.get(w, []) + sets.get(w + ' EXT', []))
    for _, (w, ws) in banks.items():
        if len(ws) > 256:
            raise SystemExit(f'⛔ bank {w} needs {len(ws)} slots')

    return {
        'code': code, 'words': words, 'sections': SECTIONS, 'promoted': set(hot), 'banks': banks,
        'sets': sets, 'dups': dups, 'allnames': allnames,
        'n_push': N_PUSH, 'n_lit': n_lit, 'reserve': reserve,
        'resv_at': at, 'esc0': ESC0, 'plane': PLANE,
    }


if __name__ == '__main__':
    m = assign()
    print(f"single byte : {m['n_push']} pushes + {m['n_lit']} literals + {len(m['words'])} words "
          f"+ {m['reserve']} reserved + {256 - ESC0} escapes = 256")
    print(f"banks       : {len(m['banks'])} Forth ({len(m['allnames'])} words, largest "
          f"{max((len(w), n) for n, w in m['banks'].values())[1]} "
          f"{max(len(w) for _, w in m['banks'].values())}/256)")
    print(f"promoted    : {len(m['promoted'])} (bank form reserved-illegal)")
