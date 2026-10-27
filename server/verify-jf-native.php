<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// The JF engine on PHP ints, graded against the engine it replaced: server/interpreter-jf.php at f4f05d1, the last
// revision whose cells were GMP numbers. JF revision 3 is what that engine does, so on every case here the two
// must give the same verdict, the same final stack and the same error text.
//
//   php server/verify-jf-native.php [programs=60000] [seed=20261024] [--ticks=FILE] [--engine=FILE]
//     programs   random programs in the cells part, besides the fixed sweeps; a sixth as many in the signatures part
//     --ticks    also run the programs in FILE, a JSON list as tools/jf-run.php reads it
//     --engine   grade this copy of the engine instead of the one beside this file. Its ops-jf.php, secp256k1.php
//                and ed25519.php must be this directory's: a link to each will do.
//
// The old engine is read from git and loaded beside the new one, its classes renamed, with its own opcode table, the
// one at f4f05d1, under renamed names. The table has changed since only as DROPPED declares, and the two engines'
// results differ only as DECLARED says, on a script that starts with the lock's declaration, as forOld says, and where
// a jump lands inside an instruction, as old_landed says. Where an instruction starts is revision 3's decode on both
// sides, so a wrong length would agree with itself here, and only CELLS_DIGEST would see it: verify-jf.php pins each
// kind of instruction's length, and tools/verify-jf.mjs holds the decode to JavaScript's and the disassembler's.
// secp256k1.php is shared, so the signatures part grades the engine's signature words, and verify-secp256k1-native.php
// the curve. A case that reaches a word BUILT names has no old answer to grade: the old engine had not built it.
// Revision 3's result on it is recorded instead, and verify-jf.php grades the words.
// The old engine checks Ed25519 with ext/sodium, so its ED25519-CHECKSIG verdicts are sodium's, and the new engine's
// come from ed25519.php, which verify-ed25519.php grades. The old engine computes with ext/gmp, so it is the oracle only
// where gmp is loaded and the revision is in this repository's history. Without it the case-by-case comparison is
// skipped, and says so, and the cells part is graded instead by CELLS_DIGEST, the old engine's results recorded below.
//
// Two parts:
//   cells        every arithmetic, logic, comparison, shift, double-width, memory, literal, BIN2NUM and NUM2BIN word
//                on edge values and on random 64-bit ones; loops at the ends of the cell; every word on edge cells and
//                on too few items; random programs, some judged as ticks. No signature word, so no library is needed.
//   signatures   CHECKSIG and CHECKMULTISIG on real secp256k1 signatures, ED25519-CHECKSIG, random programs with both,
//                and whole ticks: the counter thread of verify-wired.php, signed ticks over their preimage, and ticks
//                at the version's limits. It compares with the old engine, so it runs only beside the oracle.
declare(strict_types=1);

const REV = 'f4f05d192bbd44e47f22447c9b4b51a1f8215abb';
const DEFAULT_PROGRAMS = 60000, DEFAULT_SEED = 20261024;
/** sha256 over the cells part at the default programs and seed: each case, then the old engine's result with forOld,
 *  old_landed and DECLARED applied, or revision 3's on a case that reaches a word BUILT names. */
const CELLS_DIGEST = 'f1d6a8b7145c8a9d340e181d9004d7c2b0bad998a6500108e937c356cd5a328f';
/** What the opcode table has changed since REV: these words were dropped from revision 3, their bytes left unassigned,
 *  and nothing else moved. */
const DROPPED = ['TXVERSION' => 0xd0, 'VERIF' => 0xd2, 'VERNOTIF' => 0xd3];
/** What that changes in a result: the old engine's refusal on a dropped word's byte, and revision 3's on the same byte,
 *  the unknown-opcode refusal. And VER, built since REV as the lock's declaration: the old engine refused it everywhere,
 *  and revision 3 refuses it anywhere but a lock's first instruction (forOld below has that one). Nothing else may differ. */
const DECLARED = [
  'TXVERSION: not built yet — derive it from PREIMAGE with SUBSTR' => 'unknown opcode 0xd0',
  'TXVERSION is covenant-tier only: a stdForth function computes from what it was given, and reaches for nothing else'
    => 'unknown opcode 0xd0',
  'VERIF: version words are §6b and not built yet' => 'unknown opcode 0xd2',
  'VERNOTIF: version words are §6b and not built yet' => 'unknown opcode 0xd3',
  'VER: version words are §6b and not built yet'
    => 'VER declares the version a lock is written for, and is valid only as its first instruction',
];
/** The words built since REV, the preimage's fields. The old engine refused each, in the covenant tier, as not built yet:
 *  a case where that is its answer reached the word, and from there the old engine has nothing to compare. */
const BUILT = ['PREVOUTS-HASH', 'SEQUENCES-HASH', 'OUTPOINT', 'SCRIPTCODE', 'TXVALUE', 'NSEQUENCE', 'OUTPUTS-HASH', 'LOCKTIME'];

$plain = array_values(array_filter(array_slice($argv, 1), fn($a) => !str_starts_with($a, '--')));
$opt = function (string $name) use ($argv): ?string {
  foreach ($argv as $a) if (str_starts_with($a, "--$name=")) return substr($a, strlen($name) + 3);
  return null;
};
$programs = (int)($plain[0] ?? DEFAULT_PROGRAMS);
$seed = (int)($plain[1] ?? DEFAULT_SEED);
$engine = $opt('engine') ?? __DIR__ . '/interpreter-jf.php';
$ticksFile = $opt('ticks');

foreach (['ops-jf.php', 'secp256k1.php', 'ed25519.php'] as $f)
  if (realpath(dirname($engine) . "/$f") !== realpath(__DIR__ . "/$f")) {
    fwrite(STDERR, "⛔ $engine must share $f with " . __DIR__ . "\n"); exit(2);
  }
require_once $engine;
require_once __DIR__ . '/jf-asm.php';
require_once __DIR__ . '/wallet/jetmora/thread.php';

$pass = 0; $fail = 0;
function ok(bool $c, string $what): void {
  global $pass, $fail;
  if ($c) { $pass++; printf("  ✓ %s\n", $what); } else { $fail++; printf("  ✗ %s\n", $what); }
}

// ── the oracle: the old engine, from git ─────────────────────────────────────────────────────────────
function git_show(string $path): ?string {
  $p = @proc_open(['git', '-C', dirname(__DIR__), 'show', REV . ':' . $path], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
  if (!is_resource($p)) return null;
  $out = stream_get_contents($pipes[1]); stream_get_contents($pipes[2]);
  fclose($pipes[1]); fclose($pipes[2]);
  return proc_close($p) === 0 && $out !== '' ? $out : null;
}
$noOracle = null;                                                  // why the old engine cannot be run here, if it cannot
if (!extension_loaded('gmp')) $noOracle = 'the old engine computes with ext/gmp, which this PHP has not loaded';
elseif (($old = git_show('server/interpreter-jf.php')) === null) $noOracle = 'revision ' . substr(REV, 0, 7) . ' is not in this repository';
else {
  // the old engine reads the opcode table it was written against, f4f05d1's, its names renamed beside this one's
  $tableNames = '/\b(JF_PUSH_MAX|JF_SMALL0|JF_SMALL_NEG1|JF_LIT|JF_WORD|JF_SECTION|JF_ESC0|JF_PLANE|JF_RESERVED0|JF_BANK|JF_BANK_WORD'
              . '|JF_CORE_KIND|JF_PROMOTED|jf_op_name|jf_bank_name)\b/';
  $oldTable = preg_replace('/^<\?php\s*/', '', (string)git_show('server/ops-jf.php'));
  $oldTable = preg_replace_callback($tableNames, fn($m) => ($m[1][0] === 'J' ? 'OLD_' : 'old_') . $m[1], $oldTable, -1, $tableN);
  eval($oldTable);
  ok(oldTableIsDeclared(), 'ops-jf.php is ' . substr(REV, 0, 7) . "'s but for DROPPED: " . implode(', ', array_keys(DROPPED))
     . ' gone, their bytes unassigned, every other name keeping its byte');
  $old = preg_replace('/^<\?php\s*/', '', $old);
  // ...and given the rule a jump lands by, as old_landed below: the word that jumps passed to jump and call, and its target
  // checked after the range
  $old = preg_replace('/\$this->(jump|call)\((\$code, [^()]*)\)/', '$this->$1($2, $op)', $old, -1, $sites);
  $old = preg_replace('/(private function (?:jump|call)\(string \$code, [^()]*)\)/', '$1, int $op)', $old, -1, $signatures);
  $old = preg_replace("/(throw new JfScriptError\\('(?:branch|call) out of range'\\);)/", '$1 old_landed($code, $op, $to);', $old, -1, $checks);
  ok($sites === 7 && $signatures === 2 && $checks === 2,
     "the old engine checks where its jumps land, as revision 3 does: its $sites jumps and calls name their word, and its $checks range checks are followed by old_landed's");
  $old = str_replace('__DIR__', var_export(dirname(realpath($engine)), true), $old, $dirs);
  $old = preg_replace('/\b(InterpreterJF|JfScriptError|JfHostError|JfBankUnsupported)\b/', 'Old$1', $old, -1, $names);
  $old = preg_replace('/\bjf_stack_hash\b/', 'old_jf_stack_hash', $old);
  $old = preg_replace_callback($tableNames, fn($m) => ($m[1][0] === 'J' ? 'OLD_' : 'old_') . $m[1], $old, -1, $oldReads);
  ok($dirs === 2 && $names > 20 && $tableN > 20 && $oldReads > 20,
     "the old engine loads beside the new one: its 2 requires pointed here, $names names renamed, and it reads its own table ($oldReads uses)");
  eval($old);
}

/** The opcode table now is the old one with DROPPED taken out and their bytes declared unassigned, and nothing else. */
function oldTableIsDeclared(): bool {
  $words = array_diff_key(OLD_JF_WORD, DROPPED);
  $sections = array_map(fn($ws) => array_values(array_diff($ws, array_keys(DROPPED))), OLD_JF_SECTION);
  foreach (range(0, 255) as $b) if (!in_array($b, DROPPED, true) && old_jf_op_name($b) !== jf_op_name($b)) return false;
  foreach (DROPPED as $b) if (jf_op_name($b) !== sprintf('JF_UNKNOWN_%02x', $b)) return false;
  return array_intersect_key(OLD_JF_WORD, DROPPED) === DROPPED && JF_WORD === $words && JF_SECTION === $sections
      && JF_UNASSIGNED === array_values(DROPPED)
      && [JF_PUSH_MAX, JF_SMALL0, JF_SMALL_NEG1, JF_LIT, JF_ESC0, JF_PLANE, JF_RESERVED0, JF_BANK, JF_BANK_WORD, JF_CORE_KIND, JF_PROMOTED]
     === [OLD_JF_PUSH_MAX, OLD_JF_SMALL0, OLD_JF_SMALL_NEG1, OLD_JF_LIT, OLD_JF_ESC0, OLD_JF_PLANE, OLD_JF_RESERVED0, OLD_JF_BANK,
          OLD_JF_BANK_WORD, OLD_JF_CORE_KIND, OLD_JF_PROMOTED];
}
/** The script a case runs in the covenant tier: a program, or a tick's lock. */
function covenantScript(array $c): string { return $c[0] === 'tick' ? $c[2] : $c[1]; }
/**
 * The case as the old engine is given it. A script that starts with VER starts with the lock's declaration, VER and its
 * four version bytes, which revision 3 steps over and the old engine did not have: so it is given the same script with
 * those five bytes as five CHARS, the word that does nothing, and every other byte where it was.
 */
function forOld(array $c): array {
  $s = covenantScript($c);
  if (strlen($s) >= 5 && ord($s[0]) === JF_WORD['VER']) $c[$c[0] === 'tick' ? 2 : 1] = str_repeat(chr(JF_WORD['CHARS']), 5) . substr($s, 5);
  return $c;
}
/** The old engine's result as revision 3 gives it: a refusal DECLARED names becomes revision 3's, anything else is kept.
 *  A script that is VER and fewer than its four version bytes is refused by revision 3 as a truncated operand. */
function declared(string $outcome, array $c): string {
  $map = DECLARED;
  $s = covenantScript($c);
  if ($s !== '' && strlen($s) < 5 && ord($s[0]) === JF_WORD['VER']) $map['VER: version words are §6b and not built yet'] = 'truncated operand';
  foreach ($map as $was => $now)
    foreach (['JfScriptError: ', 'refused | '] as $form)
      if ($outcome === $form . $was) return $form . $now;
  return $outcome;
}
/**
 * The rule built since REV: a jump or a call lands on the start of an instruction, or on the end of its code (his call,
 * 27 Oct). The old engine checked the range alone, so it is loaded with this check after that one, where revision 3 makes
 * it: a case where it landed inside an instruction is refused there, in revision 3's words, naming the word that jumped.
 * The starts are revision 3's, InterpreterJF::instructionStarts, which verify-jf.php pins for each kind of instruction
 * and tools/verify-jf.mjs holds to the disassembler's offsets, and they are those of the code revision 3 is given: a
 * script forOld changed is read as the one it stands for.
 * $landing holds the case's script both ways, the starts found, and whether this check refused it.
 */
function old_landed(string $code, int $op, int $to): void {
  global $landing;
  if ($to === strlen($code)) return;
  $starts = $landing['starts'][$code] ??= InterpreterJF::instructionStarts($code === $landing['given'] ? $landing['as'] : $code);
  if ($starts[$to] === "\x01") return;
  $landing['refused'] = true;
  throw new OldJfScriptError(jf_op_name($op) . ': the target is not the start of an instruction');
}
/** The word BUILT names that the old engine's result refuses as not built, or null when it is no such refusal. */
function reachedBuilt(string $outcome): ?string {
  foreach (BUILT as $word)
    foreach (['JfScriptError: ', 'refused | '] as $form)
      if ($outcome === $form . "$word: not built yet — derive it from PREIMAGE with SUBSTR") return $word;
  return null;
}
if ($noOracle !== null) echo "  - no oracle: $noOracle. The case-by-case comparison is skipped, never counted as passed.\n";

// ── what an engine did with a case, as one string ────────────────────────────────────────────────────
/** A refusal's class (Old stripped), its message and diagnostic; anything else thrown is a fault, a defect. */
function said(Throwable $e): string {
  $class = preg_replace('/^Old/', '', get_class($e));
  if ($e instanceof JfScriptError || (class_exists('OldJfScriptError', false) && $e instanceof OldJfScriptError))
    return "$class: " . $e->getMessage() . ($e->diagnostic === null ? '' : ' | diagnostic ' . bin2hex($e->diagnostic));
  if ($e instanceof JfHostError || (class_exists('OldJfHostError', false) && $e instanceof OldJfHostError))
    return "$class: " . $e->getMessage();
  return "fault $class";
}
/** A cell as decimal. A GMP number from the old engine; from the new one an int, and anything else is shown as such. */
function cellText($c): string {
  if ($c instanceof GMP) return gmp_strval($c);
  return is_int($c) ? (string)$c : 'NOT AN INT: ' . var_export($c, true);
}
/** ['run', script, preimage, maxOps] runs a program; ['tick', unlocking, lock, preimage] judges a tick. */
function outcome(string $class, array $c): string {
  if ($c[0] === 'tick') {
    try { $v = $class::verifyTick($c[1], $c[2], $c[3]); } catch (Throwable $e) { return said($e); }
    return ($v['accepted'] ? 'accepted' : 'refused')
         . (isset($v['stack']) ? ' | stack ' . implode(' ', array_map('cellText', $v['stack'])) : ' | ' . $v['error']);
  }
  try {
    $vm = new $class($c[3]);
    $vm->setPreimage($c[2]);
    return 'stack ' . implode(' ', array_map('cellText', $vm->run($c[1])));
  } catch (Throwable $e) { return said($e); }
}
function caseKey(array $c): string {
  return $c[0] === 'tick' ? "tick\0" . bin2hex($c[1]) . "\0" . bin2hex($c[2]) . "\0" . ($c[3] === null ? '-' : bin2hex($c[3]))
                          : "run\0" . bin2hex($c[1]) . "\0" . ($c[2] === null ? '-' : bin2hex($c[2])) . "\0" . $c[3];
}
$shown = fn(string $s): string => strlen($s) > 160 ? substr($s, 0, 160) . '...' : $s;

/** Run every case of a part through both engines, or the new one alone with no oracle, and report. Returns the sha256
 *  over each case and the old engine's result with old_landed and DECLARED applied, or on a case that reaches a word BUILT
 *  names, the new engine's: with no oracle, the new engine's on every case. */
function grade(string $part, iterable $cases, ?string $noOracle, callable $shown): string {
  global $landing;
  $h = hash_init('sha256'); $n = $same = $faults = $changed = $landed = 0; $diffs = []; $kinds = ['stack' => 0, 'accepted' => 0, 'refused' => 0, 'error' => 0];
  $built = [];                                                     // the cases that reached a word BUILT names, by word
  foreach ($cases as $c) {
    $new = outcome('InterpreterJF', $c);
    if ($noOracle === null) {
      $given = forOld($c);
      $landing = ['given' => covenantScript($given), 'as' => covenantScript($c), 'starts' => [], 'refused' => false];
      $raw = outcome('OldInterpreterJF', $given); $old = declared($raw, $c);
      if ($old !== $raw || $given !== $c) $changed++;
      if ($landing['refused']) $landed++;
      if (($word = reachedBuilt($raw)) !== null) { $old = $new; $built[$word] = ($built[$word] ?? 0) + 1; }
    }
    else $old = $new;
    $n++;
    hash_update($h, caseKey($c) . "\0" . $old . "\n");
    $kind = strtok($old, ' ');
    $kinds[in_array($kind, ['stack', 'accepted', 'refused'], true) ? $kind : 'error']++;
    if (str_starts_with($new, 'fault ') || str_contains($new, 'the interpreter faulted')) $faults++;
    if ($old === $new) { $same++; continue; }
    if (count($diffs) < 8) $diffs[] = [$c, $old, $new];
  }
  foreach ($diffs as [$c, $old, $new])
    printf("  ✗ differ  %s %s\n      old: %s\n      new: %s\n", $c[0], $shown(bin2hex($c[0] === 'tick' ? $c[1] . '|' . $c[2] : $c[1])),
           $shown(addcslashes($old, "\0..\37\177..\377")), $shown(addcslashes($new, "\0..\37\177..\377")));
  $nb = array_sum($built);                                         // on these the two results are the same by construction
  if ($noOracle === null) ok($same === $n, "$part: " . ($same - $nb) . ' of ' . ($n - $nb) . ' cases give the same verdict, stack and '
                                          . "error text in both engines, $changed of them through DECLARED, $landed refused by old_landed");
  if ($nb) printf("    %d cases reach a word BUILT names, which %s had not built, and are recorded as revision 3 gives them: %s\n",
                  $nb, substr(REV, 0, 7), implode(', ', array_map(fn($w, $k) => "$w $k", array_keys($built), $built)));
  printf("    %d programs ended with a stack and %d with an error; %d ticks accepted and %d refused\n",
         $kinds['stack'], $kinds['error'], $kinds['accepted'], $kinds['refused']);
  if ($faults) echo "  ⚠ $part: the new engine faulted outside its own errors on $faults cases, a defect even where the old one did too\n";
  return hash_final($h);
}

// ── building cases ───────────────────────────────────────────────────────────────────────────────────
function w(string $name): string { return chr(JF_WORD[$name]); }
function lit(int $v): string { return chr(JF_LIT['LIT64']) . pack('P', $v); }
function lits(int ...$v): string { return implode('', array_map('lit', $v)); }
function small(int $n): string { return chr($n === -1 ? JF_SMALL_NEG1 : JF_SMALL0 + $n); }
/** One byte push: direct up to 72 bytes, STR8 or STR16 above. */
function push(string $b): string {
  $n = strlen($b);
  return $n <= JF_PUSH_MAX ? chr($n) . $b : ($n <= 255 ? chr(JF_LIT['STR8']) . chr($n) . $b : chr(JF_LIT['STR16']) . pack('v', $n) . $b);
}
/** `n 0 (DO) body (LOOP)` */
function doLoop(int $n, string $body): string {
  return chr(JF_LIT['LIT32']) . pack('V', $n) . small(0) . w('(DO)') . $body . w('(LOOP)') . pack('v', -(3 + strlen($body)) & 0xffff);
}
function runCase(string $script, ?string $pre = null, int $maxOps = 200000): array { return ['run', $script, $pre, $maxOps]; }

/** xorshift64: the same sequence on every host, from nothing but ints. */
final class Rng {
  public function __construct(private int $s) { if ($this->s === 0) $this->s = 1; }
  public function next(): int {
    $s = $this->s; $s ^= $s << 13; $s ^= ($s >> 7) & (PHP_INT_MAX >> 6); $s ^= $s << 17;
    return $this->s = $s;
  }
  public function int(int $lo, int $hi): int { return $lo + ($this->next() & PHP_INT_MAX) % ($hi - $lo + 1); }
  public function chance(float $p): bool { return ($this->next() & 0xffffff) < $p * 0x1000000; }
  public function pick(array $a) { return $a[$this->int(0, count($a) - 1)]; }
  public function bytes(int $n): string { $b = ''; for ($k = 0; $k < $n; $k++) $b .= chr($this->next() & 0xff); return $b; }
  /** A cell: fully random, or a power of two and its neighbours, or that inverted. */
  public function cell(): int {
    if ($this->chance(0.5)) return $this->next();
    $v = (1 << $this->int(0, 63)) + $this->int(0, 2);
    return $this->chance(0.5) ? $v : ~$v;
  }
}

/** Edge cells: 0, 1, 2, 3, 7, 8, 63, 64, 2^31, 2^32, 2^47, 2^48, 2^62, each with its neighbours and negated, and the ends. */
function edges(): array {
  $e = [];
  foreach ([0, 1, 2, 3, 7, 8, 63, 64, 1 << 31, 1 << 32, 1 << 47, 1 << 48, 1 << 62] as $b)
    foreach ([$b - 1, $b, $b + 1] as $v) { $e[] = $v; $e[] = -$v; }
  array_push($e, PHP_INT_MAX, PHP_INT_MAX - 1, PHP_INT_MAX - 6, PHP_INT_MAX - 7, PHP_INT_MIN, PHP_INT_MIN + 1, PHP_INT_MIN + 2,
             0x5555555555555555, ~0x5555555555555555, 3037000499, 3037000500, -3037000500, PHP_INT_MIN | 0x80000000,
             0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff);
  return array_values(array_unique($e));
}
/** Divisors and third arguments: zero, the units, the ends, and values whose quotient overflows a cell. */
const DIVISORS = [0, 1, -1, 2, -2, 7, -7, PHP_INT_MAX, PHP_INT_MIN, PHP_INT_MIN + 1, 4294967295, 4294967297, 4611686018427387905,
                  -3, 3037000500, 0x5555555555555555, 4294967296];
/** Addresses: around program memory's end, the push space, a function's spaces, and the ends of the cell. */
const ADDRESSES = [-1, 0, 8, 65527, 65528, 65529, 65535, 65536, 16777216, 16777224, 33554432, 41943040,
                   PHP_INT_MAX - 8, PHP_INT_MAX - 7, PHP_INT_MAX - 1, PHP_INT_MAX, PHP_INT_MIN];
const SIG_WORDS = ['CHECKSIG', 'CHECKSIGVERIFY', 'CHECKMULTISIG', 'CHECKMULTISIGVERIFY', 'ED25519-CHECKSIG', 'ED25519-CHECKSIGVERIFY'];

/** The cells part. */
function cellCases(int $programs, int $seed): Generator {
  $E = edges(); $r = new Rng($seed);
  $E3 = [0, 1, -1, 2, 7, -8, 63, 64, 1 << 32, -(1 << 32), 1 << 62, PHP_INT_MAX, PHP_INT_MAX - 7, PHP_INT_MIN, PHP_INT_MIN + 1, 0x5555555555555555, 3037000500];
  $unary = ['1+', '1-', '2*', '2/', 'ABS', 'NEGATE', 'INVERT', '0=', '0<>', '0<', '0>', 'CELLS', 'CELL+', 'CHAR+', 'CHARS',
            'ALIGNED', 'S>D', '?DUP', 'DUP', 'DROP', 'PICK', 'ROLL', 'C@', '@', '2@', 'BIN2NUM'];
  $binary = ['+', '-', '*', '/', 'MOD', '/MOD', 'FM/MOD', 'SM/REM', 'UM*', 'M*', 'MIN', 'MAX', 'AND', 'OR', 'XOR',
             'LSHIFT', 'RSHIFT', '=', '<>', '<', '>', 'U<', 'U>', 'SWAP', 'OVER', 'NIP', 'TUCK', '!', 'C!', '+!', 'BYTES='];
  $ternary = ['*/', '*/MOD', 'UM/MOD'];
  // one word on edge cells: every value, every pair, and for the double-width words every pair over the divisors
  foreach ($unary as $op) foreach ($E as $a) yield runCase(lit($a) . w($op));
  foreach ($binary as $op) foreach ($E as $a) foreach ($E as $b) yield runCase(lits($a, $b) . w($op));
  foreach ($ternary as $op) foreach ($E as $a) foreach ($E as $b) foreach (DIVISORS as $c) yield runCase(lits($a, $b, $c) . w($op));
  foreach (['WITHIN', 'ROT', 'SPLIT', '2!', 'MOVE', 'FILL', 'NUM2BIN'] as $op)
    foreach ($E3 as $a) foreach ($E3 as $b) foreach ($E3 as $c) yield runCase(lits($a, $b, $c) . w($op));
  // and on random cells
  foreach ($unary as $op) for ($k = 0; $k < 300; $k++) yield runCase(lit($r->cell()) . w($op));
  foreach ($binary as $op) for ($k = 0; $k < 2000; $k++) yield runCase(lits($r->cell(), $r->cell()) . w($op));
  foreach ([...$ternary, 'WITHIN'] as $op) for ($k = 0; $k < 5000; $k++)
    yield runCase(lits($r->cell(), $r->cell(), $r->chance(0.5) ? $r->pick(DIVISORS) : $r->cell()) . w($op));
  // shifts: every count from 0 to 70, and the negative and huge ones
  foreach (['LSHIFT', 'RSHIFT'] as $op) foreach ($E as $a) foreach ([...range(0, 70), -1, -64, PHP_INT_MAX, PHP_INT_MIN] as $n)
    yield runCase(lits($a, $n) . w($op));
  // every word, with operands where it has them, on edge cells and on too few items: the order of pops against checks
  $tops = [0, -1, 1, 8, PHP_INT_MAX, PHP_INT_MIN];
  foreach (JF_WORD as $name => $byte) {
    if (in_array($name, SIG_WORDS, true)) continue;
    for ($k = 0; $k <= 3; $k++) yield runCase(str_repeat(small(1), $k) . chr($byte));
    foreach ($tops as $a) foreach ($tops as $b) foreach ($tops as $c) yield runCase(lits($a, $b, $c) . chr($byte) . "\x00\x00", null, 2000);
  }
  // memory: every address, with the push space holding bytes, and stores read back byte by byte
  $pushed = push(str_repeat("\xa5", 16)) . w('2DROP');
  foreach (ADDRESSES as $a) {
    foreach (['@', 'C@', '2@'] as $op) { yield runCase(lit($a) . w($op)); yield runCase($pushed . lit($a) . w($op)); }
    foreach ($E3 as $v) foreach (['!', 'C!', '+!'] as $op) yield runCase(lits($v, $a) . w($op) . lit($a) . w('@'));
    yield runCase(lits(5, 6, $a) . w('2!') . lit($a) . w('2@'));
    foreach (ADDRESSES as $b) foreach ([-1, 0, 1, 8, 65536, PHP_INT_MAX] as $u) {
      yield runCase($pushed . lits($a, $b, $u) . w('MOVE'));
      yield runCase(lits($a, $u, $b) . w('FILL'));
    }
    foreach ([-1, 0, 1, 8, 65536, PHP_INT_MAX] as $u) yield runCase(lits($a, $u) . w('ERASE'));
  }
  foreach ($E as $v) {
    $bytes = ''; for ($k = 0; $k < 8; $k++) $bytes .= lit($k) . w('C@');
    yield runCase(lits($v, 0) . w('!') . $bytes);
    yield runCase(lits(0x0102030405060708, 0) . w('!') . lits($v, 0) . w('+!') . lit(0) . w('@'));
    yield runCase(lits(PHP_INT_MIN, 8, $v, 0) . w('2!') . lit(0) . w('2@') . lit(8) . w('@'));
  }
  // NUM2BIN at every size around a cell's, read back with BIN2NUM; BIN2NUM of spans around 8 bytes
  foreach ($E as $v) {
    foreach ([-1, 0, 1, 2, 7, 8, 9, 16, 65536, 65537] as $sz) foreach ([0, 100, 65530, -1, 16777216] as $d)
      yield runCase(lits($v, $sz, $d) . w('NUM2BIN'));
    foreach (range(0, 9) as $sz) yield runCase(lits($v, $sz, 0) . w('NUM2BIN') . w('BIN2NUM'));
  }
  foreach (['', "\x00", "\xff", "\x80", str_repeat("\xff", 7), str_repeat("\x00", 7) . "\x80", str_repeat("\xff", 8),
            str_repeat("\xff", 9), str_repeat("\x00", 8) . "\x01", "\x01" . str_repeat("\x00", 8)] as $s)
    yield runCase(push($s) . w('BIN2NUM'));
  for ($k = 0; $k < 400; $k++) yield runCase(push($r->bytes($r->int(0, 12))) . w('BIN2NUM'));
  // the literal forms: each width at its ends and at random, and cut short
  foreach (['LIT8' => 1, 'LIT16' => 2, 'LIT32' => 4, 'LIT64' => 8] as $form => $width) {
    $ends = [str_repeat("\x00", $width), str_repeat("\xff", $width), str_repeat("\xff", $width - 1) . "\x7f",
             str_repeat("\x00", $width - 1) . "\x80", "\x01" . str_repeat("\x00", $width - 1)];
    for ($k = 0; $k < 50; $k++) $ends[] = $r->bytes($width);
    foreach ($ends as $b) yield runCase(chr(JF_LIT[$form]) . $b);
    for ($cut = 0; $cut < $width; $cut++) yield runCase(chr(JF_LIT[$form]) . str_repeat("\x01", $cut));
  }
  // loops at the ends of the cell: (+LOOP) and (LOOP) push I each trip, so the stack shows every index; (?DO) skips on equal
  $ends = [0, 1, -1, 10, PHP_INT_MAX, PHP_INT_MAX - 1, PHP_INT_MIN, PHP_INT_MIN + 1];
  foreach ($ends as $lim) foreach ($ends as $start) {
    foreach ([1, -1, 2, -2, 0, PHP_INT_MAX, PHP_INT_MIN, 1 << 62] as $step)
      yield runCase(lits($lim, $start) . w('(DO)') . w('I') . lit($step) . w('(+LOOP)') . pack('v', -13 & 0xffff), null, 300);
    yield runCase(lits($lim, $start) . w('(DO)') . w('I') . w('(LOOP)') . pack('v', -4 & 0xffff), null, 300);
    yield runCase(lits($lim, $start) . w('(?DO)') . pack('v', 4) . w('I') . w('(LOOP)') . pack('v', -4 & 0xffff) . small(7), null, 300);
  }
  // flags consumed: 0BRANCH and (ABORT") on every edge cell, and each edge cell as a tick's last item
  foreach ($E as $v) {
    yield runCase(lit($v) . w('0BRANCH') . pack('v', 1) . w('TRUE') . w('FALSE'));
    yield runCase(lit($v) . w('(ABORT")') . "\x02hi" . small(5));
    yield ['tick', '', lit($v), null];
  }
  // random programs, a quarter of them judged as ticks
  for ($k = 0; $k < $programs; $k++) {
    $p = randomProgram($r, false);
    $pre = $r->chance(0.3) ? $r->bytes($r->int(0, 200)) : null;
    if ($r->chance(0.25)) {
      $u = ''; for ($j = $r->int(0, 3); $j > 0; $j--) $u .= push($r->bytes($r->pick([0, 1, 8, 32, 40])));
      yield ['tick', $u, $p, $pre];
    } else yield runCase($p, $pre);
  }
}

/** A random program, as tools/verify-jf.mjs generates them, with more 64-bit literals. Signature words only when $sigs. */
function randomProgram(Rng $r, bool $sigs, ?array $keys = null): string {
  $plain = array_values(array_filter(array_keys(JF_WORD), fn($n) => !in_array($n, ['BRANCH', '0BRANCH', '(?DO)', '(LOOP)', '(+LOOP)',
    'LEAVE', 'CALL', 'EXECUTE', '(FRAME)', '(LOCAL@)', '(LOCAL!)', 'INVOKE', '(ABORT")'], true) && ($sigs || !in_array($n, SIG_WORDS, true))));
  $sigBytes = array_map(fn($n) => JF_WORD[$n], SIG_WORDS);
  $E = edges();
  $token = function () use ($r, $sigs, $keys, $plain, $sigBytes, $E): string {
    $x = $r->int(0, 9999) / 10000;
    if ($x < 0.18) return chr(JF_SMALL0 + $r->int(0, 9));
    if ($x < 0.26) { $width = $r->pick([1, 2, 4, 8]); $form = [1 => 'LIT8', 2 => 'LIT16', 4 => 'LIT32', 8 => 'LIT64'][$width];
                     $v = $r->pick([0, 1, -1, $r->int(-300, 300), $r->int(-70000, 70000), $r->next()]);
                     return chr(JF_LIT[$form]) . substr(pack('P', $v), 0, $width); }
    if ($x < 0.32) return push($r->bytes($r->pick([0, 1, 2, 8, 20, 32, 40])));
    if ($x < 0.34) { $n = $r->int(0, 12); return chr(JF_LIT['STR8']) . chr($n) . $r->bytes($n); }
    if ($x < 0.35) { $n = $r->int(0, 9); return chr(JF_LIT['LITBIG']) . chr($n) . $r->bytes($n); }
    if ($x < 0.37) return w('0BRANCH') . pack('v', $r->int(0, 6));
    if ($x < 0.38) return w('BRANCH') . pack('v', $r->int(0, 6));
    if ($x < 0.39) return w('(ABORT")') . "\x03abc";
    if ($x < 0.40) return w('(FRAME)') . chr($r->int(0, 3));
    if ($x < 0.41) return w($r->pick(['(LOCAL@)', '(LOCAL!)'])) . chr($r->int(0, 3));
    if ($x < 0.42) return w('(UNFRAME)');
    if ($x < 0.45 && $sigs) return signatureToken($r, $keys);
    if ($x < 0.47) return chr($r->int(0xf0, 0xff)) . chr($r->int(0, 140));
    if ($x < 0.48) { do $b = $r->int(0, 255); while (!$sigs && in_array($b, $sigBytes, true)); return chr($b); }
    if ($x < 0.60) return lit($r->chance(0.5) ? $r->pick($E) : $r->cell());
    return w($r->pick($plain));
  };
  $out = '';
  if ($r->chance(0.25)) {
    $defs = [];
    for ($k = $r->int(1, 2); $k > 0; $k--) {
      $body = ''; for ($j = $r->int(0, 8); $j > 0; $j--) $body .= $token();
      if ($r->chance(0.3)) $body .= chr($r->int(0xf0, 0xf8)) . chr($r->int(0, 130));     // a bank word, legal inside a function
      $defs[] = chr($r->int(0, 2)) . chr($r->int(0, 2)) . chr($r->pick([0, 0, 8])) . chr($r->pick([0, 0, 16]))
              . chr(strlen($body) & 0xff) . $body;
    }
    $out .= chr(JF_RESERVED0) . chr(count($defs)) . implode('', $defs);
    for ($j = $r->int(0, 4); $j > 0; $j--) $out .= $token();
    $out .= w('INVOKE') . chr($r->int(0, count($defs)));
  }
  for ($j = $r->int(1, 25); $j > 0; $j--) $out .= $token();
  return $out;
}

// ── the signatures part ──────────────────────────────────────────────────────────────────────────────
function hash256(string $b): string { return hash('sha256', hash('sha256', $b, true), true); }
/** Keys and signatures made once: secp256k1 signing costs milliseconds. */
function signingKeys(): array {
  $k = ['ec' => [], 'ed' => []];
  foreach (['a test key', 'another key', 'a third key'] as $name) {
    $d = gmp_init(hash('sha256', $name), 16);
    $k['ec'][] = ['d' => $d, 'pub' => Secp256k1::publicKey($d), 'unc' => Secp256k1::publicKey($d, false)];
    $k['ed'][] = sodium_crypto_sign_seed_keypair(hash('sha256', $name, true));
  }
  $k['digests'] = [hash('sha256', 'a message', true), "\x00" . substr(hash('sha256', 'b', true), 0, 31), hash('sha256', '', true)];
  foreach ($k['ec'] as $i => $key) foreach ($k['digests'] as $j => $dg) $k['sigs'][$i][$j] = Secp256k1::sign($key['d'], $dg);
  return $k;
}
function flipBit(string $b, int $at): string { $b[$at] = chr(ord($b[$at]) ^ 1); return $b; }
function signatureToken(Rng $r, array $k): string {
  $x = $r->int(0, 2);
  if ($x === 0) {                                                  // ED25519-CHECKSIG, sometimes tampered
    $pair = $r->pick($k['ed']); $msg = $r->bytes($r->int(0, 40));
    $sig = sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($pair));
    if ($r->chance(0.3)) $sig = flipBit($sig, $r->int(0, 63));
    return push($sig) . push(sodium_crypto_sign_publickey($r->pick($k['ed']))) . push($msg) . w($r->pick(['ED25519-CHECKSIG', 'ED25519-CHECKSIGVERIFY']));
  }
  $i = $r->int(0, 2); $j = $r->int(0, 2);
  $sig = $k['sigs'][$i][$j];
  if ($r->chance(0.2)) $sig = flipBit($sig, $r->int(4, strlen($sig) - 1));
  $digest = $k['digests'][$r->chance(0.8) ? $j : $r->int(0, 2)];
  if ($r->chance(0.1)) $digest = substr($digest, 1);
  $pub = $r->chance(0.8) ? $k['ec'][$i][$r->chance(0.7) ? 'pub' : 'unc'] : $k['ec'][$r->int(0, 2)]['pub'];
  if ($x === 1) return push($sig) . push($pub) . push($digest) . w($r->pick(['CHECKSIG', 'CHECKSIGVERIFY']));
  // CHECKMULTISIG: m of n, signatures in key order or not
  $n = $r->int(0, 3); $m = $r->int(0, $n + 1);
  $t = push($k['digests'][0]);
  for ($q = 0; $q < $n; $q++) $t .= push($k['ec'][$q]['pub']);
  $t .= small($n);
  $order = $n === 0 ? [] : range(0, $n - 1); if ($r->chance(0.3)) $order = array_reverse($order);
  for ($q = 0; $q < $m; $q++) $t .= push($k['sigs'][$order[$q] ?? 0][0]);
  return $t . small($m) . w($r->pick(['CHECKMULTISIG', 'CHECKMULTISIGVERIFY']));
}
function signatureCases(int $programs, int $seed): Generator {
  $k = signingKeys(); $r = new Rng($seed ^ 0x5157);
  [$sig, $pub, $dg] = [$k['sigs'][0][0], $k['ec'][0]['pub'], $k['digests'][0]];
  $padR = fn(string $s) => "\x30" . chr(ord($s[1]) + 1) . "\x02" . chr(ord($s[3]) + 1) . "\x00" . substr($s, 4);
  // CHECKSIG: good, each kind of bad, and the strictness of DER
  foreach ([[$sig, $pub, $dg], [$sig, $k['ec'][0]['unc'], $dg], [$sig, $pub, flipBit($dg, 0)], [flipBit($sig, 20), $pub, $dg],
            [$sig, $k['ec'][1]['pub'], $dg], [$padR($sig), $pub, $dg], [$sig . "\x01", $pub, $dg], [$sig, $pub, substr($dg, 1)],
            [$sig, "\x02" . str_repeat("\x11", 32), $dg], ["\x30\x06\x02\x01\x01\x02\x01\x01", $pub, $dg], ['', '', '']] as [$s, $p, $d])
    foreach (['CHECKSIG', 'CHECKSIGVERIFY'] as $op) { yield runCase(push($s) . push($p) . push($d) . w($op)); yield ['tick', push($s), push($p) . push($d) . w($op), null]; }
  // Ed25519
  $pair = $k['ed'][0]; $msg = 'a message';
  $esig = sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($pair)); $epub = sodium_crypto_sign_publickey($pair);
  foreach ([[$esig, $epub, $msg], [$esig, $epub, 'a messagf'], [flipBit($esig, 10), $epub, $msg], [$esig, sodium_crypto_sign_publickey($k['ed'][1]), $msg],
            [$esig, $epub . "\x00", $msg], [substr($esig, 1), $epub, $msg]] as [$s, $p, $m])
    foreach (['ED25519-CHECKSIG', 'ED25519-CHECKSIGVERIFY'] as $op) yield runCase(push($s) . push($p) . push($m) . w($op));
  // whole ticks over their preimage: a key's signature on the preimage's HASH256, checked by the lock
  foreach ([['ec', 0], ['ec', 1], ['ed', 0], ['ed', 1]] as [$scheme, $who]) {
    $key = $scheme === 'ec' ? '$' . bin2hex($pub) : '$' . bin2hex($epub);
    $lock = jf_asm("1000 PREIMAGE 3000 HASH256 $key 3000 32 " . ($scheme === 'ec' ? 'CHECKSIG' : 'ED25519-CHECKSIG'));
    $t = CovenantThread::tick(hash('sha256', 'a tip', true), 0, $lock, pack('P', 5), [['value' => 6, 'locking' => $lock]], 6,
      fn(string $pre) => push($scheme === 'ec' ? Secp256k1::sign($k['ec'][$who]['d'], hash256($pre))
                                              : sodium_crypto_sign_detached(hash256($pre), sodium_crypto_sign_secretkey($k['ed'][$who]))));
    yield ['tick', $t['entry']['inputs'][0]['unlocking'], $lock, Preimage::build($t['entry'], 0, $lock, pack('P', 5))];
    $t['entry']['outputs'][0]['value'] = 7;                         // changed after signing: the preimage rebuilt from the entry differs
    yield ['tick', $t['entry']['inputs'][0]['unlocking'], $lock, Preimage::build($t['entry'], 0, $lock, pack('P', 5))];
  }
  // the counter thread of verify-wired.php: value + 1 and the same script, or not
  preg_match("/const COUNTER_SRC = <<<'ASM'\n(.*?)\nASM;/s", (string)file_get_contents(__DIR__ . '/verify-wired.php'), $src);
  $counter = jf_asm($src[1]);
  foreach ([[0, 1, $counter], [0, 2, $counter], [41, 42, $counter], [41, 40, $counter], [7, 8, $counter . w('DROP')],
            [PHP_INT_MAX, PHP_INT_MIN, $counter], [-1, 0, $counter]] as [$from, $to, $next]) {
    $t = CovenantThread::tick(hash('sha256', 'the counter', true), 0, $counter, pack('P', $from), [['value' => $to, 'locking' => $next]], 1,
                              fn(string $pre) => "\x01\x01");
    yield ['tick', "\x01\x01", $counter, Preimage::build($t['entry'], 0, $counter, pack('P', $from))];
  }
  // the version's limits, as tools/verify-tick.mjs sets them out
  $loop = fn(int $n) => doLoop($n, '') . w('TRUE');
  $limits = [
    ['', $loop(400000)], ['', $loop(600000)], ['', str_repeat("\x02\x00\x00", 166667) . w('TRUE')],
    [push(str_repeat("\x01", 65535)) . push("\x02"), w('2DROP') . w('2DROP') . w('TRUE')],
    [push(str_repeat("\x01", 65535)) . push("\x02") . push("\x03"), w('2DROP') . w('2DROP') . w('2DROP') . w('TRUE')],
    ['', doLoop(100, str_repeat(small(0), 6) . w('CHECKSIG') . w('DROP')) . w('TRUE')],
    ['', doLoop(101, str_repeat(small(0), 6) . w('CHECKSIG') . w('DROP')) . w('TRUE')],
    ['', small(1) . doLoop(997, w('DUP')) . doLoop(997, w('DROP'))], ['', small(1) . doLoop(998, w('DUP')) . doLoop(998, w('DROP'))],
    ['', lit(PHP_INT_MAX) . w('ALIGNED')], ['', lits(PHP_INT_MAX, 5, 3) . w('SPLIT') . w('2SWAP') . w('2DROP') . w('DROP')],
    ['', lit(PHP_INT_MAX - 3) . w('2@')], ['', small(0) . small(0) . lit(PHP_INT_MAX - 3) . w('2!')],
    [w('TRUE') . w('EXIT'), w('FALSE')], [chr(JF_LIT['LIT8']) . "\x05", small(5) . w('=')], ["\x02" . w('TRUE') . w('EXIT'), w('2DROP') . w('BRANCH') . pack('v', -6 & 0xffff)],
  ];
  foreach ($limits as [$u, $lock]) yield ['tick', $u, $lock, null];
  // random programs with signature words
  for ($q = 0; $q < intdiv($programs, 6); $q++) {
    $p = randomProgram($r, true, $k);
    yield $r->chance(0.25) ? ['tick', '', $p, null] : runCase($p, $r->chance(0.3) ? $r->bytes($r->int(0, 200)) : null);
  }
}

/** Programs from a file, a JSON list as tools/jf-run.php reads it: a case with "unlocking" is judged as a tick. */
function fileCases(string $file): Generator {
  foreach (json_decode((string)file_get_contents($file), true, 512, JSON_THROW_ON_ERROR) as $c) {
    $pre = isset($c['preimage']) ? hex2bin($c['preimage']) : null;
    yield isset($c['unlocking']) ? ['tick', hex2bin($c['unlocking']), hex2bin($c['script']), $pre] : runCase(hex2bin($c['script']), $pre);
  }
}

// ── run ──────────────────────────────────────────────────────────────────────────────────────────────
$counted = function (iterable $g, int &$n): Generator { foreach ($g as $c) { $n++; yield $c; } };
$t0 = hrtime(true); $nCells = 0;
echo "── cells: " . ($noOracle === null ? 'both engines, case by case' : 'the new engine, against the recorded digest') . " ──\n";
$digest = grade('cells', $counted(cellCases($programs, $seed), $nCells), $noOracle, $shown);
$atDefault = $programs === DEFAULT_PROGRAMS && $seed === DEFAULT_SEED;
if ($atDefault && $noOracle === null)
  ok($digest === CELLS_DIGEST, "the old engine's results on the cells part, old_landed and DECLARED applied and BUILT recorded, are the ones recorded in CELLS_DIGEST (sha256 $digest)");
elseif ($atDefault)
  ok($digest === CELLS_DIGEST, "$nCells cases: the new engine's results are the old engine's, old_landed and DECLARED applied and BUILT recorded, by the recorded digest (sha256 $digest)");
else echo "  - programs or seed differ from the defaults, so the recorded digest does not apply\n";
printf("  %d cases, %.1f s\n", $nCells, (hrtime(true) - $t0) / 1e9);

echo "\n── signatures and whole ticks ──\n";
if ($noOracle !== null) echo "  - skipped: no oracle\n";
elseif (!extension_loaded('sodium')) echo "  - skipped: Ed25519 signing needs ext/sodium\n";
else { $nSig = 0; grade('signatures', $counted(signatureCases($programs, $seed), $nSig), $noOracle, $shown); printf("  %d cases\n", $nSig); }

if ($ticksFile !== null) {
  echo "\n── programs from $ticksFile ──\n";
  if ($noOracle !== null) echo "  - skipped: no oracle\n";
  else { $nFile = 0; grade('the file', $counted(fileCases($ticksFile), $nFile), $noOracle, $shown); printf("  %d cases\n", $nFile); }
}

printf("\n%s  %d passed, %d failed   [JF on PHP ints · against the GMP engine at %s]\n", $fail === 0 ? '✅' : '⚠', $pass, $fail, substr(REV, 0, 7));
exit($fail === 0 ? 0 : 1);
