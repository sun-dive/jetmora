<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ── VERSION DISPATCH (spec §6b) ──────────────────────────────────────────────────────────────────────
// §6b: "A verifier replaying an entry MUST apply the semantics of the version named IN THAT ENTRY, and
// MUST NOT apply its own." ⇒ This file is how that sentence becomes code.
//
// ⚠⚠ THIS IS THE ONLY SHARED PIECE, AND IT IS DELIBERATELY IGNORANT (gaps §10.9).
// It reads two characters and loads a module. ⛔ It MUST NOT contain set-specific knowledge — no opcode
// numbers, no semantics, no `if family === 'SV'` special cases. The moment it knows something about a
// set, it becomes the coupling point the whole file layout exists to prevent.
// ★ Which is why it is a REGISTRY and not a switch: a third party registers `XY`, ships
//   `interpreter-xy.php`, and touches nothing of ours.
//
// ── THE FIELD ────────────────────────────────────────────────────────────────────────────────────────
// `nVersion` is a u32, and it is BYTES, not a number. That is the point of using characters: a string
// has no byte order to disagree about.
//
//   67 00 00 00   high half ZERO      ⇒ LEGACY INTEGER version — here, 103
//   01 00 53 56   high half is ASCII  ⇒ revision 1 of family `SV`
//
// ★★★ THE DISCRIMINATOR COSTS NOTHING AND NEEDS NO FLAG DAY: uppercase ASCII is 0x41–0x5A and digits are
// 0x30–0x39, so a family's bytes can never be zero, and a small integer's high bytes always are.
// ⇒ jetmora.org's 264 live entries at version 103 keep meaning EXACTLY what they mean today. §6b forbids
//   anything else — reinterpreting them as a family retroactively would change what they said.
declare(strict_types=1);

final class VersionError extends RuntimeException {}

/**
 * Split an `nVersion` u32 into what it names.
 *   legacy  → ['legacy' => int]
 *   family  → ['family' => 'SV', 'revision' => int]
 * @throws VersionError on a family that is not two legal characters.
 */
function version_parse(int $nVersion): array
{
  if ($nVersion < 0 || $nVersion > 0xffffffff) throw new VersionError('nVersion out of u32 range');

  $c0 = ($nVersion >> 16) & 0xff;   // the third byte on the wire
  $c1 = ($nVersion >> 24) & 0xff;   // the fourth

  if ($c0 === 0 && $c1 === 0) return ['legacy' => $nVersion & 0xffff];

  // ⚠ Uppercase A–Z and digits only, so there is ONE spelling of one thing. `sv` is not a family.
  $legal = fn(int $c) => ($c >= 0x41 && $c <= 0x5a) || ($c >= 0x30 && $c <= 0x39);
  if (!$legal($c0) || !$legal($c1)) {
    throw new VersionError(sprintf('illegal family bytes %02x %02x', $c0, $c1));
  }
  return ['family' => chr($c0) . chr($c1), 'revision' => $nVersion & 0xffff];
}

/** Build an `nVersion` from a family and revision. The inverse of the above. */
function version_build(string $family, int $revision): int
{
  if (strlen($family) !== 2) throw new VersionError('a family is exactly two characters');
  if ($revision < 0 || $revision > 0xffff) throw new VersionError('revision out of range');
  return (ord($family[1]) << 24) | (ord($family[0]) << 16) | $revision;
}

// ── THE REGISTRY ─────────────────────────────────────────────────────────────────────────────────────
// ⚠ `\0\0` is not registrable and cannot be: version_parse() returns it as a LEGACY version, never as a
//   family, so an uninitialised field can never dispatch anywhere.

/** @var array<string, array{file:string, class:string, revisions:int[]}> */
$GLOBALS['JETMORA_SETS'] = [];

/**
 * Register an instruction set. A third party calls this and ships one file.
 * @param int[] $revisions which revisions of this family the module implements.
 */
function register_set(string $family, string $file, string $class, array $revisions = [1]): void
{
  if (strlen($family) !== 2) throw new VersionError('a family is exactly two characters');
  $GLOBALS['JETMORA_SETS'][$family] = ['file' => $file, 'class' => $class, 'revisions' => $revisions];
}

/**
 * The whole job: given an entry's nVersion, return the interpreter that entry named.
 * ⛔ Never returns "the newest" or "ours" — §6b forbids a verifier applying its own semantics.
 */
function interpreter_for(int $nVersion): object
{
  $v = version_parse($nVersion);

  if (isset($v['legacy'])) {
    throw new VersionError(
      "entry names legacy version {$v['legacy']}; no interpreter is registered for legacy versions. " .
      '⚠ Legacy entries predate the family scheme and keep their own semantics (§6b) — they are not ' .
      'reinterpretable as a family.');
  }

  $f = $v['family'];
  $sets = $GLOBALS['JETMORA_SETS'];
  if (!isset($sets[$f])) {
    $known = $sets ? implode(', ', array_keys($sets)) : 'none';
    throw new VersionError("no interpreter registered for family `$f` (registered: $known)");
  }
  $set = $sets[$f];
  if (!in_array($v['revision'], $set['revisions'], true)) {
    throw new VersionError(
      "family `$f` is registered, but not revision {$v['revision']} " .
      '(has: ' . implode(', ', $set['revisions']) . ')');
  }

  require_once $set['file'];
  if (!class_exists($set['class'])) throw new VersionError("{$set['file']} does not define {$set['class']}");
  return new $set['class']();
}

// ── what this installation carries ───────────────────────────────────────────────────────────────────
// ⚠ A host ships only the sets it serves. On a $2/month tier that is not a rounding error.
register_set('SV', __DIR__ . '/interpreter-sv.php', 'InterpreterSV', [1]);
register_set('BT', __DIR__ . '/interpreter-bt.php', 'InterpreterBT', [1]);
register_set('JF', __DIR__ . '/interpreter-jf.php', 'InterpreterJF', [1]);
