<?php
// © 2026 sun-dive. Business Source License 1.1 — see LICENSE.
//
// Run programs through the PHP `JF` interpreter and print what each did, for tools/verify-jf.mjs to compare
// with the JavaScript one. Reads JSON from stdin: [{"script": hex, "preimage": hex|null}, ...]; argv[1] = first index.
// Writes ONE JSON line per program, flushed, so a program that ends the PHP process loses only itself:
//   {"stack": ["1", "-2", ...]} | {"error": hex(message), "diag": hex|null, "jf": bool}
//   "jf" is false when the refusal did not come from the interpreter itself (a PHP fault), so it can be reported.
declare(strict_types=1);
require_once __DIR__ . '/../server/interpreter-jf.php';

$in = json_decode((string)stream_get_contents(STDIN), true);
for ($k = (int)($argv[1] ?? 0); $k < count($in); $k++) {
  $c = $in[$k];
  $vm = new InterpreterJF();
  $vm->setPreimage(isset($c['preimage']) ? hex2bin($c['preimage']) : null);
  try {
    $r = ['stack' => array_map(fn($g) => gmp_strval($g), $vm->run(hex2bin($c['script'])))];
  } catch (Throwable $e) {
    $r = ['error' => bin2hex($e->getMessage()), 'diag' => $e instanceof JfScriptError && $e->diagnostic !== null ? bin2hex($e->diagnostic) : null,
          'jf' => $e instanceof JfScriptError];
  }
  echo json_encode($r), "\n";
  flush();
}
