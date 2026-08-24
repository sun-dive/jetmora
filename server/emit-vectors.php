<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
// Emit tree data from the PHP implementation so the JS one can be checked against it, byte for byte.
// ⚠ Two implementations each agreeing with THEMSELVES proves nothing. This is the comparison.
declare(strict_types=1);
require __DIR__ . '/merkle.php';
$H = fn(string $b) => bin2hex($b);
// ⚠ range(0, -1) in PHP is [0, -1] — a DESCENDING two-element range, not an empty one. Written the
//   obvious way, n=0 silently builds a two-entry tree and calls it empty.
$E = fn(int $n) => $n === 0 ? []
    : array_map(fn($i) => chr($i & 0xff) . chr(($i >> 8) & 0xff) . 'e', range(0, $n - 1));
$out = [];
foreach ([0,1,2,3,4,5,7,8,9,15,16,17,31,32,33,63,64,65,100] as $n) {
    $e = $E($n);
    $rec = ['n' => $n, 'root' => $H(mt_root($e)), 'inclusion' => [], 'consistency' => []];
    for ($m = 0; $m < $n; $m++) $rec['inclusion'][(string)$m] = array_map($H, mt_inclusion_proof($m, $e));
    for ($m = 1; $m <= $n; $m++) $rec['consistency'][(string)$m] = array_map($H, mt_consistency_proof($m, $e));
    $out[] = $rec;
}
echo json_encode($out), "\n";
