<?php
// One worker in the concurrent-append test. Appends $count entries to $path, tagged with $id.
// ⚠ Reports its own failures rather than dying, so the harness can count them by class.
require_once __DIR__ . '/../server/store.php';
[$path, $id, $count] = [$argv[1], (int)$argv[2], (int)$argv[3]];
$store = new LogStore($path);
$ok = 0; $errs = [];
// ⚠ Every worker opens the DB, then they all wait for the same wall-clock instant. Without this the
//   processes stagger by however long PHP takes to start and the race never happens.
$startAt = (float)$argv[4];
while (microtime(true) < $startAt) { usleep(200); }
for ($i = 0; $i < $count; $i++) {
    $body = "worker-$id-entry-$i-" . str_repeat('x', 20);
    try { $store->append($body); $ok++; }
    catch (Throwable $e) {
        $m = $e->getMessage();
        // classify: the shape of the failure matters more than the count
        if (str_contains($m, 'UNIQUE'))      $errs[] = 'UNIQUE(duplicate seq)';
        elseif (str_contains($m, 'locked'))  $errs[] = 'database is locked';
        elseif (str_contains($m, 'busy'))    $errs[] = 'busy';
        else                                 $errs[] = substr($m, 0, 60);
    }
}
echo json_encode(['id'=>$id, 'ok'=>$ok, 'errs'=>$errs]), "\n";
