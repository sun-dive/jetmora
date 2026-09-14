<?php
// © 2026 sun-dive. Apache License 2.0 — see LICENSE.
//
// ══ THE RATE-LIMITED HTTP PATH — EVERYTHING SERVER-SIDE GOES THROUGH HERE ════════════════════════════
//
// His call, 8 Sept: *"everything on a server needs to pass through that when talking to Bananablocks
// or WoC."*
//
// ⚠⚠⚠ WHY THIS IS NOT A PORT OF `queuedFetch`, AND COULD NOT BE.
//   PharLap paces requests with an **in-process promise chain** (`walletProvider.ts:78`). That is
//   correct in a browser, where one tab is one process and `fetchQueue` is one variable.
//   ⛔ **PHP IS NOT THAT.** Every HTTP request is its OWN PROCESS with its own memory. A promise chain,
//     a static, a global — none of them are shared. ⇒ Ten concurrent visitors would each believe they
//     were first, and burst straight through the limit **exactly when the site is busiest**, which is
//     the one moment the pacing was for.
//   ★ So the queue has to live somewhere ALL the processes can see. `flock()` is that place: POSIX,
//     built in, no extension, works on the cheapest hosting there is. → [[great-session-2026-09-01]]
//
// ★★ WHAT CARRIES OVER FROM PharLap UNCHANGED, because it was right:
//   | a MINIMUM GAP between requests | 350 ms, so concurrent paths cannot burst |
//   | a 429 branch with BACKOFF | 500 / 1000 / 1500 ms, 3 retries |
//   ⇒ The SDK has NEITHER. `WhatsOnChain.isValidRootForHeight` has three cases — ok, 404, and
//     **`else → throw`** — so a rate limit surfaces as *"failed to verify merkleroot"*, indistinguishable
//     from a bad proof. ⛔ A verifier that reports "invalid" when it was merely throttled is worse than
//     one that waits.
//
// ⚠ TWO DELIBERATE DIFFERENCES FROM THE REFERENCE, stated rather than smuggled in:
//   1. **The queue is PER HOST.** PharLap uses one global chain for both WoC and BananaBlocks, which is
//      safe but throws away half the throughput — they are different services with different limits.
//   2. **`Retry-After` is honoured** when the server sends one. PharLap does not read it. If a service
//      tells you exactly how long to wait, guessing 500 ms instead is worse for both sides.
declare(strict_types=1);

final class HttpError extends RuntimeException {}

/**
 * A cross-process minimum-gap pacer.
 *
 * ⚠ The lock is held ACROSS the request, not just the wait. That is what makes it a QUEUE rather than
 *   a check: a second process blocks until the first is genuinely finished. A check-then-release would
 *   let every waiting process fire at the same instant, which is the burst we are preventing.
 */
final class RateLimiter
{
  /** ★ PharLap's number, and it has survived contact with WoC's free tier. */
  public const DEFAULT_GAP_MS = 350;

  private string $lockFile;

  public function __construct(
    private string $host,
    private int $minGapMs = self::DEFAULT_GAP_MS,
    private int $maxWaitMs = 30000,
    ?string $dir = null,
  ) {
    $dir = $dir ?? (is_dir(__DIR__ . '/../../data') ? __DIR__ . '/../../data' : sys_get_temp_dir());
    // ⚠ the host is hashed: it reaches the FILESYSTEM, and a hostname is not a safe filename
    $this->lockFile = rtrim($dir, '/') . '/.ratelimit-' . substr(hash('sha256', $host), 0, 16);
  }

  public function host(): string { return $this->host; }

  /**
   * Run `$fn` with this host's slot held. Returns whatever `$fn` returns.
   * ★ A wrapper rather than acquire/release because PHP has no RAII: an exception inside `$fn` must
   *   still free the lock, or one failure wedges every later request on the site.
   */
  public function run(callable $fn): mixed
  {
    $h = @fopen($this->lockFile, 'c+');
    // ⚠ NEVER FAIL CLOSED ON A PACER. If the directory is read-only we lose pacing, which risks a 429
    //   the retry loop can absorb; refusing to work at all would take the site down over a lock file.
    if ($h === false) return $fn();

    $waited = 0;
    while (!flock($h, LOCK_EX | LOCK_NB)) {
      if ($waited >= $this->maxWaitMs) {
        fclose($h);
        throw new HttpError(sprintf(
          'waited %dms for the %s rate-limit slot and never got it — something upstream is stalled',
          $waited, $this->host));
      }
      usleep(25000); $waited += 25;
    }

    try {
      // ★ Sleep only the REMAINDER of the gap. If the previous request was slow, its own duration has
      //   already paid for part of the wait, and sleeping the full gap again would be pure waste.
      $last = (float)(fgets($h) ?: 0);
      $due  = $last + $this->minGapMs / 1000;
      $now  = microtime(true);
      if ($last > 0 && $now < $due) usleep((int)(($due - $now) * 1_000_000));

      return $fn();
    } finally {
      // ⚠ The stamp is written AFTER the call — PharLap enforces its delay after completion too, so
      //   the gap is between the END of one request and the START of the next.
      ftruncate($h, 0); rewind($h); fwrite($h, (string)microtime(true)); fflush($h);
      flock($h, LOCK_UN); fclose($h);
    }
  }
}

/**
 * The only way this wallet talks to a chain service.
 *
 * ⚠ `$transport` is injectable so every behaviour below is graded OFFLINE. A rate limiter that has only
 *   ever been tested against a live API has not been tested — the interesting cases are the ones the
 *   service will not produce on demand.
 */
final class BsvHttp
{
  /** @var array<string,RateLimiter> one per host */
  private array $limiters = [];

  /** @param callable|null $transport fn(string $method, string $url, ?string $body, array $headers)
   *                                  => ['status'=>int,'body'=>string,'headers'=>array] */
  public function __construct(
    private $transport = null,
    private int $maxRetries = 3,
    private int $minGapMs = RateLimiter::DEFAULT_GAP_MS,
    // ⚠ Where the cross-process lock files live. Configurable because the default may be read-only on
    //   some hosts, and because a test must not share pacing state with the live wallet.
    private ?string $lockDir = null,
  ) {}

  private function limiter(string $url): RateLimiter
  {
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || $host === '') throw new HttpError("no host in URL: $url");
    return $this->limiters[$host] ??=
      new RateLimiter($host, $this->minGapMs, 30000, $this->lockDir);
  }

  /** @return array{status:int,body:string,headers:array} */
  public function request(string $method, string $url, ?string $body = null, array $headers = []): array
  {
    $lim = $this->limiter($url);
    for ($attempt = 0; ; $attempt++) {
      $resp = $lim->run(fn() => $this->send($method, $url, $body, $headers));
      // ⛔ 429 is NOT an error and must never be reported as one. It is "ask again shortly".
      if ($resp['status'] !== 429 || $attempt >= $this->maxRetries) return $resp;
      // ★ Honour Retry-After when the service sends one — it knows and we are guessing.
      $after = $resp['headers']['retry-after'] ?? null;
      $ms = is_numeric($after) ? (int)((float)$after * 1000) : 500 * ($attempt + 1);
      usleep(min($ms, 60000) * 1000);
    }
  }

  public function get(string $url, array $headers = []): array
  {
    return $this->request('GET', $url, null, $headers);
  }

  /** @return mixed decoded JSON, or null if the body is not JSON */
  public function getJson(string $url, array $headers = []): mixed
  {
    $r = $this->get($url, $headers + ['Accept' => 'application/json']);
    if ($r['status'] < 200 || $r['status'] >= 300)
      throw new HttpError(sprintf('%s returned HTTP %d', $url, $r['status']));
    return json_decode($r['body'], true);
  }

  private function send(string $method, string $url, ?string $body, array $headers): array
  {
    if ($this->transport !== null) return ($this->transport)($method, $url, $body, $headers);
    if (!function_exists('curl_init')) throw new HttpError('ext-curl is required for network calls');
    $ch = curl_init($url);
    $hdr = [];
    foreach ($headers as $k => $v) $hdr[] = "$k: $v";
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method,
      CURLOPT_HTTPHEADER => $hdr, CURLOPT_TIMEOUT => 30, CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_HEADER => true,
    ] + ($body !== null ? [CURLOPT_POSTFIELDS => $body] : []));
    $raw = curl_exec($ch);
    if ($raw === false) { $e = curl_error($ch); curl_close($ch); throw new HttpError("request failed: $e"); }
    $status  = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $hdrSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    $out = [];
    foreach (explode("\r\n", substr((string)$raw, 0, $hdrSize)) as $line)
      if (str_contains($line, ':')) {
        [$k, $v] = explode(':', $line, 2);
        $out[strtolower(trim($k))] = trim($v);
      }
    return ['status' => (int)$status, 'body' => substr((string)$raw, $hdrSize), 'headers' => $out];
  }
}
