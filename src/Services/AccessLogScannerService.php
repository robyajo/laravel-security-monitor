<?php

namespace Internal\SecurityMonitor\Services;

use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Internal\SecurityMonitor\Models\SecurityLog;
use Throwable;

/**
 * Analisis log akses web server (nginx/Apache, format "combined").
 *
 * Middleware keamanan hanya bisa menilai request yang benar-benar sampai ke
 * aplikasi. Serangan yang ditolak web server lebih dulu — berkas `.php` yang
 * di-`return 403` oleh nginx, percobaan `POST /index.php?file=...`, scanning
 * massal terhadap aplikasi lain di server yang sama — TIDAK pernah terlihat
 * oleh aplikasi, sehingga satu-satunya jejaknya ada di access log.
 *
 * Service ini membaca access log baris per baris (streaming, aman untuk berkas
 * besar), menjalankan pola deteksi yang sama dengan middleware, lalu
 * mengelompokkan temuan per alamat IP supaya admin dapat melihat siapa yang
 * menyerang dan pola apa yang dipakai.
 */
class AccessLogScannerService
{
    public function __construct(protected SecurityMonitorService $security) {}

    /**
     * Berkas log default yang diperiksa bila `--file` tidak diisi.
     *
     * @return array<int, string>
     */
    public function defaultFiles(): array
    {
        $configured = array_filter((array) config('security.access_log.paths', []));

        $candidates = $configured !== [] ? $configured : [
            '/var/log/nginx/access.log',
            '/var/log/nginx/*access.log',
            storage_path('logs/access.log'),
        ];

        $files = [];

        foreach ($candidates as $candidate) {
            foreach (glob((string) $candidate) ?: [] as $path) {
                if (is_file($path) && is_readable($path)) {
                    $files[] = $path;
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * Periksa satu atau beberapa berkas access log.
     *
     * @param  array<int, string>  $files
     * @param  array{min_level?: string|null, since?: CarbonInterface|null, until?: CarbonInterface|null, keep_lines?: int}  $options
     * @return array<string, mixed>
     */
    public function scan(array $files, array $options = []): array
    {
        $minLevel = $this->normalizeLevel($options['min_level'] ?? null);
        $since = $options['since'] ?? null;
        $until = $options['until'] ?? null;
        $maxLines = max(1000, (int) config('security.access_log.max_lines', 500_000));

        $stats = [
            'files' => [],
            'total_lines' => 0,
            'parsed_lines' => 0,
            'skipped_lines' => 0,
            'out_of_range_lines' => 0,
            'matched_lines' => 0,
            'threats' => 0,
        ];

        /** @var array<string, array<string, mixed>> $attackers */
        $attackers = [];

        /** @var array<string, int> $ruleCounts */
        $ruleCounts = [];

        foreach ($files as $file) {
            $fileStats = $this->scanFile($file, $minLevel, $since, $until, $maxLines, $attackers, $ruleCounts);

            $stats['files'][] = $fileStats;
            $stats['total_lines'] += $fileStats['total_lines'];
            $stats['parsed_lines'] += $fileStats['parsed_lines'];
            $stats['skipped_lines'] += $fileStats['skipped_lines'];
            $stats['out_of_range_lines'] += $fileStats['out_of_range_lines'];
            $stats['matched_lines'] += $fileStats['matched_lines'];
            $stats['threats'] += $fileStats['threats'];
        }

        $sorted = collect($attackers)
            ->sortByDesc(fn (array $entry) => [$entry['weight'], $entry['hits']])
            ->values();

        return [
            'stats' => $stats,
            'attackers' => $sorted->all(),
            'rules' => $this->sortCounts($ruleCounts),
            'files_scanned' => count($files),
        ];
    }

    /**
     * @param  array<string, array<string, mixed>>  $attackers
     * @param  array<string, int>  $ruleCounts
     * @return array<string, mixed>
     */
    protected function scanFile(
        string $file,
        ?string $minLevel,
        ?CarbonInterface $since,
        ?CarbonInterface $until,
        int $maxLines,
        array &$attackers,
        array &$ruleCounts,
    ): array {
        $stats = [
            'file' => $file,
            'total_lines' => 0,
            'parsed_lines' => 0,
            'skipped_lines' => 0,
            'out_of_range_lines' => 0,
            'matched_lines' => 0,
            'threats' => 0,
            'error' => null,
        ];

        $handle = @fopen($file, 'rb');

        if ($handle === false) {
            $stats['error'] = 'Berkas tidak dapat dibaca (periksa izin akses).';

            return $stats;
        }

        try {
            while (($line = fgets($handle)) !== false) {
                if (++$stats['total_lines'] > $maxLines) {
                    $stats['error'] = "Dibatasi {$maxLines} baris pertama (SECURITY_ACCESS_LOG_MAX_LINES).";

                    break;
                }

                $entry = $this->parse($line);

                if ($entry === null) {
                    $stats['skipped_lines']++;

                    continue;
                }

                $stats['parsed_lines']++;

                if (! $this->inRange($entry['time'], $since, $until)) {
                    $stats['out_of_range_lines']++;

                    continue;
                }

                $threats = $this->inspect($entry, $minLevel);

                if ($threats === []) {
                    continue;
                }

                $stats['matched_lines']++;
                $stats['threats'] += count($threats);

                foreach ($threats as $threat) {
                    $ruleCounts[$threat['rule']] = ($ruleCounts[$threat['rule']] ?? 0) + 1;
                }

                $this->recordAttacker($attackers, $entry, $threats);
            }
        } catch (Throwable $exception) {
            $stats['error'] = $exception->getMessage();
        } finally {
            fclose($handle);
        }

        return $stats;
    }

    /**
     * Apakah waktu baris log berada dalam rentang yang diminta.
     *
     * Baris tanpa waktu yang dapat diurai tetap diikutkan agar log dengan format
     * waktu tidak dikenal tidak diam-diam terlewat.
     */
    protected function inRange(?CarbonInterface $time, ?CarbonInterface $since, ?CarbonInterface $until): bool
    {
        if ($time === null) {
            return true;
        }

        if ($since !== null && $time->lt($since)) {
            return false;
        }

        return ! ($until !== null && $time->gt($until));
    }

    /**
     * Jalankan pola deteksi yang sama dengan middleware terhadap satu baris log.
     *
     * @param  array<string, mixed>  $entry
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    public function inspect(array $entry, ?string $minLevel = null): array
    {
        $haystacks = [
            'path' => (string) $entry['path'],
            'query' => (string) $entry['query'],
            'query-decoded' => $this->decode((string) $entry['query']),
            'user_agent' => (string) $entry['user_agent'],
            'referer' => (string) $entry['referer'],
        ];

        try {
            $threats = $this->security->inspectHaystacks($haystacks);
        } catch (Throwable) {
            return [];
        }

        if ($minLevel === null) {
            return $threats;
        }

        $minimum = SecurityLog::weightOf($minLevel);

        return array_values(array_filter(
            $threats,
            fn (array $threat): bool => SecurityLog::weightOf((string) $threat['level']) >= $minimum
        ));
    }

    /**
     * Urai satu baris log format "combined" (nginx default / Apache).
     *
     * Contoh:
     *   203.0.113.9 - - [20/Sep/2026:17:27:41 +0700] "POST /index.php HTTP/1.1" 403 153 "-" "curl/8.0"
     *
     * @return array{ip: string, time: Carbon|null, method: string, target: string, path: string, query: string, protocol: string, status: int|null, bytes: int|null, referer: string, user_agent: string, raw: string}|null
     */
    public function parse(string $line): ?array
    {
        $line = trim($line);

        if ($line === '') {
            return null;
        }

        $pattern = '/^(?<ip>\S+) \S+ (?<user>\S+) \[(?<time>[^\]]+)] "(?<request>[^"]*)" (?<status>\S+) (?<bytes>\S+)(?: "(?<referer>[^"]*)" "(?<agent>[^"]*)")?/';

        if (preg_match($pattern, $line, $matches) !== 1) {
            return null;
        }

        $request = (string) $matches['request'];

        // "-" pada request menandakan baris tanpa request yang valid.
        if ($request === '-' || $request === '') {
            return null;
        }

        $parts = explode(' ', $request);

        if (count($parts) < 2) {
            return null;
        }

        $method = strtoupper((string) $parts[0]);
        $target = (string) $parts[1];
        $protocol = (string) ($parts[2] ?? '');

        // Nama berkas yang diunggah lewat PUT/POST tidak terlihat di access log,
        // tetapi path traversal pada URL tetap ikut terperiksa di sini.
        $path = $target;
        $query = '';

        if (($position = strpos($target, '?')) !== false) {
            $path = substr($target, 0, $position);
            $query = substr($target, $position + 1);
        }

        $status = is_numeric($matches['status']) ? (int) $matches['status'] : null;
        $bytes = isset($matches['bytes']) && is_numeric($matches['bytes']) ? (int) $matches['bytes'] : null;

        return [
            'ip' => (string) $matches['ip'],
            'time' => $this->parseTime((string) $matches['time']),
            'method' => $method,
            'target' => $target,
            'path' => $path,
            'query' => $query,
            'protocol' => $protocol,
            'status' => $status,
            'bytes' => $bytes,
            'referer' => $this->normalizeDash($matches['referer'] ?? ''),
            'user_agent' => $this->normalizeDash($matches['agent'] ?? ''),
            'raw' => Str::limit($line, 2000, ''),
        ];
    }

    protected function parseTime(string $value): ?Carbon
    {
        try {
            return Carbon::createFromFormat('d/M/Y:H:i:s P', $value) ?: null;
        } catch (Throwable) {
            try {
                return Carbon::parse($value);
            } catch (Throwable) {
                return null;
            }
        }
    }

    protected function normalizeDash(string $value): string
    {
        return in_array($value, ['-', ''], true) ? '' : $value;
    }

    /**
     * Terjemahkan escape pada query string tanpa mengubah tanda "+" menjadi spasi
     * (banyak payload memakai "+" secara harfiah).
     */
    protected function decode(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $decoded = rawurldecode($value);

        return mb_check_encoding($decoded, 'UTF-8') ? $decoded : $value;
    }

    /**
     * @param  array<string, array<string, mixed>>  $attackers
     * @param  array<string, mixed>  $entry
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>  $threats
     */
    protected function recordAttacker(array &$attackers, array $entry, array $threats): void
    {
        $ip = (string) $entry['ip'];

        $primary = $this->primaryThreat($threats);
        $level = (string) $primary['level'];
        $weight = SecurityLog::weightOf($level);

        if (! isset($attackers[$ip])) {
            $attackers[$ip] = [
                'ip' => $ip,
                'hits' => 0,
                'weight' => 0,
                'level' => $level,
                'first_seen' => $entry['time'],
                'last_seen' => $entry['time'],
                'rules' => [],
                'instant' => false,
                'statuses' => [],
                'samples' => [],
                'user_agent' => (string) $entry['user_agent'],
                'blocked' => 0,
                'errors' => 0,
            ];
        }

        $attacker = &$attackers[$ip];
        $attacker['hits']++;

        if ($weight > $attacker['weight']) {
            $attacker['weight'] = $weight;
            $attacker['level'] = $level;
        }

        if ($entry['time'] !== null) {
            if ($attacker['first_seen'] === null || $entry['time']->lt($attacker['first_seen'])) {
                $attacker['first_seen'] = $entry['time'];
            }

            if ($attacker['last_seen'] === null || $entry['time']->gt($attacker['last_seen'])) {
                $attacker['last_seen'] = $entry['time'];
            }
        }

        foreach ($threats as $threat) {
            $rule = (string) $threat['rule'];
            $attacker['rules'][$rule] = ($attacker['rules'][$rule] ?? 0) + 1;

            if (($threat['instant'] ?? false) === true) {
                $attacker['instant'] = true;
            }
        }

        $status = $entry['status'];

        if ($status !== null) {
            $attacker['statuses'][(string) $status] = ($attacker['statuses'][(string) $status] ?? 0) + 1;

            if ($status === 403) {
                $attacker['blocked']++;
            }

            if ($status >= 500) {
                $attacker['errors']++;
            }
        }

        $target = Str::limit((string) $entry['target'], 180, '');

        if (! in_array($target, $attacker['samples'], true) && count($attacker['samples']) < 8) {
            $attacker['samples'][] = $target;
        }

        unset($attacker);
    }

    /**
     * @param  array<int, array{level: string}>  $threats
     * @return array<string, mixed>
     */
    protected function primaryThreat(array $threats): array
    {
        usort($threats, fn (array $a, array $b) => SecurityLog::weightOf((string) $b['level']) <=> SecurityLog::weightOf((string) $a['level']));

        return $threats[0];
    }

    /**
     * Ringkasan singkat temuan untuk sebuah IP (dipakai saat mengimpor log).
     *
     * @param  array<string, mixed>  $attacker
     */
    public function attackerSummary(array $attacker): string
    {
        $rules = $this->sortCounts((array) $attacker['rules']);
        $parts = [];

        foreach ($rules as $rule => $count) {
            $parts[] = $count.'x '.$rule;
        }

        return 'Terlihat di access log: '.$attacker['hits'].' request mencurigakan ('
            .implode(', ', array_slice($parts, 0, 5)).').';
    }

    /**
     * @param  array<string, int>  $counts
     * @return array<string, int>
     */
    protected function sortCounts(array $counts): array
    {
        arsort($counts);

        return $counts;
    }

    protected function normalizeLevel(?string $level): ?string
    {
        $level = is_string($level) ? strtolower(trim($level)) : '';

        return in_array($level, SecurityLog::LEVELS, true) ? $level : null;
    }

    /**
     * Ubah hasil scan menjadi baris tabel untuk CLI.
     *
     * @param  array<int, array<string, mixed>>  $attackers
     * @return array<int, array<int, string>>
     */
    public function toTableRows(array $attackers, int $limit = 20): array
    {
        return collect($attackers)
            ->take($limit)
            ->map(function (array $attacker): array {
                return [
                    (string) $attacker['ip'],
                    (string) $attacker['hits'],
                    Str::upper((string) $attacker['level']),
                    implode(', ', array_keys($this->sortCounts((array) $attacker['rules']))),
                    (string) $attacker['blocked'],
                    $attacker['instant'] ? 'ya' : 'tidak',
                    $this->formatTime($attacker['first_seen'], $attacker['last_seen']),
                ];
            })
            ->all();
    }

    protected function formatTime(?CarbonInterface $from, ?CarbonInterface $to): string
    {
        if ($from === null && $to === null) {
            return '-';
        }

        $start = $from?->format('d/m H:i');
        $end = $to?->format('d/m H:i');

        return $start === $end || $end === null ? (string) $start : $start.' - '.$end;
    }
}
