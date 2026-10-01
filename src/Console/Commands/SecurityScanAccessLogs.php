<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Internal\SecurityMonitor\Services\AccessLogScannerService;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Carbon\CarbonInterface;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Throwable;

/**
 * Menganalisis access log web server untuk menemukan serangan yang tidak
 * terlihat oleh application middleware (request yang sudah ditolak nginx
 * sebelum sampai ke PHP, scanning massal, probe berkas sensitif).
 *
 * Contoh pemakaian di server:
 *
 *   php artisan security:scan-logs                       # semua berkas default
 *   php artisan security:scan-logs --ip=104.207.74.38    # lacak satu IP
 *   php artisan security:scan-logs --since="2 days ago"  # batasi rentang waktu
 *   php artisan security:scan-logs --import --block      # catat + blokir
 */
class SecurityScanAccessLogs extends Command
{
    protected $signature = 'security:scan-logs
                            {--file=* : Berkas log yang diperiksa (boleh diulang; default dari config/security.php)}
                            {--ip= : Tampilkan hanya aktivitas satu alamat IP}
                            {--since= : Hanya baris sejak waktu tertentu, mis. "2 days ago" atau "2026-09-20 00:00"}
                            {--until= : Hanya baris sampai waktu tertentu}
                            {--min-level= : Saring temuan minimal level: low|medium|high|critical}
                            {--top=20 : Jumlah IP yang ditampilkan}
                            {--samples : Tampilkan contoh request tiap IP}
                            {--json : Keluarkan hasil sebagai JSON}
                            {--import : Simpan temuan ke tabel security_logs}
                            {--block : Blokir IP yang memicu zero tolerance signature (otomatis dicatat ke log)}
                            {--dry-run : Tampilkan rencana impor/pemblokiran tanpa mengubah apa pun}';

    protected $description = 'Analisis access log web server untuk mendeteksi serangan yang tidak tercatat aplikasi';

    public function handle(AccessLogScannerService $scanner, SecurityMonitorService $security): int
    {
        $files = $this->resolveFiles($scanner);

        if ($files === []) {
            $this->error('Tidak ada berkas access log yang dapat dibaca.');
            $this->line('Tentukan lokasinya, mis.: --file=/var/log/nginx/access.log');
            $this->line('atau setel SECURITY_ACCESS_LOG_PATHS pada .env.');

            return self::FAILURE;
        }

        $since = $this->parseDate((string) $this->option('since'));

        if ($this->option('since') !== null && $since === null) {
            $this->error('Format --since tidak dikenali. Contoh: "2 days ago" atau "2026-09-20 00:00".');

            return self::FAILURE;
        }

        $until = $this->parseDate((string) $this->option('until'));

        if ($this->option('until') !== null && $until === null) {
            $this->error('Format --until tidak dikenali. Contoh: "yesterday" atau "2026-09-20 23:59".');

            return self::FAILURE;
        }

        $this->info('Memindai '.count($files).' berkas access log...');

        $result = $scanner->scan($files, [
            'min_level' => $this->option('min-level'),
            'since' => $since,
            'until' => $until,
        ]);

        $attackers = $this->filterByIp($result['attackers']);

        if ($this->option('json')) {
            $this->line(json_encode([
                'stats' => $result['stats'],
                'rules' => $result['rules'],
                'attackers' => $attackers,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '{}');
        } else {
            $this->renderReport($result, $attackers, $scanner);
        }

        if ($attackers === []) {
            $this->newLine();
            $this->info('Tidak ada request mencurigakan yang cocok dengan pola deteksi pada rentang tersebut.');

            return self::SUCCESS;
        }

        if ($this->option('import')) {
            $this->importFindings($attackers, $scanner, $security);
        }

        if ($this->option('block')) {
            $this->blockAttackers($attackers, $scanner, $security);
        }

        return self::SUCCESS;
    }

    /**
     * @return array<int, string>
     */
    protected function resolveFiles(AccessLogScannerService $scanner): array
    {
        /** @var array<int, string> $requested */
        $requested = array_filter((array) $this->option('file'));

        if ($requested === []) {
            return $scanner->defaultFiles();
        }

        $files = [];

        foreach ($requested as $pattern) {
            foreach (glob($pattern) ?: [] as $path) {
                if (is_file($path)) {
                    $files[] = $path;
                } elseif (is_file($pattern)) {
                    $files[] = $pattern;
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * @param  array<int, array<string, mixed>>  $attackers
     * @return array<int, array<string, mixed>>
     */
    protected function filterByIp(array $attackers): array
    {
        $ip = $this->option('ip');

        if (! is_string($ip) || $ip === '') {
            return $attackers;
        }

        return array_values(array_filter($attackers, fn (array $attacker): bool => $attacker['ip'] === $ip));
    }

    /**
     * @param  array<string, mixed>  $result
     * @param  array<int, array<string, mixed>>  $attackers
     */
    protected function renderReport(array $result, array $attackers, AccessLogScannerService $scanner): void
    {
        $this->newLine();

        foreach ($result['stats']['files'] as $file) {
            $line = sprintf(
                '  %s → %s baris dibaca, %s request mencurigakan, %s temuan',
                $file['file'],
                number_format((int) $file['total_lines'], 0, ',', '.'),
                number_format((int) $file['matched_lines'], 0, ',', '.'),
                number_format((int) $file['threats'], 0, ',', '.'),
            );

            $this->line($file['error'] === null ? $line : $line.' ('.$file['error'].')');
        }

        $this->newLine();
        $this->line(sprintf(
            'Total: %s baris, %s berhasil diurai, %s dilewati, %s di luar rentang waktu, %s request mencurigakan dari %s IP.',
            number_format((int) $result['stats']['total_lines'], 0, ',', '.'),
            number_format((int) $result['stats']['parsed_lines'], 0, ',', '.'),
            number_format((int) $result['stats']['skipped_lines'], 0, ',', '.'),
            number_format((int) $result['stats']['out_of_range_lines'], 0, ',', '.'),
            number_format((int) $result['stats']['matched_lines'], 0, ',', '.'),
            count($attackers),
        ));

        if ($attackers === []) {
            return;
        }

        $this->newLine();
        $this->table(
            ['IP', 'Request', 'Level', 'Pola terdeteksi', 'HTTP 403', 'Instan', 'Rentang waktu'],
            $scanner->toTableRows($attackers, max(1, (int) $this->option('top'))),
        );

        $this->newLine();
        $this->line('Ringkasan pola:');

        foreach ($result['rules'] as $rule => $count) {
            $this->line(sprintf('  %-24s %s', $rule, number_format((int) $count, 0, ',', '.')));
        }

        if ($this->option('samples')) {
            $this->newLine();
            $this->line('Contoh request per IP:');

            foreach ($attackers as $attacker) {
                $this->line('  '.$attacker['ip'].':');

                foreach ($attacker['samples'] as $sample) {
                    $this->line('    - '.$sample);
                }
            }
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $attackers
     */
    protected function importFindings(array $attackers, AccessLogScannerService $scanner, SecurityMonitorService $security): void
    {
        $this->newLine();

        if ($this->option('dry-run')) {
            $this->warn(sprintf('[dry-run] %d IP akan dicatat ke security_logs.', count($attackers)));

            return;
        }

        $created = 0;

        foreach ($attackers as $attacker) {
            $rules = array_keys((array) $attacker['rules']);

            $log = $security->log([
                'ip_address' => (string) $attacker['ip'],
                'event_type' => $this->primaryRule($attacker),
                'threat_level' => (string) $attacker['level'],
                'method' => null,
                'path' => Str::limit((string) ($attacker['samples'][0] ?? ''), 2000, ''),
                'full_url' => null,
                'rule_label' => 'Serangan terdeteksi pada access log web server',
                'evidence' => Str::limit($scanner->attackerSummary($attacker), 1000, ''),
                'user_agent' => Str::limit((string) $attacker['user_agent'], 500, ''),
                'action_taken' => 'logged',
                'meta' => [
                    'source' => 'access_log',
                    'hits' => $attacker['hits'],
                    'rules' => $rules,
                    'statuses' => $attacker['statuses'],
                    'first_seen' => $attacker['first_seen']?->toIso8601String(),
                    'last_seen' => $attacker['last_seen']?->toIso8601String(),
                    'samples' => $attacker['samples'],
                ],
            ]);

            if ($log !== null) {
                $created++;
            }
        }

        $this->info("{$created} temuan access log disimpan ke security_logs.");
        $this->line('Tinjau di halaman /security/logs (jenis event "access_log:*").');
    }

    /**
     * @param  array<int, array<string, mixed>>  $attackers
     */
    protected function blockAttackers(array $attackers, AccessLogScannerService $scanner, SecurityMonitorService $security): void
    {
        $candidates = array_values(array_filter(
            $attackers,
            fn (array $attacker): bool => $attacker['instant'] === true
        ));

        $this->newLine();

        if ($candidates === []) {
            $this->line('Tidak ada IP dengan zero tolerance signature, tidak ada yang diblokir.');
            $this->line('Gunakan --min-level=high --import lalu blokir manual dari /security/blocked-ips bila perlu.');

            return;
        }

        if ($this->option('dry-run')) {
            $this->warn(sprintf('[dry-run] %d IP akan diblokir:', count($candidates)));

            foreach ($candidates as $candidate) {
                $this->line('  - '.$candidate['ip'].' ('.$scanner->attackerSummary($candidate).')');
            }

            return;
        }

        $blocked = 0;
        $skipped = 0;

        foreach ($candidates as $candidate) {
            $ip = (string) $candidate['ip'];

            if ($security->isWhitelisted($ip)) {
                $skipped++;
                $this->warn("Dilewati (ada di whitelist): {$ip}");

                continue;
            }

            $block = $security->block($ip, [
                'reason' => 'Diblokir dari analisis access log: '.$this->primaryRule($candidate),
                'notes' => $scanner->attackerSummary($candidate),
                'source' => 'automatic',
                'duration_hours' => (int) config('security.instant_block.duration_hours', 720),
            ]);

            $security->log([
                'ip_address' => $ip,
                'event_type' => 'access_log_block',
                'threat_level' => (string) $candidate['level'],
                'path' => '/security/scan-logs',
                'rule_label' => 'Pemblokiran berdasarkan analisis access log',
                'evidence' => $scanner->attackerSummary($candidate),
                'action_taken' => 'blocked',
            ]);

            $blocked++;
            $this->info("Diblokir: {$ip} sampai ".($block->expires_at?->translatedFormat('d M Y H:i') ?? 'permanen'));
        }

        $this->newLine();
        $this->info("{$blocked} IP diblokir, {$skipped} dilewati.");

        if ($blocked > 0) {
            $this->line('Buka blokir bila salah: php artisan security:unblock-ip <ip>');
        }
    }

    /**
     * @param  array<string, mixed>  $attacker
     */
    protected function primaryRule(array $attacker): string
    {
        $rules = (array) $attacker['rules'];
        arsort($rules);

        $rule = (string) (array_key_first($rules) ?? 'access_log');

        return 'access_log:'.$rule;
    }

    protected function parseDate(string $value): ?CarbonInterface
    {
        $value = trim($value);

        if ($value === '') {
            return null;
        }

        try {
            return Carbon::parse($value);
        } catch (Throwable) {
            return null;
        }
    }
}
