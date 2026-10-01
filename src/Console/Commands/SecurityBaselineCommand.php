<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;
use Internal\SecurityMonitor\Services\ServerSecurityService;

/**
 * Membuat / memeriksa baseline hash berkas penting.
 *
 * Baseline dipakai halaman /security/server untuk mendeteksi perubahan berkas
 * yang tidak berasal dari deployment resmi (mis. backdoor yang disisipkan
 * setelah insiden marker "wne").
 */
class SecurityBaselineCommand extends Command
{
    protected $signature = 'security:baseline
                            {--check : Bandingkan berkas saat ini dengan baseline tanpa menulis apa pun}
                            {--prune : Hapus baseline yang tersimpan}
                            {--force : Lewati konfirmasi saat membuat baseline}';

    protected $description = 'Buat atau periksa baseline integritas berkas penting aplikasi';

    public function handle(ServerSecurityService $service): int
    {
        if ($this->option('prune')) {
            return $this->prune($service);
        }

        if ($this->option('check')) {
            return $this->check($service);
        }

        return $this->create($service);
    }

    protected function create(ServerSecurityService $service): int
    {
        $files = $service->watchedFiles();

        if ($files === []) {
            $this->error('Tidak ada berkas yang cocok dengan security.server_scan.integrity_paths.');

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm('Buat baseline baru untuk '.count($files).' berkas?', true)) {
            return self::SUCCESS;
        }

        $baseline = $service->createBaseline();

        $this->info('Baseline dibuat: '.count((array) ($baseline['files'] ?? [])).' berkas di-hash.');
        $this->line('Disimpan di: '.$service->baselinePath());

        return self::SUCCESS;
    }

    protected function check(ServerSecurityService $service): int
    {
        $summary = $service->baselineSummary();

        if (! $summary['exists']) {
            $this->warn('Baseline belum dibuat. Jalankan php artisan security:baseline terlebih dahulu.');

            return self::FAILURE;
        }

        $report = $service->integrityReport();
        $rows = [];

        foreach ($report['modified'] as $path) {
            $rows[] = [$path, 'DIUBAH'];
        }

        foreach ($report['missing'] as $path) {
            $rows[] = [$path, 'HILANG'];
        }

        foreach ($report['added'] as $path) {
            $rows[] = [$path, 'BARU'];
        }

        $this->line('Baseline: '.($summary['created_at'] ?? '-').' ('.($summary['files'] ?? 0).' berkas)');

        if ($rows === []) {
            $this->info('Tidak ada perubahan pada berkas yang dipantau.');

            return self::SUCCESS;
        }

        $this->table(['Berkas', 'Status'], $rows);
        $this->warn('Ada '.count($rows).' berkas yang berbeda dari baseline. Periksa apakah berasal dari deployment resmi.');

        return self::FAILURE;
    }

    protected function prune(ServerSecurityService $service): int
    {
        if (! $service->baselineSummary()['exists']) {
            $this->info('Baseline belum ada, tidak ada yang perlu dihapus.');

            return self::SUCCESS;
        }

        if (! $this->confirm('Hapus baseline integritas berkas?', false)) {
            return self::SUCCESS;
        }

        $service->deleteBaseline();
        $this->info('Baseline dihapus. Pemeriksaan integritas akan berhenti sampai baseline dibuat lagi.');

        return self::SUCCESS;
    }
}
