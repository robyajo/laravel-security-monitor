<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Internal\SecurityMonitor\Services\VersionCheckService;
use Symfony\Component\Process\Process;
use Throwable;

class SecurityUpgradeCommand extends Command
{
    protected $signature = 'security:upgrade
                            {--check : Hanya periksa apakah ada versi baru tanpa menjalankan pembaruan}
                            {--force : Paksa jalankan pembaruan dan sinkronisasi meskipun sudah di versi terbaru}
                            {--no-composer : Lewati pembaruan package via Composer (hanya sinkronkan aset lokal)}
                            {--no-migrate : Lewati eksekusi migrasi database}
                            {--sync-routes : Paksa sinkronkan ulang berkas routes/security.php dan routes/security-api.php}
                            {--sync-views : Paksa sinkronkan ulang berkas tampilan dashboard (Blade / React)}';

    protected $description = 'Periksa dan perbarui package Laravel Security Monitor (Bulwark) ke versi terbaru serta sinkronkan migrasi, rute, dan tampilan dashboard';

    public function handle(VersionCheckService $versionChecker): int
    {
        $this->newLine();
        $this->line('  <bg=blue;fg=white;options=bold> BULWARK SECURITY UPGRADE </>');
        $this->newLine();

        $this->comment('Memeriksa ketersediaan versi terbaru...');

        $current = $versionChecker->getCurrentVersion();
        $latest = $versionChecker->getLatestVersion(true); // segarkan dari sumber rilis

        $this->line("  Versi Terpasang : <options=bold;fg=cyan>v{$current}</>");
        $this->line('  Versi Terbaru   : '.($latest ? "<options=bold;fg=green>v{$latest}</>" : '<comment>Tidak dapat menjangkau repositori rilis (offline/timeout)</comment>'));
        $this->newLine();

        $hasUpdate = $latest && version_compare($latest, $current, '>');

        if ($this->option('check')) {
            if ($hasUpdate) {
                $this->warn("  Tersedia pembaruan: v{$current} → v{$latest}");
                $this->line('  Jalankan <info>php artisan security:upgrade</info> untuk memperbarui.');
            } else {
                $this->info("  ✓ Package sudah berada pada versi terbaru (v{$current}).");
            }

            return 0;
        }

        if (! $hasUpdate && ! $this->option('force')) {
            $this->info("  ✓ Package sudah berada pada versi terbaru (v{$current}).");

            if ($this->input->isInteractive()) {
                if (! $this->confirm('Apakah Anda ingin tetap menyinkronkan aset (migrasi database, rute, dan tampilan)?', false)) {
                    return 0;
                }
            } else {
                return 0;
            }
        }

        $this->info('Memulai proses pembaruan dan sinkronisasi...');
        $this->newLine();

        // 1. Composer Update
        if (! $this->option('no-composer')) {
            $this->comment('1/5. Memperbarui package via Composer...');
            $composer = $this->findComposer();
            $cmd = array_merge($composer, ['update', 'robyajo/laravel-security-monitor', '--with-all-dependencies']);

            if (function_exists('proc_open')) {
                try {
                    $process = new Process($cmd, base_path());
                    $process->setTimeout(300);
                    $process->run(function ($type, $buffer) {
                        $this->output->write($buffer);
                    });

                    if (! $process->isSuccessful()) {
                        $this->warn('  Peringatan: Composer update selesai dengan kode non-nol. Melanjutkan sinkronisasi aset lokal...');
                    } else {
                        $this->info('  ✓ Composer package berhasil diperbarui.');
                    }
                } catch (Throwable $e) {
                    $this->warn('  Gagal menjalankan Composer otomatis: '.$e->getMessage());
                    $this->line('  Silakan jalankan <info>composer update robyajo/laravel-security-monitor</info> secara manual jika diperlukan.');
                }
            } else {
                $this->warn('  Fungsi proc_open dinonaktifkan di server. Silakan jalankan composer update secara manual.');
            }
            $this->newLine();
        } else {
            $this->line('  (1/5. Pembaruan Composer dilewati via --no-composer).');
            $this->newLine();
        }

        // 2. Publish & Run Migrations
        $this->comment('2/5. Menyinkronkan dan menerapkan migrasi database...');
        $this->call('vendor:publish', [
            '--tag' => 'security-migrations',
            '--force' => true,
        ]);
        if (! $this->option('no-migrate')) {
            $this->call('migrate', ['--force' => true]);
        }
        $this->info('  ✓ Berkas migrasi telah disinkronkan dan diterapkan.');
        $this->newLine();

        // 3. Synchronize routes
        $this->comment('3/5. Menyinkronkan berkas rute kustom...');
        $hasWebRoutes = File::exists(base_path('routes/security.php'));
        $hasApiRoutes = File::exists(base_path('routes/security-api.php'));

        if ($hasWebRoutes || $hasApiRoutes || $this->option('sync-routes')) {
            $this->call('vendor:publish', [
                '--tag' => 'security-routes',
                '--force' => true,
            ]);
            $this->info('  ✓ Berkas routes/security.php dan routes/security-api.php telah disinkronkan.');
        } else {
            $this->line('  (Rute internal paket aktif secara otomatis, berkas rute lokal tidak ditemukan).');
        }
        $this->newLine();

        // 4. Synchronize dashboard views
        $this->comment('4/5. Menyinkronkan tampilan dashboard monitoring...');
        $hasBladeViews = File::isDirectory(resource_path('views/pages/security'));
        $hasReactViews = File::isDirectory(resource_path('js/pages/security'));

        if ($hasBladeViews || $this->option('sync-views')) {
            $this->call('vendor:publish', [
                '--tag' => 'security-dashboard-blade-views',
                '--force' => true,
            ]);
            $this->info('  ✓ Tampilan dashboard Blade/Livewire telah disinkronkan.');
        }

        if ($hasReactViews) {
            $this->call('vendor:publish', [
                '--tag' => 'security-dashboard-react-views',
                '--force' => true,
            ]);
            $this->info('  ✓ Tampilan dashboard React/Inertia telah disinkronkan.');
        }

        if (File::exists(resource_path('views/errors/blocked.blade.php'))) {
            $this->call('vendor:publish', [
                '--tag' => 'security-views',
                '--force' => true,
            ]);
            $this->info('  ✓ Halaman error blokir (errors/blocked.blade.php) telah disinkronkan.');
        }
        $this->newLine();

        // 5. Clear Caches & Refresh
        $this->comment('5/5. Membersihkan cache konfigurasi, rute, dan tampilan...');
        try {
            $this->callSilent('optimize:clear');
        } catch (Throwable) {
            // Abaikan jika optimize:clear tidak didukung di environment tertentu
        }
        Cache::forget(VersionCheckService::CACHE_KEY);
        $this->info('  ✓ Cache framework telah disegarkan.');
        $this->newLine();

        $refreshedVersion = $versionChecker->getCurrentVersion();
        $this->info("  🎉 Laravel Security Monitor berhasil diperbarui dan disinkronkan (v{$refreshedVersion})!");
        $this->newLine();

        return 0;
    }

    /**
     * Temukan biner composer yang valid di lingkungan sistem.
     *
     * @return array<int, string>
     */
    protected function findComposer(): array
    {
        if (File::exists(base_path('composer.phar'))) {
            return [PHP_BINARY, base_path('composer.phar')];
        }

        return ['composer'];
    }
}
