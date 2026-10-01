<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class SecurityInstallCommand extends Command
{
    protected $signature = 'security:install
                            {--force : Timpa berkas konfigurasi, migrasi, nginx, htaccess, dan halaman blokir yang sudah ada}
                            {--without-nginx : Jangan publikasikan berkas nginx.conf}
                            {--without-htaccess : Jangan perbarui berkas public/.htaccess}
                            {--without-views : Jangan publikasikan halaman blokir errors/blocked.blade.php}
                            {--without-env : Jangan tambahkan variabel konfigurasi ke berkas .env}
                            {--with-htaccess : Paksa perbarui berkas public/.htaccess dengan aturan hardening}';

    protected $description = 'Instalasi dan publikasi aset Laravel Security Monitor (konfigurasi, migrasi, Nginx, Apache .htaccess, halaman blokir, dan .env)';

    public function handle(): int
    {
        $this->info('Memulai instalasi Laravel Security Monitor (Bulwark)...');
        $this->newLine();

        $force = (bool) $this->option('force');
        $withoutNginx = (bool) $this->option('without-nginx');
        $withoutHtaccess = (bool) $this->option('without-htaccess');
        $withoutViews = (bool) $this->option('without-views');
        $withoutEnv = (bool) $this->option('without-env');

        // 1. Publish Config
        $this->comment('Mempublikasikan berkas konfigurasi...');
        $this->call('vendor:publish', [
            '--tag' => 'security-config',
            '--force' => $force,
        ]);

        // 2. Publish Migrations
        $this->comment('Mempublikasikan berkas migrasi database...');
        $this->call('vendor:publish', [
            '--tag' => 'security-migrations',
            '--force' => $force,
        ]);

        // 3. Publish Nginx Configuration
        if (! $withoutNginx) {
            $this->comment(
                'Mempublikasikan konfigurasi server Nginx (nginx.conf)...',
            );
            $this->call('vendor:publish', [
                '--tag' => 'security-nginx',
                '--force' => $force,
            ]);
        }

        // 4. Publish / Hardening Apache .htaccess
        if (! $withoutHtaccess) {
            $this->comment(
                'Mempublikasikan dan menerapkan aturan hardening Apache (public/.htaccess)...',
            );
            $this->applyHtaccessHardening($force);
        }

        // 5. Publish Default Blocked (403) Page
        if (! $withoutViews) {
            $this->comment(
                'Mempublikasikan halaman blokir default (resources/views/errors/blocked.blade.php)...',
            );
            $this->call('vendor:publish', [
                '--tag' => 'security-views',
                '--force' => $force,
            ]);
        }

        // 6. Append Environment Variables with rich comments to .env & .env.example
        if (! $withoutEnv) {
            $this->comment(
                'Menyematkan variabel konfigurasi dan panduan ke berkas .env...',
            );
            $this->appendEnvironmentVariables();
        }

        $this->newLine();
        $this->info('Instalasi aset berhasil diselesaikan!');
        $this->newLine();

        $this->line(
            '<fg=cyan>Langkah selanjutnya untuk mengaktifkan proteksi:</>',
        );
        $this->line('  1. Jalankan migrasi database:');
        $this->line('     <fg=yellow>php artisan migrate</>');
        $this->line(
            '  2. Tambahkan trait <fg=yellow>HasSecurityRelations</> ke model User:',
        );
        $this->line(
            "     <fg=gray>use Internal\SecurityMonitor\Concerns\HasSecurityRelations;</>",
        );
        $this->line(
            '  3. Daftarkan middleware proteksi WAF di <fg=yellow>bootstrap/app.php</> (Laravel 11+)',
        );
        $this->line(
            '     atau <fg=yellow>app/Http/Kernel.php</> (Laravel 10):',
        );
        $this->line(
            "     <fg=gray>\Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class</>",
        );
        $this->line(
            "     <fg=gray>\Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class</>",
        );
        $this->line(
            '  4. Sesuaikan nilai variabel <fg=yellow>SECURITY_*</> dan <fg=yellow>CAPTCHA_*</> di berkas <fg=yellow>.env</>',
        );
        if (! $withoutNginx) {
            $this->line(
                '  5. Web Server Nginx: Periksa dan sesuaikan <fg=yellow>nginx.conf</> di root proyek.',
            );
        }
        if (! $withoutHtaccess) {
            $this->line(
                '  6. Web Server Apache / cPanel: Berkas <fg=yellow>public/.htaccess</> telah diperkuat',
            );
            $this->line(
                '     terhadap upload webshell, double extension, pembacaan dotfile, dan file backup.',
            );
        }
        if (! $withoutViews) {
            $this->line(
                '  7. Halaman blokir: Sesuaikan <fg=yellow>resources/views/errors/blocked.blade.php</> sesuai branding aplikasi Anda.',
            );
        }

        return self::SUCCESS;
    }

    /**
     * Terapkan aturan hardening pada public/.htaccess.
     */
    protected function applyHtaccessHardening(bool $force): void
    {
        $stubPath = __DIR__.'/../../../stubs/htaccess.stub';
        if (! File::exists($stubPath)) {
            $stubPath = dirname(__DIR__, 2).'/stubs/htaccess.stub';
        }

        if (! File::exists($stubPath)) {
            $this->warn(
                'Berkas stub htaccess tidak ditemukan pada path: '.$stubPath,
            );

            return;
        }

        $stubContent = File::get($stubPath);
        $publicDir = public_path();
        if (! File::isDirectory($publicDir)) {
            File::makeDirectory($publicDir, 0755, true, true);
        }

        $htaccessPath = public_path('.htaccess');

        if (! File::exists($htaccessPath) || $force) {
            // Buat atau timpa dengan stub lengkap
            File::put($htaccessPath, $stubContent);
            $this->info(
                '  ✓ Berkas public/.htaccess berhasil diperbarui dengan aturan hardening lengkap.',
            );

            return;
        }

        $currentContent = File::get($htaccessPath);

        // Cek apakah hardening rules sudah terpasang
        if (
            str_contains($currentContent, 'Hardening keamanan') ||
            str_contains($currentContent, 'Hardening Keamanan') ||
            str_contains($currentContent, 'FilesMatch "^\."') ||
            str_contains($currentContent, 'phtml|pht|phar')
        ) {
            $this->line(
                '  ✓ Berkas public/.htaccess sudah memiliki aturan hardening keamanan.',
            );

            return;
        }

        // Backup htaccess lama
        $backupPath = public_path('.htaccess.backup-'.date('Ymd_His'));
        File::copy($htaccessPath, $backupPath);
        $this->line("  ℹ Cadangan dibuat di: <fg=gray>{$backupPath}</>");

        // Ambil bagian hardening dari stub
        $pos = strpos(
            $stubContent,
            '# ---------------------------------------------------------------------------',
        );
        $hardeningSection =
            $pos !== false
                ? '

'.substr($stubContent, $pos)
                : '

'.$stubContent;
        File::append($htaccessPath, $hardeningSection);

        $this->info(
            '  ✓ Aturan hardening keamanan berhasil ditambahkan ke berkas public/.htaccess.',
        );
    }

    /**
     * Sematkan variabel konfigurasi lingkungan dan penjelasannya ke berkas .env & .env.example.
     */
    protected function appendEnvironmentVariables(): void
    {
        $stubPath = __DIR__.'/../../../stubs/env.stub';
        if (! File::exists($stubPath)) {
            $stubPath = dirname(__DIR__, 2).'/stubs/env.stub';
        }

        if (! File::exists($stubPath)) {
            return;
        }

        $stubContent =
            '

'.
            trim(File::get($stubPath)).
            '
';
        $envTargets = ['.env', '.env.example'];

        foreach ($envTargets as $envFile) {
            $targetPath = base_path($envFile);
            if (! File::exists($targetPath)) {
                continue;
            }

            $currentContent = File::get($targetPath);
            if (str_contains($currentContent, 'SECURITY_MONITOR_ENABLED')) {
                $this->line(
                    "  ✓ Berkas {$envFile} sudah memiliki variabel konfigurasi keamanan.",
                );

                continue;
            }

            File::append($targetPath, $stubContent);
            $this->info(
                "  ✓ Variabel konfigurasi keamanan berhasil ditambahkan ke berkas {$envFile}.",
            );
        }
    }
}
