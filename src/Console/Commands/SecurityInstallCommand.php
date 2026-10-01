<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;

class SecurityInstallCommand extends Command
{
    protected $signature = 'security:install
                            {--force : Timpa berkas konfigurasi, migrasi, dan nginx yang sudah ada}
                            {--without-nginx : Jangan publikasikan berkas nginx.conf}';

    protected $description = 'Instalasi dan publikasi aset Laravel Security Monitor (konfigurasi, migrasi, dan konfigurasi Nginx)';

    public function handle(): int
    {
        $this->info('Memulai instalasi Laravel Security Monitor (Bulwark)...');
        $this->newLine();

        $force = (bool) $this->option('force');
        $withoutNginx = (bool) $this->option('without-nginx');

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
            $this->comment('Mempublikasikan konfigurasi server Nginx (nginx.conf)...');
            $this->call('vendor:publish', [
                '--tag' => 'security-nginx',
                '--force' => $force,
            ]);
        }

        $this->newLine();
        $this->info('Instalasi aset berhasil diselesaikan!');
        $this->newLine();

        $this->line('<fg=cyan>Langkah selanjutnya untuk mengaktifkan proteksi:</>');
        $this->line('  1. Jalankan migrasi database:');
        $this->line('     <fg=yellow>php artisan migrate</>');
        $this->line('  2. Tambahkan trait <fg=yellow>HasSecurityRelations</> ke model User:');
        $this->line('     <fg=gray>use Internal\SecurityMonitor\Concerns\HasSecurityRelations;</>');
        $this->line('  3. Daftarkan middleware proteksi WAF di <fg=yellow>bootstrap/app.php</> (Laravel 11+)');
        $this->line('     atau <fg=yellow>app/Http/Kernel.php</> (Laravel 10):');
        $this->line('     <fg=gray>\Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class</>');
        $this->line('     <fg=gray>\Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class</>');
        if (! $withoutNginx) {
            $this->line('  4. Periksa dan sesuaikan berkas <fg=yellow>nginx.conf</> di root proyek Anda');
            $this->line('     untuk konfigurasi virtual host web server Nginx produksi.');
        }

        return self::SUCCESS;
    }
}
