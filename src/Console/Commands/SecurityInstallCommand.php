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
                            {--without-user-trait : Jangan tambahkan trait HasSecurityRelations ke model User}
                            {--without-middleware : Jangan daftarkan middleware WAF ke bootstrap/app.php atau Kernel.php}
                            {--with-dashboard : Publikasikan tampilan dashboard monitoring Livewire / Blade Starter Kit}
                            {--with-blade : Publikasikan tampilan dashboard monitoring Livewire / Blade Starter Kit (alias)}
                            {--with-react-dashboard : Publikasikan tampilan dashboard monitoring React / TSX Starter Kit}
                            {--with-tsx : Publikasikan tampilan dashboard monitoring React / TSX Starter Kit (alias)}
                            {--with-both : Publikasikan kedua tampilan dashboard monitoring (Blade & TSX)}
                            {--stack= : Tentukan stack tampilan dashboard (blade, tsx, both, none)}
                            {--with-htaccess : Paksa perbarui berkas public/.htaccess dengan aturan hardening}';

    protected $description = 'Instalasi dan publikasi aset Laravel Security Monitor (konfigurasi, migrasi, Nginx, Apache .htaccess, halaman blokir, tampilan Blade/TSX, trait User, middleware WAF, dan .env)';

    public function handle(): int
    {
        $this->info('Memulai instalasi Laravel Security Monitor (Bulwark)...');
        $this->newLine();

        $force = (bool) $this->option('force');
        $withoutNginx = (bool) $this->option('without-nginx');
        $withoutHtaccess = (bool) $this->option('without-htaccess');
        $withoutViews = (bool) $this->option('without-views');
        $withoutEnv = (bool) $this->option('without-env');
        $withoutUserTrait = (bool) $this->option('without-user-trait');
        $withoutMiddleware = (bool) $this->option('without-middleware');
        $withDashboard = (bool) ($this->option('with-dashboard') || $this->option('with-blade'));
        $withReactDashboard = (bool) ($this->option('with-react-dashboard') || $this->option('with-tsx'));
        $withBoth = (bool) $this->option('with-both');
        $stack = $this->option('stack');

        if ($stack) {
            match (strtolower((string) $stack)) {
                'blade', 'livewire' => $withDashboard = true,
                'react', 'tsx' => $withReactDashboard = true,
                'both', 'all' => $withBoth = true,
                'none' => [$withDashboard, $withReactDashboard, $withBoth] = [false, false, false],
                default => null,
            };
        }

        if ($withBoth) {
            $withDashboard = true;
            $withReactDashboard = true;
        }

        // Jika dijalankan interaktif di terminal (bukan test suite) dan opsi dashboard belum dipilih
        if (! app()->runningUnitTests() && ! $withDashboard && ! $withReactDashboard && ! $withoutViews && $this->input->isInteractive()) {
            $choice = $this->choice(
                'Sediakan tampilan dashboard monitoring di prefix /security (wajib login)?',
                [
                    'blade' => 'Blade (Livewire / Flux UI Starter Kit)',
                    'tsx' => 'TSX (Inertia + React / shadcn Starter Kit)',
                    'both' => 'Keduanya (Blade & TSX)',
                    'none' => 'Lewati (Headless REST API saja)',
                ],
                'blade'
            );

            if ($choice === 'blade') {
                $withDashboard = true;
            } elseif ($choice === 'tsx') {
                $withReactDashboard = true;
            } elseif ($choice === 'both') {
                $withDashboard = true;
                $withReactDashboard = true;
            }
        }

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

        // 6. Publish Blade / Livewire Starter Kit monitoring dashboard
        if ($withDashboard) {
            $this->comment(
                'Mempublikasikan dashboard monitoring Blade (resources/views/pages/security)...',
            );
            $this->call('vendor:publish', [
                '--tag' => 'starterkit-blade',
                '--force' => $force,
            ]);
        }

        // 7. Publish React / TSX Starter Kit monitoring dashboard
        if ($withReactDashboard) {
            $this->comment(
                'Mempublikasikan dashboard monitoring TSX (resources/js/pages/security & components)...',
            );
            $this->call('vendor:publish', [
                '--tag' => 'starterkit-tsx',
                '--force' => $force,
            ]);
        }

        // 8. Auto-inject trait HasSecurityRelations ke model User
        if (! $withoutUserTrait) {
            $this->comment(
                'Menyematkan trait HasSecurityRelations ke model User...',
            );
            $this->injectUserTrait();
        }

        // 9. Auto-register WAF middlewares ke bootstrap/app.php atau app/Http/Kernel.php
        if (! $withoutMiddleware) {
            $this->comment(
                'Mendaftarkan middleware proteksi WAF ke aplikasi host...',
            );
            $this->registerMiddlewareInApp();
        }

        // 10. Append / Update Environment Variables with rich comments to .env & .env.example
        if (! $withoutEnv) {
            $this->comment(
                'Menyematkan variabel konfigurasi dan panduan ke berkas .env...',
            );
            $this->appendEnvironmentVariables($withDashboard, $withReactDashboard);
        }

        $this->newLine();
        $this->info('Instalasi aset berhasil diselesaikan!');
        $this->newLine();

        $this->line(
            '<fg=cyan>Langkah selanjutnya untuk mengaktifkan proteksi & dashboard:</>',
        );
        $this->line('  1. Jalankan migrasi database:');
        $this->line('     <fg=yellow>php artisan migrate</>');
        if (! $withoutUserTrait) {
            $this->line(
                '  2. Model User: Trait <fg=green>HasSecurityRelations</> berhasil disematkan secara otomatis.',
            );
        } else {
            $this->line(
                '  2. Tambahkan trait <fg=yellow>HasSecurityRelations</> ke model User:',
            );
            $this->line(
                "     <fg=gray>use Internal\SecurityMonitor\Concerns\HasSecurityRelations;</>",
            );
        }
        if (! $withoutMiddleware) {
            $this->line(
                '  3. Middleware WAF: <fg=green>BlockIpAddress</> & <fg=green>DetectSecurityThreats</> berhasil didaftarkan otomatis.',
            );
        } else {
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
        }
        $this->line(
            '  4. Sesuaikan nilai variabel <fg=yellow>SECURITY_*</> di berkas <fg=yellow>.env</>',
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
        if ($withDashboard && $withReactDashboard) {
            $this->line(
                '  8. Dashboard Blade & TSX: Siap diakses pada prefix <fg=yellow>/security</> (wajib login pengguna).',
            );
            $this->line(
                '     Ganti driver aktif di .env (<fg=yellow>SECURITY_DASHBOARD_DRIVER=blade</> atau <fg=yellow>react</>).',
            );
        } elseif ($withDashboard) {
            $this->line(
                '  8. Dashboard Blade: Siap diakses pada prefix <fg=yellow>/security</> (wajib login pengguna).',
            );
        } elseif ($withReactDashboard) {
            $this->line(
                '  8. Dashboard TSX: Siap diakses pada prefix <fg=yellow>/security</> (wajib login pengguna).',
            );
            $this->line(
                '     Jalankan <fg=yellow>npm run build</> untuk memproses aset TSX pada Vite.',
            );
        } else {
            $this->line(
                '  8. Dashboard monitoring (opsional): Sediakan kapan saja dengan <fg=yellow>php artisan security:install --with-blade</> atau <fg=yellow>--with-tsx</>.',
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
    protected function appendEnvironmentVariables(bool $withDashboard = false, bool $withReactDashboard = false): void
    {
        $stubPath = __DIR__.'/../../../stubs/env.stub';
        if (! File::exists($stubPath)) {
            $stubPath = dirname(__DIR__, 2).'/stubs/env.stub';
        }

        if (! File::exists($stubPath)) {
            return;
        }

        $stubContent = File::get($stubPath);

        if ($withDashboard || $withReactDashboard) {
            $driver = ($withReactDashboard && ! $withDashboard) ? 'react' : 'livewire';
            $stubContent = str_replace(
                ['SECURITY_DASHBOARD_ENABLED=false', 'SECURITY_DASHBOARD_DRIVER=livewire'],
                ['SECURITY_DASHBOARD_ENABLED=true', "SECURITY_DASHBOARD_DRIVER={$driver}"],
                $stubContent
            );
        }

        $stubContent =
            '

'.
            trim($stubContent).
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
                if ($withDashboard || $withReactDashboard) {
                    $driver = ($withReactDashboard && ! $withDashboard) ? 'react' : 'livewire';
                    $updated = preg_replace(
                        '/SECURITY_DASHBOARD_ENABLED=(false|0)/',
                        'SECURITY_DASHBOARD_ENABLED=true',
                        $currentContent
                    );
                    $updated = preg_replace(
                        '/SECURITY_DASHBOARD_DRIVER=[^\r\n]+/',
                        "SECURITY_DASHBOARD_DRIVER={$driver}",
                        (string) $updated
                    );
                    if ($updated !== null && $updated !== $currentContent) {
                        File::put($targetPath, $updated);
                        $this->info("  ✓ Berkas {$envFile} diperbarui: SECURITY_DASHBOARD_ENABLED=true ({$driver}).");
                    }
                }
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

    /**
     * Sematkan trait HasSecurityRelations ke model User secara otomatis.
     */
    protected function injectUserTrait(): void
    {
        $possiblePaths = [
            app_path('Models/User.php'),
            app_path('User.php'),
        ];

        $userModelClass = config('security.user_model');
        if (is_string($userModelClass) && class_exists($userModelClass)) {
            try {
                $reflector = new \ReflectionClass($userModelClass);
                $filename = $reflector->getFileName();
                if ($filename && File::exists($filename)) {
                    array_unshift($possiblePaths, $filename);
                }
            } catch (\Throwable) {
                // Abaikan jika refleksi gagal
            }
        }

        $userPath = null;
        foreach ($possiblePaths as $path) {
            if ($path && File::exists($path)) {
                $userPath = $path;
                break;
            }
        }

        if (! $userPath) {
            $this->line('  ℹ Model User tidak ditemukan di lokasi standar (app/Models/User.php). Lewati injeksi trait.');

            return;
        }

        $content = File::get($userPath);

        if (str_contains($content, 'HasSecurityRelations')) {
            $this->line('  ✓ Model User sudah memiliki trait HasSecurityRelations.');

            return;
        }

        // 1. Tambahkan import `use Internal\SecurityMonitor\Concerns\HasSecurityRelations;`
        $importStatement = "use Internal\\SecurityMonitor\\Concerns\\HasSecurityRelations;\n";
        if (! str_contains($content, 'use Internal\\SecurityMonitor\\Concerns\\HasSecurityRelations;')) {
            $lastUsePos = strrpos($content, "\nuse ");
            if ($lastUsePos !== false) {
                $endOfLine = strpos($content, "\n", $lastUsePos + 1);
                if ($endOfLine !== false) {
                    $content = substr_replace($content, $importStatement, $endOfLine + 1, 0);
                }
            } elseif (preg_match('/namespace\s+[^;]+;\s*/', $content, $nsMatches, PREG_OFFSET_CAPTURE)) {
                $nsEnd = $nsMatches[0][1] + strlen($nsMatches[0][0]);
                $content = substr_replace($content, "\n".$importStatement, $nsEnd, 0);
            }
        }

        // 2. Tambahkan trait di dalam deklarasi kelas User
        $classPos = strpos($content, 'class User');
        if ($classPos !== false) {
            $classOpenBrace = strpos($content, '{', $classPos);
            if ($classOpenBrace !== false) {
                $afterBrace = substr($content, $classOpenBrace + 1);
                // Cocokkan `use Trait...;` yang berada di baris tersendiri (bukan @use pada PHPDoc)
                if (preg_match('/(?m)^\s*use\s+([^;]+);/', $afterBrace, $useMatches, PREG_OFFSET_CAPTURE)) {
                    $matchOffset = $classOpenBrace + 1 + $useMatches[1][1];
                    $existingTraits = $useMatches[1][0];
                    $replacement = 'HasSecurityRelations, '.trim($existingTraits);
                    $content = substr_replace($content, $replacement, $matchOffset, strlen($existingTraits));
                } else {
                    $content = substr_replace($content, "\n    use HasSecurityRelations;", $classOpenBrace + 1, 0);
                }
            }
        }

        File::put($userPath, (string) $content);
        $this->info("  ✓ Trait HasSecurityRelations berhasil disematkan ke model User ({$userPath}).");
    }

    /**
     * Daftarkan middleware BlockIpAddress dan DetectSecurityThreats ke aplikasi host secara otomatis.
     */
    protected function registerMiddlewareInApp(): void
    {
        $bootstrapAppPath = base_path('bootstrap/app.php');
        $kernelPath = app_path('Http/Kernel.php');

        // Laravel 11 & 12 (bootstrap/app.php)
        if (File::exists($bootstrapAppPath)) {
            $content = File::get($bootstrapAppPath);

            if (
                str_contains($content, 'BlockIpAddress') &&
                str_contains($content, 'DetectSecurityThreats')
            ) {
                $this->line('  ✓ Middleware WAF sudah terdaftar di bootstrap/app.php.');

                return;
            }

            // Pola: ->withMiddleware(function (Middleware $middleware) ... {
            if (preg_match('/->withMiddleware\s*\(\s*function\s*\(\s*(?:Middleware\s+)?\$([a-zA-Z0-9_]+)\s*\)(?:\s*:\s*void)?\s*\{/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
                $varName = $matches[1][0];
                $snippet = "        \${$varName}->append([\n"
                    ."            \\Internal\\SecurityMonitor\\Http\\Middleware\\BlockIpAddress::class,\n"
                    ."            \\Internal\\SecurityMonitor\\Http\\Middleware\\DetectSecurityThreats::class,\n"
                    ."        ]);\n";

                $matchEnd = $matches[0][1] + strlen($matches[0][0]);

                $remaining = substr($content, $matchEnd);
                if (preg_match('/^\s*\/\/\s*\n/', $remaining, $commentMatch)) {
                    $content = substr_replace($content, "\n".$snippet, $matchEnd, strlen($commentMatch[0]));
                } else {
                    $content = substr_replace($content, "\n".$snippet, $matchEnd, 0);
                }

                File::put($bootstrapAppPath, $content);
                $this->info('  ✓ Middleware WAF berhasil didaftarkan di bootstrap/app.php.');

                return;
            }
        }

        // Laravel 10 (app/Http/Kernel.php)
        if (File::exists($kernelPath)) {
            $content = File::get($kernelPath);

            if (
                str_contains($content, 'BlockIpAddress') &&
                str_contains($content, 'DetectSecurityThreats')
            ) {
                $this->line('  ✓ Middleware WAF sudah terdaftar di app/Http/Kernel.php.');

                return;
            }

            $middlewareSnippet = "        \\Internal\\SecurityMonitor\\Http\\Middleware\\BlockIpAddress::class,\n"
                ."        \\Internal\\SecurityMonitor\\Http\\Middleware\\DetectSecurityThreats::class,\n";

            if (preg_match('/protected\s+\$middleware\s*=\s*\[/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
                $pos = $matches[0][1] + strlen($matches[0][0]);
                $content = substr_replace($content, "\n".$middlewareSnippet, $pos, 0);
                File::put($kernelPath, $content);
                $this->info('  ✓ Middleware WAF berhasil didaftarkan di app/Http/Kernel.php.');

                return;
            }
        }

        $this->line('  ℹ Berkas bootstrap/app.php atau Kernel.php tidak dapat diperbarui secara otomatis. Silakan daftarkan middleware secara manual.');
    }
}
