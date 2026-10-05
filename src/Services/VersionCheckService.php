<?php

namespace Internal\SecurityMonitor\Services;

use Composer\InstalledVersions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

class VersionCheckService
{
    /**
     * Cache key untuk menyimpan versi rilis terbaru dari Packagist/GitHub.
     */
    public const CACHE_KEY = 'security_monitor_latest_version';

    /**
     * Endpoint API Packagist v2.
     */
    public const PACKAGIST_URL = 'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json';

    /**
     * Fallback endpoint API GitHub Tags.
     */
    public const GITHUB_TAGS_URL = 'https://api.github.com/repos/robyajo/laravel-security-monitor/tags';

    /**
     * Menandai apakah notifikasi terminal sudah dicetak dalam siklus proses PHP ini.
     */
    protected static bool $hasNotified = false;

    /**
     * Dapatkan versi package yang sedang terpasang di aplikasi.
     */
    public function getCurrentVersion(): string
    {
        try {
            if (class_exists(InstalledVersions::class) && InstalledVersions::isInstalled('robyajo/laravel-security-monitor')) {
                $pretty = (string) InstalledVersions::getPrettyVersion('robyajo/laravel-security-monitor');
                if (! empty($pretty) && ! str_starts_with($pretty, 'dev-')) {
                    return ltrim($pretty, 'v');
                }
            }
        } catch (Throwable) {
            // Lanjutkan ke fallback konstanta
        }

        return ltrim(SecurityMonitorService::VERSION, 'v');
    }

    /**
     * Dapatkan versi rilis stabil terbaru dari Packagist (dengan fallback GitHub tags).
     */
    public function getLatestVersion(bool $forceRefresh = false): ?string
    {
        if (! $forceRefresh) {
            try {
                $cached = Cache::get(self::CACHE_KEY);
                if ($cached !== null && is_string($cached) && $cached !== '') {
                    return $cached;
                }
            } catch (Throwable) {
                // Abaikan jika cache driver sedang tidak siap
            }
        }

        $latest = $this->fetchLatestFromPackagist();

        if (! $latest) {
            $latest = $this->fetchLatestFromGitHub();
        }

        if ($latest) {
            $ttl = (int) config('security.version_check.cache_ttl', 3600);
            try {
                Cache::put(self::CACHE_KEY, $latest, $ttl);
            } catch (Throwable) {
                // Abaikan kesalahan penulisan cache
            }
        }

        return $latest;
    }

    /**
     * Ambil versi terbaru dari endpoint Packagist p2.
     */
    protected function fetchLatestFromPackagist(): ?string
    {
        try {
            $response = Http::timeout(2)
                ->connectTimeout(1)
                ->withHeaders([
                    'User-Agent' => 'laravel-security-monitor/'.$this->getCurrentVersion(),
                    'Accept' => 'application/json',
                ])
                ->get(self::PACKAGIST_URL);

            if (! $response->successful()) {
                return null;
            }

            $packages = $response->json('packages.robyajo/laravel-security-monitor') ?? [];

            foreach ($packages as $pkg) {
                $rawVersion = (string) ($pkg['version'] ?? '');
                $clean = ltrim($rawVersion, 'v');

                // Hanya ambil rilis semver stabil (contoh: 2.0.8, bukan dev-main atau alpha/beta/rc)
                if (preg_match('/^\d+\.\d+\.\d+$/', $clean)) {
                    return $clean;
                }
            }
        } catch (Throwable) {
            // Abaikan kegagalan jaringan
        }

        return null;
    }

    /**
     * Fallback pengambilan versi dari GitHub tags jika Packagist gagal dijangkau.
     */
    protected function fetchLatestFromGitHub(): ?string
    {
        try {
            $response = Http::timeout(2)
                ->connectTimeout(1)
                ->withHeaders([
                    'User-Agent' => 'laravel-security-monitor/'.$this->getCurrentVersion(),
                    'Accept' => 'application/vnd.github.v3+json',
                ])
                ->get(self::GITHUB_TAGS_URL);

            if (! $response->successful()) {
                return null;
            }

            $tags = $response->json() ?? [];

            foreach ($tags as $tag) {
                $name = (string) ($tag['name'] ?? '');
                $clean = ltrim($name, 'v');
                if (preg_match('/^\d+\.\d+\.\d+$/', $clean)) {
                    return $clean;
                }
            }
        } catch (Throwable) {
            // Abaikan kegagalan jaringan
        }

        return null;
    }

    /**
     * Periksa apakah versi rilis terbaru lebih tinggi dari versi yang terpasang.
     */
    public function isUpdateAvailable(bool $forceRefresh = false): bool
    {
        $current = $this->getCurrentVersion();
        $latest = $this->getLatestVersion($forceRefresh);

        if (! $latest) {
            return false;
        }

        return version_compare($latest, $current, '>');
    }

    /**
     * Cetak notifikasi pembaruan ke terminal jika tersedia versi baru.
     */
    public function notifyIfUpdateAvailable(OutputInterface $output): void
    {
        if (static::$hasNotified) {
            return;
        }

        if (! (bool) config('security.version_check.enabled', true)) {
            return;
        }

        if (! $this->isUpdateAvailable()) {
            return;
        }

        static::$hasNotified = true;

        $current = $this->getCurrentVersion();
        $latest = $this->getLatestVersion();

        $output->writeln([
            '',
            '  <bg=blue;fg=white;options=bold> BULWARK SECURITY </> <options=bold;fg=yellow>Pembaruan Tersedia!</> Versi terbaru <options=bold;fg=green>v'.$latest.'</> telah dirilis (versi saat ini: <fg=red>v'.$current.'</>).',
            '  <fg=gray>Jalankan perintah berikut untuk memperbarui package dan menyinkronkan seluruh komponen:</>',
            '  <options=bold;fg=cyan>php artisan security:upgrade</>',
            '',
        ]);
    }

    /**
     * Setel ulang status notifikasi (terutama untuk pengujian).
     */
    public static function resetNotificationState(): void
    {
        static::$hasNotified = false;
    }
}
