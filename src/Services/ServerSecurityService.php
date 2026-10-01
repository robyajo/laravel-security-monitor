<?php

namespace Internal\SecurityMonitor\Services;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\LoginAttempt;
use Internal\SecurityMonitor\Models\SecurityLog;
use Laravel\Fortify\Features;
use Throwable;

/**
 * Pemeriksaan keamanan sisi server ("server security scan") yang ditampilkan di
 * /security/server.
 *
 * Tujuan: memberi admin satu halaman untuk melihat konfigurasi aplikasi/server
 * yang berisiko (debug mode, kredensial default, folder publik yang writable),
 * sisa berkas serangan (webshell di folder unggahan), serta perubahan berkas
 * penting dibandingkan baseline hash.
 *
 * Semua pemeriksaan bersifat gagal-aman: satu pemeriksaan yang error tidak
 * boleh menggagalkan pemeriksaan lain maupun halamannya.
 */
class ServerSecurityService
{
    public const CACHE_KEY = 'security:server-scan';

    /** Kunci cache daftar berkas mencurigakan. */
    public const SUSPICIOUS_CACHE_KEY = 'security:suspicious-files';

    /** Lokasi baseline hash (relatif terhadap storage_path()). */
    public const BASELINE_PATH = 'app/security/baseline.json';

    /** Kunci cache heartbeat scheduler (diisi oleh routes/console.php). */
    public const HEARTBEAT_KEY = 'security:schedule-heartbeat';

    /** Ekstensi yang tidak boleh berada di folder publik. */
    protected const DANGEROUS_EXTENSIONS = [
        'php',
        'php3',
        'php4',
        'php5',
        'php7',
        'php8',
        'phtml',
        'pht',
        'phar',
        'phps',
        'cgi',
        'pl',
        'py',
        'rb',
        'sh',
        'bash',
        'asp',
        'aspx',
        'jsp',
        'jspx',
        'exe',
        'dll',
        'bat',
        'cmd',
        'scr',
    ];

    /** Pola konten mencurigakan untuk mendeteksi webshell/backdoor tersembunyi. */
    protected const MALICIOUS_PATTERNS = [
        'eval_base64' => [
            'pattern' => "/eval\s*\(\s*base64_decode\s*\(/i",
            'label' => 'Eksekusi kode terenkode (eval base64_decode)',
        ],
        'eval_gz' => [
            'pattern' => "/eval\s*\(\s*gzinflate\s*\(/i",
            'label' => 'Eksekusi kode terkompresi (eval gzinflate)',
        ],
        'eval_rot13' => [
            'pattern' => "/eval\s*\(\s*str_rot13\s*\(/i",
            'label' => 'Eksekusi kode rot13 (eval str_rot13)',
        ],
        'eval_request' => [
            'pattern' => '/eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b/i',
            'label' => 'Eksekusi kode dinamis dari input pengguna',
        ],
        'assert_request' => [
            'pattern' => '/assert\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\b/i',
            'label' => 'Assertion dinamis dari input pengguna',
        ],
        'system_request' => [
            'pattern' => '/(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\b/i',
            'label' => 'Eksekusi perintah shell langsung dari input pengguna',
        ],
        'preg_replace_e' => [
            'pattern' => '/preg_replace\s*\(\s*[\'"][^\'"]*\/e[\'"]\s*,/i',
            'label' => 'Penggunaan regex berbahaya (preg_replace /e)',
        ],
        'known_webshell' => [
            'pattern' => "/\b(c99shell|r57shell|WSO_VERSION|FilesMan|ALFA\s*TEaM|b374k|IndoXploit|weevely|China\s*Chopper)\b/i",
            'label' => 'Signature webshell populer terdeteksi',
        ],
    ];

    /** Ekstensi media yang tidak boleh memuat skrip atau kode PHP tersembunyi. */
    protected const MEDIA_EXTENSIONS = [
        'jpg',
        'jpeg',
        'png',
        'gif',
        'svg',
        'webp',
        'bmp',
        'ico',
        'pdf',
        'txt',
    ];

    /** Direktori yang dipantau untuk perubahan berkas mencurigakan. */
    protected const WATCHED_DIRECTORIES = [
        'app',
        'bootstrap',
        'config',
        'database',
        'public',
        'routes',
    ];

    /** Direktori yang dilewati saat menelusuri berkas. */
    protected const SKIPPED_DIRECTORIES = [
        'vendor',
        'node_modules',
        '.git',
        'storage',
        'build',
        'cache',
    ];

    /** Ukuran maksimum berkas yang di-hash pada baseline (5 MB). */
    protected const MAX_HASH_BYTES = 5_242_880;

    /** Berkas bawaan yang selalu dikecualikan dari pemindaian berkas mencurigakan / webshell. */
    protected const DEFAULT_SUSPICIOUS_EXCLUDES = [
        'config/security.php',
        'config/captcha.php',
        'app/Services/ServerSecurityService.php',
        'app/Services/SecurityMonitorService.php',
        'app/Http/Middleware/DetectSecurityThreats.php',
        'app/Console/Commands/SecurityBaselineCommand.php',
        'app/Console/Commands/PurgeInjectedData.php',
        'app/Console/Commands/SecurityScanAccessLogs.php',
        'routes/console.php',
        'public/index.php',
        'public/robots.txt',
    ];

    public function __construct(
        protected SecurityMonitorService $security,
        protected LoginThrottleService $throttle,
    ) {}

    /*
    |--------------------------------------------------------------------------
    | Scan
    |--------------------------------------------------------------------------
    */

    /**
     * Jalankan (atau ambil dari cache) seluruh pemeriksaan.
     *
     * @return array<string, mixed>
     */
    public function scan(bool $force = false): array
    {
        $minutes = max(
            1,
            (int) config('security.server_scan.cache_minutes', 10),
        );

        if (! $force) {
            $cached = $this->cachedScan();

            if ($cached !== null) {
                return $cached;
            }
        }

        $started = microtime(true);

        $checks = array_merge(
            $this->safe(fn (): array => $this->applicationChecks(), 'aplikasi'),
            $this->safe(fn (): array => $this->databaseChecks(), 'database'),
            $this->safe(fn (): array => $this->filesystemChecks(), 'berkas'),
            $this->safe(fn (): array => $this->accountChecks(), 'akun'),
            $this->safe(fn (): array => $this->integrityChecks(), 'integritas'),
            $this->safe(fn (): array => $this->monitoringChecks(), 'pemantauan'),
        );

        $result = [
            'generated_at' => now()->toIso8601String(),
            'duration_ms' => (int) round((microtime(true) - $started) * 1000),
            'cached' => false,
            'cache_minutes' => $minutes,
            'summary' => $this->summarize($checks),
            'categories' => $this->group($checks),
        ];

        try {
            Cache::put(self::CACHE_KEY, $result, now()->addMinutes($minutes));
        } catch (Throwable) {
            // Cache yang bermasalah tidak boleh menggagalkan halaman.
        }

        return $result;
    }

    /**
     * Lupakan hasil scan yang tersimpan sehingga halaman memuat data baru.
     */
    public function forget(): void
    {
        try {
            Cache::forget(self::CACHE_KEY);
            Cache::forget(self::SUSPICIOUS_CACHE_KEY);
        } catch (Throwable) {
            // diabaikan
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function cachedScan(): ?array
    {
        try {
            $cached = Cache::get(self::CACHE_KEY);
        } catch (Throwable) {
            return null;
        }

        if (
            ! is_array($cached) ||
            ! isset($cached['summary'], $cached['categories'])
        ) {
            return null;
        }

        return [...$cached, 'cached' => true];
    }

    /**
     * Jalankan satu kelompok pemeriksaan; kegagalan tidak menghentikan scan.
     *
     * @param  callable(): array<int, array<string, mixed>>  $callback
     * @return array<int, array<string, mixed>>
     */
    protected function safe(callable $callback, string $group): array
    {
        try {
            return $callback();
        } catch (Throwable $exception) {
            return [
                [
                    'id' => 'scan_failed_'.$group,
                    'category' => 'Lain-lain',
                    'category_id' => 'other',
                    'label' => 'Pemeriksaan kelompok "'.
                        $group.
                        '" gagal dijalankan',
                    'status' => 'warning',
                    'value' => null,
                    'detail' => $exception->getMessage(),
                    'recommendation' => 'Periksa log aplikasi (storage/logs) untuk mengetahui penyebabnya.',
                ],
            ];
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: aplikasi
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function applicationChecks(): array
    {
        $environment = (string) config('app.env', 'production');
        $production = $environment === 'production';
        $debug = (bool) config('app.debug', false);
        $appUrl = (string) config('app.url', '');
        $https = str_starts_with($appUrl, 'https://');

        $checks = [];

        $checks[] = $this->check(
            'app_environment',
            'Aplikasi',
            'app',
            'Lingkungan aplikasi (APP_ENV)',
            'info',
            $environment,
            'Nilai APP_ENV menentukan perilaku framework, termasuk penanganan error.',
        );

        $checks[] = $this->check(
            'app_debug',
            'Aplikasi',
            'app',
            'Mode debug (APP_DEBUG)',
            $debug ? ($production ? 'critical' : 'info') : 'ok',
            $debug ? 'aktif' : 'nonaktif',
            $debug
                ? 'Mode debug menampilkan stack trace, jalur berkas, dan potongan konfigurasi (termasuk kredensial) kepada pengunjung.'
                : 'Mode debug tidak aktif sehingga detail error tidak tampil ke pengunjung.',
            $debug && $production
                ? 'Setel APP_DEBUG=false pada .env produksi, lalu jalankan php artisan config:clear.'
                : null,
        );

        $key = (string) config('app.key', '');
        $checks[] = $this->check(
            'app_key',
            'Aplikasi',
            'app',
            'APP_KEY terisi',
            $key === '' ? 'critical' : 'ok',
            $key === '' ? 'kosong' : 'terisi ('.strlen($key).' karakter)',
            $key === ''
                ? 'Tanpa APP_KEY, cookie, session, dan data terenkripsi tidak aman (dapat dipalsukan atau gagal dibuka).'
                : 'APP_KEY tersedia sehingga cookie/session dapat dienkripsi dengan benar.',
            $key === '' ? 'Jalankan php artisan key:generate.' : null,
        );

        $checks[] = $this->check(
            'app_url_https',
            'Aplikasi',
            'app',
            'HTTPS pada APP_URL',
            $production && ! $https ? 'warning' : 'ok',
            $appUrl !== '' ? $appUrl : '(kosong)',
            $production && ! $https
                ? 'Aplikasi produksi sebaiknya hanya diakses melalui HTTPS agar kredensial dan token tidak dikirim dalam bentuk polos.'
                : 'APP_URL tidak menunjukkan penggunaan HTTP polos pada produksi.',
            $production && ! $https
                ? 'Setel APP_URL=https://... dan paksa redirect HTTP ke HTTPS di nginx/Apache.'
                : null,
        );

        $sessionSecure = (bool) config('session.secure', false);
        $checks[] = $this->check(
            'session_secure_cookie',
            'Aplikasi',
            'app',
            'Cookie session hanya lewat HTTPS',
            $https && ! $sessionSecure ? 'warning' : 'ok',
            $sessionSecure ? 'aktif' : 'nonaktif',
            $https && ! $sessionSecure
                ? 'Cookie session masih boleh dikirim melalui HTTP sehingga rentan dicuri pada jaringan yang tidak aman.'
                : 'Pengaturan cookie session sesuai dengan skema URL aplikasi.',
            $https && ! $sessionSecure
                ? 'Setel SESSION_SECURE_COOKIE=true pada .env.'
                : null,
        );

        $encrypted = (bool) config('session.encrypt', false);
        $checks[] = $this->check(
            'session_encrypt',
            'Aplikasi',
            'app',
            'Isi cookie session dienkripsi',
            $production && ! $encrypted ? 'warning' : 'ok',
            $encrypted ? 'aktif' : 'nonaktif',
            $production && ! $encrypted
                ? 'Tanpa enkripsi, isi cookie session dapat dibaca (walau tetap ditandatangani) bila ada kebocoran.'
                : 'Isi cookie session dienkripsi.',
            $production && ! $encrypted
                ? 'Setel SESSION_ENCRYPT=true pada .env (pengguna akan diminta login ulang).'
                : null,
        );

        $twoFactor = $this->featureEnabled('two-factor-authentication');
        $checks[] = $this->check(
            'two_factor',
            'Aplikasi',
            'app',
            'Autentikasi dua faktor (2FA) tersedia',
            $twoFactor ? 'ok' : 'warning',
            $twoFactor ? 'aktif' : 'nonaktif',
            $twoFactor
                ? 'Akun dapat dilindungi dengan aplikasi authenticator.'
                : 'Tanpa 2FA, satu password yang bocor sudah cukup untuk menguasai panel admin (seperti pada insiden marker "wne").',
            $twoFactor
                ? null
                : 'Aktifkan Features::twoFactorAuthentication() di config/fortify.php.',
        );

        $registration = $this->featureEnabled('registration');
        $checks[] = $this->check(
            'registration',
            'Aplikasi',
            'app',
            'Pendaftaran akun publik',
            $registration ? 'warning' : 'ok',
            $registration ? 'terbuka' : 'tertutup',
            $registration
                ? 'Halaman pendaftaran terbuka untuk umum sehingga siapa pun dapat membuat akun.'
                : 'Pendaftaran akun publik tidak dibuka.',
            $registration
                ? 'Nonaktifkan fitur registration pada config/fortify.php bila akun hanya dibuat oleh admin.'
                : null,
        );

        $captchaEnabled =
            (bool) config('captcha.enabled', true) &&
            (bool) config('captcha.for.login', true);
        $checks[] = $this->check(
            'captcha_login',
            'Aplikasi',
            'app',
            'Captcha pada form login',
            $captchaEnabled ? 'ok' : 'warning',
            $captchaEnabled ? 'aktif' : 'nonaktif',
            $captchaEnabled
                ? 'Percobaan login otomatis (credential stuffing) tertahan sebelum memverifikasi password.'
                : 'Tanpa captcha, bot dapat mencoba ribuan kombinasi password tanpa hambatan tambahan.',
            $captchaEnabled
                ? null
                : 'Setel CAPTCHA_ENABLED=true dan CAPTCHA_ON_LOGIN=true.',
        );

        // Dibaca sama seperti CheckPublicApiHeader agar hasil pemeriksaan konsisten.
        $apiKey = (string) env('PUBLIC_API_KEY', 'pekanbaru-2026');
        $defaultKey = in_array($apiKey, ['', 'pekanbaru-2026'], true);
        $checks[] = $this->check(
            'public_api_key',
            'Aplikasi',
            'app',
            'Kunci API publik (X-public)',
            $defaultKey ? 'warning' : 'ok',
            $apiKey === '' ? '(kosong)' : $apiKey,
            $defaultKey
                ? 'Kunci API masih kosong atau memakai nilai contoh yang tertulis di dokumentasi sehingga mudah ditebak.'
                : 'Kunci API sudah diganti dari nilai contoh.',
            $defaultKey
                ? 'Ganti PUBLIC_API_KEY pada .env dengan nilai acak yang panjang.'
                : null,
        );

        $enforced = $this->apiHeaderMiddlewareInstalled();
        $checks[] = $this->check(
            'api_header_enforced',
            'Aplikasi',
            'app',
            'Header X-public diwajibkan pada API publik',
            $enforced ? 'ok' : 'warning',
            $enforced ? 'aktif' : 'belum dipasang',
            $enforced
                ? 'Endpoint api/* menolak request tanpa header X-public.'
                : 'Endpoint api/master/* dan api/v2/* masih dapat dipanggil tanpa header X-public (terbuka untuk umum).',
            $enforced
                ? null
                : "Pasang App\Http\Middleware\CheckPublicApiHeader pada grup middleware api di routes/api.php.",
        );

        // Dibaca sama seperti bootstrap/app.php (trustProxies).
        $proxies = (string) env('TRUSTED_PROXIES', '');
        $checks[] = $this->check(
            'trusted_proxies',
            'Aplikasi',
            'app',
            'Daftar reverse proxy terpercaya',
            $proxies === '' ? 'warning' : 'ok',
            $proxies === '' ? '(kosong)' : $proxies,
            $proxies === ''
                ? 'Tanpa TRUSTED_PROXIES, IP klien dibaca dari koneksi langsung. Di belakang nginx/load balancer semua request tampak berasal dari IP proxy sehingga blokir IP tidak efektif.'
                : 'Header X-Forwarded-* hanya dipercaya dari proxy yang terdaftar.',
            $proxies === ''
                ? 'Isi TRUSTED_PROXIES dengan IP proxy (mis. 10.0.0.1) bila aplikasi berada di belakang nginx/load balancer.'
                : null,
        );

        $monitor = $this->security->enabled();
        $checks[] = $this->check(
            'security_monitor',
            'Aplikasi',
            'app',
            'Pemantauan keamanan (SECURITY_MONITOR_ENABLED)',
            $monitor ? 'ok' : 'critical',
            $monitor ? 'aktif' : 'nonaktif',
            $monitor
                ? 'Deteksi ancaman, pencatatan log, dan pemblokiran IP berjalan.'
                : 'Pemantauan dimatikan sehingga serangan tidak terdeteksi maupun tercatat.',
            $monitor ? null : 'Setel SECURITY_MONITOR_ENABLED=true pada .env.',
        );

        $checks[] = $this->check(
            'security_enforcement',
            'Aplikasi',
            'app',
            'Penegakan blokir IP (SECURITY_BLOCK_ENFORCEMENT)',
            $this->security->enforcementEnabled() ? 'ok' : 'warning',
            $this->security->enforcementEnabled() ? 'aktif' : 'nonaktif',
            $this->security->enforcementEnabled()
                ? 'Request dari IP yang diblokir ditolak dengan HTTP 403.'
                : 'IP terblokir masih dapat mengakses aplikasi; hanya tercatat di log.',
            $this->security->enforcementEnabled()
                ? null
                : 'Setel SECURITY_BLOCK_ENFORCEMENT=true pada .env.',
        );

        $instant = (bool) config('security.instant_block.enabled', true);
        $checks[] = $this->check(
            'instant_block',
            'Aplikasi',
            'app',
            'Blokir instan (zero tolerance)',
            $instant ? 'ok' : 'warning',
            $instant ? 'aktif' : 'nonaktif',
            $instant
                ? 'Pola serangan berbahaya (webshell, path traversal, SSTI, scanner) memblokir IP pada percobaan pertama.'
                : 'Pola serangan berbahaya hanya dicatat, tidak langsung memblokir IP.',
            $instant
                ? null
                : 'Setel SECURITY_INSTANT_BLOCK_ENABLED=true pada .env.',
        );

        $whitelist = array_filter((array) config('security.whitelist', []));
        $checks[] = $this->check(
            'whitelist',
            'Aplikasi',
            'app',
            'Daftar putih IP (whitelist)',
            $whitelist === [] ? 'warning' : 'ok',
            $whitelist === [] ? '(kosong)' : implode(', ', $whitelist),
            $whitelist === []
                ? 'Tanpa whitelist, admin yang salah memicu deteksi dapat ikut terblokir (harus dibuka lewat CLI).'
                : 'IP pada daftar putih tidak pernah diblokir otomatis.',
            $whitelist === []
                ? 'Tambahkan IP kantor/internal ke SECURITY_IP_WHITELIST.'
                : null,
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: database & antrian
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function databaseChecks(): array
    {
        $checks = [];
        $connection = (string) config('database.default', 'mysql');
        $driver = (string) config(
            "database.connections.{$connection}.driver",
            $connection,
        );
        $database = (string) config(
            "database.connections.{$connection}.database",
            '',
        );
        $username = (string) config(
            "database.connections.{$connection}.username",
            '',
        );

        try {
            DB::connection($connection)->getPdo();
            $reachable = true;
        } catch (Throwable $exception) {
            $reachable = false;
        }

        $checks[] = $this->check(
            'db_connection',
            'Database & Antrian',
            'database',
            'Koneksi database',
            $reachable ? 'ok' : 'critical',
            $reachable
                ? $driver.' / '.($database !== '' ? $database : '(default)')
                : 'gagal terhubung',
            $reachable
                ? 'Koneksi database dapat dibuka oleh aplikasi.'
                : 'Aplikasi tidak dapat terhubung ke database sehingga data keamanan tidak dapat dibaca/ditulis.',
            $reachable
                ? null
                : 'Periksa DB_HOST, DB_DATABASE, DB_USERNAME, dan DB_PASSWORD pada .env.',
        );

        $weakUser = in_array(
            strtolower($username),
            ['root', 'postgres', 'sa', 'admin'],
            true,
        );
        $checks[] = $this->check(
            'db_privileges',
            'Database & Antrian',
            'database',
            'Hak akses user database',
            $weakUser ? 'warning' : 'ok',
            $username !== '' ? $username : '(kosong)',
            $weakUser
                ? 'Aplikasi memakai akun superuser database. Bila kredensial bocor (mis. lewat .env), seluruh server database dapat dikuasai.'
                : 'Aplikasi tidak memakai akun superuser database.',
            $weakUser
                ? 'Buat user MySQL khusus aplikasi dengan hak terbatas pada satu database.'
                : null,
        );

        $pending = $this->pendingMigrations();
        $checks[] = $this->check(
            'pending_migrations',
            'Database & Antrian',
            'database',
            'Migrasi database',
            $pending === [] ? 'ok' : 'warning',
            $pending === []
                ? 'semua migrasi dijalankan'
                : count($pending).' belum dijalankan',
            $pending === []
                ? 'Struktur tabel sesuai berkas migrasi.'
                : 'Ada migrasi belum dijalankan: '.
                    implode(', ', array_slice($pending, 0, 5)).
                    (count($pending) > 5 ? ', ...' : ''),
            $pending === [] ? null : 'Jalankan php artisan migrate.',
        );

        $queue = (string) config('queue.default', 'sync');
        $checks[] = $this->check(
            'queue_driver',
            'Database & Antrian',
            'database',
            'Driver antrian',
            $queue === 'sync' ? 'warning' : 'ok',
            $queue,
            $queue === 'sync'
                ? 'Driver "sync" menjalankan pekerjaan di dalam request sehingga pekerjaan berat (prune log, notifikasi) memperlambat respons pengguna.'
                : 'Pekerjaan berat yang dikirim ke antrian diproses di luar request pengguna.',
            $queue === 'sync'
                ? 'Setel QUEUE_CONNECTION=database dan jalankan php artisan queue:work.'
                : null,
        );

        $failedJobs = $this->countTable('failed_jobs');
        $checks[] = $this->check(
            'failed_jobs',
            'Database & Antrian',
            'database',
            'Pekerjaan antrian yang gagal',
            $failedJobs > 0 ? 'warning' : 'ok',
            $failedJobs === null
                ? 'tabel tidak tersedia'
                : (string) $failedJobs,
            $failedJobs > 0
                ? 'Ada pekerjaan antrian yang gagal; bila berulang dapat menandakan masalah konfigurasi atau data.'
                : 'Tidak ada pekerjaan antrian yang gagal.',
            $failedJobs > 0
                ? 'Periksa dengan php artisan queue:failed, lalu hapus setelah diperbaiki.'
                : null,
        );

        $cache = (string) config('cache.default', 'database');
        $checks[] = $this->check(
            'cache_driver',
            'Database & Antrian',
            'database',
            'Driver cache',
            $cache === 'array' ? 'warning' : 'ok',
            $cache,
            $cache === 'array'
                ? 'Cache "array" hanya hidup selama satu request sehingga pembatas login, anti-flood log, dan heartbeat scheduler tidak berfungsi lintas request.'
                : 'Cache bersifat persisten sehingga pembatas login dan anti-flood berfungsi benar.',
            $cache === 'array'
                ? 'Setel CACHE_STORE=database (atau redis).'
                : null,
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: berkas & penyimpanan
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function filesystemChecks(): array
    {
        $checks = [];

        $paths = [
            'storage/app' => storage_path('app'),
            'storage/framework' => storage_path('framework'),
            'storage/logs' => storage_path('logs'),
            'bootstrap/cache' => base_path('bootstrap/cache'),
        ];

        $notWritable = [];

        foreach ($paths as $label => $path) {
            if (! File::isDirectory($path) || ! is_writable($path)) {
                $notWritable[] = $label;
            }
        }

        $checks[] = $this->check(
            'storage_permissions',
            'Berkas & Penyimpanan',
            'files',
            'Folder yang harus dapat ditulis aplikasi',
            $notWritable === [] ? 'ok' : 'warning',
            $notWritable === []
                ? 'semua dapat ditulis'
                : 'tidak dapat ditulis: '.implode(', ', $notWritable),
            $notWritable === []
                ? 'Folder runtime dapat ditulis oleh user web server.'
                : 'Folder runtime yang tidak dapat ditulis menyebabkan aplikasi gagal menyimpan log, session, atau cache.',
            $notWritable === []
                ? null
                : 'Perbaiki kepemilikan folder (mis. chown -R www-data:www-data storage bootstrap/cache).',
        );

        $publicWritable = is_writable(public_path());
        $checks[] = $this->check(
            'public_writable',
            'Berkas & Penyimpanan',
            'files',
            'Folder public dapat ditulis web server',
            $publicWritable ? 'warning' : 'ok',
            $publicWritable ? 'dapat ditulis' : 'tidak dapat ditulis',
            $publicWritable
                ? 'Bila web server dapat menulis ke folder public, berkas yang berhasil diunggah lewat celah apa pun dapat langsung diakses sebagai URL (penyebab insiden wne.php).'
                : 'Folder public tidak dapat ditulis oleh user web server sehingga webshell tidak dapat ditaruh di webroot.',
            $publicWritable
                ? 'Setel kepemilikan folder public ke user deploy (bukan www-data) dengan izin 755.'
                : null,
        );

        $envPermissions = $this->envFilePermissions();
        $checks[] = $this->check(
            'env_permissions',
            'Berkas & Penyimpanan',
            'files',
            'Izin berkas .env',
            $envPermissions['status'],
            $envPermissions['value'],
            $envPermissions['detail'],
            $envPermissions['recommendation'],
        );

        $envInPublic = File::exists(public_path('.env'));
        $checks[] = $this->check(
            'env_in_public',
            'Berkas & Penyimpanan',
            'files',
            'Salinan .env di folder public',
            $envInPublic ? 'critical' : 'ok',
            $envInPublic ? 'ditemukan' : 'tidak ada',
            $envInPublic
                ? 'Berkas .env yang berada di folder public dapat diunduh langsung dan membocorkan kredensial database serta APP_KEY.'
                : 'Tidak ada berkas .env yang bocor ke folder publik.',
            $envInPublic
                ? 'Hapus public/.env dan pastikan dotfile ditolak oleh web server.'
                : null,
        );

        $publicScan = $this->scanDangerousFiles(public_path(), ['build']);
        $checks[] = $this->check(
            'public_backdoor_scan',
            'Berkas & Penyimpanan',
            'files',
            'Berkas berbahaya di folder public',
            $publicScan['files'] === [] ? 'ok' : 'critical',
            $publicScan['files'] === []
                ? $publicScan['count'].' berkas diperiksa'
                : count($publicScan['files']).' berkas mencurigakan',
            $publicScan['files'] === []
                ? 'Tidak ditemukan berkas dengan ekstensi dapat dieksekusi (selain index.php) di folder public.'
                : 'Ditemukan berkas yang dapat dieksekusi/diunduh di folder publik: '.
                    implode(', ', array_slice($publicScan['files'], 0, 8)),
            $publicScan['files'] === []
                ? null
                : 'Periksa berkas tersebut, hapus bila bukan bagian aplikasi, dan ganti kredensial yang mungkin bocor.',
        );

        $uploadPath = storage_path('app/public');
        $uploadScan = $this->scanDangerousFiles($uploadPath, []);
        $checks[] = $this->check(
            'upload_backdoor_scan',
            'Berkas & Penyimpanan',
            'files',
            'Berkas berbahaya di folder unggahan',
            $uploadScan['files'] === [] ? 'ok' : 'critical',
            $uploadScan['files'] === []
                ? $uploadScan['count'].' berkas diperiksa'
                : count($uploadScan['files']).' berkas mencurigakan',
            $uploadScan['files'] === []
                ? 'Folder unggahan publik hanya berisi berkas non-eksekusi.'
                : 'Ada berkas berekstensi skrip di folder unggahan: '.
                    implode(', ', array_slice($uploadScan['files'], 0, 8)),
            $uploadScan['files'] === []
                ? null
                : 'Jalankan php artisan security:purge-injected-data --model=... lalu hapus berkas tersebut secara manual.',
        );

        $htaccess = [
            'public/.htaccess' => public_path('.htaccess'),
            'storage/app/public/.htaccess' => $uploadPath.DIRECTORY_SEPARATOR.'.htaccess',
        ];

        $missing = [];

        foreach ($htaccess as $label => $path) {
            if (! File::exists($path)) {
                $missing[] = $label;
            }
        }

        $checks[] = $this->check(
            'htaccess_defense',
            'Berkas & Penyimpanan',
            'files',
            'Aturan .htaccess pertahanan berlapis',
            $missing === [] ? 'ok' : 'warning',
            $missing === []
                ? 'terpasang'
                : 'belum ada: '.implode(', ', $missing),
            $missing === []
                ? 'Penolakan dotfile, double extension, dan eksekusi PHP di folder unggahan sudah terpasang untuk Apache.'
                : 'Tanpa .htaccess ini, server berbasis Apache dapat mengeksekusi berkas yang diunggah ke folder publik.',
            $missing === []
                ? null
                : 'Salin aturan hardening dari DOCS/security-monitor.md ke berkas tersebut.',
        );

        $storageLink = public_path('storage');
        $checks[] = $this->check(
            'storage_link',
            'Berkas & Penyimpanan',
            'files',
            'Tautan public/storage',
            'info',
            is_link($storageLink)
                ? 'symlink'
                : (File::exists($storageLink)
                    ? 'folder biasa'
                    : 'belum dibuat'),
            is_link($storageLink)
                ? 'Folder unggahan diakses melalui symlink sehingga tetap berada di luar webroot aslinya.'
                : 'Tanpa symlink php artisan storage:link, berkas unggahan disalin ke dalam folder public.',
            File::exists($storageLink)
                ? null
                : 'Jalankan php artisan storage:link.',
        );

        $disk = $this->diskUsage();
        $checks[] = $this->check(
            'disk_space',
            'Berkas & Penyimpanan',
            'files',
            'Ruang penyimpanan server',
            $disk['status'],
            $disk['value'],
            $disk['detail'],
            $disk['recommendation'],
        );

        $logSize = $this->directorySize(storage_path('logs'));
        $warningMb = max(
            1,
            (int) config('security.server_scan.log_size_warning_mb', 100),
        );
        $logMb = $logSize / 1_048_576;
        $checks[] = $this->check(
            'log_size',
            'Berkas & Penyimpanan',
            'files',
            'Ukuran berkas log aplikasi',
            $logMb >= $warningMb ? 'warning' : 'ok',
            number_format($logMb, $logMb >= 10 ? 0 : 1, ',', '.').' MB',
            $logMb >= $warningMb
                ? 'Berkas log tumbuh besar. Selain memenuhi disk, log yang menumpuk dapat memperlambat proses debugging dan menyulitkan pencarian insiden.'
                : 'Ukuran log masih wajar.',
            $logMb >= $warningMb
                ? 'Kosongkan log lama (mis. truncate storage/logs/laravel.log) atau naikkan rotasi log.'
                : null,
        );

        $accessLogs = $this->accessLogFiles();
        $checks[] = $this->check(
            'access_log_readable',
            'Berkas & Penyimpanan',
            'files',
            'Access log web server dapat dibaca',
            $accessLogs === [] ? 'warning' : 'ok',
            $accessLogs === []
                ? 'tidak ditemukan'
                : count($accessLogs).' berkas',
            $accessLogs === []
                ? 'Serangan yang ditolak web server sebelum sampai ke PHP (mis. berkas .php yang di-return 403, probe .env, scanning massal) hanya tercatat di access log, sehingga tidak akan pernah muncul di Log Keamanan.'
                : 'Tersedia: '.implode(', ', array_slice($accessLogs, 0, 3)),
            $accessLogs === []
                ? 'Setel SECURITY_ACCESS_LOG_PATHS ke lokasi access log (mis. /var/log/nginx/access.log) dan pastikan user aplikasi boleh membacanya.'
                : 'Jalankan php artisan security:scan-logs untuk menganalisis berkas tersebut.',
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: akun & akses
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function accountChecks(): array
    {
        $checks = [];

        $maxAdmins = max(
            1,
            (int) config('security.server_scan.max_admin_accounts', 5),
        );
        $admins = $this->adminQuery()->get([
            'id',
            'name',
            'email',
            'two_factor_confirmed_at',
        ]);
        $adminCount = $admins->count();

        $checks[] = $this->check(
            'admin_accounts',
            'Akun & Akses',
            'accounts',
            'Jumlah akun administrator',
            $adminCount === 0
                ? 'critical'
                : ($adminCount > $maxAdmins
                    ? 'warning'
                    : 'ok'),
            (string) $adminCount.' akun',
            match (true) {
                $adminCount === 0 => 'Tidak ada akun ber-role admin sehingga panel keamanan tidak dapat diakses siapa pun.',
                $adminCount > $maxAdmins => 'Jumlah akun admin melebihi batas wajar ('.
                    $maxAdmins.
                    '). Semakin banyak akun istimewa, semakin luas permukaan serangan.',
                default => 'Jumlah akun administrator masih dalam batas wajar.',
            },
            match (true) {
                $adminCount === 0 => 'Setel kolom role = admin pada minimal satu akun (lihat DOCS/security-monitor.md > Menjadikan user sebagai admin).',
                $adminCount > $maxAdmins => 'Kurangi hak akses akun yang tidak lagi membutuhkan panel admin.',
                default => null,
            },
        );

        $withoutTwoFactor = $admins->filter(
            fn ($user): bool => $user->two_factor_confirmed_at === null,
        );
        $checks[] = $this->check(
            'admin_two_factor',
            'Akun & Akses',
            'accounts',
            '2FA pada akun administrator',
            $withoutTwoFactor->isEmpty() ? 'ok' : 'warning',
            $withoutTwoFactor->isEmpty()
                ? 'seluruh admin memakai 2FA'
                : $withoutTwoFactor->count().
                    ' dari '.
                    $adminCount.
                    ' admin belum 2FA',
            $withoutTwoFactor->isEmpty()
                ? 'Semua akun admin dilindungi faktor kedua.'
                : 'Akun admin tanpa 2FA dapat dikuasai hanya dengan menebak/mencuri password: '.
                    implode(
                        ', ',
                        $withoutTwoFactor->take(5)->pluck('email')->all(),
                    ),
            $withoutTwoFactor->isEmpty()
                ? null
                : 'Minta setiap admin mengaktifkan 2FA melalui halaman Pengaturan > Keamanan.',
        );

        $lockouts = $this->lockoutCount();
        $checks[] = $this->check(
            'active_lockouts',
            'Akun & Akses',
            'accounts',
            'Akun terkunci sementara (cooldown login)',
            $lockouts > 0 ? 'warning' : 'ok',
            (string) $lockouts.' akun',
            $lockouts > 0
                ? 'Ada akun yang terkunci karena percobaan login gagal berulang; periksa apakah ini serangan brute force atau pengguna lupa password.'
                : 'Tidak ada akun yang sedang terkunci.',
            $lockouts > 0
                ? 'Tinjau daftar di bawah halaman ini; buka blokir bila pengguna sah.'
                : null,
        );

        $blocked = BlockedIp::query()->active()->count();
        $checks[] = $this->check(
            'blocked_ips',
            'Akun & Akses',
            'accounts',
            'IP yang sedang diblokir',
            'info',
            (string) $blocked.' IP',
            $blocked > 0
                ? 'Ada IP yang diblokir karena aktivitas mencurigakan. Tinjau daftarnya di halaman IP Diblokir.'
                : 'Saat ini tidak ada IP yang diblokir.',
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: integritas berkas
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function integrityChecks(): array
    {
        $checks = [];
        $baseline = $this->baseline();

        $checks[] = $this->check(
            'integrity_baseline',
            'Integritas Berkas',
            'integrity',
            'Baseline hash berkas penting',
            $baseline === null ? 'warning' : 'ok',
            $baseline === null
                ? 'belum dibuat'
                : 'dibuat '.$this->humanDate($baseline['created_at'] ?? null),
            $baseline === null
                ? 'Tanpa baseline, perubahan berkas penting (mis. backdoor pada index.php atau middleware) tidak dapat dibedakan dari perubahan resmi.'
                : 'Baseline berisi '.
                    count((array) ($baseline['files'] ?? [])).
                    ' berkas yang dipantau.',
            $baseline === null
                ? 'Klik "Buat Baseline" pada halaman ini (atau jalankan php artisan security:baseline).'
                : null,
        );

        $report = $this->integrityReport();

        if ($baseline !== null) {
            $changed = array_merge($report['modified'], $report['missing']);
            $status = match (true) {
                $report['missing'] !== [] => 'critical',
                $report['modified'] !== [] => 'warning',
                $report['added'] !== [] => 'warning',
                default => 'ok',
            };

            $checks[] = $this->check(
                'integrity_changes',
                'Integritas Berkas',
                'integrity',
                'Perubahan berkas sejak baseline',
                $status,
                $changed === [] && $report['added'] === []
                    ? 'tidak ada perubahan'
                    : count($report['modified']).
                        ' diubah, '.
                        count($report['missing']).
                        ' hilang, '.
                        count($report['added']).
                        ' baru',
                match (true) {
                    $report['missing'] !== [] => 'Berkas yang dipantau hilang: '.
                        implode(', ', array_slice($report['missing'], 0, 5)),
                    $report['modified'] !== [] => 'Berkas yang dipantau berubah: '.
                        implode(', ', array_slice($report['modified'], 0, 5)),
                    $report['added'] !== [] => 'Berkas baru pada lokasi terpantau: '.
                        implode(', ', array_slice($report['added'], 0, 5)),
                    default => 'Tidak ada perbedaan hash antara berkas saat ini dan baseline.',
                },
                $status === 'ok'
                    ? null
                    : 'Bila perubahan tersebut bukan berasal dari deployment resmi, pulihkan berkas dari repositori dan buat ulang baseline.',
            );
        }

        $recent = $this->recentChanges();
        $days = max(
            1,
            (int) config('security.server_scan.recent_changes_days', 7),
        );
        $checks[] = $this->check(
            'recent_changes',
            'Integritas Berkas',
            'integrity',
            'Berkas aplikasi yang baru berubah',
            $recent['count'] === 0 ? 'ok' : 'info',
            (string) $recent['count'].' berkas dalam '.$days.' hari',
            $recent['count'] === 0
                ? 'Tidak ada berkas aplikasi yang berubah dalam periode pemantauan.'
                : 'Berkas terbaru: '.
                    implode(', ', array_slice($recent['files'], 0, 6)),
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Kelompok pemeriksaan: pemantauan & log
    |--------------------------------------------------------------------------
    */

    /**
     * @return array<int, array<string, mixed>>
     */
    protected function monitoringChecks(): array
    {
        $checks = [];

        $heartbeat = $this->heartbeat();
        $checks[] = $this->check(
            'scheduler_heartbeat',
            'Pemantauan & Log',
            'monitoring',
            'Penjadwal Laravel (scheduler)',
            $heartbeat['status'],
            $heartbeat['value'],
            $heartbeat['detail'],
            $heartbeat['recommendation'],
        );

        $errors = $this->recentApplicationErrors();
        $checks[] = $this->check(
            'app_errors',
            'Pemantauan & Log',
            'monitoring',
            'Error aplikasi dalam 24 jam terakhir',
            $errors['count'] === 0 ? 'ok' : 'warning',
            (string) $errors['count'].' baris error',
            $errors['count'] === 0
                ? 'Tidak ada baris ERROR baru pada berkas log aplikasi.'
                : 'Ada error tercatat pada log aplikasi; error yang tampak ke pengunjung dapat membocorkan informasi. Contoh: '.
                    $errors['sample'],
            $errors['count'] === 0
                ? null
                : 'Periksa storage/logs/laravel.log dan pastikan APP_DEBUG=false pada produksi.',
        );

        $sevenDays = $this->securityLogStats();
        $checks[] = $this->check(
            'security_activity',
            'Pemantauan & Log',
            'monitoring',
            'Aktivitas keamanan 7 hari terakhir',
            'info',
            (string) $sevenDays['total'].
                ' kejadian ('.
                $sevenDays['critical'].
                ' kritis)',
            $sevenDays['total'] === 0
                ? 'Belum ada kejadian keamanan tercatat. Ini normal bila tidak ada percobaan serangan.'
                : 'Tercatat '.
                    $sevenDays['total'].
                    ' kejadian, terbanyak: '.
                    ($sevenDays['top_event'] ?? '-').
                    '. Log lengkap tersedia di halaman Log Keamanan.',
        );

        $retention = (int) config('security.log_retention_days', 90);
        $checks[] = $this->check(
            'log_retention',
            'Pemantauan & Log',
            'monitoring',
            'Masa simpan log keamanan',
            $retention === 0 ? 'warning' : 'ok',
            $retention === 0 ? 'selamanya' : $retention.' hari',
            $retention === 0
                ? 'Log disimpan tanpa batas sehingga tabel dapat tumbuh besar dan memperlambat query.'
                : 'Log lama dihapus otomatis oleh security:prune-logs setiap pukul 02:30.',
            $retention === 0
                ? 'Setel SECURITY_LOG_RETENTION_DAYS (mis. 90) pada .env.'
                : null,
        );

        return $checks;
    }

    /*
    |--------------------------------------------------------------------------
    | Baseline integritas
    |--------------------------------------------------------------------------
    */

    /**
     * Baca baseline dari disk.
     *
     * @return array<string, mixed>|null
     */
    public function baseline(): ?array
    {
        $path = $this->baselinePath();

        if (! File::exists($path)) {
            return null;
        }

        try {
            $decoded = json_decode((string) File::get($path), true);
        } catch (Throwable) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }

    public function baselinePath(): string
    {
        return storage_path(self::BASELINE_PATH);
    }

    /**
     * Hash seluruh berkas yang dipantau dan simpan sebagai baseline baru.
     *
     * @return array<string, mixed>
     */
    public function createBaseline(?int $userId = null): array
    {
        $files = [];

        foreach ($this->watchedFiles() as $relative) {
            $absolute = base_path($relative);

            try {
                if (
                    ! File::isFile($absolute) ||
                    File::size($absolute) > self::MAX_HASH_BYTES
                ) {
                    continue;
                }

                $hash = hash_file('sha256', $absolute);

                if ($hash === false) {
                    continue;
                }

                $files[$relative] = [
                    'hash' => $hash,
                    'size' => File::size($absolute),
                    'modified_at' => Carbon::createFromTimestamp(
                        (int) File::lastModified($absolute),
                    )->toIso8601String(),
                ];
            } catch (Throwable) {
                continue;
            }
        }

        $baseline = [
            'created_at' => now()->toIso8601String(),
            'created_by' => $userId,
            'app_env' => (string) config('app.env', 'production'),
            'php_version' => PHP_VERSION,
            'files' => $files,
        ];

        File::ensureDirectoryExists(dirname($this->baselinePath()));
        File::put(
            $this->baselinePath(),
            json_encode(
                $baseline,
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
            ) ?:
            '{}',
        );

        $this->forget();

        return $baseline;
    }

    public function deleteBaseline(): bool
    {
        $this->forget();

        return File::exists($this->baselinePath()) &&
            File::delete($this->baselinePath());
    }

    /**
     * Bandingkan berkas saat ini dengan baseline.
     *
     * @return array{modified: array<int, string>, missing: array<int, string>, added: array<int, string>}
     */
    public function integrityReport(): array
    {
        $baseline = $this->baseline();
        $known = is_array($baseline['files'] ?? null) ? $baseline['files'] : [];

        $modified = [];
        $missing = [];

        foreach ($known as $relative => $meta) {
            $relative = (string) $relative;
            $absolute = base_path($relative);

            if (! File::isFile($absolute)) {
                $missing[] = $relative;

                continue;
            }

            try {
                if (File::size($absolute) > self::MAX_HASH_BYTES) {
                    continue;
                }

                $hash = hash_file('sha256', $absolute);
            } catch (Throwable) {
                continue;
            }

            if ($hash === false) {
                continue;
            }

            if ($hash !== (string) ($meta['hash'] ?? '')) {
                $modified[] = $relative;
            }
        }

        $added = array_values(
            array_diff(
                $this->watchedFiles(),
                array_map('strval', array_keys($known)),
            ),
        );

        return [
            'modified' => $modified,
            'missing' => $missing,
            'added' => $added,
        ];
    }

    /**
     * Daftar berkas yang dipantau (relatif terhadap base_path), tanpa duplikat.
     *
     * @return array<int, string>
     */
    public function watchedFiles(): array
    {
        $patterns = (array) config('security.server_scan.integrity_paths', []);
        $files = [];

        foreach ($patterns as $pattern) {
            $pattern = str_replace('\\', '/', trim((string) $pattern));

            if ($pattern === '') {
                continue;
            }

            foreach (glob(base_path($pattern)) ?: [] as $path) {
                if (! File::isFile($path)) {
                    continue;
                }

                $files[] = str_replace(
                    '\\',
                    '/',
                    str_replace(base_path().DIRECTORY_SEPARATOR, '', $path),
                );
            }
        }

        $files = array_values(array_unique($files));
        sort($files);

        return $files;
    }

    /**
     * Ringkasan baseline untuk ditampilkan di halaman.
     *
     * @return array<string, mixed>
     */
    public function baselineSummary(): array
    {
        $baseline = $this->baseline();

        if ($baseline === null) {
            return [
                'exists' => false,
                'created_at' => null,
                'created_by' => null,
                'files' => 0,
                'watched' => count($this->watchedFiles()),
            ];
        }

        return [
            'exists' => true,
            'created_at' => $baseline['created_at'] ?? null,
            'created_by' => $baseline['created_by'] ?? null,
            'files' => count((array) ($baseline['files'] ?? [])),
            'watched' => count($this->watchedFiles()),
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | Info pendukung untuk halaman
    |--------------------------------------------------------------------------
    */

    /**
     * Daftar akun yang sedang terkunci (cooldown login).
     *
     * @return array<int, array<string, mixed>>
     */
    public function activeLockouts(): array
    {
        try {
            return $this->throttle
                ->activeLockouts()
                ->map(
                    fn (LoginAttempt $attempt): array => [
                        'id' => $attempt->id,
                        'email' => $attempt->email,
                        'ip_address' => $attempt->ip_address,
                        'attempts' => $attempt->attempts,
                        'lockout_level' => $attempt->lockout_level,
                        'locked_until' => optional(
                            $attempt->locked_until,
                        )->toIso8601String(),
                        'remaining' => $attempt->secondsRemaining(),
                        'last_attempt_at' => optional(
                            $attempt->last_attempt_at,
                        )->toIso8601String(),
                    ],
                )
                ->all();
        } catch (Throwable) {
            return [];
        }
    }

    /**
     * Buka paksa blokir (cooldown) sebuah akun.
     */
    public function releaseLockout(LoginAttempt $attempt): int
    {
        $deleted = $this->throttle->release(
            (string) $attempt->email,
            $attempt->ip_address,
        );
        $this->forget();

        return $deleted;
    }

    /**
     * Informasi lingkungan server (versi PHP, database, cache, dsb).
     *
     * @return array<string, string>
     */
    public function environmentInfo(): array
    {
        $info = [
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
            'app_env' => (string) config('app.env', 'production'),
            'debug_mode' => (bool) config('app.debug', false)
                ? 'aktif'
                : 'nonaktif',
            'database' => (string) config('database.default', 'mysql'),
            'cache' => (string) config('cache.default', 'database'),
            'queue' => (string) config('queue.default', 'sync'),
            'session' => (string) config('session.driver', 'database'),
            'timezone' => (string) config('app.timezone', 'UTC'),
            'server_time' => now()->toIso8601String(),
            'os' => PHP_OS_FAMILY.' '.php_uname('r'),
        ];

        if (function_exists('opcache_get_status')) {
            $status = @opcache_get_status(false);
            $info['opcache'] =
                is_array($status) && ($status['opcache_enabled'] ?? false)
                    ? 'aktif'
                    : 'nonaktif';
        }

        return $info;
    }

    /**
     * Pindai dan temukan berkas-berkas mencurigakan di folder publik, folder
     * unggahan, dan direktori aplikasi (webshell, backdoor, ekstensi terlarang, dsb).
     *
     * @return array<int, array<string, mixed>>
     */
    public function suspiciousFiles(bool $force = false): array
    {
        if (! $force) {
            try {
                $cached = Cache::get(self::SUSPICIOUS_CACHE_KEY);

                if (is_array($cached)) {
                    return $cached;
                }
            } catch (Throwable) {
                // Lewati cache bila bermasalah
            }
        }

        $items = [];
        $scannedPaths = [];

        // 1. Pindai folder public
        $this->collectSuspiciousInDirectory(
            public_path(),
            'public',
            'Folder Publik (public/)',
            ['build', 'vendor', 'node_modules', '.git', 'storage'],
            $items,
            $scannedPaths,
        );

        // 2. Pindai folder unggahan
        $uploadPath = storage_path('app/public');
        if (File::isDirectory($uploadPath)) {
            $this->collectSuspiciousInDirectory(
                $uploadPath,
                'storage_public',
                'Folder Unggahan (storage/app/public/)',
                [],
                $items,
                $scannedPaths,
            );
        }

        // 3. Periksa berkas baru/diubah pada baseline integritas yang memuat pola webshell
        $this->collectSuspiciousFromIntegrity($items, $scannedPaths);

        // Urutkan: ancaman critical di atas, lalu berdasarkan waktu modifikasi terbaru
        usort($items, function (array $a, array $b): int {
            $threatRank = [
                'critical' => 3,
                'high' => 2,
                'warning' => 1,
                'info' => 0,
            ];
            $rankA = $threatRank[$a['threat_level'] ?? 'info'] ?? 0;
            $rankB = $threatRank[$b['threat_level'] ?? 'info'] ?? 0;

            if ($rankA !== $rankB) {
                return $rankB <=> $rankA;
            }

            return strcmp(
                (string) ($b['modified_at'] ?? ''),
                (string) ($a['modified_at'] ?? ''),
            );
        });

        // Batasi maksimal 100 temuan untuk performa antarmuka
        $result = array_slice($items, 0, 100);

        try {
            $minutes = max(
                1,
                (int) config('security.server_scan.cache_minutes', 10),
            );
            Cache::put(
                self::SUSPICIOUS_CACHE_KEY,
                $result,
                now()->addMinutes($minutes),
            );
        } catch (Throwable) {
            // diabaikan
        }

        return $result;
    }

    /**
     * Hapus berkas mencurigakan dari disk secara aman dengan audit log.
     *
     * @return array{success: bool, message: string}
     */
    public function deleteSuspiciousFile(
        string $relativePath,
        ?int $userId = null,
        ?string $ip = null,
    ): array {
        $relative = str_replace(['\\', "\0"], ['/', ''], trim($relativePath));
        $relative = ltrim($relative, '/');

        if (
            $relative === '' ||
            str_contains($relative, '..') ||
            preg_match('/^[a-zA-Z]:/', $relative)
        ) {
            return [
                'success' => false,
                'message' => 'Jalur berkas tidak valid atau memuat path traversal.',
            ];
        }

        $absolute = base_path($relative);
        $real = realpath($absolute);

        if ($real === false || ! File::isFile($real)) {
            return [
                'success' => false,
                'message' => 'Berkas tidak ditemukan pada server.',
            ];
        }

        $normalizedReal = str_replace('\\', '/', $real);
        $normalizedBase = str_replace('\\', '/', base_path());

        if (! str_starts_with($normalizedReal, $normalizedBase)) {
            return [
                'success' => false,
                'message' => 'Jalur berkas berada di luar direktori aplikasi.',
            ];
        }

        $relativeToApp = ltrim(
            substr($normalizedReal, strlen($normalizedBase)),
            '/',
        );

        if (! $this->isDeletablePath($relativeToApp)) {
            return [
                'success' => false,
                'message' => 'Berkas sistem inti dilindungi dan tidak dapat dihapus melalui fitur ini demi stabilitas aplikasi.',
            ];
        }

        $size = (int) File::size($real);
        $hash = hash_file('sha256', $real) ?: 'unknown';
        $filename = basename($real);

        $deleted = File::delete($real);

        if (! $deleted) {
            return [
                'success' => false,
                'message' => 'Gagal menghapus berkas dari disk. Periksa izin akses (permission) berkas di server.',
            ];
        }

        $this->security->log([
            'ip_address' => $ip ?? '127.0.0.1',
            'user_id' => $userId,
            'event_type' => 'suspicious_file_deleted',
            'threat_level' => 'high',
            'method' => 'DELETE',
            'path' => '/security/server/suspicious-files',
            'rule_label' => 'Berkas mencurigakan dihapus oleh admin',
            'evidence' => "Admin menghapus berkas '{$relativeToApp}' (SHA-256: {$hash}, Ukuran: {$this->humanBytes(
                (float) $size,
            )}).",
            'action_taken' => 'file_deleted',
        ]);

        $this->forget();

        return [
            'success' => true,
            'message' => "Berkas mencurigakan '{$filename}' berhasil dihapus dari server.",
        ];
    }

    /**
     * Memeriksa apakah suatu berkas dikecualikan dari pemindaian berkas mencurigakan / webshell.
     */
    public function isExcludedFromSuspiciousScan(string $relative): bool
    {
        $normalized = str_replace('\\', '/', trim($relative));
        $normalized = ltrim($normalized, '/');

        $configured = (array) config(
            'security.server_scan.suspicious_files_exclude',
            [],
        );
        $patterns = array_merge(self::DEFAULT_SUSPICIOUS_EXCLUDES, $configured);

        foreach ($patterns as $pattern) {
            $pattern = str_replace('\\', '/', trim((string) $pattern));
            $pattern = ltrim($pattern, '/');

            if ($pattern === '') {
                continue;
            }

            if (
                $normalized === $pattern ||
                fnmatch($pattern, $normalized) ||
                Str::is($pattern, $normalized)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Menentukan apakah suatu berkas aman untuk dihapus oleh admin lewat aksi tombol.
     */
    public function isDeletablePath(string $relative): bool
    {
        $relative = str_replace(['\\', "\0"], ['/', ''], trim($relative));
        $relative = ltrim($relative, '/');

        if ($this->isExcludedFromSuspiciousScan($relative)) {
            return false;
        }

        $protectedFiles = [
            'public/index.php',
            'public/.htaccess',
            'public/robots.txt',
            '.env',
            '.env.example',
            'artisan',
            'composer.json',
            'composer.lock',
            'package.json',
            'package-lock.json',
            'vite.config.js',
            'bootstrap/app.php',
            'bootstrap/providers.php',
            'routes/web.php',
            'routes/api.php',
            'routes/console.php',
            'config/security.php',
            'config/captcha.php',
            'app/Providers/AppServiceProvider.php',
        ];

        if (in_array($relative, $protectedFiles, true)) {
            return false;
        }

        if (
            str_starts_with($relative, 'vendor/') ||
            str_starts_with($relative, 'node_modules/') ||
            str_starts_with($relative, '.git/') ||
            str_starts_with($relative, 'config/') ||
            str_starts_with($relative, 'bootstrap/') ||
            str_starts_with($relative, 'routes/') ||
            str_starts_with($relative, 'database/')
        ) {
            return false;
        }

        return true;
    }

    /**
     * Menelusuri direktori untuk mencari berkas berbahaya atau terindikasi disisipi webshell.
     *
     * @param  array<int, string>  $skipDirectories
     * @param  array<int, array<string, mixed>>  $items
     * @param  array<string, bool>  $scannedPaths
     */
    protected function collectSuspiciousInDirectory(
        string $root,
        string $locationKey,
        string $locationLabel,
        array $skipDirectories,
        array &$items,
        array &$scannedPaths,
    ): void {
        if (! File::isDirectory($root)) {
            return;
        }

        $limit = max(
            500,
            (int) config('security.server_scan.max_files_scanned', 20000),
        );
        $count = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveCallbackFilterIterator(
                    new \RecursiveDirectoryIterator(
                        $root,
                        \FilesystemIterator::SKIP_DOTS |
                            \FilesystemIterator::CURRENT_AS_FILEINFO,
                    ),
                    function (\SplFileInfo $file) use ($skipDirectories): bool {
                        if (! $file->isDir()) {
                            return true;
                        }

                        $name = $file->getFilename();

                        return ! in_array($name, $skipDirectories, true) &&
                            ! in_array($name, self::SKIPPED_DIRECTORIES, true);
                    },
                ),
                \RecursiveIteratorIterator::SELF_FIRST,
            );

            foreach ($iterator as $file) {
                if (! $file instanceof \SplFileInfo || ! $file->isFile()) {
                    continue;
                }

                if (++$count > $limit) {
                    break;
                }

                $pathname = $file->getPathname();
                $normalizedPath = str_replace('\\', '/', $pathname);

                if (isset($scannedPaths[$normalizedPath])) {
                    continue;
                }
                $scannedPaths[$normalizedPath] = true;

                $baseNormalized = str_replace('\\', '/', base_path());
                $relative = ltrim(
                    str_replace($baseNormalized.'/', '', $normalizedPath),
                    '/',
                );

                $filename = $file->getFilename();
                $extension = strtolower($file->getExtension());
                $mtime = (int) $file->getMTime();
                $size = (int) $file->getSize();

                // Pengecualian resmi berkas sistem & keamanan
                if ($this->isExcludedFromSuspiciousScan($relative)) {
                    continue;
                }

                // Cek 1: Ekstensi berbahaya di webroot atau folder unggahan
                $isDangerousExt = in_array(
                    $extension,
                    self::DANGEROUS_EXTENSIONS,
                    true,
                );

                // Cek 2: File dotfile berbahaya (.env di public, atau file tersembunyi berakhiran skrip)
                $isDotScript =
                    str_starts_with($filename, '.') &&
                    ($isDangerousExt || str_starts_with($filename, '.env'));

                // Cek 3: Double extension (misal: image.php.jpg atau doc.phtml.png)
                $hasDoubleExt =
                    preg_match(
                        '/\.(?:php[0-9]?|phtml|phar|sh|cgi|asp|jsp)\.[a-z0-9]+$/i',
                        $filename,
                    ) === 1 ||
                    preg_match(
                        '/\.[a-z0-9]+\.(?:php[0-9]?|phtml|phar|sh|cgi|asp|jsp)$/i',
                        $filename,
                    ) === 1;

                // Cek 4: Konten mencurigakan (webshell patterns & tag PHP pada media)
                $contentCheck = $this->inspectFileContent(
                    $pathname,
                    $filename,
                    $extension,
                    $size,
                );

                $threatLevel = null;
                $category = null;
                $reason = null;
                $snippet = null;

                if ($contentCheck['is_suspicious']) {
                    $threatLevel = 'critical';
                    $category = $contentCheck['category'];
                    $reason = $contentCheck['reason'];
                    $snippet = $contentCheck['snippet'];
                } elseif ($hasDoubleExt) {
                    $threatLevel = 'critical';
                    $category = 'Ekstensi Ganda (Disamarkan)';
                    $reason = "Nama berkas memuat pola ekstensi ganda ({$filename}) yang umum digunakan untuk mengelabui filter unggahan.";
                } elseif ($isDotScript) {
                    $threatLevel = 'critical';
                    $category = 'Berkas Tersembunyi Berbahaya';
                    $reason =
                        'Berkas tersembunyi (dotfile) berekstensi skrip atau berkas konfigurasi sensitif (.env) di lokasi publik.';
                } elseif ($isDangerousExt) {
                    $threatLevel = 'critical';
                    $category = 'Ekstensi Skrip Terlarang';
                    $reason =
                        $locationKey === 'storage_public'
                            ? "Berkas berekstensi eksekusi (.{$extension}) ditemukan di folder unggahan pengguna. Berkas ini berpotensi berupa webshell backdoor."
                            : "Berkas berekstensi eksekusi (.{$extension}) ditemukan di folder public (webroot).";
                }

                if ($threatLevel !== null) {
                    $items[] = [
                        'id' => md5($relative),
                        'path' => $relative,
                        'filename' => $filename,
                        'location' => $locationLabel,
                        'location_key' => $locationKey,
                        'threat_level' => $threatLevel,
                        'category' => $category ?? 'Berkas Mencurigakan',
                        'reason' => $reason ??
                            'Berkas terdeteksi tidak wajar pada pemeriksaan keamanan server.',
                        'snippet' => $snippet,
                        'size' => $this->humanBytes((float) $size),
                        'size_bytes' => $size,
                        'modified_at' => Carbon::createFromTimestamp(
                            $mtime,
                        )->toIso8601String(),
                        'modified_at_human' => $this->humanDate(
                            Carbon::createFromTimestamp(
                                $mtime,
                            )->toIso8601String(),
                        ),
                        'is_deletable' => $this->isDeletablePath($relative),
                    ];
                }
            }
        } catch (Throwable) {
            // Penelusuran selesai atau dibatasi
        }
    }

    /**
     * Memeriksa berkas yang baru atau dimodifikasi dari baseline apakah memuat pola berbahaya.
     *
     * @param  array<int, array<string, mixed>>  $items
     * @param  array<string, bool>  $scannedPaths
     */
    protected function collectSuspiciousFromIntegrity(
        array &$items,
        array &$scannedPaths,
    ): void {
        $report = $this->integrityReport();
        $candidates = array_merge($report['modified'], $report['added']);

        foreach ($candidates as $relative) {
            if ($this->isExcludedFromSuspiciousScan($relative)) {
                continue;
            }

            $absolute = base_path($relative);
            $normalizedPath = str_replace('\\', '/', $absolute);

            if (isset($scannedPaths[$normalizedPath])) {
                continue;
            }
            $scannedPaths[$normalizedPath] = true;

            if (! File::isFile($absolute)) {
                continue;
            }

            $size = (int) File::size($absolute);
            $filename = basename($absolute);
            $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            $contentCheck = $this->inspectFileContent(
                $absolute,
                $filename,
                $extension,
                $size,
            );

            if ($contentCheck['is_suspicious']) {
                $mtime = (int) File::lastModified($absolute);

                $items[] = [
                    'id' => md5($relative),
                    'path' => $relative,
                    'filename' => $filename,
                    'location' => 'Direktori Aplikasi ('.dirname($relative).')',
                    'location_key' => 'app_core',
                    'threat_level' => 'critical',
                    'category' => $contentCheck['category'] ?? 'Injeksi Kode Aplikasi',
                    'reason' => "Berkas integritas baru/termodifikasi mengandung pola berbahaya: {$contentCheck['reason']}",
                    'snippet' => $contentCheck['snippet'],
                    'size' => $this->humanBytes((float) $size),
                    'size_bytes' => $size,
                    'modified_at' => Carbon::createFromTimestamp(
                        $mtime,
                    )->toIso8601String(),
                    'modified_at_human' => $this->humanDate(
                        Carbon::createFromTimestamp($mtime)->toIso8601String(),
                    ),
                    'is_deletable' => $this->isDeletablePath($relative),
                ];
            }
        }
    }

    /**
     * Inspeksi konten berkas untuk mencari signature webshell atau injeksi tag PHP.
     *
     * @return array{is_suspicious: bool, category: string|null, reason: string|null, snippet: string|null}
     */
    protected function inspectFileContent(
        string $pathname,
        string $filename,
        string $extension,
        int $size,
    ): array {
        if ($size <= 0 || $size > 2_097_152) {
            return [
                'is_suspicious' => false,
                'category' => null,
                'reason' => null,
                'snippet' => null,
            ];
        }

        $isMedia = in_array($extension, self::MEDIA_EXTENSIONS, true);
        $isScript = in_array(
            $extension,
            array_merge(self::DANGEROUS_EXTENSIONS, [
                'txt',
                'html',
                'htm',
                'inc',
                'bak',
                'old',
            ]),
            true,
        );

        if (! $isMedia && ! $isScript) {
            return [
                'is_suspicious' => false,
                'category' => null,
                'reason' => null,
                'snippet' => null,
            ];
        }

        try {
            $content = (string) @file_get_contents(
                $pathname,
                false,
                null,
                0,
                524_288,
            );
        } catch (Throwable) {
            return [
                'is_suspicious' => false,
                'category' => null,
                'reason' => null,
                'snippet' => null,
            ];
        }

        if ($content === '') {
            return [
                'is_suspicious' => false,
                'category' => null,
                'reason' => null,
                'snippet' => null,
            ];
        }

        if (
            $isMedia &&
            preg_match(
                '/<\?php[\s\r\n\t;\$\/]|<\?=\s*[\$a-zA-Z_0-9\'"\(]/i',
                $content,
                $m,
                PREG_OFFSET_CAPTURE,
            )
        ) {
            $offset = (int) ($m[0][1] ?? 0);
            $rawSnippet = substr($content, max(0, $offset - 10), 80);
            $snippet = preg_replace('/[^\x20-\x7E]/', ' ', $rawSnippet);

            return [
                'is_suspicious' => true,
                'category' => 'Injeksi PHP pada Media',
                'reason' => "Ditemukan tag PHP ('{$m[0][0]}') di dalam berkas media .{$extension}. Ini merupakan teknik umum penyusupan webshell polyglot.",
                'snippet' => trim((string) $snippet),
            ];
        }

        foreach (self::MALICIOUS_PATTERNS as $rule) {
            if (
                preg_match(
                    $rule['pattern'],
                    $content,
                    $matches,
                    PREG_OFFSET_CAPTURE,
                )
            ) {
                $offset = (int) ($matches[0][1] ?? 0);
                $rawSnippet = substr($content, max(0, $offset - 20), 100);
                $snippet = preg_replace('/[^\x20-\x7E]/', ' ', $rawSnippet);

                return [
                    'is_suspicious' => true,
                    'category' => 'Webshell / Backdoor',
                    'reason' => "Ditemukan pola kode berbahaya: {$rule['label']}.",
                    'snippet' => trim((string) $snippet),
                ];
            }
        }

        return [
            'is_suspicious' => false,
            'category' => null,
            'reason' => null,
            'snippet' => null,
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | Helper pemeriksaan
    |--------------------------------------------------------------------------
    */

    /**
     * Susun satu baris hasil pemeriksaan.
     *
     * @return array<string, mixed>
     */
    protected function check(
        string $id,
        string $category,
        string $categoryId,
        string $label,
        string $status,
        ?string $value = null,
        string $detail = '',
        ?string $recommendation = null,
    ): array {
        return [
            'id' => $id,
            'category' => $category,
            'category_id' => $categoryId,
            'label' => $label,
            'status' => $status,
            'value' => $value,
            'detail' => $detail,
            'recommendation' => $recommendation,
        ];
    }

    /**
     * @param  array<int, array<string, mixed>>  $checks
     * @return array{total: int, ok: int, info: int, warning: int, critical: int, score: int, status: string}
     */
    protected function summarize(array $checks): array
    {
        $counts = ['ok' => 0, 'info' => 0, 'warning' => 0, 'critical' => 0];

        foreach ($checks as $check) {
            $status = (string) ($check['status'] ?? 'info');
            $counts[array_key_exists($status, $counts) ? $status : 'info']++;
        }

        $score = max(
            0,
            100 - $counts['critical'] * 12 - $counts['warning'] * 4,
        );

        return [
            'total' => count($checks),
            'ok' => $counts['ok'],
            'info' => $counts['info'],
            'warning' => $counts['warning'],
            'critical' => $counts['critical'],
            'score' => $score,
            'status' => match (true) {
                $counts['critical'] > 0 => 'critical',
                $counts['warning'] > 0 => 'warning',
                default => 'ok',
            },
        ];
    }

    /**
     * Kelompokkan hasil pemeriksaan per kategori.
     *
     * @param  array<int, array<string, mixed>>  $checks
     * @return array<int, array<string, mixed>>
     */
    protected function group(array $checks): array
    {
        $order = [
            'app' => 'Aplikasi & Konfigurasi',
            'database' => 'Database & Antrian',
            'files' => 'Berkas & Penyimpanan',
            'accounts' => 'Akun & Akses',
            'integrity' => 'Integritas Berkas',
            'monitoring' => 'Pemantauan & Log',
            'other' => 'Lain-lain',
        ];

        $grouped = [];

        foreach ($checks as $check) {
            $id = (string) ($check['category_id'] ?? 'other');
            $grouped[$id][] = $check;
        }

        $categories = [];

        foreach ($order as $id => $label) {
            if (! isset($grouped[$id])) {
                continue;
            }

            $categories[] = [
                'id' => $id,
                'label' => $label,
                'checks' => $grouped[$id],
            ];

            unset($grouped[$id]);
        }

        foreach ($grouped as $id => $items) {
            $categories[] = [
                'id' => (string) $id,
                'label' => (string) ($items[0]['category'] ?? 'Lain-lain'),
                'checks' => $items,
            ];
        }

        return $categories;
    }

    /**
     * @return Builder<Model>
     */
    protected function adminQuery()
    {
        return $this->userModel()::query()->where('role', 'admin');
    }

    protected function userModel(): string
    {
        return config('security.user_model', "App\Models\User");
    }

    protected function lockoutCount(): int
    {
        try {
            return LoginAttempt::query()->locked()->count();
        } catch (Throwable) {
            return 0;
        }
    }

    protected function featureEnabled(string $feature): bool
    {
        try {
            if (class_exists(Features::class)) {
                return Features::enabled($feature);
            }

            return false;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @return array<int, string>
     */
    protected function pendingMigrations(): array
    {
        try {
            $migrator = app('migrator');

            if (! $migrator->repositoryExists()) {
                return [];
            }

            $ran = $migrator->getRepository()->getRan();
            $files = array_map(
                fn (string $file): string => $migrator->getMigrationName($file),
                array_values(
                    $migrator->getMigrationFiles([database_path('migrations')]),
                ),
            );

            return array_values(array_diff($files, $ran));
        } catch (Throwable) {
            return [];
        }
    }

    protected function countTable(string $table): ?int
    {
        try {
            return (int) DB::table($table)->count();
        } catch (Throwable) {
            return null;
        }
    }

    protected function apiHeaderMiddlewareInstalled(): bool
    {
        try {
            $groups = app('router')->getMiddlewareGroups();
            $middleware = $groups['api'] ?? [];
        } catch (Throwable) {
            return false;
        }

        foreach ($middleware as $class) {
            if (
                is_string($class) &&
                str_contains($class, 'CheckPublicApiHeader')
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{status: string, value: string, detail: string, recommendation: string|null}
     */
    protected function envFilePermissions(): array
    {
        $path = base_path('.env');

        if (! File::exists($path)) {
            return [
                'status' => 'warning',
                'value' => 'tidak ditemukan',
                'detail' => 'Berkas .env tidak ditemukan. Konfigurasi mungkin dibaca dari environment server (cara ini justru lebih aman).',
                'recommendation' => null,
            ];
        }

        if (DIRECTORY_SEPARATOR === '\\') {
            return [
                'status' => 'info',
                'value' => 'tidak dapat diperiksa di Windows',
                'detail' => 'Pemeriksaan izin berkas .env hanya tersedia pada sistem operasi berbasis Unix.',
                'recommendation' => null,
            ];
        }

        $permissions = (int) fileperms($path) & 0777;
        $worldReadable = ($permissions & 0x0004) !== 0;

        return [
            'status' => $worldReadable ? 'warning' : 'ok',
            'value' => '0'.decoct($permissions),
            'detail' => $worldReadable
                ? 'Berkas .env dapat dibaca oleh semua user sistem sehingga kredensial database, APP_KEY, dan kunci API berisiko bocor.'
                : 'Berkas .env hanya dapat dibaca pemiliknya.',
            'recommendation' => $worldReadable
                ? 'Jalankan chmod 600 .env dan pastikan pemiliknya adalah user deploy.'
                : null,
        ];
    }

    /**
     * Cari berkas berekstensi berbahaya pada sebuah folder.
     *
     * @param  array<int, string>  $skipDirectories
     * @return array{files: array<int, string>, count: int}
     */
    protected function scanDangerousFiles(
        string $root,
        array $skipDirectories,
    ): array {
        if (! File::isDirectory($root)) {
            return ['files' => [], 'count' => 0];
        }

        $limit = max(
            100,
            (int) config('security.server_scan.max_files_scanned', 20000),
        );
        $suspicious = [];
        $scanned = 0;

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveCallbackFilterIterator(
                    new \RecursiveDirectoryIterator(
                        $root,
                        \FilesystemIterator::SKIP_DOTS |
                            \FilesystemIterator::CURRENT_AS_FILEINFO,
                    ),
                    function (\SplFileInfo $file) use ($skipDirectories): bool {
                        if (! $file->isDir()) {
                            return true;
                        }

                        $name = $file->getFilename();

                        return ! in_array($name, $skipDirectories, true) &&
                            ! in_array($name, self::SKIPPED_DIRECTORIES, true);
                    },
                ),
                \RecursiveIteratorIterator::SELF_FIRST,
            );

            foreach ($iterator as $file) {
                if (! $file instanceof \SplFileInfo || ! $file->isFile()) {
                    continue;
                }

                if (++$scanned > $limit) {
                    break;
                }

                $name = $file->getFilename();
                $extension = strtolower($file->getExtension());

                $dangerous =
                    in_array($extension, self::DANGEROUS_EXTENSIONS, true) ||
                    str_starts_with($name, '.env');

                // index.php adalah front controller resmi aplikasi.
                if (
                    $dangerous &&
                    $file->getPathname() === public_path('index.php')
                ) {
                    $dangerous = false;
                }

                if (! $dangerous) {
                    continue;
                }

                $relative = str_replace(
                    '\\',
                    '/',
                    str_replace(
                        $root.DIRECTORY_SEPARATOR,
                        '',
                        $file->getPathname(),
                    ),
                );
                $suspicious[] = $relative;

                if (count($suspicious) >= 25) {
                    break;
                }
            }
        } catch (Throwable) {
            // Penelusuran gagal: laporkan apa yang sudah ditemukan.
        }

        return ['files' => $suspicious, 'count' => $scanned];
    }

    /**
     * @return array{status: string, value: string, detail: string, recommendation: string|null}
     */
    protected function diskUsage(): array
    {
        $path = storage_path();

        try {
            $free = @disk_free_space($path);
            $total = @disk_total_space($path);
        } catch (Throwable) {
            $free = false;
            $total = false;
        }

        if ($free === false || $total === false || $total <= 0) {
            return [
                'status' => 'info',
                'value' => 'tidak dapat dibaca',
                'detail' => 'Informasi ruang penyimpanan tidak tersedia pada server ini.',
                'recommendation' => null,
            ];
        }

        $freePercent = (int) round(($free / $total) * 100);
        $critical = max(
            1,
            (int) config('security.server_scan.disk_critical_percent', 10),
        );
        $warning = max(
            $critical,
            (int) config('security.server_scan.disk_warning_percent', 20),
        );

        return [
            'status' => match (true) {
                $freePercent <= $critical => 'critical',
                $freePercent <= $warning => 'warning',
                default => 'ok',
            },
            'value' => $freePercent.
                '% tersisa ('.
                $this->humanBytes((float) $free).
                ' dari '.
                $this->humanBytes((float) $total).
                ')',
            'detail' => match (true) {
                $freePercent <= $critical => 'Ruang disk hampir habis. Aplikasi dapat gagal menyimpan log, session, dan file unggahan.',
                $freePercent <= $warning => 'Ruang disk menipis sehingga perlu dibersihkan sebelum mengganggu operasional.',
                default => 'Ruang penyimpanan masih memadai.',
            },
            'recommendation' => $freePercent <= $warning
                    ? 'Bersihkan log lama, berkas cache, dan cadangan usang; atau tambah kapasitas disk.'
                    : null,
        ];
    }

    protected function directorySize(string $path): int
    {
        if (! File::isDirectory($path)) {
            return 0;
        }

        $size = 0;

        try {
            foreach (File::files($path) as $file) {
                $size += $file->getSize();
            }

            foreach (File::directories($path) as $directory) {
                $size += $this->directorySize($directory);
            }
        } catch (Throwable) {
            return $size;
        }

        return $size;
    }

    /**
     * Berkas access log web server yang dapat dibaca aplikasi.
     *
     * @return array<int, string>
     */
    protected function accessLogFiles(): array
    {
        $files = [];

        foreach ((array) config('security.access_log.paths', []) as $pattern) {
            foreach (glob((string) $pattern) ?: [] as $path) {
                if (is_file($path) && is_readable($path)) {
                    $files[] = $path;
                }
            }
        }

        return array_values(array_unique($files));
    }

    /**
     * Berkas aplikasi yang berubah dalam beberapa hari terakhir.
     *
     * @return array{count: int, files: array<int, string>}
     */
    protected function recentChanges(): array
    {
        $days = max(
            1,
            (int) config('security.server_scan.recent_changes_days', 7),
        );
        $threshold = now()->subDays($days)->getTimestamp();
        $limit = max(
            500,
            (int) config('security.server_scan.max_files_scanned', 20000),
        );

        $files = [];
        $scanned = 0;

        foreach (self::WATCHED_DIRECTORIES as $directory) {
            $root = base_path($directory);

            if (! File::isDirectory($root)) {
                continue;
            }

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveCallbackFilterIterator(
                        new \RecursiveDirectoryIterator(
                            $root,
                            \FilesystemIterator::SKIP_DOTS |
                                \FilesystemIterator::CURRENT_AS_FILEINFO,
                        ),
                        function (\SplFileInfo $file) use ($directory): bool {
                            if (! $file->isDir()) {
                                return true;
                            }

                            if (
                                $directory === 'public' &&
                                $file->getFilename() === 'build'
                            ) {
                                return false;
                            }

                            return ! in_array(
                                $file->getFilename(),
                                ['vendor', 'node_modules', '.git', 'storage'],
                                true,
                            );
                        },
                    ),
                    \RecursiveIteratorIterator::SELF_FIRST,
                );

                foreach ($iterator as $file) {
                    if (! $file instanceof \SplFileInfo || ! $file->isFile()) {
                        continue;
                    }

                    if (++$scanned > $limit) {
                        break 2;
                    }

                    if ($file->getMTime() < $threshold) {
                        continue;
                    }

                    $relative = str_replace(
                        '\\',
                        '/',
                        str_replace(
                            base_path().DIRECTORY_SEPARATOR,
                            '',
                            $file->getPathname(),
                        ),
                    );
                    $files[$relative] = $file->getMTime();
                }
            } catch (Throwable) {
                continue;
            }
        }

        arsort($files);

        return [
            'count' => count($files),
            'files' => array_slice(array_keys($files), 0, 15),
        ];
    }

    /**
     * @return array{status: string, value: string, detail: string, recommendation: string|null}
     */
    protected function heartbeat(): array
    {
        try {
            $last = Cache::get(self::HEARTBEAT_KEY);
        } catch (Throwable) {
            $last = null;
        }

        if (! is_string($last) || $last === '') {
            return [
                'status' => 'warning',
                'value' => 'belum terdeteksi',
                'detail' => 'Belum ada tanda penjadwal berjalan. Tanpa scheduler, pembersihan log otomatis (security:prune-logs) tidak pernah dijalankan.',
                'recommendation' => 'Tambahkan cron: * * * * * cd /path/artisan && php artisan schedule:run >> /dev/null 2>&1',
            ];
        }

        try {
            $at = Carbon::parse($last);
        } catch (Throwable) {
            return [
                'status' => 'warning',
                'value' => 'tidak valid',
                'detail' => 'Nilai heartbeat penjadwal tidak dapat dibaca.',
                'recommendation' => 'Pastikan cron schedule:run berjalan setiap menit.',
            ];
        }

        $stale = $at->diffInMinutes(now()) > 5;

        return [
            'status' => $stale ? 'warning' : 'ok',
            'value' => 'terakhir '.$this->humanDate($last),
            'detail' => $stale
                ? 'Penjadwal terakhir terlihat lebih dari 5 menit lalu sehingga tugas terjadwal (prune log, baseline) kemungkinan tidak berjalan.'
                : 'Penjadwal berjalan normal sesuai jadwal setiap menit.',
            'recommendation' => $stale
                ? 'Periksa cron schedule:run pada server.'
                : null,
        ];
    }

    /**
     * Hitung baris ERROR pada berkas log aplikasi hari ini.
     *
     * @return array{count: int, sample: string}
     */
    protected function recentApplicationErrors(): array
    {
        $path = storage_path('logs/laravel.log');

        if (! File::exists($path)) {
            return ['count' => 0, 'sample' => ''];
        }

        try {
            $handle = @fopen($path, 'rb');

            if ($handle === false) {
                return ['count' => 0, 'sample' => ''];
            }

            $size = (int) File::size($path);
            $tail = 1_048_576;

            if ($size > $tail) {
                fseek($handle, -$tail, SEEK_END);
            }

            $content = (string) stream_get_contents($handle);
            fclose($handle);
        } catch (Throwable) {
            return ['count' => 0, 'sample' => ''];
        }

        $today = now()->toDateString();
        $count = 0;
        $sample = '';

        foreach (explode("\n", $content) as $line) {
            if (
                ! str_contains($line, '.ERROR') &&
                ! str_contains($line, 'ERROR:')
            ) {
                continue;
            }

            if (
                ! str_starts_with(trim($line), '[') ||
                ! str_contains($line, $today)
            ) {
                continue;
            }

            $count++;

            if ($sample === '') {
                $sample = Str::limit(trim($line), 180);
            }
        }

        return ['count' => $count, 'sample' => $sample];
    }

    /**
     * @return array{total: int, critical: int, top_event: string|null}
     */
    protected function securityLogStats(int $days = 7): array
    {
        try {
            $query = SecurityLog::query()->where(
                'created_at',
                '>=',
                now()->subDays($days),
            );

            $total = (clone $query)->count();
            $critical = (clone $query)
                ->whereIn('threat_level', ['high', 'critical'])
                ->count();
            $top = (clone $query)
                ->selectRaw('event_type, COUNT(*) as total')
                ->groupBy('event_type')
                ->orderByDesc('total')
                ->value('event_type');
        } catch (Throwable) {
            return ['total' => 0, 'critical' => 0, 'top_event' => null];
        }

        return [
            'total' => $total,
            'critical' => $critical,
            'top_event' => is_string($top) ? $top : null,
        ];
    }

    protected function humanDate(?string $value): string
    {
        if (! is_string($value) || $value === '') {
            return '-';
        }

        try {
            return Carbon::parse($value)->translatedFormat('d M Y H:i');
        } catch (Throwable) {
            return $value;
        }
    }

    protected function humanBytes(float $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $index = 0;

        while ($bytes >= 1024 && $index < count($units) - 1) {
            $bytes /= 1024;
            $index++;
        }

        return number_format($bytes, $index === 0 ? 0 : 1, ',', '.').
            ' '.
            $units[$index];
    }
}
