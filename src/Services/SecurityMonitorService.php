<?php

namespace Internal\SecurityMonitor\Services;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;
use Throwable;

/**
 * Central place for threat detection, security logging and IP blocking.
 *
 * The service is intentionally defensive: every database interaction is
 * wrapped so that a broken/missing table can never take the application
 * down or expose an error to the attacker.
 */
class SecurityMonitorService
{
    /**
     * Rentang waktu yang didukung grafik tren serangan.
     *
     * @var array<int, string>
     */
    public const TREND_RANGES = ['week', 'month', 'year'];

    /**
     * Block state memoized for the current request lifecycle.
     *
     * @var array<string, BlockedIp|null>
     */
    protected array $blockCache = [];

    /**
     * Patterns already validated by PCRE during this process.
     *
     * @var array<string, bool>
     */
    protected static array $patternCache = [];

    public function enabled(): bool
    {
        return (bool) config('security.enabled', true);
    }

    public function enforcementEnabled(): bool
    {
        return $this->enabled() && (bool) config('security.block_enforcement', true);
    }

    /*
    |--------------------------------------------------------------------------
    | IP Matching
    |--------------------------------------------------------------------------
    */

    /**
     * Resolve the client's true public IP address, respecting reverse proxies and CDNs.
     */
    public function resolveClientIp(Request $request): string
    {
        // 1. Cloudflare CDN
        if ($cfIp = $request->header('CF-Connecting-IP')) {
            $candidate = trim(explode(',', $cfIp)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        // 2. Akamai / Cloudflare Enterprise
        if ($trueIp = $request->header('True-Client-IP')) {
            $candidate = trim(explode(',', $trueIp)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        // 3. Reverse Proxies (Nginx, Caddy, Traefik, Apache)
        if ($realIp = $request->header('X-Real-IP')) {
            $candidate = trim(explode(',', $realIp)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        // 4. Standard Forwarded / X-Forwarded-For header
        if ($forwarded = $request->header('X-Forwarded-For')) {
            $candidate = trim(explode(',', $forwarded)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return (string) ($request->ip() ?? '127.0.0.1');
    }

    /**
     * Resolve the unique device identifier sent from the client or derive from fingerprint.
     */
    public function resolveDeviceId(?Request $request = null, bool $allowFingerprint = true): ?string
    {
        $request = $request ?? request();

        if (! $request instanceof Request) {
            return null;
        }

        $id = $request->header('X-Device-Id')
            ?? $request->header('X-Client-Id')
            ?? $request->header('X-Client-Device-Id')
            ?? $request->cookie('app_device_id')
            ?? $request->cookie('sec_device_id')
            ?? $request->input('device_id');

        if (is_string($id) && trim($id) !== '') {
            return trim($id);
        }

        if ($allowFingerprint) {
            return $this->generateDeviceFingerprint($request);
        }

        return null;
    }

    /**
     * Generate a deterministic device fingerprint based on client request signatures.
     */
    public function generateDeviceFingerprint(Request $request): string
    {
        $ua = (string) $request->userAgent();
        $lang = (string) $request->header('Accept-Language');
        $platform = (string) ($request->header('Sec-Ch-Ua-Platform') ?? $request->header('Sec-Ch-Ua') ?? '');
        $encoding = (string) $request->header('Accept-Encoding');
        $accept = (string) $request->header('Accept');

        $raw = $ua.'|'.$lang.'|'.$platform.'|'.$encoding.'|'.$accept;

        if (trim($raw, '|') === '') {
            $raw = 'raw_client_'.($request->server('HTTP_ACCEPT') ?? '').'_'.($request->server('REMOTE_PORT') ?? '0');
        }

        return 'dev_'.substr(hash('sha256', $raw), 0, 16);
    }

    /**
     * Resolve the local/private LAN IP discovered on the client side via WebRTC.
     */
    public function resolveLocalIp(?Request $request = null): ?string
    {
        $request = $request ?? request();

        if (! $request instanceof Request) {
            return null;
        }

        $ip = $request->header('X-Local-Ip')
            ?? $request->header('X-Client-Local-Ip')
            ?? $request->cookie('app_local_ip')
            ?? $request->input('local_ip');

        return is_string($ip) && $ip !== '' ? trim($ip) : null;
    }

    /**
     * Check whether an IP/device is part of the configured whitelist or trusted IP table.
     */
    public function isWhitelisted(?string $ip, ?string $deviceId = null, ?string $localIp = null): bool
    {
        if (! is_string($ip) || $ip === '') {
            return false;
        }

        foreach (config('security.whitelist', []) as $pattern) {
            if (self::ipMatches($ip, (string) $pattern)) {
                return true;
            }
        }

        try {
            if (TrustedIp::isAnyTrusted($ip, $deviceId, $localIp)) {
                return true;
            }

            if ($deviceId && UserLogin::query()->where('device_id', $deviceId)->whereNull('logout_at')->exists()) {
                return true;
            }

            if ($localIp && UserLogin::query()->where('local_ip', $localIp)->whereNull('logout_at')->exists()) {
                return true;
            }

            if (UserLogin::query()->where('ip_address', $ip)->whereNull('logout_at')->exists()) {
                return true;
            }

            if (Schema::hasTable('sessions') && DB::table('sessions')->where('ip_address', $ip)->whereNotNull('user_id')->exists()) {
                return true;
            }
        } catch (Throwable) {
            // Silently fallback if table query fails
        }

        return false;
    }

    /**
     * Match an IP against an exact address, a wildcard (192.168.1.*) or CIDR.
     */
    public static function ipMatches(string $ip, string $pattern): bool
    {
        $pattern = trim($pattern);

        if ($pattern === '') {
            return false;
        }

        if ($pattern === '*' || $pattern === $ip) {
            return true;
        }

        if (str_contains($pattern, '/')) {
            return self::ipInCidr($ip, $pattern);
        }

        if (str_contains($pattern, '*')) {
            return Str::is($pattern, $ip);
        }

        return false;
    }

    protected static function ipInCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);

        if ($bits === null || ! is_numeric($bits)) {
            return false;
        }

        $ipBinary = @inet_pton($ip);
        $subnetBinary = $subnet === null ? false : @inet_pton($subnet);

        if ($ipBinary === false || $subnetBinary === false || strlen($ipBinary) !== strlen($subnetBinary)) {
            return false;
        }

        $bits = (int) $bits;
        $maxBits = strlen($ipBinary) * 8;

        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);

        if ($wholeBytes > 0 && substr($ipBinary, 0, $wholeBytes) !== substr($subnetBinary, 0, $wholeBytes)) {
            return false;
        }

        $remainingBits = $bits % 8;

        if ($remainingBits === 0) {
            return true;
        }

        $mask = ~((1 << (8 - $remainingBits)) - 1) & 0xFF;

        return (ord($ipBinary[$wholeBytes]) & $mask) === (ord($subnetBinary[$wholeBytes]) & $mask);
    }

    /*
    |--------------------------------------------------------------------------
    | Blocked IPs
    |--------------------------------------------------------------------------
    */

    /**
     * Return the active block record for an IP / device, if any.
     */
    public function activeBlock(?string $ip, ?string $deviceId = null, ?string $localIp = null): ?BlockedIp
    {
        if (! is_string($ip) || $ip === '') {
            return null;
        }

        $cacheKey = $ip.'|'.($deviceId ?? '').'|'.($localIp ?? '');

        if (array_key_exists($cacheKey, $this->blockCache)) {
            return $this->blockCache[$cacheKey];
        }

        try {
            $blocks = BlockedIp::query()
                ->active()
                ->where(function (Builder $query) use ($ip, $deviceId) {
                    $query->where('ip_address', $ip);
                    if ($deviceId) {
                        $query->orWhere('device_id', $deviceId);
                    }
                })
                ->get();

            if ($blocks->isEmpty()) {
                return $this->blockCache[$cacheKey] = null;
            }

            foreach ($blocks as $block) {
                // If block is specifically scoped to device
                if ($block->block_scope === 'device') {
                    if (($deviceId && $block->device_id === $deviceId) ||
                        ($localIp && $block->local_ip === $localIp)) {
                        return $this->blockCache[$cacheKey] = $block;
                    }

                    continue;
                }

                // If block is for the entire IP address
                if ($block->ip_address === $ip) {
                    return $this->blockCache[$cacheKey] = $block;
                }
            }
        } catch (Throwable) {
            return $this->blockCache[$cacheKey] = null;
        }

        return $this->blockCache[$cacheKey] = null;
    }

    public function isBlocked(?string $ip, ?string $deviceId = null, ?string $localIp = null): bool
    {
        return $this->activeBlock($ip, $deviceId, $localIp) !== null;
    }

    /**
     * Block an IP address or specific device (creating or re-activating the record).
     *
     * @param  array{reason?: string|null, notes?: string|null, source?: string, blocked_by?: int|null, duration_hours?: int|string|null, expires_at?: mixed, local_ip?: string|null, device_id?: string|null, block_scope?: string}  $attributes
     */
    public function block(string $ip, array $attributes = []): BlockedIp
    {
        $deviceId = $attributes['device_id'] ?? null;
        $localIp = $attributes['local_ip'] ?? null;
        $blockScope = $attributes['block_scope'] ?? 'ip';

        if ($this->isWhitelisted($ip, $deviceId, $localIp)) {
            return BlockedIp::query()->firstOrNew(['ip_address' => $ip, 'is_active' => false]);
        }

        $duration = $attributes['duration_hours'] ?? null;
        $expiresAt = $attributes['expires_at'] ?? null;

        if ($expiresAt === null && $duration !== null && (int) $duration > 0) {
            $expiresAt = now()->addHours((int) $duration);
        }

        /** @var BlockedIp $block */
        $blockQuery = BlockedIp::query()->where('ip_address', $ip);
        if ($deviceId) {
            $blockQuery->where('device_id', $deviceId);
        }
        $block = $blockQuery->firstOrNew([
            'ip_address' => $ip,
            'device_id' => $deviceId,
        ]);

        $block->fill([
            'local_ip' => $localIp ?? $block->local_ip,
            'block_scope' => $blockScope,
            'reason' => $attributes['reason'] ?? $block->reason ?? 'Aktivitas mencurigakan terdeteksi',
            'notes' => $attributes['notes'] ?? $block->notes,
            'source' => $attributes['source'] ?? $block->source ?? 'manual',
            'blocked_by' => $attributes['blocked_by'] ?? $block->blocked_by,
            'blocked_at' => now(),
            'expires_at' => $expiresAt,
            'is_active' => true,
            'hit_count' => $block->exists ? $block->hit_count : 0,
        ]);

        $block->save();

        $cacheKey = $ip.'|'.($deviceId ?? '').'|'.($localIp ?? '');
        $this->blockCache[$cacheKey] = $block;

        return $block;
    }

    /**
     * Lift a block. The record is kept for audit purposes.
     */
    public function unblock(BlockedIp $block): void
    {
        $block->forceFill([
            'is_active' => false,
        ])->save();

        $this->blockCache = [];
    }

    /**
     * Lift any active block for a given IP address or device.
     */
    public function unblockIp(?string $ip, ?string $deviceId = null): bool
    {
        if ((! is_string($ip) || $ip === '') && ! is_string($deviceId)) {
            return false;
        }

        $this->blockCache = [];

        try {
            $query = BlockedIp::query()->where('is_active', true);

            if ($deviceId) {
                $query->where(function (Builder $q) use ($ip, $deviceId) {
                    $q->where('device_id', $deviceId);
                    if ($ip) {
                        $q->orWhere('ip_address', $ip);
                    }
                });
            } else {
                $query->where('ip_address', $ip);
            }

            $blocks = $query->get();

            if ($blocks->isEmpty()) {
                return false;
            }

            foreach ($blocks as $block) {
                $block->forceFill(['is_active' => false])->save();
            }

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Count a hit on a blocked IP (and log it, throttled per IP).
     */
    public function logBlockedAttempt(BlockedIp $block, Request $request): void
    {
        try {
            $block->forceFill([
                'hit_count' => $block->hit_count + 1,
                'last_hit_at' => now(),
            ])->save();
        } catch (Throwable) {
            // Never let logging break the response.
        }

        if (! $this->shouldLogBlockedAttempt($block->ip_address)) {
            return;
        }

        $this->record($request, [[
            'rule' => 'blocked_ip',
            'label' => 'Akses ditolak dari IP yang diblokir',
            'level' => 'medium',
            'evidence' => 'IP '.$block->ip_address.' mencoba mengakses '.$request->fullUrl(),
        ]], 'blocked');
    }

    protected function shouldLogBlockedAttempt(string $ip): bool
    {
        $interval = (int) config('security.blocked_log_interval', 10);

        if ($interval <= 0) {
            return true;
        }

        try {
            return (bool) Cache::add("security:blocked-log:{$ip}", 1, now()->addSeconds($interval));
        } catch (Throwable) {
            return true;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Detection
    |--------------------------------------------------------------------------
    */

    /**
     * Inspect a request and return every threat that was detected.
     *
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    public function inspect(Request $request): array
    {
        if (! $this->enabled() || $this->isWhitelisted($request->ip())) {
            return [];
        }

        if ($this->isExcludedPath($request->path())) {
            return [];
        }

        return $this->inspectHaystacks($this->haystacks($request));
    }

    /**
     * Inspect raw request parts instead of a live Request object.
     *
     * Dipakai oleh pemindai access log (security:scan-access-log) sehingga pola
     * deteksi tetap hanya didefinisikan sekali di config/security.php.
     *
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    public function inspectRaw(string $path, string $query = '', string $userAgent = '', string $body = '', string $referer = ''): array
    {
        if (! $this->enabled() || $this->isExcludedPath($path)) {
            return [];
        }

        return $this->inspectHaystacks(
            $this->haystacksFromParts($path, $query, $body, $userAgent, $referer)
        );
    }

    /**
     * Run every detection layer against a set of request parts and return the
     * threats that were found (most severe entry per rule id).
     *
     * @param  array<string, string>  $haystacks
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    public function inspectHaystacks(array $haystacks): array
    {
        $paths = array_unique(array_filter([
            (string) ($haystacks['path'] ?? ''),
            (string) ($haystacks['path-decoded'] ?? ''),
        ]));

        $pathThreats = [];

        foreach ($paths as $path) {
            $pathThreats = array_merge(
                $pathThreats,
                $this->inspectSensitivePath($path, (string) ($haystacks['query-decoded'] ?? $haystacks['query'] ?? '')),
            );
        }

        return $this->deduplicate(array_merge(
            $pathThreats,
            $this->inspectScannerAgent((string) ($haystacks['user_agent'] ?? '')),
            $this->inspectRules($haystacks),
            $this->inspectSignatures($haystacks),
        ));
    }

    /**
     * Zero tolerance signatures: a single match blocks the source IP at once.
     *
     * @param  array<string, string>  $all
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    protected function inspectSignatures(array $all): array
    {
        if (! $this->instantBlockEnabled()) {
            return [];
        }

        $threats = [];

        foreach (config('security.instant_block.signatures', []) as $signature) {
            $id = (string) ($signature['id'] ?? 'signature');
            $targets = $this->targetsFor((string) ($signature['target'] ?? 'any'), $all);

            foreach ($signature['patterns'] ?? [] as $pattern) {
                $pattern = (string) $pattern;

                if (! $this->isValidPattern($pattern)) {
                    continue;
                }

                foreach ($targets as $source => $value) {
                    if (preg_match($pattern, $value, $matches) !== 1) {
                        continue;
                    }

                    $threats[] = [
                        'rule' => $id,
                        'label' => (string) ($signature['label'] ?? Str::headline($id)),
                        'level' => 'critical',
                        'evidence' => $this->buildEvidence((string) $source, $value, (string) $matches[0]),
                        'instant' => true,
                    ];

                    continue 3;
                }
            }
        }

        return $threats;
    }

    /**
     * Pick the haystacks a signature is allowed to inspect.
     *
     * @param  array<string, string>  $all
     * @return array<string, string>
     */
    protected function targetsFor(string $target, array $all): array
    {
        $sources = match ($target) {
            'path' => ['path', 'path-decoded'],
            'query' => ['query', 'query-decoded'],
            'body' => ['body', 'file_content'],
            'filename' => ['filename'],
            'input' => ['query', 'query-decoded', 'body', 'file_content'],
            'user_agent' => ['user_agent'],
            default => array_keys($all),
        };

        return array_intersect_key($all, array_flip($sources));
    }

    public function instantBlockEnabled(): bool
    {
        return $this->enabled()
            && (bool) config('security.instant_block.enabled', true)
            && config('security.instant_block.signatures', []) !== [];
    }

    /**
     * Whether the detected threats include a zero tolerance signature.
     *
     * @param  array<int, array{instant?: bool}>  $threats
     */
    public function shouldInstantBlock(array $threats): bool
    {
        foreach ($threats as $threat) {
            if (($threat['instant'] ?? false) === true) {
                return true;
            }
        }

        return false;
    }

    /**
     * Reason string describing which signature triggered the block.
     *
     * @param  array<int, array{label?: string, instant?: bool}>  $threats
     */
    public function instantBlockReason(array $threats): ?string
    {
        foreach ($threats as $threat) {
            if (($threat['instant'] ?? false) === true) {
                return (string) ($threat['label'] ?? 'Pola serangan terdeteksi');
            }
        }

        return null;
    }

    /**
     * Block an IP/device straight away because of a zero tolerance signature.
     *
     * @param  array<int, array{label?: string, instant?: bool}>  $threats
     */
    public function blockImmediately(string $ip, array $threats, ?string $deviceId = null, ?string $localIp = null): ?BlockedIp
    {
        if (! $this->instantBlockEnabled() || $this->isWhitelisted($ip, $deviceId, $localIp)) {
            return null;
        }

        $config = config('security.instant_block', []);
        $scope = (string) ($config['scope'] ?? 'device');

        if ($scope === 'device' && empty($deviceId)) {
            $deviceId = $this->resolveDeviceId();
        }

        if (empty($localIp)) {
            $localIp = $this->resolveLocalIp();
        }

        $reason = $this->instantBlockReason($threats) ?? 'Pola serangan terdeteksi';

        return $this->block($ip, [
            'device_id' => $deviceId,
            'local_ip' => $localIp,
            'block_scope' => $scope,
            'reason' => 'Diblokir instan: '.$reason,
            'notes' => 'Terdeteksi otomatis oleh Security Monitor (zero tolerance signature).'.($deviceId ? " (Perangkat: {$deviceId})" : ''),
            'source' => 'automatic',
            'duration_hours' => (int) ($config['duration_hours'] ?? 720),
        ]);
    }

    protected function isExcludedPath(string $path): bool
    {
        $path = trim($path, '/');

        foreach (config('security.exclude_paths', []) as $excluded) {
            if (Str::is(trim((string) $excluded, '/'), $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Look for probes against sensitive files or admin panels of other apps.
     */
    protected function inspectSensitivePath(string $path, string $query = ''): array
    {
        $path = trim($path, '/');
        $segments = $path === '' ? [] : explode('/', $path);

        $threats = [];

        foreach (['critical', 'high'] as $level) {
            foreach (config("security.sensitive_paths.{$level}", []) as $pattern) {
                $pattern = (string) $pattern;

                if ($this->matchesAny($pattern, [$path, ...$segments])) {
                    $threats[] = [
                        'rule' => 'sensitive_path',
                        'label' => 'Pemindaian berkas sensitif / panel pihak ketiga',
                        'level' => $level,
                        'evidence' => 'path: /'.$path,
                    ];

                    continue 2;
                }

                // Credential files are frequently probed through a query string
                // (e.g. /index.php?file=.env); only the critical list is checked
                // here to avoid false positives.
                if ($level === 'critical' && $query !== '' && str_contains($query, $pattern)) {
                    $threats[] = [
                        'rule' => 'sensitive_path',
                        'label' => 'Pemindaian berkas sensitif melalui parameter',
                        'level' => $level,
                        'evidence' => 'query: '.Str::limit($query, 120, ''),
                    ];

                    continue 2;
                }
            }
        }

        return $threats;
    }

    /**
     * @param  array<int, string>  $values
     */
    protected function matchesAny(string $pattern, array $values): bool
    {
        foreach ($values as $value) {
            if ($value === '') {
                continue;
            }

            if (Str::is($pattern, $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect automated vulnerability scanners.
     */
    protected function inspectScannerAgent(string $userAgent): array
    {
        $agent = Str::lower($userAgent);

        if ($agent === '') {
            return [];
        }

        foreach (config('security.scanner_agents', []) as $scanner) {
            $scanner = Str::lower((string) $scanner);

            if ($scanner !== '' && str_contains($agent, $scanner)) {
                return [[
                    'rule' => 'scanner',
                    'label' => 'Perangkat lunak pemindai keamanan terdeteksi',
                    'level' => 'high',
                    'evidence' => 'user-agent: '.Str::limit($userAgent, 120, ''),
                ]];
            }
        }

        return [];
    }

    /**
     * Run every configured regex rule against the request payload.
     *
     * @param  array<string, string>  $haystacks
     */
    protected function inspectRules(array $haystacks): array
    {
        $threats = [];

        foreach (config('security.rules', []) as $rule) {
            $ruleId = (string) ($rule['id'] ?? 'unknown');

            foreach ($rule['patterns'] ?? [] as $pattern) {
                $pattern = (string) $pattern;

                if (! $this->isValidPattern($pattern)) {
                    continue;
                }

                foreach ($haystacks as $source => $value) {
                    if (preg_match($pattern, $value, $matches) !== 1) {
                        continue;
                    }

                    $threats[] = [
                        'rule' => $ruleId,
                        'label' => (string) ($rule['label'] ?? Str::headline($ruleId)),
                        'level' => (string) ($rule['level'] ?? 'medium'),
                        'evidence' => $this->buildEvidence((string) $source, $value, (string) $matches[0]),
                    ];

                    continue 3;
                }
            }
        }

        return $threats;
    }

    /**
     * Request data that gets scanned, keyed by its origin.
     *
     * @return array<string, string>
     */
    protected function haystacks(Request $request): array
    {
        $limit = max(500, (int) config('security.max_inspect_length', 4000));

        $haystacks = $this->haystacksFromParts(
            (string) $request->path(),
            (string) $request->getQueryString(),
            Str::limit($this->flattenInput($request->all()), $limit, ''),
            (string) $request->userAgent(),
            (string) $request->headers->get('referer'),
        );

        // Nama berkas unggahan hanya ada pada request multipart.
        $filenames = Str::limit($this->flattenFileNames($request->allFiles()), $limit, '');

        if ($filenames !== '') {
            $haystacks['filename'] = $filenames;
        }

        // Pindai konten berkas unggahan untuk mendeteksi Polyglot Webshell (mis. PHP dalam JPEG/PNG).
        $fileContents = Str::limit($this->extractUploadedFileContents($request->allFiles()), $limit, '');

        if ($fileContents !== '') {
            $haystacks['file_content'] = $fileContents;
        }

        return $haystacks;
    }

    /**
     * Build the inspectable parts of a request from raw strings.
     *
     * @return array<string, string>
     */
    protected function haystacksFromParts(string $path, string $query, string $body, string $userAgent, string $referer = ''): array
    {
        $limit = max(500, (int) config('security.max_inspect_length', 4000));

        return array_filter(
            [
                'path' => $path,
                'path-decoded' => rawurldecode($path),
                'query' => $query,
                'query-decoded' => rawurldecode($query),
                'body' => Str::limit($body, $limit, ''),
                'referer' => $referer,
                'user_agent' => $userAgent,
            ],
            fn (string $value) => $value !== ''
        );
    }

    /**
     * Collect the client supplied names of every uploaded file.
     * Attackers hide the payload here (wne.php%00.jpg) instead of the body.
     *
     * @param  array<array-key, mixed>  $files
     */
    protected function flattenFileNames(array $files, int $depth = 0): string
    {
        if ($depth > 5) {
            return '';
        }

        $names = [];

        foreach ($files as $file) {
            if ($file instanceof UploadedFile) {
                $names[] = $file->getClientOriginalName();

                continue;
            }

            if (is_array($file)) {
                $names[] = $this->flattenFileNames($file, $depth + 1);
            }
        }

        return implode(' ', array_filter($names, fn (string $name) => $name !== ''));
    }

    /**
     * Inspect uploaded files for embedded malicious scripts (Polyglot Webshells).
     *
     * @param  array<array-key, mixed>  $files
     */
    protected function extractUploadedFileContents(array $files, int $depth = 0): string
    {
        if ($depth > 5) {
            return '';
        }

        $snippets = [];

        foreach ($files as $file) {
            if ($file instanceof UploadedFile && $file->isValid()) {
                try {
                    $content = '';
                    if (method_exists($file, 'get')) {
                        $content = (string) $file->get();
                    } elseif ($file->getRealPath() && is_readable($file->getRealPath())) {
                        $size = (int) $file->getSize();
                        if ($size <= 262144) {
                            $content = (string) @file_get_contents($file->getRealPath());
                        } else {
                            $head = (string) @file_get_contents($file->getRealPath(), false, null, 0, 131072);
                            $tail = (string) @file_get_contents($file->getRealPath(), false, null, max(0, $size - 65536), 65536);
                            $content = $head.' '.$tail;
                        }
                    }

                    // Capture snippet if dangerous tokens/tags appear.
                    if ($content !== '' && preg_match('/(<\?|<script\b|eval\s*\(|base64_decode|system\s*\(|shell_exec|__HALT_COMPILER)/i', $content, $match)) {
                        $pos = strpos($content, $match[0]);
                        $start = max(0, (int) $pos - 40);
                        $snippets[] = substr($content, $start, 300);
                    }
                } catch (Throwable) {
                    // Skip unreadable files safely
                }

                continue;
            }

            if (is_array($file)) {
                $extracted = $this->extractUploadedFileContents($file, $depth + 1);
                if ($extracted !== '') {
                    $snippets[] = $extracted;
                }
            }
        }

        return implode(' ', $snippets);
    }

    /**
     * Flatten request input (including keys) into a single inspectable string.
     *
     * @param  array<array-key, mixed>  $input
     */
    protected function flattenInput(array $input, int $depth = 0): string
    {
        if ($depth > 5) {
            return '';
        }

        $values = [];

        foreach ($input as $key => $value) {
            if ($value instanceof UploadedFile) {
                continue;
            }

            if (is_array($value)) {
                $values[] = (string) $key;
                $values[] = $this->flattenInput($value, $depth + 1);

                continue;
            }

            if (is_scalar($value) || $value === null) {
                $values[] = (string) $key;
                $values[] = (string) $value;
            }
        }

        return implode(' ', array_filter($values, fn (string $value) => $value !== ''));
    }

    protected function isValidPattern(string $pattern): bool
    {
        if (array_key_exists($pattern, self::$patternCache)) {
            return self::$patternCache[$pattern];
        }

        return self::$patternCache[$pattern] = @preg_match($pattern, '') !== false;
    }

    protected function buildEvidence(string $source, string $haystack, string $match): string
    {
        $position = strpos($haystack, $match);
        $start = $position === false ? 0 : max(0, $position - 40);
        $snippet = substr($haystack, $start, strlen($match) + 80);
        $snippet = trim((string) preg_replace('/\s+/', ' ', $snippet));

        return $source.': '.Str::limit($snippet, 200, '…');
    }

    /**
     * Keep the most severe entry per rule id.
     *
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string, instant?: bool}>  $threats
     * @return array<int, array{rule: string, label: string, level: string, evidence: string, instant: bool}>
     */
    protected function deduplicate(array $threats): array
    {
        $deduplicated = [];

        foreach ($threats as $threat) {
            $threat['instant'] = (bool) ($threat['instant'] ?? false);
            $current = $deduplicated[$threat['rule']] ?? null;

            if ($current === null || $this->weight($threat['level']) > $this->weight($current['level'])) {
                $deduplicated[$threat['rule']] = $threat;
            }
        }

        return array_values($deduplicated);
    }

    protected function weight(string $level): int
    {
        return SecurityLog::LEVEL_WEIGHTS[$level] ?? 0;
    }

    /*
    |--------------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------------
    */

    /**
     * Persist the detected threats. Returns null when there is nothing to save
     * or when the write fails (logging must never break a response).
     *
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string}>  $threats
     */
    public function record(Request $request, array $threats, ?string $action = null): ?SecurityLog
    {
        if ($threats === [] || ! $this->enabled()) {
            return null;
        }

        $primary = $this->primaryThreat($threats);

        try {
            return SecurityLog::create([
                'ip_address' => $this->resolveClientIp($request),
                'local_ip' => $this->resolveLocalIp($request),
                'device_id' => $this->resolveDeviceId($request),
                'user_id' => $this->resolveUserId($request),
                'event_type' => $primary['rule'],
                'threat_level' => $primary['level'],
                'method' => Str::limit($request->method(), 10, ''),
                'path' => Str::limit('/'.ltrim($request->path(), '/'), 2000, ''),
                'full_url' => Str::limit($request->fullUrl(), 2000, ''),
                'rule_label' => $primary['label'],
                'evidence' => Str::limit($primary['evidence'], 1000, ''),
                'user_agent' => Str::limit((string) $request->userAgent(), 500, ''),
                'referer' => Str::limit((string) $request->headers->get('referer'), 500, ''),
                'was_blocked' => $action === 'blocked',
                'action_taken' => $action,
                'meta' => [
                    'threats' => array_map(fn (array $threat) => [
                        'rule' => $threat['rule'],
                        'level' => $threat['level'],
                    ], $threats),
                ],
            ]);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string}>  $threats
     * @return array{rule: string, label: string, level: string, evidence: string}
     */
    protected function primaryThreat(array $threats): array
    {
        usort($threats, fn (array $a, array $b) => $this->weight($b['level']) <=> $this->weight($a['level']));

        return $threats[0];
    }

    /**
     * Resolve the authenticated user from the request, auth guards,
     * active session, or by decrypting the session cookie if session
     * middleware has not started yet.
     */
    public function resolveUser(Request $request): ?Authenticatable
    {
        // 1. Direct user on request (if already resolved or set via actingAs)
        try {
            if ($user = $request->user()) {
                if ($user instanceof Authenticatable) {
                    return $user;
                }
            }
        } catch (Throwable) {
            // ignore
        }

        // 2. Auth facade default / web guard
        try {
            if ($user = Auth::user()) {
                if ($user instanceof Authenticatable) {
                    return $user;
                }
            }
        } catch (Throwable) {
            // ignore
        }

        // 3. Active session on request
        try {
            if ($request->hasSession()) {
                $session = $request->session();
                $guardKey = Auth::getName();
                if ($session->has($guardKey)) {
                    $userId = $session->get($guardKey);
                    if ($userId && ($user = ($this->userModel())::query()->find($userId))) {
                        $request->setUserResolver(fn () => $user);

                        return $user;
                    }
                }
            }
        } catch (Throwable) {
            // ignore
        }

        // 4. Session cookie when global middleware runs before session starts
        try {
            $cookieName = (string) config('session.cookie');
            $cookie = $request->cookies->get($cookieName);

            if (is_string($cookie) && $cookie !== '') {
                $encrypter = app('encrypter');
                $decrypted = $encrypter->decrypt($cookie, false);
                $sessionId = CookieValuePrefix::validate($cookieName, $decrypted, [$encrypter->getKey()]);

                if (is_string($sessionId) && $sessionId !== '') {
                    $driver = config('session.driver', 'database');
                    if ($driver === 'database') {
                        $table = config('session.table', 'sessions');
                        $userId = DB::table($table)->where('id', $sessionId)->value('user_id');
                        if ($userId && ($user = ($this->userModel())::query()->find($userId))) {
                            $request->setUserResolver(fn () => $user);

                            return $user;
                        }
                    } else {
                        $handler = app('session')->driver()->getHandler();
                        $payload = $handler->read($sessionId);
                        if (is_string($payload) && $payload !== '') {
                            $data = @unserialize($payload);
                            if (is_array($data)) {
                                foreach ($data as $k => $v) {
                                    if (str_starts_with((string) $k, 'login_web_') && is_numeric($v)) {
                                        if ($user = ($this->userModel())::query()->find($v)) {
                                            $request->setUserResolver(fn () => $user);

                                            return $user;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable) {
            // ignore
        }

        return null;
    }

    /**
     * Check whether the request originates from an authenticated administrator.
     */
    public function isAdminRequest(Request $request): bool
    {
        $user = $this->resolveUser($request);
        if (! $user) {
            return false;
        }

        if (Gate::has('manage-security-monitor')) {
            return Gate::forUser($user)->allows('manage-security-monitor');
        }

        if (method_exists($user, 'isAdmin')) {
            return (bool) $user->isAdmin();
        }

        if (in_array($user->role ?? null, ['admin', 'superadmin'], true)) {
            return true;
        }

        return (bool) ($user->is_admin ?? false);
    }

    protected function userModel(): string
    {
        return config('security.user_model', "App\Models\User");
    }

    /**
     * Resolve the authenticated user ID without depending strictly on the
     * session middleware having already executed.
     */
    protected function resolveUserId(Request $request): ?int
    {
        try {
            return $this->resolveUser($request)?->getKey();
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Record a single event that is not derived from request inspection
     * (failed login, manual block, ...).
     *
     * @param  array<string, mixed>  $attributes
     */
    public function log(array $attributes): ?SecurityLog
    {
        if (! $this->enabled()) {
            return null;
        }

        try {
            return SecurityLog::create($attributes);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Block an IP/device once it crossed the configured threshold.
     */
    public function autoBlockIfNeeded(string $ip, ?string $deviceId = null, ?string $localIp = null): ?BlockedIp
    {
        $config = config('security.auto_block', []);

        if (! ($config['enabled'] ?? false) || $this->isWhitelisted($ip, $deviceId, $localIp)) {
            return null;
        }

        $scope = (string) ($config['scope'] ?? 'device');

        if ($scope === 'device' && empty($deviceId)) {
            $deviceId = $this->resolveDeviceId();
        }

        if (empty($localIp)) {
            $localIp = $this->resolveLocalIp();
        }

        $existing = $this->activeBlock($ip, $deviceId, $localIp);

        if ($existing !== null) {
            return $existing;
        }

        try {
            $threshold = max(1, (int) ($config['threshold'] ?? 3));
            $window = max(1, (int) ($config['window_minutes'] ?? 10));
            $levels = $config['levels'] ?? ['high', 'critical'];

            $query = SecurityLog::query()
                ->whereIn('threat_level', $levels)
                ->where('created_at', '>=', now()->subMinutes($window));

            if ($scope === 'device' && $deviceId) {
                $query->where(function (Builder $q) use ($deviceId, $localIp) {
                    $q->where('device_id', $deviceId);
                    if ($localIp) {
                        $q->orWhere('local_ip', $localIp);
                    }
                });
            } else {
                $query->where('ip_address', $ip);
            }

            $count = $query->count();

            if ($count < $threshold) {
                return null;
            }
        } catch (Throwable) {
            return null;
        }

        return $this->block($ip, [
            'device_id' => $deviceId,
            'local_ip' => $localIp,
            'block_scope' => $scope,
            'reason' => sprintf(
                'Diblokir otomatis: %d aktivitas berisiko terdeteksi dalam %d menit terakhir.'.($scope === 'device' ? ' (Hanya isolasi perangkat penyerang)' : ''),
                $count,
                $window
            ),
            'source' => 'automatic',
            'duration_hours' => (int) ($config['duration_hours'] ?? 24),
        ]);
    }

    /*
    |--------------------------------------------------------------------------
    | Reporting
    |--------------------------------------------------------------------------
    */

    /**
     * Summary numbers for the admin dashboard.
     *
     * @return array<string, int>
     */
    public function stats(): array
    {
        $startOfDay = now()->startOfDay();

        return [
            'total_logs' => SecurityLog::query()->count(),
            'logs_today' => SecurityLog::query()->where('created_at', '>=', $startOfDay)->count(),
            'critical_today' => SecurityLog::query()
                ->where('created_at', '>=', $startOfDay)
                ->where('threat_level', 'critical')
                ->count(),
            'blocked_attempts_today' => SecurityLog::query()
                ->where('created_at', '>=', $startOfDay)
                ->where('event_type', 'blocked_ip')
                ->count(),
            'unique_ips_today' => SecurityLog::query()
                ->where('created_at', '>=', $startOfDay)
                ->distinct()
                ->count('ip_address'),
            'active_blocks' => BlockedIp::query()->active()->count(),
            'total_blocks' => BlockedIp::query()->count(),
        ];
    }

    /**
     * Most frequent offenders within a time window.
     *
     * @return Collection<int, SecurityLog>
     */
    public function topAttackers(int $limit = 5, int $hours = 24)
    {
        return SecurityLog::query()
            ->selectRaw('ip_address, COUNT(*) as hits, MAX(threat_level) as level, MAX(created_at) as last_seen')
            ->where('created_at', '>=', now()->subHours($hours))
            ->groupBy('ip_address')
            ->orderByDesc('hits')
            ->limit($limit)
            ->get();
    }

    /**
     * Number of logs per severity level within a time window.
     *
     * @return array<string, int>
     */
    public function levelBreakdown(int $hours = 24): array
    {
        $counts = SecurityLog::query()
            ->selectRaw('threat_level, COUNT(*) as total')
            ->where('created_at', '>=', now()->subHours($hours))
            ->groupBy('threat_level')
            ->pluck('total', 'threat_level');

        $breakdown = [];

        foreach (SecurityLog::LEVELS as $level) {
            $breakdown[$level] = (int) ($counts[$level] ?? 0);
        }

        return $breakdown;
    }

    /*
    |--------------------------------------------------------------------------
    | Attack Trend (Chart)
    |--------------------------------------------------------------------------
    */

    /**
     * Tren percobaan serangan untuk grafik dashboard.
     *
     * - `week`  → 7 titik harian terakhir
     * - `month` → 30 titik harian terakhir
     * - `year`  → 12 titik bulanan terakhir
     *
     * Setiap titik memuat total serangan beserta rinciannya per tingkat
     * ancaman. Periode tanpa serangan tetap dikembalikan dengan nilai 0 agar
     * garis grafik tidak berlubang.
     *
     * @return array{range: string, granularity: string, total: int, peak: array{label: string, total: int}, points: array<int, array{key: string, label: string, tooltip: string, total: int, levels: array<string, int>}>}
     */
    public function attackTrend(string $range = 'week'): array
    {
        $range = in_array($range, self::TREND_RANGES, true) ? $range : 'week';
        $granularity = $range === 'year' ? 'month' : 'day';

        $start = $granularity === 'month'
            ? now()->startOfMonth()->subMonths(11)
            : now()->subDays($range === 'month' ? 29 : 6)->startOfDay();

        try {
            $rows = SecurityLog::query()
                ->selectRaw('DATE(created_at) as day, threat_level, COUNT(*) as total')
                ->where('created_at', '>=', $start)
                ->groupBy('day', 'threat_level')
                ->get();
        } catch (Throwable) {
            $rows = collect();
        }

        // Kelompokkan per hari terlebih dahulu (portable untuk semua driver),
        // lalu digulung ke bulanan saat rentangnya setahun.
        $buckets = [];

        foreach ($rows as $row) {
            $day = (string) $row->day;
            $key = $granularity === 'month' ? substr($day, 0, 7) : $day;
            $level = (string) $row->threat_level;
            $total = (int) $row->total;

            $buckets[$key]['total'] = ($buckets[$key]['total'] ?? 0) + $total;
            $buckets[$key]['levels'][$level] = ($buckets[$key]['levels'][$level] ?? 0) + $total;
        }

        $points = $granularity === 'month'
            ? $this->monthlyTrendPoints($start, $buckets)
            : $this->dailyTrendPoints($start, $range === 'month' ? 30 : 7, $buckets);

        $peak = ['label' => '-', 'total' => 0];

        foreach ($points as $point) {
            if ($point['total'] > $peak['total']) {
                $peak = ['label' => $point['label'], 'total' => $point['total']];
            }
        }

        return [
            'range' => $range,
            'granularity' => $granularity,
            'total' => array_sum(array_column($points, 'total')),
            'peak' => $peak,
            'points' => $points,
        ];
    }

    /**
     * @param  array<string, array{total?: int, levels?: array<string, int>}>  $buckets
     * @return array<int, array{key: string, label: string, tooltip: string, total: int, levels: array<string, int>}>
     */
    protected function dailyTrendPoints(CarbonInterface $start, int $days, array $buckets): array
    {
        $points = [];

        for ($offset = 0; $offset < $days; $offset++) {
            $date = $start->copy()->addDays($offset);
            $key = $date->toDateString();

            $points[] = $this->trendPoint(
                $key,
                $date->locale('id')->translatedFormat('d M'),
                $date->locale('id')->translatedFormat('l, d F Y'),
                $buckets[$key] ?? [],
            );
        }

        return $points;
    }

    /**
     * @param  array<string, array{total?: int, levels?: array<string, int>}>  $buckets
     * @return array<int, array{key: string, label: string, tooltip: string, total: int, levels: array<string, int>}>
     */
    protected function monthlyTrendPoints(CarbonInterface $start, array $buckets): array
    {
        $points = [];

        for ($offset = 0; $offset < 12; $offset++) {
            $date = $start->copy()->addMonthsNoOverflow($offset);
            $key = $date->format('Y-m');

            $points[] = $this->trendPoint(
                $key,
                $date->locale('id')->translatedFormat('M Y'),
                $date->locale('id')->translatedFormat('F Y'),
                $buckets[$key] ?? [],
            );
        }

        return $points;
    }

    /**
     * @param  array{total?: int, levels?: array<string, int>}  $bucket
     * @return array{key: string, label: string, tooltip: string, total: int, levels: array<string, int>}
     */
    protected function trendPoint(string $key, string $label, string $tooltip, array $bucket): array
    {
        $levels = [];

        foreach (SecurityLog::LEVELS as $level) {
            $levels[$level] = (int) ($bucket['levels'][$level] ?? 0);
        }

        return [
            'key' => $key,
            'label' => $label,
            'tooltip' => $tooltip,
            'total' => (int) ($bucket['total'] ?? 0),
            'levels' => $levels,
        ];
    }
}
