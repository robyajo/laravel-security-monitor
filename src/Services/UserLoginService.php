<?php

namespace Internal\SecurityMonitor\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;
use Throwable;

class UserLoginService
{
    /**
     * Record a user login with parsed device, OS, browser, and location.
     */
    public function recordLogin(Authenticatable $user, Request $request): UserLogin
    {
        $securityService = app(SecurityMonitorService::class);
        $ip = $securityService->resolveClientIp($request);
        $deviceId = $securityService->resolveDeviceId($request);
        $localIp = $securityService->resolveLocalIp($request);
        $userAgent = (string) ($request->userAgent() ?? '');
        $sessionId = session()->getId();

        $clientInfo = $this->parseUserAgent($userAgent);
        $geo = $this->resolveLocation($ip);

        return UserLogin::create([
            'user_id' => $user->id,
            'session_id' => $sessionId,
            'ip_address' => $ip,
            'local_ip' => $localIp,
            'device_id' => $deviceId,
            'user_agent' => $userAgent,
            'device_type' => $clientInfo['device'],
            'operating_system' => $clientInfo['os'],
            'browser' => $clientInfo['browser'],
            'city' => $geo['city'] ?? null,
            'region' => $geo['region'] ?? null,
            'country' => $geo['country'] ?? null,
            'country_code' => $geo['country_code'] ?? null,
            'latitude' => $geo['latitude'] ?? null,
            'longitude' => $geo['longitude'] ?? null,
            'isp' => $geo['isp'] ?? null,
            'login_at' => now(),
            'last_activity_at' => now(),
        ]);
    }

    /**
     * Update last activity for an active user session.
     */
    public function updateActivity(int $userId, string $ip, ?string $sessionId = null): void
    {
        try {
            $query = UserLogin::query()
                ->where('user_id', $userId)
                ->whereNull('logout_at');

            if ($sessionId) {
                $query->where('session_id', $sessionId);
            } else {
                $query->where('ip_address', $ip);
            }

            $login = $query->latest('id')->first();

            if ($login) {
                $login->update(['last_activity_at' => now()]);
            }
        } catch (Throwable) {
            // Ignore database errors during heartbeat to preserve user experience
        }
    }

    /**
     * Parse User-Agent string to extract Operating System, Browser, and Device.
     *
     * @return array{os: string, browser: string, device: string}
     */
    public function parseUserAgent(?string $userAgent): array
    {
        if (empty($userAgent)) {
            return [
                'os' => 'Unknown OS',
                'browser' => 'Unknown Browser',
                'device' => 'desktop',
            ];
        }

        $os = 'Unknown OS';
        $browser = 'Unknown Browser';
        $device = 'desktop';

        // 1. Device Type Detection
        if (preg_match('/(tablet|ipad|playbook|silk)|(android(?!.*mobile))/i', $userAgent)) {
            $device = 'tablet';
        } elseif (preg_match('/(mobile|iphone|ipod|blackberry|opera mini|iemobile|mobile.*firefox)/i', $userAgent)) {
            $device = 'mobile';
        }

        // 2. Operating System Detection
        if (preg_match('/windows nt 10\.0/i', $userAgent)) {
            $os = 'Windows 11 / 10';
        } elseif (preg_match('/windows nt 6\.3/i', $userAgent)) {
            $os = 'Windows 8.1';
        } elseif (preg_match('/windows nt 6\.2/i', $userAgent)) {
            $os = 'Windows 8';
        } elseif (preg_match('/windows nt 6\.1/i', $userAgent)) {
            $os = 'Windows 7';
        } elseif (preg_match('/windows/i', $userAgent)) {
            $os = 'Windows';
        } elseif (preg_match('/android\s*([0-9\.]+)?/i', $userAgent, $matches)) {
            $os = 'Android'.(! empty($matches[1]) ? ' '.$matches[1] : '');
        } elseif (preg_match('/(iphone|ipad|ipod)/i', $userAgent)) {
            if (preg_match('/os\s*([0-9_]+)/i', $userAgent, $matches)) {
                $os = 'iOS '.str_replace('_', '.', $matches[1]);
            } else {
                $os = 'iOS';
            }
        } elseif (preg_match('/macintosh|mac os x/i', $userAgent)) {
            if (preg_match('/mac os x\s*([0-9_]+)/i', $userAgent, $matches)) {
                $os = 'macOS '.str_replace('_', '.', $matches[1]);
            } else {
                $os = 'macOS';
            }
        } elseif (preg_match('/cros/i', $userAgent)) {
            $os = 'Chrome OS';
        } elseif (preg_match('/ubuntu/i', $userAgent)) {
            $os = 'Ubuntu Linux';
        } elseif (preg_match('/linux/i', $userAgent)) {
            $os = 'Linux';
        }

        // 3. Browser Detection
        if (preg_match('/edg(e)?\/([0-9\.]+)/i', $userAgent, $matches)) {
            $browser = 'Microsoft Edge '.explode('.', $matches[2])[0];
        } elseif (preg_match('/opr\/([0-9\.]+)/i', $userAgent, $matches) || preg_match('/opera\/([0-9\.]+)/i', $userAgent, $matches)) {
            $browser = 'Opera '.explode('.', $matches[1])[0];
        } elseif (preg_match('/samsungbrowser\/([0-9\.]+)/i', $userAgent, $matches)) {
            $browser = 'Samsung Internet '.explode('.', $matches[1])[0];
        } elseif (preg_match('/chrome\/([0-9\.]+)/i', $userAgent, $matches)) {
            $browser = 'Google Chrome '.explode('.', $matches[1])[0];
        } elseif (preg_match('/firefox\/([0-9\.]+)/i', $userAgent, $matches)) {
            $browser = 'Mozilla Firefox '.explode('.', $matches[1])[0];
        } elseif (preg_match('/version\/([0-9\.]+).*safari/i', $userAgent, $matches)) {
            $browser = 'Apple Safari '.explode('.', $matches[1])[0];
        } elseif (preg_match('/safari\/([0-9\.]+)/i', $userAgent)) {
            $browser = 'Apple Safari';
        }

        return [
            'os' => $os,
            'browser' => $browser,
            'device' => $device,
        ];
    }

    /**
     * Resolve IP Geolocation info.
     *
     * @return array{city: string|null, region: string|null, country: string|null, country_code: string|null, latitude: float|null, longitude: float|null, isp: string|null}
     */
    public function resolveLocation(string $ip): array
    {
        $isLocal = in_array($ip, ['127.0.0.1', '::1'], true)
            || preg_match('/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/', $ip);

        if ($isLocal) {
            return [
                'city' => 'Pekanbaru',
                'region' => 'Riau',
                'country' => 'Indonesia',
                'country_code' => 'ID',
                'latitude' => 0.5071,
                'longitude' => 101.4478,
                'isp' => 'Jaringan Lokal / Intranet',
            ];
        }

        return Cache::remember("geoip:{$ip}", now()->addDays(30), function () use ($ip) {
            try {
                $response = Http::timeout(2)
                    ->get("http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp");

                if ($response->successful() && ($response->json('status') === 'success')) {
                    $data = $response->json();

                    return [
                        'city' => $data['city'] ?? null,
                        'region' => $data['regionName'] ?? null,
                        'country' => $data['country'] ?? null,
                        'country_code' => $data['countryCode'] ?? null,
                        'latitude' => isset($data['lat']) ? (float) $data['lat'] : null,
                        'longitude' => isset($data['lon']) ? (float) $data['lon'] : null,
                        'isp' => $data['isp'] ?? null,
                    ];
                }
            } catch (Throwable) {
                // Return generic fallback on timeout or error
            }

            return [
                'city' => null,
                'region' => null,
                'country' => 'Indonesia',
                'country_code' => 'ID',
                'latitude' => null,
                'longitude' => null,
                'isp' => null,
            ];
        });
    }

    /**
     * Check if an IP/device is trusted for a specific user.
     */
    public function isIpTrusted(string $ip, int $userId, ?string $deviceId = null, ?string $localIp = null): bool
    {
        return TrustedIp::isTrusted($ip, $userId, $deviceId, $localIp);
    }

    /**
     * Check if an IP/device is trusted across the system (used for firewall whitelisting).
     */
    public function isIpGloballyTrusted(string $ip, ?string $deviceId = null, ?string $localIp = null): bool
    {
        return TrustedIp::isAnyTrusted($ip, $deviceId, $localIp);
    }

    /**
     * Save current IP and device as trusted for the given user.
     */
    public function trustIp(User $user, string $ip, ?string $deviceName = null, ?string $userAgent = null, ?string $localIp = null, ?string $deviceId = null): TrustedIp
    {
        $clientInfo = $this->parseUserAgent($userAgent ?? request()?->userAgent());
        $geo = $this->resolveLocation($ip);

        $locationParts = array_filter([$geo['city'] ?? null, $geo['region'] ?? null, $geo['country'] ?? null]);
        $locationStr = ! empty($locationParts) ? implode(', ', $locationParts) : 'Indonesia';

        $defaultName = $deviceName ?: ($clientInfo['os'].' - '.$clientInfo['browser']);

        $matchCriteria = [
            'user_id' => $user->id,
            'ip_address' => $ip,
        ];

        if ($deviceId) {
            $matchCriteria['device_id'] = $deviceId;
        }

        return TrustedIp::updateOrCreate(
            $matchCriteria,
            [
                'local_ip' => $localIp,
                'device_name' => $defaultName,
                'operating_system' => $clientInfo['os'],
                'browser' => $clientInfo['browser'],
                'location' => $locationStr,
                'is_active' => true,
                'verified_at' => now(),
            ]
        );
    }

    /**
     * Get real-time active users accessing the application right now.
     *
     * @return array{
     *     count: int,
     *     is_multi_user: bool,
     *     users: array<int, array<string, mixed>>
     * }
     */
    public function getRealtimeActiveUsers(): array
    {
        $fiveMinutesAgo = now()->subMinutes(5)->getTimestamp();

        // 1. Fetch active session entries from sessions table
        $activeSessions = DB::table('sessions')
            ->whereNotNull('user_id')
            ->where('last_activity', '>=', $fiveMinutesAgo)
            ->get();

        $userIds = $activeSessions->pluck('user_id')->unique()->values()->all();

        // 2. Fetch corresponding users
        $users = User::query()
            ->whereIn('id', $userIds)
            ->get()
            ->keyBy('id');

        $activeList = [];

        foreach ($activeSessions as $session) {
            $user = $users->get($session->user_id);
            if (! $user) {
                continue;
            }

            $clientInfo = $this->parseUserAgent($session->user_agent);
            $lastActivity = Carbon::createFromTimestamp($session->last_activity);

            $activeList[] = [
                'session_id' => $session->id,
                'user_id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
                'ip_address' => $session->ip_address,
                'operating_system' => $clientInfo['os'],
                'browser' => $clientInfo['browser'],
                'device_type' => $clientInfo['device'],
                'last_activity' => $lastActivity->toIso8601String(),
                'last_activity_human' => $lastActivity->diffForHumans(),
            ];
        }

        $uniqueUserCount = count($userIds);

        return [
            'count' => $uniqueUserCount,
            'is_multi_user' => $uniqueUserCount >= 2,
            'users' => $activeList,
        ];
    }
}
