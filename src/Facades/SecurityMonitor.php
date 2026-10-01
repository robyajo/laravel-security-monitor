<?php

namespace Internal\SecurityMonitor\Facades;

use Illuminate\Support\Facades\Facade;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * @method static bool enabled()
 * @method static bool enforcementEnabled()
 * @method static string resolveClientIp(\Illuminate\Http\Request $request)
 * @method static string|null resolveDeviceId(\Illuminate\Http\Request $request)
 * @method static string|null resolveLocalIp(\Illuminate\Http\Request $request)
 * @method static bool isWhitelisted(?string $ip, ?string $deviceId = null, ?string $localIp = null)
 * @method static bool isBlocked(?string $ip, ?string $deviceId = null, ?string $localIp = null)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp|null activeBlock(?string $ip, ?string $deviceId = null, ?string $localIp = null)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp block(string $ip, array $attributes = [])
 * @method static void unblock(\Internal\SecurityMonitor\Models\BlockedIp $block)
 * @method static bool unblockIp(?string $ip, ?string $deviceId = null)
 * @method static void logBlockedAttempt(\Internal\SecurityMonitor\Models\BlockedIp $block, \Illuminate\Http\Request $request)
 * @method static array inspect(\Illuminate\Http\Request $request)
 * @method static array inspectRaw(string $path, string $query = '', string $userAgent = '', string $body = '', string $referer = '')
 * @method static array inspectHaystacks(array $haystacks)
 * @method static bool instantBlockEnabled()
 * @method static bool shouldInstantBlock(array $threats)
 * @method static string|null instantBlockReason(array $threats)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp|null blockImmediately(string $ip, array $threats, ?string $deviceId = null, ?string $localIp = null)
 * @method static \Internal\SecurityMonitor\Models\SecurityLog|null record(\Illuminate\Http\Request $request, array $threats, ?string $action = null)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null resolveUser(\Illuminate\Http\Request $request)
 * @method static bool isAdminRequest(\Illuminate\Http\Request $request)
 * @method static \Internal\SecurityMonitor\Models\SecurityLog|null log(array $attributes)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp|null autoBlockIfNeeded(string $ip, ?string $deviceId = null, ?string $localIp = null)
 * @method static array stats()
 * @method static \Illuminate\Support\Collection<int, \Internal\SecurityMonitor\Models\SecurityLog> topAttackers(int $limit = 5, int $hours = 24)
 * @method static array levelBreakdown(int $hours = 24)
 * @method static array attackTrend(string $range = 'week')
 *
 * @see \Internal\SecurityMonitor\Services\SecurityMonitorService
 */
class SecurityMonitor extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SecurityMonitorService::class;
    }
}
