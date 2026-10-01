<?php

namespace Internal\SecurityMonitor\Facades;

use Illuminate\Support\Facades\Facade;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * @method static bool enabled()
 * @method static bool enforcementEnabled()
 * @method static string resolveClientIp(\Illuminate\Http\Request \)
 * @method static string|null resolveDeviceId(\Illuminate\Http\Request \)
 * @method static string|null resolveLocalIp(\Illuminate\Http\Request \)
 * @method static bool isWhitelisted(?string \, ?string \ = null, ?string \ = null)
 * @method static bool isBlocked(?string \, ?string \ = null, ?string \ = null)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp|null activeBlock(?string \, ?string \ = null, ?string \ = null)
 * @method static \Internal\SecurityMonitor\Models\BlockedIp block(string \, array \ = [])
 * @method static void unblock(\Internal\SecurityMonitor\Models\BlockedIp \)
 * @method static bool unblockIp(?string \, ?string \ = null)
 * @method static array inspect(\Illuminate\Http\Request \)
 * @method static \Internal\SecurityMonitor\Models\SecurityLog|null record(\Illuminate\Http\Request \, array \, ?string \ = null)
 * @method static \Internal\SecurityMonitor\Models\SecurityLog|null log(array \)
 * @method static array stats()
 * @method static array attackTrend(string \ = 'week')
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
