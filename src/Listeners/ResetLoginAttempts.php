<?php

namespace Internal\SecurityMonitor\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Gate;
use Internal\SecurityMonitor\Services\LoginThrottleService;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Mengosongkan riwayat kegagalan login setelah pengguna berhasil masuk,
 * sehingga cooldown bertingkat tidak "menempel" pada pengguna yang sah,
 * serta otomatis membuka blokir IP apabila yang login adalah admin.
 */
class ResetLoginAttempts
{
    public function __construct(
        protected LoginThrottleService $throttle,
        protected SecurityMonitorService $security,
    ) {}

    public function handle(Login $event): void
    {
        $ip = request()->ip();
        $this->throttle->registerSuccess($event->user?->email, $ip);

        // Buka blokir IP otomatis bila yang login adalah administrator.
        if (
            $ip &&
            $event->user &&
            Gate::forUser($event->user)->allows('manage-security-monitor')
        ) {
            $this->security->unblockIp($ip);
        }
    }
}
