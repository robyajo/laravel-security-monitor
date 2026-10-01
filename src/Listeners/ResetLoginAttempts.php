<?php

namespace Internal\SecurityMonitor\Listeners;


use Internal\SecurityMonitor\Services\LoginThrottleService;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Illuminate\Auth\Events\Login;

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
        $ip = request()?->ip();
        $this->throttle->registerSuccess($event->user?->email, $ip);

        if ($event->user instanceof User && $event->user->isAdmin() && $ip) {
            $this->security->unblockIp($ip);
        }
    }
}
