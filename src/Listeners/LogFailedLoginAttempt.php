<?php

namespace Internal\SecurityMonitor\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Internal\SecurityMonitor\Services\LoginThrottleService;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Throwable;

/**
 * Stores every failed authentication attempt so brute force attacks are
 * visible in the security log and can trigger the automatic IP block.
 *
 * Kegagalan yang sama juga dihitung oleh LoginThrottleService untuk menerapkan
 * cooldown bertingkat (3x gagal → 1 menit, 6x → 2 menit, dan seterusnya).
 */
class LogFailedLoginAttempt
{
    public function __construct(
        protected SecurityMonitorService $service,
        protected LoginThrottleService $throttle,
        protected Request $request,
    ) {}

    public function handle(Failed $event): void
    {
        $email = $event->credentials['email'] ?? $event->credentials['username'] ?? null;
        $ip = $this->request->ip();

        // Cooldown bertingkat berlaku juga pada IP yang masuk whitelist, karena
        // ini proteksi akun (bukan proteksi IP).
        try {
            $this->throttle->registerFailure(is_string($email) ? $email : null, $ip);
        } catch (Throwable) {
            // Proteksi akun tidak boleh menggagalkan respons login.
        }

        if (! $this->service->enabled() || $this->service->isWhitelisted($ip)) {
            return;
        }

        $this->service->log([
            'ip_address' => (string) ($ip ?? 'unknown'),
            'user_id' => $event->user?->getKey(),
            'event_type' => 'login_failed',
            'threat_level' => 'medium',
            'method' => Str::limit($this->request->method(), 10, ''),
            'path' => '/'.ltrim($this->request->path(), '/'),
            'full_url' => Str::limit($this->request->fullUrl(), 2000, ''),
            'rule_label' => 'Percobaan login gagal',
            'evidence' => 'Login gagal untuk akun: '.Str::limit((string) $email, 120, ''),
            'user_agent' => Str::limit((string) $this->request->userAgent(), 500, ''),
            'referer' => Str::limit((string) $this->request->headers->get('referer'), 500, ''),
            'action_taken' => 'logged',
        ]);

        try {
            $this->service->autoBlockIfNeeded((string) $ip);
        } catch (Throwable) {
            // Brute force protection must never break the login response.
        }
    }
}
