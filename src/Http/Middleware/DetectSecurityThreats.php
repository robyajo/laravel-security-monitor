<?php

namespace Internal\SecurityMonitor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Inspects every incoming request for attack payloads (SQL injection, XSS,
 * path traversal, ...), stores the findings and blocks repeat offenders.
 */
class DetectSecurityThreats
{
    public function __construct(protected SecurityMonitorService $service) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->service->enabled()) {
            return $next($request);
        }

        try {
            $threats = $this->service->inspect($request);
        } catch (Throwable) {
            $threats = [];
        }

        if ($threats === []) {
            return $next($request);
        }

        $ip = $this->service->resolveClientIp($request);
        $deviceId = $this->service->resolveDeviceId($request);
        $localIp = $this->service->resolveLocalIp($request);

        // An authenticated administrator is never blocked or rejected.
        // Threats are logged for audit purposes with 'admin_bypass'.
        if ($this->service->isAdminRequest($request)) {
            $this->service->record($request, $threats, 'admin_bypass');

            return $next($request);
        }

        $log = $this->service->record($request, $threats);

        // A whitelisted IP/device is only logged for the record, never blocked.
        if ($this->service->isWhitelisted($ip, $deviceId, $localIp)) {
            return $next($request);
        }

        // Zero tolerance signatures (webshell upload, null byte, path
        // traversal, .htaccess/.env probing, SSTI, scanners, injected PHP)
        // block the client on the very first hit.
        if ($this->service->shouldInstantBlock($threats)) {
            $block = $this->service->blockImmediately($ip, $threats, $deviceId, $localIp);

            $this->markLogAsBlocked($log, 'instant_block');

            return BlockIpAddress::blockedResponse($request, $block?->reason);
        }

        $block = $this->service->autoBlockIfNeeded($ip, $deviceId, $localIp);

        if ($block !== null) {
            $this->markLogAsBlocked($log);

            return BlockIpAddress::blockedResponse($request, $block->reason);
        }

        if ($this->shouldReject($threats)) {
            $this->markLogAsBlocked($log, 'rejected');

            return BlockIpAddress::forbiddenResponse(
                $request,
                'Permintaan ditolak karena mengandung payload yang tidak diizinkan.',
                'Payload berbahaya terdeteksi.',
            );
        }

        return $next($request);
    }

    /**
     * Reject the request outright when it carries a critical payload and the
     * "block_suspicious_requests" option is enabled.
     *
     * @param  array<int, array{rule: string, label: string, level: string, evidence: string}>  $threats
     */
    protected function shouldReject(array $threats): bool
    {
        if (! config('security.block_suspicious_requests', false)) {
            return false;
        }

        foreach ($threats as $threat) {
            if (($threat['level'] ?? 'low') === 'critical') {
                return true;
            }
        }

        return false;
    }

    protected function markLogAsBlocked(?SecurityLog $log, string $action = 'auto_blocked'): void
    {
        if ($log === null) {
            return;
        }

        try {
            $log->forceFill([
                'was_blocked' => true,
                'action_taken' => $action,
            ])->save();
        } catch (Throwable) {
            // Ignore: the audit entry is already stored.
        }
    }
}
