<?php

namespace Internal\SecurityMonitor\Http\Middleware;

use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rejects every request coming from an IP that has been blocked by an
 * administrator or by the automatic blocker.
 */
class BlockIpAddress
{
    public function handle(Request $request, Closure $next): Response
    {
        $service = app(SecurityMonitorService::class);
        $ip = $service->resolveClientIp($request);
        $deviceId = $service->resolveDeviceId($request);
        $localIp = $service->resolveLocalIp($request);

        if (
            !$service->enforcementEnabled() ||
            $service->isWhitelisted($ip, $deviceId, $localIp)
        ) {
            return $next($request);
        }

        // Requests from authenticated administrators are never blocked.
        // If their IP/device was previously blocked, clear the block automatically.
        if ($service->isAdminRequest($request)) {
            $service->unblockIp($ip, $deviceId);

            return $next($request);
        }

        // Allow access to auth routes so administrators can log in even if their IP was blocked.
        if ($this->isAuthRoute($request)) {
            return $next($request);
        }

        $block = $service->activeBlock($ip, $deviceId, $localIp);

        if ($block === null) {
            return $next($request);
        }

        $service->logBlockedAttempt($block, $request);

        return self::blockedResponse($request, $block);
    }

    /**
     * Determine if the request is targeting an authentication or verification route.
     */
    protected function isAuthRoute(Request $request): bool
    {
        return $request->is(
            "login",
            "login/*",
            "two-factor-challenge",
            "two-factor-challenge/*",
            "captcha",
            "forgot-password",
            "reset-password",
            "reset-password/*",
            "assets/*",
            "favicon.*",
            "security/unblock-tickets/submit",
            "security/unblock-tickets/check/*",
        );
    }

    /**
     * Build the 403 response for a blocked client (JSON for API calls, rich view for web).
     */
    public static function blockedResponse(
        Request $request,
        mixed $block = null,
    ): Response {
        $service = app(SecurityMonitorService::class);
        $ip = $service->resolveClientIp($request);
        $deviceId = $service->resolveDeviceId($request);
        $localIp = $service->resolveLocalIp($request);

        if (is_string($block)) {
            $reason = $block;
            $blockModel = $service->activeBlock($ip, $deviceId, $localIp);
        } elseif ($block instanceof BlockedIp) {
            $reason = $block->reason;
            $blockModel = $block;
        } else {
            $blockModel = $service->activeBlock($ip, $deviceId, $localIp);
            $reason =
                $blockModel?->reason ?? "Aktivitas mencurigakan terdeteksi";
        }

        $referenceId =
            "SEC-" .
            strtoupper(
                substr(
                    md5($ip . ($blockModel?->id ?? "manual") . date("Ymd")),
                    0,
                    8,
                ),
            );
        $message =
            "Akses ditolak. Alamat IP atau perangkat Anda diblokir karena terdeteksi aktivitas mencurigakan. " .
            "Hubungi administrator apabila Anda merasa ini sebuah kesalahan.";

        if ($request->expectsJson() || $request->is("api/*")) {
            return response()->json(
                [
                    "success" => false,
                    "message" => $message,
                    "reason" => $reason,
                    "ip_address" => $ip,
                    "device_id" => $deviceId,
                    "local_ip" => $localIp,
                    "block_scope" => $blockModel?->block_scope ?? "ip",
                    "reference_id" => $referenceId,
                    "expires_at" => $blockModel?->expires_at?->toIso8601String(),
                    "blocked" => true,
                ],
                403,
            );
        }

        if (view()->exists("errors.blocked")) {
            return response()->view(
                "errors.blocked",
                [
                    "ip" => $ip,
                    "deviceId" => $deviceId,
                    "localIp" => $localIp,
                    "block" => $blockModel ?? ($block ?? null),
                    "reason" => $reason ?? $message,
                    "message" => $message,
                    "blockedAt" => now(),
                    "expiresAt" => null,
                    "remaining" => null,
                    "referenceId" => $referenceId,
                    "supportEmail" => config(
                        "security.support_email",
                        "security@example.com",
                    ),
                ],
                403,
            );
        }

        return response(
            "<h1>403 - Akses Ditolak</h1><p>{$message}</p><p>Ref: {$referenceId}</p>",
            403,
            ["Content-Type" => "text/html; charset=utf-8"],
        );
    }

    /**
     * Build a 403 response, using JSON when the client expects it.
     *
     * @param  array<string, mixed>  $extra
     */
    public static function forbiddenResponse(
        Request $request,
        string $message,
        ?string $reason = null,
        array $extra = [],
    ): Response {
        $service = app(SecurityMonitorService::class);
        $ip = $service->resolveClientIp($request);
        $deviceId = $service->resolveDeviceId($request);
        $localIp = $service->resolveLocalIp($request);
        $referenceId =
            "SEC-" . strtoupper(substr(md5($ip . date("Ymd")), 0, 8));

        if ($request->expectsJson() || $request->is("api/*")) {
            return response()->json(
                [
                    "success" => false,
                    "message" => $message,
                    "reason" => $reason,
                    "ip_address" => $ip,
                    "device_id" => $deviceId,
                    "local_ip" => $localIp,
                    "reference_id" => $referenceId,
                    "blocked" => true,
                    ...$extra,
                ],
                403,
            );
        }

        if (view()->exists("errors.blocked")) {
            return response()->view(
                "errors.blocked",
                [
                    "ip" => $ip,
                    "deviceId" => $deviceId,
                    "localIp" => $localIp,
                    "block" => null,
                    "reason" => $reason ?? $message,
                    "message" => $message,
                    "blockedAt" => now(),
                    "expiresAt" => null,
                    "remaining" => null,
                    "referenceId" => $referenceId,
                    "supportEmail" => config(
                        "security.support_email",
                        "security@example.com",
                    ),
                ],
                403,
            );
        }

        return response(
            "<h1>403 - Akses Ditolak</h1><p>{$message}</p><p>Ref: {$referenceId}</p>",
            403,
            ["Content-Type" => "text/html; charset=utf-8"],
        );
    }
}
