<?php

use Illuminate\Support\Facades\Route;
use Internal\SecurityMonitor\Http\Controllers\Api\BlockedIpApiController;
use Internal\SecurityMonitor\Http\Controllers\Api\CaptchaApiController;
use Internal\SecurityMonitor\Http\Controllers\Api\IpUnblockRequestApiController;
use Internal\SecurityMonitor\Http\Controllers\Api\SecurityLogApiController;
use Internal\SecurityMonitor\Http\Controllers\Api\ServerSecurityApiController;
use Internal\SecurityMonitor\Http\Controllers\Api\UserSessionApiController;

/*
|--------------------------------------------------------------------------
| Security Monitor Headless REST API Routes
|--------------------------------------------------------------------------
*/

$prefix = config('security.routes.prefix', 'api/security');
$middleware = (array) config('security.routes.middleware', ['api']);
$authMiddleware = (array) config('security.routes.auth_middleware', ['auth']);
$adminMiddleware = (array) config('security.routes.admin_middleware', [
    'Internal\SecurityMonitor\Http\Middleware\EnsureSecurityAdmin',
]);

Route::prefix($prefix)->middleware($middleware)->name('security.')->group(function () use ($authMiddleware, $adminMiddleware) {
    // Public Endpoints
    Route::get('captcha', [CaptchaApiController::class, 'image'])->name('captcha.image');
    Route::post('captcha/verify', [CaptchaApiController::class, 'verify'])->name('captcha.verify');

    Route::post('unblock-tickets/submit', [IpUnblockRequestApiController::class, 'submit'])->name('unblock-tickets.submit');
    Route::get('unblock-tickets/check/{ticketNumber}', [IpUnblockRequestApiController::class, 'checkStatus'])->name('unblock-tickets.check');

    // Authenticated User Endpoints
    Route::middleware($authMiddleware)->group(function () {
        Route::post('trusted-ips/save-my-ip', [UserSessionApiController::class, 'storeMyIp'])->name('trusted-ips.store-my-ip');
    });

    // Admin Protected Endpoints
    Route::middleware(array_merge($authMiddleware, $adminMiddleware))->group(function () {
        // Logs
        Route::get('logs', [SecurityLogApiController::class, 'index'])->name('logs.index');
        Route::delete('logs/clear', [SecurityLogApiController::class, 'clear'])->name('logs.clear');
        Route::delete('logs/{id}', [SecurityLogApiController::class, 'destroy'])->name('logs.destroy');

        // Blocked IPs
        Route::get('blocked-ips', [BlockedIpApiController::class, 'index'])->name('blocked-ips.index');
        Route::post('blocked-ips', [BlockedIpApiController::class, 'store'])->name('blocked-ips.store');
        Route::get('blocked-ips/{id}', [BlockedIpApiController::class, 'show'])->name('blocked-ips.show');
        Route::patch('blocked-ips/{id}/toggle', [BlockedIpApiController::class, 'toggle'])->name('blocked-ips.toggle');
        Route::delete('blocked-ips/{id}', [BlockedIpApiController::class, 'destroy'])->name('blocked-ips.destroy');

        // Server Security & Audit
        Route::get('server', [ServerSecurityApiController::class, 'index'])->name('server.index');
        Route::post('server/baseline', [ServerSecurityApiController::class, 'storeBaseline'])->name('server.baseline');
        Route::delete('server/baseline', [ServerSecurityApiController::class, 'destroyBaseline'])->name('server.baseline.destroy');
        Route::delete('server/suspicious-files', [ServerSecurityApiController::class, 'destroySuspiciousFile'])->name('server.suspicious-files.destroy');
        Route::delete('lockouts/{id}', [ServerSecurityApiController::class, 'releaseLockout'])->name('lockouts.destroy');

        // User Sessions & Trusted IPs
        Route::get('user-sessions', [UserSessionApiController::class, 'index'])->name('user-sessions.index');
        Route::get('user-sessions/realtime', [UserSessionApiController::class, 'realtime'])->name('user-sessions.realtime');
        Route::get('user-sessions/{id}', [UserSessionApiController::class, 'show'])->name('user-sessions.show');
        Route::delete('user-sessions/{id}', [UserSessionApiController::class, 'destroy'])->name('user-sessions.destroy');
        Route::delete('user-sessions/session/{sessionId}', [UserSessionApiController::class, 'destroySession'])->name('user-sessions.destroy-session');
        Route::delete('trusted-ips/{id}', [UserSessionApiController::class, 'destroyTrustedIp'])->name('trusted-ips.destroy');

        // Unblock Tickets Management
        Route::get('unblock-tickets', [IpUnblockRequestApiController::class, 'index'])->name('unblock-tickets.index');
        Route::post('unblock-tickets/{id}/respond', [IpUnblockRequestApiController::class, 'respond'])->name('unblock-tickets.respond');
        Route::delete('unblock-tickets/{id}', [IpUnblockRequestApiController::class, 'destroy'])->name('unblock-tickets.destroy');
    });
});
