<?php

use Illuminate\Support\Facades\Route;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\BlockedIpController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\LogController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\OverviewController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\ServerController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\SessionController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\SettingController;
use Internal\SecurityMonitor\Http\Controllers\Dashboard\TicketController;

/*
|--------------------------------------------------------------------------
| Security Monitor Inertia + React Dashboard Routes
|--------------------------------------------------------------------------
|
| Rute ini hanya dimuat ketika "security.dashboard.enabled" bernilai true,
| "security.dashboard.driver" disetel ke "react", dan paket Inertia tersedia.
| Seluruh halaman dilindungi middleware autentikasi dan, secara default, juga
| middleware "security.admin" (Gate "manage-security-monitor").
|
*/

$prefix = config('security.dashboard.prefix', 'security');
$middleware = array_filter((array) config('security.dashboard.middleware', ['web', 'auth']));
$adminMiddleware = array_filter((array) config('security.dashboard.admin_middleware', []));

Route::middleware(array_merge($middleware, $adminMiddleware))
    ->prefix($prefix)
    ->name('security.dashboard.')
    ->group(function (): void {
        Route::get('/', OverviewController::class)->name('overview');

        // Security logs
        Route::get('logs', [LogController::class, 'index'])->name('logs');
        Route::delete('logs', [LogController::class, 'clear'])->name('logs.clear');
        Route::delete('logs/{id}', [LogController::class, 'destroy'])->whereNumber('id')->name('logs.destroy');

        // Blocked IPs
        Route::get('blocked-ips', [BlockedIpController::class, 'index'])->name('blocked-ips');
        Route::post('blocked-ips', [BlockedIpController::class, 'store'])->name('blocked-ips.store');
        Route::patch('blocked-ips/{id}/toggle', [BlockedIpController::class, 'toggle'])->whereNumber('id')->name('blocked-ips.toggle');
        Route::delete('blocked-ips/{id}', [BlockedIpController::class, 'destroy'])->whereNumber('id')->name('blocked-ips.destroy');

        // Server audit
        Route::get('server', [ServerController::class, 'index'])->name('server');
        Route::post('server/baseline', [ServerController::class, 'createBaseline'])->name('server.baseline');
        Route::delete('server/baseline', [ServerController::class, 'deleteBaseline'])->name('server.baseline.destroy');
        Route::delete('server/suspicious-files', [ServerController::class, 'deleteSuspiciousFile'])->name('server.suspicious-files.destroy');
        Route::delete('lockouts/{id}', [ServerController::class, 'releaseLockout'])->whereNumber('id')->name('lockouts.destroy');

        // User sessions & trusted IPs
        Route::get('sessions', [SessionController::class, 'index'])->name('sessions');
        Route::delete('user-sessions/{id}', [SessionController::class, 'destroyLogin'])->whereNumber('id')->name('user-sessions.destroy');
        Route::delete('sessions/{sessionId}', [SessionController::class, 'destroySession'])->name('sessions.destroy');
        Route::delete('trusted-ips/{id}', [SessionController::class, 'destroyTrusted'])->whereNumber('id')->name('trusted-ips.destroy');
        Route::post('trusted-ips/my-ip', [SessionController::class, 'storeMyIp'])->name('trusted-ips.store-my-ip');

        // Unblock appeal tickets
        Route::get('tickets', [TicketController::class, 'index'])->name('tickets');
        Route::post('tickets/{id}/respond', [TicketController::class, 'respond'])->whereNumber('id')->name('tickets.respond');
        Route::delete('tickets/{id}', [TicketController::class, 'destroy'])->whereNumber('id')->name('tickets.destroy');

        // Security Settings
        Route::get('settings', [SettingController::class, 'index'])->name('settings');
        Route::post('settings', [SettingController::class, 'update'])->name('settings.update');
    });
