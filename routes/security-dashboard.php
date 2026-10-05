<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Security Monitor Livewire Dashboard Routes
|--------------------------------------------------------------------------
|
| Rute ini hanya dimuat ketika "security.dashboard.enabled" bernilai true dan
| paket Livewire tersedia di aplikasi host. Seluruh halaman dilindungi oleh
| middleware autentikasi ("auth") dan, secara default, juga oleh middleware
| "security.admin" yang memeriksa Gate "manage-security-monitor".
|
*/

$prefix = config('security.dashboard.prefix', 'security');
$middleware = array_filter((array) config('security.dashboard.middleware', ['web', 'auth']));
$adminMiddleware = array_filter((array) config('security.dashboard.admin_middleware', []));

Route::middleware(array_merge($middleware, $adminMiddleware))
    ->prefix($prefix)
    ->name('security.dashboard.')
    ->group(function () {
        Route::livewire('/', 'pages::security.overview')->name('overview');
        Route::livewire('logs', 'pages::security.logs')->name('logs');
        Route::livewire('blocked-ips', 'pages::security.blocked-ips')->name('blocked-ips');
        Route::livewire('server', 'pages::security.server')->name('server');
        Route::livewire('sessions', 'pages::security.sessions')->name('sessions');
        Route::livewire('tickets', 'pages::security.tickets')->name('tickets');
        Route::livewire('settings', 'pages::security.settings')->name('settings');
    });
