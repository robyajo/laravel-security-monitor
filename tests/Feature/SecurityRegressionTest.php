<?php

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Services\ServerSecurityService;
use Internal\SecurityMonitor\Services\UserLoginService;

test('captcha image endpoint returns an svg challenge', function () {
    $response = $this->get(route('security.captcha.image'));

    $response->assertSuccessful();

    expect((string) $response->headers->get('Content-Type'))
        ->toContain('image/svg+xml')
        ->and($response->getContent())
        ->toContain('<svg');
});

test('captcha verify endpoint reports an invalid answer', function () {
    $this->get(route('security.captcha.image'));

    $response = $this->postJson(route('security.captcha.verify'), [
        'captcha' => 'WRONG-ANSWER',
    ]);

    $response
        ->assertSuccessful()
        ->assertJson(['success' => false, 'valid' => false]);
});

test('login event records a user login session', function () {
    $user = $this->createRegularUser();

    $before = UserLogin::query()->count();

    event(new Login('web', $user, false));

    expect(UserLogin::query()->count())->toBe($before + 1);
});

test('logoutSession marks the matching session as logged out', function () {
    $user = $this->createRegularUser();

    $login = UserLogin::create([
        'user_id' => $user->id,
        'session_id' => 'session-abc-123',
        'ip_address' => '127.0.0.1',
        'device_type' => 'desktop',
        'operating_system' => 'Linux',
        'browser' => 'Pest',
        'login_at' => now(),
        'last_activity_at' => now(),
    ]);

    expect($login->logout_at)->toBeNull();

    $affected = app(UserLoginService::class)->logoutSession('session-abc-123');

    expect($affected)
        ->toBe(1)
        ->and($login->fresh()->logout_at)
        ->not->toBeNull();
});

test('trustIp stores a trusted ip for the user', function () {
    $user = $this->createRegularUser();

    $trusted = app(UserLoginService::class)->trustIp(
        $user,
        '127.0.0.1',
        'Perangkat Uji',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    );

    expect($trusted)
        ->toBeInstanceOf(TrustedIp::class)
        ->and($trusted->ip_address)
        ->toBe('127.0.0.1')
        ->and((int) $trusted->user_id)
        ->toBe((int) $user->id);
});

test('admin login automatically lifts an ip block', function () {
    $this->app->instance(
        'request',
        Request::create(
            '/',
            'GET',
            [],
            [],
            [],
            ['REMOTE_ADDR' => '203.0.113.99'],
        ),
    );

    $admin = $this->createAdminUser();
    $security = app(SecurityMonitorService::class);

    $security->block('203.0.113.99', [
        'reason' => 'uji regresi',
        'duration_hours' => 1,
    ]);
    expect($security->activeBlock('203.0.113.99'))->not->toBeNull();

    event(new Login('web', $admin, false));

    expect($security->activeBlock('203.0.113.99'))->toBeNull();
});

test('server scan runs when admin accounts exist', function () {
    $this->createAdminUser();

    $scan = app(ServerSecurityService::class)->scan(force: true);

    expect($scan)
        ->toBeArray()
        ->toHaveKeys(['summary', 'categories']);
});

test('application audit marks a strong public api key and trusted proxies as ok', function () {
    config()->set('security.server_scan.public_api_key', 'long-random-secret-value');
    config()->set('security.server_scan.trusted_proxies', '10.0.0.1');

    $checks = collect(app(ServerSecurityService::class)->scan(force: true)['categories'])
        ->flatMap(fn (array $category): array => $category['checks'])
        ->keyBy('id');

    expect($checks['public_api_key']['status'])->toBe('ok')
        ->and($checks['trusted_proxies']['status'])->toBe('ok')
        ->and($checks['public_api_key']['value'])->toBe('long-random-secret-value');
});

test('application audit warns when public api key and trusted proxies are empty', function () {
    config()->set('security.server_scan.public_api_key', '');
    config()->set('security.server_scan.trusted_proxies', '');

    $checks = collect(app(ServerSecurityService::class)->scan(force: true)['categories'])
        ->flatMap(fn (array $category): array => $category['checks'])
        ->keyBy('id');

    expect($checks['public_api_key']['status'])->toBe('warning')
        ->and($checks['trusted_proxies']['status'])->toBe('warning');
});
