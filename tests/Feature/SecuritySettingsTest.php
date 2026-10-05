<?php

use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Tests\TestUser;

beforeEach(function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
    config()->set('security.auto_block.enabled', true);
    config()->set('security.auto_block.threshold', 3);
    config()->set('security.auto_block.scope', 'device');
    config()->set('security.instant_block.enabled', true);
    config()->set('security.instant_block.scope', 'device');
});

test('admin can retrieve current security settings via api', function () {
    $admin = TestUser::create([
        'name' => 'Admin User',
        'email' => 'admin-settings@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);

    $response = $this->actingAs($admin)->getJson('/api/security/settings');

    $response->assertSuccessful();
    $response->assertJson([
        'success' => true,
        'settings' => [
            'auto_block_scope' => 'device',
            'instant_block_scope' => 'device',
            'auto_block_enabled' => true,
            'auto_block_threshold' => 3,
        ],
    ]);
});

test('admin can update settings to switch between device and ip scope', function () {
    $admin = TestUser::create([
        'name' => 'Admin User 2',
        'email' => 'admin-settings2@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);

    $service = app(SecurityMonitorService::class);

    // 1. Update to IP scope
    $response = $this->actingAs($admin)->postJson('/api/security/settings', [
        'auto_block_scope' => 'ip',
        'instant_block_scope' => 'ip',
        'auto_block_threshold' => 5,
    ]);

    $response->assertSuccessful();
    $response->assertJson([
        'success' => true,
        'settings' => [
            'auto_block_scope' => 'ip',
            'instant_block_scope' => 'ip',
            'auto_block_threshold' => 5,
        ],
    ]);

    expect($service->getSetting('auto_block.scope'))->toBe('ip');
    expect($service->getSetting('instant_block.scope'))->toBe('ip');
    expect($service->getSetting('auto_block.threshold'))->toBe(5);

    // 2. Switch back to device scope
    $response2 = $this->actingAs($admin)->postJson('/api/security/settings', [
        'auto_block_scope' => 'device',
        'instant_block_scope' => 'device',
        'auto_block_threshold' => 3,
    ]);

    $response2->assertSuccessful();
    $response2->assertJson([
        'success' => true,
        'settings' => [
            'auto_block_scope' => 'device',
            'instant_block_scope' => 'device',
            'auto_block_threshold' => 3,
        ],
    ]);

    expect($service->getSetting('auto_block.scope'))->toBe('device');
    expect($service->getSetting('instant_block.scope'))->toBe('device');
});

test('dynamic setting switches auto block behavior from device isolation to entire router ip', function () {
    $service = app(SecurityMonitorService::class);
    $sharedRouterIp = '103.247.10.99';
    $attackerDeviceId = 'attacker-device-99';
    $innocentDeviceId = 'innocent-device-99';

    // 1. With default 'device' scope: only attacker device is quarantined
    $service->setSetting('auto_block.scope', 'device');
    $service->setSetting('auto_block.threshold', 2);

    for ($i = 1; $i <= 2; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
            ->withHeaders(['X-Device-Id' => $attackerDeviceId])
            ->get('/?search='.urlencode("<script>alert({$i})</script>"));
    }

    $block = BlockedIp::query()->where('ip_address', $sharedRouterIp)->first();
    expect($block)->not->toBeNull();
    expect($block->block_scope)->toBe('device');

    // Attacker is 403, innocent is NOT 403
    $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['X-Device-Id' => $attackerDeviceId])
        ->get('/')
        ->assertForbidden();

    $innocentRes = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['X-Device-Id' => $innocentDeviceId])
        ->get('/');
    expect($innocentRes->status())->not->toBe(403);

    // 2. Change setting dynamically to 'ip' scope
    $service->setSetting('auto_block.scope', 'ip');
    $service->setSetting('auto_block.threshold', 2);
    BlockedIp::query()->delete();

    $newAttackerIp = '103.247.10.100';
    for ($i = 1; $i <= 2; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => $newAttackerIp])
            ->withHeaders(['X-Device-Id' => 'attacker-new'])
            ->get('/?search='.urlencode("<script>alert({$i})</script>"));
    }

    $ipBlock = BlockedIp::query()->where('ip_address', $newAttackerIp)->first();
    expect($ipBlock)->not->toBeNull();
    expect($ipBlock->block_scope)->toBe('ip');

    // Now everyone from this IP is blocked because scope is 'ip'
    $this->withServerVariables(['REMOTE_ADDR' => $newAttackerIp])
        ->withHeaders(['X-Device-Id' => 'innocent-new'])
        ->get('/')
        ->assertForbidden();
});
