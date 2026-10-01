<?php

use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\SecurityLog;

function attackFrom(string $ip = '198.51.100.7'): void
{
    test()->withServerVariables(['REMOTE_ADDR' => $ip]);
}

beforeEach(function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
    config()->set('security.auto_block.enabled', true);
    config()->set('security.auto_block.threshold', 3);
    config()->set('security.auto_block.window_minutes', 10);
});

test('ip that is blocked receives a 403 response', function () {
    attackFrom();
    BlockedIp::create([
        'ip_address' => '198.51.100.7',
        'reason' => 'Aktivitas mencurigakan',
        'source' => 'manual',
        'blocked_at' => now(),
        'is_active' => true,
    ]);

    $response = $this->get('/');

    $response->assertForbidden();
});

test('expired blocks do not reject requests', function () {
    attackFrom('198.51.100.11');
    BlockedIp::create([
        'ip_address' => '198.51.100.11',
        'source' => 'manual',
        'blocked_at' => now()->subDays(2),
        'expires_at' => now()->subDay(),
        'is_active' => true,
    ]);

    $this->get('/')->assertOk();
});

test('ip on whitelist is never blocked even after threshold is exceeded', function () {
    config()->set('security.whitelist', ['198.51.100.7']);
    attackFrom();

    for ($i = 0; $i < 5; $i++) {
        $this->get('/?test='.urlencode("' OR 1=1 --"));
    }

    expect(BlockedIp::query()->where('ip_address', '198.51.100.7')->exists())->toBeFalse();
});

test('repeated attacks trigger an automatic block', function () {
    attackFrom();

    // 1st request
    $this->get('/?search='.urlencode('<script>alert(1)</script>'));
    expect(BlockedIp::query()->where('ip_address', '198.51.100.7')->exists())->toBeFalse();

    // 2nd request
    $this->get('/?search='.urlencode('<script>alert(2)</script>'));
    expect(BlockedIp::query()->where('ip_address', '198.51.100.7')->exists())->toBeFalse();

    // 3rd request reaches threshold -> auto-blocked
    $this->get('/?search='.urlencode('<script>alert(3)</script>'));
    $block = BlockedIp::query()->where('ip_address', '198.51.100.7')->first();

    expect($block)->not->toBeNull()
        ->and($block->source)->toBe('automatic')
        ->and($block->is_active)->toBeTrue()
        ->and($block->expires_at)->not->toBeNull();

    // 4th request must be blocked
    $this->get('/')->assertForbidden();
});

test('prune command removes logs older than the retention period', function () {
    $old = new SecurityLog([
        'ip_address' => '198.51.100.21',
        'event_type' => 'sqli',
        'threat_level' => 'critical',
    ]);
    $old->created_at = now()->subDays(120);
    $old->updated_at = now()->subDays(120);
    $old->save();

    SecurityLog::create([
        'ip_address' => '198.51.100.22',
        'event_type' => 'sqli',
        'threat_level' => 'critical',
    ]);

    $this->artisan('security:prune-logs', ['--days' => 30])->assertSuccessful();

    expect(SecurityLog::query()->count())->toBe(1)
        ->and(SecurityLog::query()->first()->ip_address)->toBe('198.51.100.22');
});
