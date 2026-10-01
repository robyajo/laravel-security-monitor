<?php

use Illuminate\Http\UploadedFile;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Rules\SafeAssetPath;
use Internal\SecurityMonitor\Tests\TestUser;

beforeEach(function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
    config()->set('security.instant_block.enabled', true);
    config()->set('security.instant_block.duration_hours', 720);
    config()->set('security.whitelist', []);
});

test('null byte and double extension upload filename triggers an instant block', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.50']);

    $file = UploadedFile::fake()->image('wne.png', 10, 10);
    $file = new UploadedFile($file->getRealPath(), 'wne.php%00.jpg', 'image/jpeg', null, true);

    $this->post('/login', ['avatar' => $file]);

    $block = BlockedIp::query()->where('ip_address', '198.51.100.50')->first();

    expect($block)->not->toBeNull()
        ->and($block->source)->toBe('automatic')
        ->and($block->is_active)->toBeTrue()
        ->and($block->reason)->toContain('Diblokir instan');

    expect(SecurityLog::query()->where('ip_address', '198.51.100.50')->exists())->toBeTrue();
});

test('double extension filename triggers an instant block', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.51']);

    $file = UploadedFile::fake()->image('placeholder.png', 10, 10);
    $file = new UploadedFile($file->getRealPath(), 'wne.php.jpg', 'image/jpeg', null, true);

    $this->post('/login', ['avatar' => $file]);

    expect(BlockedIp::query()->where('ip_address', '198.51.100.51')->exists())->toBeTrue();
});

test('path traversal into the public folder triggers an instant block', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.52']);

    $response = $this->get('/?icon=../../../public/wne');

    $response->assertForbidden();

    $block = BlockedIp::query()->where('ip_address', '198.51.100.52')->first();

    expect($block)->not->toBeNull()
        ->and($block->expires_at)->not->toBeNull();
});

test('htaccess probe triggers an instant block', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.53']);

    $this->get('/.htaccess')->assertForbidden();

    expect(BlockedIp::query()->where('ip_address', '198.51.100.53')->exists())->toBeTrue();
});

test('ssti canary triggers an instant block', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.54']);

    $this->get('/?q=%7B%7B7*7%7D%7D')->assertForbidden();

    $log = SecurityLog::query()
        ->where('ip_address', '198.51.100.54')
        ->where('event_type', 'ssti')
        ->first();

    expect($log)->not->toBeNull()
        ->and($log->action_taken)->toBe('instant_block');

    expect(BlockedIp::query()->where('ip_address', '198.51.100.54')->exists())->toBeTrue();
});

test('a blocked ip stays blocked for the configured duration', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.59']);

    $this->get('/?q=%7B%7B7*7%7D%7D')->assertForbidden();

    $block = BlockedIp::query()->where('ip_address', '198.51.100.59')->first();

    expect($block)->not->toBeNull()
        ->and($block->expires_at?->greaterThan(now()->addDays(29)))->toBeTrue();

    // Subsequent requests are rejected
    $this->get('/')->assertForbidden();
});

test('legitimate traffic is never blocked', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.60']);

    $this->withHeaders([
        'User-Agent' => 'Mozilla/5.0 (Linux; Android 14) SuperApp/2.0',
    ])->get('/')->assertOk();

    $this->withHeaders([
        'User-Agent' => 'Mozilla/5.0 (Linux; Android 14) SuperApp/2.0',
    ])->get('/?search=layanan+ktp')->assertOk();

    expect(BlockedIp::query()->count())->toBe(0)
        ->and(SecurityLog::query()->count())->toBe(0);
});

test('safe asset paths are accepted by the validation rule', function (string $path) {
    expect(validator(['icon' => $path], ['icon' => [new SafeAssetPath]])->passes())->toBeTrue();
})->with([
    'relative' => 'icons/768896159-panic-button.png',
    'category' => 'category-icons/2e68ab.jpg',
    'assets' => 'assets/icons/cuaca.webp',
    'url' => 'http://localhost/assets/icons/768896159-panic-button.png',
    'https url' => 'https://superapp-api.pekanbaru.go.id/storage/icons/abc123.png',
    'filename only' => 'logo.png',
]);

test('unsafe asset paths are rejected by the validation rule', function (string $path) {
    expect(validator(['icon' => $path], ['icon' => [new SafeAssetPath]])->fails())->toBeTrue();
})->with([
    'traversal to public' => '../../../public/wne',
    'traversal simple' => '../x',
    'htaccess' => '.htaccess',
    'double extension' => 'icons/shell.php.jpg',
    'null byte' => 'icons/wne.php%00.jpg',
    'absolute path' => '/etc/passwd',
    'backslash traversal' => '..\\..\\public\\wne',
    'non image' => 'icons/payload.txt',
    'svg with php suffix' => 'icons/x.svg.php',
]);

test('the unblock command lifts a block', function () {
    $block = BlockedIp::create([
        'ip_address' => '198.51.100.61',
        'source' => 'automatic',
        'blocked_at' => now(),
        'is_active' => true,
    ]);

    $this->artisan('security:unblock-ip 198.51.100.61')->assertSuccessful();

    expect($block->fresh()->is_active)->toBeFalse();
});

test('existing block on an ip is automatically lifted when an authenticated admin makes a request', function () {
    $admin = TestUser::create([
        'name' => 'Admin User',
        'email' => 'admin-unblock@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);
    $ip = '198.51.100.64';
    $this->withServerVariables(['REMOTE_ADDR' => $ip]);

    $block = BlockedIp::create([
        'ip_address' => $ip,
        'source' => 'automatic',
        'blocked_at' => now(),
        'is_active' => true,
    ]);

    $this->actingAs($admin)
        ->get('/')
        ->assertOk();

    expect($block->fresh()->is_active)->toBeFalse();
});

test('kitchen sink request from the incident is blocked in one shot', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.63']);

    $this->withHeaders([
        'User-Agent' => 'Mozilla/5.0 wne',
    ])->get('/?file=wne.php%00.jpg&path=../../../public/wne&target=.htaccess')
        ->assertForbidden();

    $logs = SecurityLog::query()->where('ip_address', '198.51.100.63')->get();

    expect($logs)->not->toBeEmpty()
        ->and($logs->contains(fn ($log) => $log->was_blocked === true))->toBeTrue()
        ->and($logs->contains(fn ($log) => $log->threat_level === 'critical'))->toBeTrue();

    expect(BlockedIp::query()->where('ip_address', '198.51.100.63')->exists())->toBeTrue();
});
