<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Internal\SecurityMonitor\Services\ServerSecurityService;
use Internal\SecurityMonitor\Tests\TestUser;

beforeEach(function () {
    Cache::flush();
    app(ServerSecurityService::class)->forget();
});

afterEach(function () {
    $baselinePath = app(ServerSecurityService::class)->baselinePath();
    if (File::exists($baselinePath)) {
        File::delete($baselinePath);
    }
    app(ServerSecurityService::class)->forget();
});

test('server security service can run full scan and return structured report', function () {
    $service = app(ServerSecurityService::class);
    $scan = $service->scan(force: true);

    expect($scan)->toBeArray()
        ->and($scan)->toHaveKeys(['summary', 'categories']);
});

test('server integrity baseline can be created, verified, and deleted', function () {
    $service = app(ServerSecurityService::class);

    expect($service->baseline())->toBeNull();

    $baseline = $service->createBaseline();
    expect($baseline)->toBeArray();
    expect($service->baseline())->not->toBeNull();

    $integrity = $service->integrityReport();
    expect($integrity['modified'])->toBeEmpty()
        ->and($integrity['missing'])->toBeEmpty();

    $deleted = $service->deleteBaseline();
    expect($deleted)->toBeTrue();
    expect($service->baseline())->toBeNull();
});

test('admin can retrieve server scan report via api', function () {
    $admin = TestUser::create([
        'name' => 'Admin User',
        'email' => 'admin-server@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);

    $response = $this->actingAs($admin)
        ->getJson('/api/security/server');

    $response->assertSuccessful();
    $response->assertJsonStructure([
        'success',
        'data' => [
            'summary',
            'categories',
        ],
    ]);
});

test('admin can create and delete baseline via api', function () {
    $admin = TestUser::create([
        'name' => 'Admin User',
        'email' => 'admin-server2@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);

    // Create baseline
    $postResponse = $this->actingAs($admin)
        ->postJson('/api/security/server/baseline');

    $postResponse->assertSuccessful();
    $postResponse->assertJson(['success' => true]);

    // Delete baseline
    $delResponse = $this->actingAs($admin)
        ->deleteJson('/api/security/server/baseline');

    $delResponse->assertSuccessful();
    $delResponse->assertJson(['success' => true]);
});

test('deletion rejects path traversal and protected core system files', function () {
    $service = app(ServerSecurityService::class);

    $traversalResult = $service->deleteSuspiciousFile('../../etc/passwd', 1);
    expect($traversalResult['success'])->toBeFalse()
        ->and($traversalResult['message'])->toContain('traversal');

    $indexResult = $service->deleteSuspiciousFile('public/index.php', 1);
    expect($indexResult['success'])->toBeFalse()
        ->and($indexResult['message'])->toContain('dilindungi');
});
