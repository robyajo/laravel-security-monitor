<?php

use Illuminate\Http\Request;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Tests\TestUser;

test('device-scoped block only blocks the offending device while innocent devices on same public router IP remain unblocked', function () {
    $service = app(SecurityMonitorService::class);
    $publicRouterIp = '158.140.185.154';
    $rogueDeviceId = 'dev-rogue-device-001';
    $rogueLocalIp = '192.168.1.15';
    $innocentDeviceId = 'dev-innocent-phone-002';
    $innocentLocalIp = '192.168.1.20';

    BlockedIp::create([
        'ip_address' => $publicRouterIp,
        'local_ip' => $rogueLocalIp,
        'device_id' => $rogueDeviceId,
        'block_scope' => 'device',
        'reason' => 'Perangkat terdeteksi serangan SQLi',
        'source' => 'manual',
        'is_active' => true,
        'blocked_at' => now(),
    ]);

    $rogueBlocked = $service->activeBlock($publicRouterIp, $rogueDeviceId, $rogueLocalIp);
    expect($rogueBlocked)->not->toBeNull();
    expect($rogueBlocked->block_scope)->toBe('device');
    expect($rogueBlocked->device_id)->toBe($rogueDeviceId);

    $innocentBlocked = $service->activeBlock($publicRouterIp, $innocentDeviceId, $innocentLocalIp);
    expect($innocentBlocked)->toBeNull();

    $responseRogue = $this->withServerVariables(['REMOTE_ADDR' => $publicRouterIp])
        ->withHeaders([
            'X-Device-Id' => $rogueDeviceId,
            'X-Local-Ip' => $rogueLocalIp,
        ])
        ->get('/');
    $responseRogue->assertForbidden();

    $responseInnocent = $this->withServerVariables(['REMOTE_ADDR' => $publicRouterIp])
        ->withHeaders([
            'X-Device-Id' => $innocentDeviceId,
            'X-Local-Ip' => $innocentLocalIp,
        ])
        ->get('/');
    expect($responseInnocent->status())->not->toBe(403);
});

test('ip-scoped block blocks all devices coming from that router public IP', function () {
    $service = app(SecurityMonitorService::class);
    $publicRouterIp = '158.140.185.154';

    BlockedIp::create([
        'ip_address' => $publicRouterIp,
        'block_scope' => 'ip',
        'reason' => 'Router IP terindikasi botnet',
        'source' => 'manual',
        'is_active' => true,
        'blocked_at' => now(),
    ]);

    $deviceABlocked = $service->activeBlock($publicRouterIp, 'device-a', '192.168.1.10');
    $deviceBBlocked = $service->activeBlock($publicRouterIp, 'device-b', '192.168.1.25');

    expect($deviceABlocked)->not->toBeNull();
    expect($deviceBBlocked)->not->toBeNull();

    $response = $this->withServerVariables(['REMOTE_ADDR' => $publicRouterIp])
        ->withHeaders(['X-Device-Id' => 'device-b'])
        ->get('/');
    $response->assertForbidden();
});

test('submitting appeal ticket records device_id and local_ip', function () {
    $publicIp = '158.140.185.154';
    $deviceId = 'device-webrtc-uuid-999';
    $localIp = '192.168.1.42';

    $response = $this->withServerVariables(['REMOTE_ADDR' => $publicIp])
        ->postJson('/api/security/unblock-tickets/submit', [
            'name' => 'Budi Santoso',
            'email' => 'budi@example.com',
            'phone' => '08123456789',
            'reason' => 'Laptop saya terblokir saat sedang akses portal superapp di kantor.',
            'device_id' => $deviceId,
            'local_ip' => $localIp,
        ]);

    $response->assertSuccessful();
    $response->assertJson(['success' => true]);

    $ticket = IpUnblockRequest::where('email', 'budi@example.com')->first();
    expect($ticket)->not->toBeNull();
    expect($ticket->ip_address)->toBe($publicIp);
    expect($ticket->device_id)->toBe($deviceId);
    expect($ticket->local_ip)->toBe($localIp);
    expect($ticket->status)->toBe('pending');
});

test('approving unblock ticket unblocks the specific device and lifts block', function () {
    $admin = TestUser::create([
        'name' => 'Admin User',
        'email' => 'admin-unblock@example.com',
        'password' => bcrypt('password'),
        'role' => 'admin',
    ]);
    $publicIp = '158.140.185.154';
    $deviceId = 'device-laptop-abc';
    $localIp = '192.168.1.100';

    $blocked = BlockedIp::create([
        'ip_address' => $publicIp,
        'local_ip' => $localIp,
        'device_id' => $deviceId,
        'block_scope' => 'device',
        'is_active' => true,
    ]);

    $ticket = IpUnblockRequest::create([
        'ticket_number' => 'SEC-TEST1234',
        'ip_address' => $publicIp,
        'device_id' => $deviceId,
        'local_ip' => $localIp,
        'name' => 'Ahmad',
        'email' => 'ahmad@example.com',
        'reason' => 'Mohon buka blokir perangkat saya.',
        'status' => 'pending',
        'blocked_ip_id' => $blocked->id,
    ]);

    $response = $this->actingAs($admin)
        ->postJson("/api/security/unblock-tickets/{$ticket->id}/respond", [
            'action' => 'approve',
            'admin_notes' => 'Disetujui setelah diverifikasi bukan bot.',
            'whitelist_ip' => true,
        ]);

    $response->assertSuccessful();
    $ticket->refresh();
    $blocked->refresh();

    expect($ticket->status)->toBe('approved');
    expect($blocked->is_active)->toBeFalse();

    $service = app(SecurityMonitorService::class);
    expect($service->activeBlock($publicIp, $deviceId, $localIp))->toBeNull();
});

test('security monitor resolves real client IP behind reverse proxy headers', function () {
    $service = app(SecurityMonitorService::class);

    $requestCf = Request::create('/', 'GET');
    $requestCf->headers->set('CF-Connecting-IP', '203.0.113.199');
    $requestCf->server->set('REMOTE_ADDR', '172.68.0.1');

    expect($service->resolveClientIp($requestCf))->toBe('203.0.113.199');

    $requestNginx = Request::create('/', 'GET');
    $requestNginx->headers->set('X-Real-IP', '198.51.100.88');
    $requestNginx->server->set('REMOTE_ADDR', '10.0.0.2');

    expect($service->resolveClientIp($requestNginx))->toBe('198.51.100.88');
});

test('instant block automatically isolates only the attacker device without blocking other users on the same WiFi router', function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
    config()->set('security.instant_block.enabled', true);
    config()->set('security.instant_block.scope', 'device');

    $sharedRouterIp = '103.247.10.55';
    $attackerUa = 'SqlMapAttacker/1.0';
    $innocentUa = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)';

    // Penyerang mencoba path traversal fatal dari IP router WiFi
    $attackerResponse = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['User-Agent' => $attackerUa])
        ->get('/?page=../../../../etc/passwd');

    $attackerResponse->assertForbidden();

    $block = BlockedIp::query()->where('ip_address', $sharedRouterIp)->first();
    expect($block)->not->toBeNull();
    expect($block->block_scope)->toBe('device');
    expect($block->device_id)->not->toBeNull();

    // Penyerang mencoba akses kembali -> tetap 403 Forbidden
    $attackerNextResponse = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['User-Agent' => $attackerUa])
        ->get('/');
    $attackerNextResponse->assertForbidden();

    // Pengguna lain di WiFi/router yang sama mengakses website secara normal -> TIDAK terblokir (200 OK)
    $innocentResponse = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['User-Agent' => $innocentUa])
        ->get('/');
    expect($innocentResponse->status())->not->toBe(403);
});

test('auto block automatically isolates only the attacker device without blocking innocent devices on the same WiFi router', function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
    config()->set('security.auto_block.enabled', true);
    config()->set('security.auto_block.threshold', 3);
    config()->set('security.auto_block.scope', 'device');

    $sharedRouterIp = '103.247.10.77';
    $attackerDeviceId = 'rogue-laptop-office-wifi';
    $innocentDeviceId = 'innocent-colleague-phone-wifi';

    // Penyerang melakukan 3 serangan berulang dari WiFi kantor
    for ($i = 1; $i <= 3; $i++) {
        $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
            ->withHeaders(['X-Device-Id' => $attackerDeviceId])
            ->get('/?search='.urlencode("<script>alert({$i})</script>"));
    }

    $block = BlockedIp::query()->where('ip_address', $sharedRouterIp)->first();
    expect($block)->not->toBeNull();
    expect($block->block_scope)->toBe('device');
    expect($block->device_id)->toBe($attackerDeviceId);

    // Penyerang terblokir (403 Forbidden)
    $attackerResponse = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['X-Device-Id' => $attackerDeviceId])
        ->get('/');
    $attackerResponse->assertForbidden();

    // Rekan kerja di WiFi kantor yang sama TIDAK terblokir
    $innocentResponse = $this->withServerVariables(['REMOTE_ADDR' => $sharedRouterIp])
        ->withHeaders(['X-Device-Id' => $innocentDeviceId])
        ->get('/');
    expect($innocentResponse->status())->not->toBe(403);
});
