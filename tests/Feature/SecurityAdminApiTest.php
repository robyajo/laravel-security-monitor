<?php

use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Models\TrustedIp;

beforeEach(function () {
    $this->admin = $this->createAdminUser();
    $this->regularUser = $this->createRegularUser();
});

test('unauthenticated users cannot access admin security api', function () {
    $response = $this->getJson(route('security.logs.index'));
    $response->assertStatus(401);
});

test('regular users receive 403 forbidden on admin security api', function () {
    $response = $this->actingAs($this->regularUser)
        ->getJson(route('security.logs.index'));

    $response->assertStatus(403);
});

test('admin can retrieve paginated security logs with stats', function () {
    SecurityLog::create([
        'ip_address' => '1.2.3.4',
        'event_type' => 'sql_injection',
        'threat_level' => 'high',
        'method' => 'GET',
        'path' => '/search',
        'rule_label' => 'SQLi payload',
    ]);

    $response = $this->actingAs($this->admin)
        ->getJson(route('security.logs.index'));

    $response->assertOk()
        ->assertJsonPath('success', true)
        ->assertJsonStructure([
            'success',
            'data' => ['data'],
            'stats',
            'level_breakdown',
            'trend',
        ]);
});

test('admin can manually block an ip address via json api', function () {
    $response = $this->actingAs($this->admin)
        ->postJson(route('security.blocked-ips.store'), [
            'ip_address' => '198.51.100.5',
            'reason' => 'Manual blocking test',
            'duration_hours' => 48,
        ]);

    $response->assertStatus(201)
        ->assertJsonPath('success', true);

    expect(BlockedIp::query()->where('ip_address', '198.51.100.5')->exists())->toBeTrue();
});

test('admin cannot block their own ip address', function () {
    $response = $this->actingAs($this->admin)
        ->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
        ->postJson(route('security.blocked-ips.store'), [
            'ip_address' => '203.0.113.10',
            'reason' => 'Trying to block own ip',
        ]);

    $response->assertStatus(422)
        ->assertJsonPath('success', false);
});

test('admin can toggle and delete blocked ip', function () {
    $block = BlockedIp::create([
        'ip_address' => '198.51.100.77',
        'reason' => 'Toggle test',
        'is_active' => true,
    ]);

    $toggleResponse = $this->actingAs($this->admin)
        ->patchJson(route('security.blocked-ips.toggle', $block->id));

    $toggleResponse->assertOk();
    expect($block->fresh()->is_active)->toBeFalse();

    $deleteResponse = $this->actingAs($this->admin)
        ->deleteJson(route('security.blocked-ips.destroy', $block->id));

    $deleteResponse->assertOk();
    expect(BlockedIp::query()->find($block->id))->toBeNull();
});

test('public client can submit unblock appeal ticket and check status', function () {
    $submitResponse = $this->postJson(route('security.unblock-tickets.submit'), [
        'name' => 'John Doe',
        'email' => 'john@example.com',
        'reason' => 'My IP was accidentally blocked during testing.',
    ]);

    $submitResponse->assertStatus(201)
        ->assertJsonPath('success', true);

    $ticketNumber = $submitResponse->json('ticket_number');
    expect($ticketNumber)->not->toBeEmpty();

    $checkResponse = $this->getJson(route('security.unblock-tickets.check', $ticketNumber));
    $checkResponse->assertOk()
        ->assertJsonPath('data.status', 'pending');
});

test('admin can approve unblock appeal ticket and automatically lift block', function () {
    BlockedIp::create([
        'ip_address' => '198.51.100.88',
        'reason' => 'Initial test block',
        'is_active' => true,
    ]);

    $ticket = IpUnblockRequest::create([
        'ticket_number' => 'TKT-TEST1234',
        'ip_address' => '198.51.100.88',
        'name' => 'Alice',
        'email' => 'alice@example.com',
        'reason' => 'Please unblock me',
        'status' => 'pending',
    ]);

    $response = $this->actingAs($this->admin)
        ->postJson(route('security.unblock-tickets.respond', $ticket->id), [
            'action' => 'approve',
            'admin_notes' => 'Approved by administrator',
        ]);

    $response->assertOk()
        ->assertJsonPath('success', true);

    expect($ticket->fresh()->status)->toBe('approved');
    expect(BlockedIp::query()->where('ip_address', '198.51.100.88')->where('is_active', true)->exists())->toBeFalse();
});

test('authenticated user can store current ip as trusted ip', function () {
    $response = $this->actingAs($this->regularUser)
        ->withServerVariables(['REMOTE_ADDR' => '203.0.113.55'])
        ->postJson(route('security.trusted-ips.store-my-ip'), [
            'device_name' => 'Work Laptop',
        ]);

    $response->assertOk()
        ->assertJsonPath('success', true);

    expect(TrustedIp::isTrusted('203.0.113.55', $this->regularUser->id))->toBeTrue();
});
