<?php

use Illuminate\Support\Facades\File;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\SecurityLog;

function accessLogLine(
    string $ip = '104.207.74.38',
    string $request = 'GET / HTTP/1.1',
    int $status = 200,
    string $agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    string $time = '20/Sep/2026:17:21:03 +0700',
): string {
    return sprintf('%s - - [%s] "%s" %d 512 "-" "%s"', $ip, $time, $request, $status, $agent);
}

function sampleLogFile(array $lines): string
{
    $path = sys_get_temp_dir().'/test-access-'.uniqid().'.log';
    File::ensureDirectoryExists(dirname($path));
    File::put($path, implode(PHP_EOL, $lines).PHP_EOL);

    return $path;
}

beforeEach(function () {
    config()->set('security.enabled', true);
    config()->set('security.block_enforcement', true);
});

test('scanner detects zero tolerance signatures and path traversals in access logs', function () {
    $file = sampleLogFile([
        accessLogLine(request: 'GET /?icon=../../../public/wne HTTP/1.1', status: 403),
        accessLogLine(request: 'POST /login HTTP/1.1', status: 200),
    ]);

    $this->artisan('security:scan-logs', [
        '--file' => [$file],
        '--import' => true,
        '--block' => true,
    ])->assertSuccessful();

    $imported = SecurityLog::query()
        ->where('ip_address', '104.207.74.38')
        ->first();

    expect($imported)->not->toBeNull()
        ->and($imported->threat_level)->toBe('critical');

    $block = BlockedIp::query()->where('ip_address', '104.207.74.38')->first();
    expect($block)->not->toBeNull()
        ->and($block->source)->toBe('automatic')
        ->and($block->is_active)->toBeTrue();
});

test('the dry run changes nothing', function () {
    $file = sampleLogFile([accessLogLine(request: 'GET /.env HTTP/1.1', status: 403)]);

    $this->artisan('security:scan-logs', [
        '--file' => [$file],
        '--import' => true,
        '--block' => true,
        '--dry-run' => true,
    ])->assertSuccessful();

    expect(SecurityLog::query()->count())->toBe(0)
        ->and(BlockedIp::query()->count())->toBe(0);
});

test('json output contains the parsed findings', function () {
    $file = sampleLogFile([accessLogLine(request: 'GET /.git/config HTTP/1.1', status: 403)]);

    $this->artisan('security:scan-logs', ['--file' => [$file], '--json' => true])
        ->expectsOutputToContain('"ip": "104.207.74.38"')
        ->assertSuccessful();
});
