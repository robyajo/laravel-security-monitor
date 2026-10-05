<?php

namespace Internal\SecurityMonitor\Tests\Feature;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Internal\SecurityMonitor\Services\VersionCheckService;
use Internal\SecurityMonitor\Tests\TestCase;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

class SecurityVersionCheckTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        VersionCheckService::resetNotificationState();
    }

    public function test_can_detect_current_installed_version(): void
    {
        $service = app(VersionCheckService::class);
        $version = $service->getCurrentVersion();

        $this->assertNotEmpty($version);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', $version);
    }

    public function test_can_fetch_and_cache_latest_version_from_packagist(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.0.0'],
                        ['version' => 'v2.0.7'],
                    ],
                ],
            ], 200),
        ]);

        $service = app(VersionCheckService::class);
        $latest = $service->getLatestVersion(true);

        $this->assertEquals('99.0.0', $latest);
        $this->assertEquals('99.0.0', Cache::get(VersionCheckService::CACHE_KEY));
        $this->assertTrue($service->isUpdateAvailable());
    }

    public function test_fallback_to_github_if_packagist_fails(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response(null, 500),
            'https://api.github.com/repos/robyajo/laravel-security-monitor/tags' => Http::response([
                ['name' => 'v98.5.1'],
                ['name' => 'v2.0.7'],
            ], 200),
        ]);

        $service = app(VersionCheckService::class);
        $latest = $service->getLatestVersion(true);

        $this->assertEquals('98.5.1', $latest);
        $this->assertTrue($service->isUpdateAvailable());
    }

    public function test_notifies_user_in_terminal_when_update_available(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.9.9'],
                    ],
                ],
            ], 200),
        ]);

        $service = app(VersionCheckService::class);
        $output = new BufferedOutput;

        $service->notifyIfUpdateAvailable($output);
        $content = $output->fetch();

        $this->assertStringContainsString('Pembaruan Tersedia', $content);
        $this->assertStringContainsString('v99.9.9', $content);
        $this->assertStringContainsString('php artisan security:upgrade', $content);

        // Notifikasi hanya dicetak satu kali per proses
        $secondOutput = new BufferedOutput;
        $service->notifyIfUpdateAvailable($secondOutput);
        $this->assertEmpty($secondOutput->fetch());
    }

    public function test_respects_version_check_disabled_configuration(): void
    {
        config(['security.version_check.enabled' => false]);

        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.9.9'],
                    ],
                ],
            ], 200),
        ]);

        $service = app(VersionCheckService::class);
        $output = new BufferedOutput;

        $service->notifyIfUpdateAvailable($output);
        $this->assertEmpty($output->fetch());
    }

    public function test_command_starting_triggers_notice_on_serve_and_dev(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.0.0'],
                    ],
                ],
            ], 200),
        ]);

        $output = new BufferedOutput;
        $event = new CommandStarting('serve', new ArrayInput([]), $output);

        Event::dispatch($event);

        $content = $output->fetch();
        $this->assertStringContainsString('Pembaruan Tersedia', $content);
        $this->assertStringContainsString('php artisan security:upgrade', $content);
    }

    public function test_command_starting_does_not_trigger_notice_on_other_commands(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.0.0'],
                    ],
                ],
            ], 200),
        ]);

        $output = new BufferedOutput;
        $event = new CommandStarting('migrate', new ArrayInput([]), $output);

        Event::dispatch($event);

        $this->assertEmpty($output->fetch());
    }

    public function test_upgrade_command_check_option(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v99.1.0'],
                    ],
                ],
            ], 200),
        ]);

        $this->artisan('security:upgrade', ['--check' => true])
            ->expectsOutputToContain('Tersedia pembaruan: v')
            ->expectsOutputToContain('v99.1.0')
            ->expectsOutputToContain('php artisan security:upgrade')
            ->assertExitCode(0);
    }

    public function test_upgrade_command_sync_only_with_no_composer(): void
    {
        Http::fake([
            'https://repo.packagist.org/p2/robyajo/laravel-security-monitor.json' => Http::response([
                'packages' => [
                    'robyajo/laravel-security-monitor' => [
                        ['version' => 'v2.0.8'],
                    ],
                ],
            ], 200),
        ]);

        $this->artisan('security:upgrade', [
            '--force' => true,
            '--no-composer' => true,
        ])
            ->expectsOutputToContain('Pembaruan Composer dilewati')
            ->expectsOutputToContain('Menyinkronkan dan menerapkan migrasi database')
            ->expectsOutputToContain('berhasil diperbarui dan disinkronkan')
            ->assertExitCode(0);
    }
}
