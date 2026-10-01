<?php

namespace Internal\SecurityMonitor;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Internal\SecurityMonitor\Console\Commands\PruneSecurityLogs;
use Internal\SecurityMonitor\Console\Commands\PurgeInjectedData;
use Internal\SecurityMonitor\Console\Commands\SecurityBaselineCommand;
use Internal\SecurityMonitor\Console\Commands\SecurityInstallCommand;
use Internal\SecurityMonitor\Console\Commands\SecurityScanAccessLogs;
use Internal\SecurityMonitor\Console\Commands\UnblockIpAddress;
use Internal\SecurityMonitor\Http\Middleware\BlockIpAddress;
use Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats;
use Internal\SecurityMonitor\Http\Middleware\EnsureSecurityAdmin;
use Internal\SecurityMonitor\Http\Middleware\TrackUserActivity;
use Internal\SecurityMonitor\Listeners\LogFailedLoginAttempt;
use Internal\SecurityMonitor\Listeners\RecordUserLogin;
use Internal\SecurityMonitor\Listeners\ResetLoginAttempts;
use Internal\SecurityMonitor\Services\AccessLogScannerService;
use Internal\SecurityMonitor\Services\CaptchaService;
use Internal\SecurityMonitor\Services\LoginThrottleService;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Services\ServerSecurityService;
use Internal\SecurityMonitor\Services\UserLoginService;

class SecurityMonitorServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security.php', 'security');

        $this->app->singleton(SecurityMonitorService::class, function ($app) {
            return new SecurityMonitorService;
        });

        $this->app->singleton(LoginThrottleService::class, function ($app) {
            return new LoginThrottleService(
                $app->make(SecurityMonitorService::class),
            );
        });

        $this->app->singleton(CaptchaService::class, function ($app) {
            return new CaptchaService;
        });

        $this->app->singleton(UserLoginService::class, function ($app) {
            return new UserLoginService;
        });

        $this->app->singleton(ServerSecurityService::class, function ($app) {
            return new ServerSecurityService(
                $app->make(SecurityMonitorService::class),
                $app->make(LoginThrottleService::class),
            );
        });

        $this->app->singleton(AccessLogScannerService::class, function ($app) {
            return new AccessLogScannerService(
                $app->make(SecurityMonitorService::class),
            );
        });

        $this->app->alias(SecurityMonitorService::class, 'security.monitor');
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerListeners();
        $this->registerRoutes();
        $this->registerSchedule();
        $this->registerGate();
        $this->registerMiddleware();
    }

    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        // Config
        $this->publishes(
            [
                __DIR__.'/../config/security.php' => config_path(
                    'security.php',
                ),
            ],
            'security-config',
        );

        // Migrations
        $this->publishes(
            [
                __DIR__.'/../database/migrations' => database_path(
                    'migrations',
                ),
            ],
            'security-migrations',
        );

        // Nginx Hardened Configuration
        $this->publishes(
            [
                __DIR__.'/../stubs/nginx.conf.stub' => base_path(
                    'nginx.conf',
                ),
            ],
            'security-nginx',
        );

        // Apache .htaccess Hardened Configuration
        $this->publishes(
            [
                __DIR__.'/../stubs/htaccess.stub' => public_path('.htaccess'),
            ],
            'security-htaccess',
        );

        // Default 403 "blocked" error page
        $this->publishes(
            [
                __DIR__.'/../stubs/blocked.blade.php' => resource_path(
                    'views/errors/blocked.blade.php',
                ),
            ],
            'security-views',
        );

        // Publish All Assets (Config, Migrations, Nginx, Htaccess, Blocked View)
        $this->publishes(
            [
                __DIR__.'/../config/security.php' => config_path(
                    'security.php',
                ),
                __DIR__.'/../database/migrations' => database_path(
                    'migrations',
                ),
                __DIR__.'/../stubs/nginx.conf.stub' => base_path(
                    'nginx.conf',
                ),
                __DIR__.'/../stubs/htaccess.stub' => public_path('.htaccess'),
                __DIR__.'/../stubs/blocked.blade.php' => resource_path(
                    'views/errors/blocked.blade.php',
                ),
            ],
            'security-all',
        );

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function registerCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            SecurityInstallCommand::class,
            PruneSecurityLogs::class,
            UnblockIpAddress::class,
            SecurityScanAccessLogs::class,
            SecurityBaselineCommand::class,
            PurgeInjectedData::class,
        ]);
    }

    protected function registerListeners(): void
    {
        Event::listen(
            Failed::class,
            LogFailedLoginAttempt::class,
        );
        Event::listen(
            Login::class,
            ResetLoginAttempts::class,
        );
        Event::listen(
            Login::class,
            RecordUserLogin::class,
        );
    }

    protected function registerRoutes(): void
    {
        if (config('security.routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/security.php');
        }
    }

    protected function registerSchedule(): void
    {
        if (! config('security.schedule.enabled', true)) {
            return;
        }

        $this->app->booted(function (): void {
            if (! $this->app->runningInConsole()) {
                return;
            }

            try {
                $schedule = $this->app->make(Schedule::class);

                // Daily log prune
                $pruneAt = config('security.schedule.prune_at', '02:30');
                $schedule->command('security:prune-logs')->dailyAt($pruneAt);

                // Scheduler Heartbeat
                $schedule
                    ->call(function (): void {
                        Cache::put(
                            ServerSecurityService::HEARTBEAT_KEY,
                            now()->toIso8601String(),
                            now()->addHour(),
                        );
                    })
                    ->everyMinute()
                    ->name('security-heartbeat');

                // Access log auto-scan
                if (config('security.access_log.auto_scan_enabled', false)) {
                    $hours = max(
                        1,
                        (int) config(
                            'security.access_log.auto_scan_since_hours',
                            24,
                        ),
                    );
                    $schedule
                        ->command(
                            sprintf(
                                'security:scan-logs --import --min-level=high --since="%d hours ago"',
                                $hours,
                            ),
                        )
                        ->dailyAt('03:00')
                        ->name('security-scan-access-logs');
                }
            } catch (\Throwable) {
                // Ignore schedule registration errors if Schedule is not bound
            }
        });
    }

    protected function registerGate(): void
    {
        if (! Gate::has('manage-security-monitor')) {
            Gate::define('manage-security-monitor', function ($user) {
                if (method_exists($user, 'isAdmin')) {
                    return (bool) $user->isAdmin();
                }

                if (
                    in_array($user->role ?? null, ['admin', 'superadmin'], true)
                ) {
                    return true;
                }

                return (bool) ($user->is_admin ?? false);
            });
        }
    }

    protected function registerMiddleware(): void
    {
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('security.admin', EnsureSecurityAdmin::class);
        $router->aliasMiddleware('security.block', BlockIpAddress::class);
        $router->aliasMiddleware(
            'security.detect',
            DetectSecurityThreats::class,
        );
        $router->aliasMiddleware('security.activity', TrackUserActivity::class);

        if (config('security.auto_register_middleware', false)) {
            $this->app->booted(function (): void {
                $kernel = $this->app->make(
                    Kernel::class,
                );
                if (method_exists($kernel, 'pushMiddleware')) {
                    $kernel->pushMiddleware(BlockIpAddress::class);
                    $kernel->pushMiddleware(DetectSecurityThreats::class);
                }
            });
        }
    }
}
