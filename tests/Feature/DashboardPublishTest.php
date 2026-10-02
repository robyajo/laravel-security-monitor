<?php

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;

afterEach(function () {
    $directories = [
        resource_path('views/pages/security'),
        resource_path('js/pages/security'),
        resource_path('js/components/security'),
    ];

    foreach ($directories as $directory) {
        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }
    }
});

test(
    'dashboard is disabled by default so the package stays headless',
    function () {
        expect(config('security.dashboard.enabled'))
            ->toBeFalse()
            ->and(config('security.dashboard.driver'))
            ->toBe('livewire')
            ->and(config('security.dashboard.prefix'))
            ->toBe('security')
            ->and(config('security.dashboard.middleware'))
            ->toContain('auth');
    },
);

test(
    'starterkit livewire tag publishes the monitoring views and configuration',
    function () {
        $directory = resource_path('views/pages/security');

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan('vendor:publish', [
            '--tag' => 'starterkit-livewire',
            '--force' => true,
        ])->assertSuccessful();

        expect(File::exists($directory.'/overview.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/logs.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/blocked-ips.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/server.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/sessions.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/tickets.blade.php'))
            ->toBeTrue()
            ->and(File::exists($directory.'/layout.blade.php'))
            ->toBeTrue();

        expect(File::get($directory.'/overview.blade.php'))->toContain(
            'Security Overview',
        );
    },
);

test(
    'typo-compatible staterkit livewire alias publishes the monitoring views',
    function () {
        $directory = resource_path('views/pages/security');

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan('vendor:publish', [
            '--tag' => 'staterkit-livewire',
            '--force' => true,
        ])->assertSuccessful();

        expect(File::exists($directory.'/overview.blade.php'))->toBeTrue();
    },
);

test(
    'starterkit react tag publishes the react pages, components, and configuration',
    function () {
        $pages = resource_path('js/pages/security');
        $components = resource_path('js/components/security');

        foreach ([$pages, $components] as $directory) {
            if (File::isDirectory($directory)) {
                File::deleteDirectory($directory);
            }
        }

        $this->artisan('vendor:publish', [
            '--tag' => 'starterkit-react',
            '--force' => true,
        ])->assertSuccessful();

        expect(File::exists($pages.'/overview.tsx'))
            ->toBeTrue()
            ->and(File::exists($pages.'/logs.tsx'))
            ->toBeTrue()
            ->and(File::exists($pages.'/blocked-ips.tsx'))
            ->toBeTrue()
            ->and(File::exists($pages.'/server.tsx'))
            ->toBeTrue()
            ->and(File::exists($pages.'/sessions.tsx'))
            ->toBeTrue()
            ->and(File::exists($pages.'/tickets.tsx'))
            ->toBeTrue()
            ->and(File::exists($components.'/security-nav.tsx'))
            ->toBeTrue();

        expect(File::get($pages.'/overview.tsx'))->toContain(
            'Security Overview',
        );
    },
);

test(
    'typo-compatible staterkit react alias publishes the react pages',
    function () {
        $pages = resource_path('js/pages/security');

        if (File::isDirectory($pages)) {
            File::deleteDirectory($pages);
        }

        $this->artisan('vendor:publish', [
            '--tag' => 'staterkit-react',
            '--force' => true,
        ])->assertSuccessful();

        expect(File::exists($pages.'/overview.tsx'))->toBeTrue();
    },
);

test('react dashboard routes are gated behind authentication', function () {
    $routes = File::get(__DIR__.'/../../routes/security-dashboard-react.php');

    expect($routes)
        ->toContain("config('security.dashboard.middleware', ['web', 'auth'])")
        ->and($routes)
        ->toContain('OverviewController::class')
        ->and($routes)
        ->toContain("->name('security.dashboard.')");

    expect(Route::has('security.dashboard.overview'))->toBeFalse();
});

test(
    'security install command can publish the react dashboard with the with-react-dashboard flag',
    function () {
        $pages = resource_path('js/pages/security');

        if (File::isDirectory($pages)) {
            File::deleteDirectory($pages);
        }

        $this->artisan('security:install', [
            '--force' => true,
            '--with-react-dashboard' => true,
            '--without-nginx' => true,
            '--without-htaccess' => true,
            '--without-env' => true,
        ])->assertSuccessful();

        expect(File::exists($pages.'/overview.tsx'))->toBeTrue();
    },
);

test(
    'dashboard routes require authentication and livewire to be present',
    function () {
        // The published dashboard must always be gated behind authentication, and
        // the package only registers the page-component routes when Livewire is
        // actually installed in the host application.
        $routes = File::get(__DIR__.'/../../routes/security-dashboard.php');

        expect($routes)
            ->toContain(
                "config('security.dashboard.middleware', ['web', 'auth'])",
            )
            ->and($routes)
            ->toContain('Route::livewire')
            ->and($routes)
            ->toContain("->name('security.dashboard.')");

        expect(Route::has('security.dashboard.overview'))->toBeFalse();
    },
);

test(
    'security install command can publish the dashboard with the with-dashboard flag',
    function () {
        $directory = resource_path('views/pages/security');

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan('security:install', [
            '--force' => true,
            '--with-dashboard' => true,
            '--without-nginx' => true,
            '--without-htaccess' => true,
            '--without-env' => true,
        ])->assertSuccessful();

        expect(File::exists($directory.'/overview.blade.php'))->toBeTrue();
    },
);
