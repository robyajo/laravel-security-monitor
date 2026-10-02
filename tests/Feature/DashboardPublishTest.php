<?php

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;

afterEach(function () {
    $directory = resource_path("views/pages/security");
    if (File::isDirectory($directory)) {
        File::deleteDirectory($directory);
    }
});

test(
    "dashboard is disabled by default so the package stays headless",
    function () {
        expect(config("security.dashboard.enabled"))
            ->toBeFalse()
            ->and(config("security.dashboard.prefix"))
            ->toBe("security")
            ->and(config("security.dashboard.middleware"))
            ->toContain("auth");
    },
);

test(
    "starterkit livewire tag publishes the monitoring views and configuration",
    function () {
        $directory = resource_path("views/pages/security");

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan("vendor:publish", [
            "--tag" => "starterkit-livewire",
            "--force" => true,
        ])->assertSuccessful();

        expect(File::exists($directory . "/overview.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/logs.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/blocked-ips.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/server.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/sessions.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/tickets.blade.php"))
            ->toBeTrue()
            ->and(File::exists($directory . "/layout.blade.php"))
            ->toBeTrue();

        expect(File::get($directory . "/overview.blade.php"))->toContain(
            "Security Overview",
        );
    },
);

test(
    "typo-compatible staterkit livewire alias publishes the monitoring views",
    function () {
        $directory = resource_path("views/pages/security");

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan("vendor:publish", [
            "--tag" => "staterkit-livewire",
            "--force" => true,
        ])->assertSuccessful();

        expect(File::exists($directory . "/overview.blade.php"))->toBeTrue();
    },
);

test(
    "dashboard routes require authentication and livewire to be present",
    function () {
        // The published dashboard must always be gated behind authentication, and
        // the package only registers the page-component routes when Livewire is
        // actually installed in the host application.
        $routes = File::get(__DIR__ . "/../../routes/security-dashboard.php");

        expect($routes)
            ->toContain(
                "config('security.dashboard.middleware', ['web', 'auth'])",
            )
            ->and($routes)
            ->toContain("Route::livewire")
            ->and($routes)
            ->toContain("->name('security.dashboard.')");

        expect(Route::has("security.dashboard.overview"))->toBeFalse();
    },
);

test(
    "security install command can publish the dashboard with the with-dashboard flag",
    function () {
        $directory = resource_path("views/pages/security");

        if (File::isDirectory($directory)) {
            File::deleteDirectory($directory);
        }

        $this->artisan("security:install", [
            "--force" => true,
            "--with-dashboard" => true,
            "--without-nginx" => true,
            "--without-htaccess" => true,
            "--without-env" => true,
        ])->assertSuccessful();

        expect(File::exists($directory . "/overview.blade.php"))->toBeTrue();
    },
);
