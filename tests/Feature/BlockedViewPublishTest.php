<?php

use Illuminate\Support\Facades\File;

afterEach(function () {
    $view = resource_path('views/errors/blocked.blade.php');
    if (File::exists($view)) {
        File::delete($view);
    }

    $htaccess = public_path('.htaccess');
    if (File::exists($htaccess)) {
        File::delete($htaccess);
    }

    foreach (File::glob(public_path('.htaccess.backup-*')) as $backup) {
        File::delete($backup);
    }

    foreach ([base_path('.env'), base_path('.env.example')] as $envFile) {
        if (File::exists($envFile)) {
            File::delete($envFile);
        }
    }
});

test('blocked view stub can be published using vendor publish tag', function () {
    $path = resource_path('views/errors/blocked.blade.php');

    if (File::exists($path)) {
        File::delete($path);
    }

    $this->artisan('vendor:publish', [
        '--tag' => 'security-views',
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($path))->toBeTrue();

    $content = File::get($path);

    expect($content)->toContain('Permintaan Anda Diblokir')
        ->and($content)->toContain('unblock-tickets/submit')
        ->and($content)->toContain('security-appeal-form');
});

test('security install command publishes the default blocked view', function () {
    $path = resource_path('views/errors/blocked.blade.php');

    if (File::exists($path)) {
        File::delete($path);
    }

    $this->artisan('security:install', [
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($path))->toBeTrue();
});

test('security install command respects without-views option', function () {
    $path = resource_path('views/errors/blocked.blade.php');

    if (File::exists($path)) {
        File::delete($path);
    }

    $this->artisan('security:install', [
        '--without-views' => true,
    ])->assertSuccessful();

    expect(File::exists($path))->toBeFalse();
});
