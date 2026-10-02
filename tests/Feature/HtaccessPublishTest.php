<?php

use Illuminate\Support\Facades\File;

afterEach(function () {
    $publishedHtaccess = public_path('.htaccess');
    if (File::exists($publishedHtaccess)) {
        File::delete($publishedHtaccess);
    }

    $publicDir = public_path();
    if (File::isDirectory($publicDir)) {
        foreach (File::glob($publicDir.'/.htaccess.backup-*') as $backup) {
            File::delete($backup);
        }
    }

    $envPath = base_path('.env');
    if (File::exists($envPath)) {
        File::delete($envPath);
    }

    $envExamplePath = base_path('.env.example');
    if (File::exists($envExamplePath)) {
        File::delete($envExamplePath);
    }
});

test('htaccess configuration stub can be published using vendor publish tag', function () {
    $publishedPath = public_path('.htaccess');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('vendor:publish', [
        '--tag' => 'security-htaccess',
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();

    $content = File::get($publishedPath);

    // Verify key hardened Apache directives in published .htaccess
    expect($content)->toContain('<FilesMatch "^\.">')
        ->and($content)->toContain('Require all denied')
        ->and($content)->toContain('phtml|pht|phar|phps')
        ->and($content)->toContain('sql|bak|old|orig|save|swp|log')
        ->and($content)->toContain('Options -Indexes');
});

test('security install command runs and publishes htaccess configuration', function () {
    $publishedPath = public_path('.htaccess');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('security:install', [
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();
    $content = File::get($publishedPath);
    expect($content)->toContain('Hardening keamanan')
        ->and($content)->toContain('Options -Indexes');
});

test('security install command appends hardening to existing htaccess and creates backup', function () {
    $publicDir = public_path();
    if (! File::isDirectory($publicDir)) {
        File::makeDirectory($publicDir, 0755, true, true);
    }

    $publishedPath = public_path('.htaccess');
    File::put($publishedPath, "# Custom User Rewrite Rules\nRewriteEngine On\n");

    $this->artisan('security:install')
        ->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();
    $content = File::get($publishedPath);

    // Pastikan aturan custom user tidak hilang dan aturan hardening bertambah
    expect($content)->toContain('# Custom User Rewrite Rules')
        ->and($content)->toContain('Hardening keamanan')
        ->and($content)->toContain('Options -Indexes');

    // Pastikan berkas cadangan tercipta
    $backups = File::glob($publicDir.'/.htaccess.backup-*');
    expect(count($backups))->toBeGreaterThanOrEqual(1);
});

test('security install command respects without-htaccess option', function () {
    $publishedPath = public_path('.htaccess');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('security:install', [
        '--without-htaccess' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeFalse();
});

test('security install command appends environment variables to env and env example', function () {
    $envPath = base_path('.env');
    $envExamplePath = base_path('.env.example');

    File::put($envPath, "APP_NAME=Laravel\nAPP_ENV=local\n");
    File::put($envExamplePath, "APP_NAME=Laravel\nAPP_ENV=local\n");

    $this->artisan('security:install')
        ->assertSuccessful();

    $envContent = File::get($envPath);
    $exampleContent = File::get($envExamplePath);

    expect($envContent)->toContain('SECURITY_MONITOR_ENABLED=true')
        ->and($envContent)->toContain('SECURITY_INSTANT_BLOCK_ENABLED=true')
        ->and($envContent)->toContain('Sakelar utama WAF')
        ->and($exampleContent)->toContain('SECURITY_MONITOR_ENABLED=true');
});

test('security install command respects without-env option', function () {
    $envPath = base_path('.env');
    File::put($envPath, "APP_NAME=Laravel\nAPP_ENV=local\n");

    $this->artisan('security:install', [
        '--without-env' => true,
    ])->assertSuccessful();

    $envContent = File::get($envPath);
    expect($envContent)->not->toContain('SECURITY_MONITOR_ENABLED');
});
