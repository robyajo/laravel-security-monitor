<?php

use Illuminate\Support\Facades\File;

afterEach(function () {
    $publishedApache = base_path('apache2.conf');
    if (File::exists($publishedApache)) {
        File::delete($publishedApache);
    }
});

test('apache2 configuration stub can be published using vendor publish tag', function () {
    $publishedPath = base_path('apache2.conf');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('vendor:publish', [
        '--tag' => 'security-apache',
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();

    $content = File::get($publishedPath);

    // Verify key hardened WAF directives in published apache2.conf
    expect($content)->toContain('LARAVEL SECURITY MONITOR (BULWARK) - HARDENED APACHE 2 CONFIGURATION')
        ->and($content)->toContain('<VirtualHost *:80>')
        ->and($content)->toContain('DocumentRoot /var/www/your-app/public')
        ->and($content)->toContain('ServerSignature Off')
        ->and($content)->toContain('LimitRequestBody 5242880')
        ->and($content)->toContain('X-Content-Type-Options "nosniff"')
        ->and($content)->toContain('Content-Security-Policy "default-src \'none\'; style-src \'unsafe-inline\'; sandbox"')
        ->and($content)->toContain('phtml|pht|phar|phps')
        ->and($content)->toContain('mod_proxy_fcgi.c');
});

test('security install command runs and publishes apache2 configuration', function () {
    $publishedPath = base_path('apache2.conf');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('security:install', [
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();
    expect(File::get($publishedPath))->toContain('LARAVEL SECURITY MONITOR (BULWARK) - HARDENED APACHE 2 CONFIGURATION');
});

test('security install command respects without-apache option', function () {
    $publishedPath = base_path('apache2.conf');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('security:install', [
        '--without-apache' => true,
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeFalse();
});
