<?php

use Illuminate\Support\Facades\File;

afterEach(function () {
    $publishedNginx = base_path('nginx.conf');
    if (File::exists($publishedNginx)) {
        File::delete($publishedNginx);
    }
});

test('nginx configuration stub can be published using vendor publish tag', function () {
    $publishedPath = base_path('nginx.conf');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('vendor:publish', [
        '--tag' => 'security-nginx',
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();

    $content = File::get($publishedPath);

    // Verify key hardened WAF directives in published nginx.conf
    expect($content)->toContain('limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;')
        ->and($content)->toContain('limit_req_zone $binary_remote_addr zone=general_limit:10m rate=30r/s;')
        ->and($content)->toContain('root /var/www/your-app/public;')
        ->and($content)->toContain('location ~ \.php$ {')
        ->and($content)->toContain('return 403;')
        ->and($content)->toContain('location = /index.php {')
        ->and($content)->toContain('location ^~ /storage/ {')
        ->and($content)->toContain('add_header X-Content-Type-Options "nosniff" always;');
});

test('security install command runs and publishes nginx configuration', function () {
    $publishedPath = base_path('nginx.conf');

    if (File::exists($publishedPath)) {
        File::delete($publishedPath);
    }

    $this->artisan('security:install', [
        '--force' => true,
    ])->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();
    expect(File::get($publishedPath))->toContain('LARAVEL SECURITY MONITOR (BULWARK) - HARDENED NGINX CONFIGURATION');
});
