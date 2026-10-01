<?php

use Illuminate\Support\Facades\File;

afterEach(function () {
    $publishedHtaccess = public_path('.htaccess');
    if (File::exists($publishedHtaccess)) {
        File::delete($publishedHtaccess);
    }

    $publicDir = public_path();
    if (File::isDirectory($publicDir)) {
        foreach (File::glob($publicDir . '/.htaccess.backup-*') as $backup) {
            File::delete($backup);
        }
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
    File::put($publishedPath, "# Custom User Rewrite Rules
RewriteEngine On
");

    $this->artisan('security:install')
        ->assertSuccessful();

    expect(File::exists($publishedPath))->toBeTrue();
    $content = File::get($publishedPath);

    // Pastikan aturan custom user tidak hilang dan aturan hardening bertambah
    expect($content)->toContain('# Custom User Rewrite Rules')
        ->and($content)->toContain('Hardening keamanan')
        ->and($content)->toContain('Options -Indexes');

    // Pastikan berkas cadangan tercipta
    $backups = File::glob($publicDir . '/.htaccess.backup-*');
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
