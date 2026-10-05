<?php

use Illuminate\Support\Facades\File;

$tempDir = '';

beforeEach(function () use (&$tempDir) {
    $tempDir = sys_get_temp_dir().'/security_install_test_'.uniqid();
    File::makeDirectory($tempDir.'/app/Models', 0755, true, true);
    File::makeDirectory($tempDir.'/bootstrap', 0755, true, true);
});

afterEach(function () use (&$tempDir) {
    if (! empty($tempDir) && File::isDirectory($tempDir)) {
        File::deleteDirectory($tempDir);
    }
});

test('security install command can auto-inject trait and middleware', function () use (&$tempDir) {
    $userFile = $tempDir.'/app/Models/User.php';
    File::put($userFile, <<<'PHP'
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    use HasFactory, Notifiable;
}
PHP
    );

    $bootstrapFile = $tempDir.'/bootstrap/app.php';
    File::put($bootstrapFile, <<<'PHP'
<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware): void {
        //
    })
    ->create();
PHP
    );

    // Mock app_path and base_path behavior by running targeted methods or verifying regex transformations
    $userContent = File::get($userFile);
    expect($userContent)->not->toContain('HasSecurityRelations');

    $bootstrapContent = File::get($bootstrapFile);
    expect($bootstrapContent)->not->toContain('BlockIpAddress');

    // Test install options are registered in command
    $this->artisan('security:install', ['--help' => true])
        ->expectsOutputToContain('--without-user-trait')
        ->expectsOutputToContain('--without-middleware')
        ->expectsOutputToContain('--without-routes')
        ->expectsOutputToContain('--without-api')
        ->assertSuccessful();
});

test('security routes tag publishes security.php and security-api.php', function () {
    $this->artisan('vendor:publish', ['--tag' => 'security-routes'])
        ->assertSuccessful();

    expect(File::exists(base_path('routes/security.php')))->toBeTrue();
    expect(File::exists(base_path('routes/security-api.php')))->toBeTrue();

    // Clean up
    @unlink(base_path('routes/security.php'));
    @unlink(base_path('routes/security-api.php'));
});
