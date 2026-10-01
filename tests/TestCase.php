<?php

namespace Internal\SecurityMonitor\Tests;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Internal\SecurityMonitor\Http\Middleware\BlockIpAddress;
use Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats;
use Internal\SecurityMonitor\SecurityMonitorServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            SecurityMonitorServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('security.user_model', TestUser::class);
        $app['config']->set('security.enabled', true);
        $app['config']->set('security.block_enforcement', true);
        $app['config']->set('security.routes.enabled', true);

        $kernel = $app->make(Kernel::class);
        $kernel->pushMiddleware(BlockIpAddress::class);
        $kernel->pushMiddleware(DetectSecurityThreats::class);
    }

    protected function defineRoutes($router): void
    {
        $router->post('/login', function () {
            return redirect('/');
        });
        $router->get('/login', function () {
            return response('login form', 200);
        });
        $router->get('/', function () {
            return response('home', 200);
        });
    }

    protected function defineDatabaseMigrations(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password');
            $table->string('role')->default('user');
            $table->timestamps();
        });

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function createAdminUser(array $attributes = []): TestUser
    {
        return TestUser::create(array_merge([
            'name' => 'Admin User',
            'email' => 'admin@example.com',
            'password' => bcrypt('password'),
            'role' => 'admin',
        ], $attributes));
    }

    protected function createRegularUser(array $attributes = []): TestUser
    {
        return TestUser::create(array_merge([
            'name' => 'Regular User',
            'email' => 'user@example.com',
            'password' => bcrypt('password'),
            'role' => 'user',
        ], $attributes));
    }
}
