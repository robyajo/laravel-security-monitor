<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $userLoginsTable = config('security.table_names.user_logins', 'user_logins');
        $trustedIpsTable = config('security.table_names.trusted_ips', 'trusted_ips');
        $usersTable = config('security.table_names.users', 'users');

        if (! Schema::hasTable($userLoginsTable)) {
            Schema::create($userLoginsTable, function (Blueprint $blueprint) use ($usersTable) {
                $blueprint->id();
                $blueprint->foreignId('user_id')->constrained($usersTable)->cascadeOnDelete();
                $blueprint->string('session_id', 255)->nullable()->index();
                $blueprint->string('ip_address', 45)->index();
                $blueprint->string('local_ip', 45)->nullable();
                $blueprint->string('device_id', 100)->nullable()->index();
                $blueprint->text('user_agent')->nullable();
                $blueprint->string('device_type', 50)->default('desktop');
                $blueprint->string('operating_system', 100)->default('Unknown OS');
                $blueprint->string('browser', 100)->default('Unknown Browser');
                $blueprint->string('city', 100)->nullable();
                $blueprint->string('region', 100)->nullable();
                $blueprint->string('country', 100)->nullable();
                $blueprint->string('country_code', 10)->nullable();
                $blueprint->decimal('latitude', 10, 7)->nullable();
                $blueprint->decimal('longitude', 10, 7)->nullable();
                $blueprint->string('isp', 255)->nullable();
                $blueprint->timestamp('login_at');
                $blueprint->timestamp('last_activity_at')->nullable()->index();
                $blueprint->timestamp('logout_at')->nullable();
                $blueprint->timestamps();
            });
        }

        if (! Schema::hasTable($trustedIpsTable)) {
            Schema::create($trustedIpsTable, function (Blueprint $blueprint) use ($usersTable) {
                $blueprint->id();
                $blueprint->foreignId('user_id')->constrained($usersTable)->cascadeOnDelete();
                $blueprint->string('ip_address', 45)->index();
                $blueprint->string('local_ip', 45)->nullable();
                $blueprint->string('device_id', 100)->nullable()->index();
                $blueprint->string('device_name', 255)->nullable();
                $blueprint->string('operating_system', 100)->nullable();
                $blueprint->string('browser', 100)->nullable();
                $blueprint->string('location', 255)->nullable();
                $blueprint->boolean('is_active')->default(true);
                $blueprint->timestamp('verified_at')->nullable();
                $blueprint->timestamps();

                $blueprint->unique(['user_id', 'ip_address']);
            });
        }
    }

    public function down(): void
    {
        $trustedIpsTable = config('security.table_names.trusted_ips', 'trusted_ips');
        $userLoginsTable = config('security.table_names.user_logins', 'user_logins');

        Schema::dropIfExists($trustedIpsTable);
        Schema::dropIfExists($userLoginsTable);
    }
};
