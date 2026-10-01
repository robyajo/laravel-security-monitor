<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('security.table_names.security_logs', 'security_logs');
        $usersTable = config('security.table_names.users', 'users');

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $blueprint) use ($usersTable) {
                $blueprint->id();
                $blueprint->string('ip_address', 45)->index();
                $blueprint->string('local_ip', 45)->nullable();
                $blueprint->string('device_id', 100)->nullable()->index();
                $blueprint->foreignId('user_id')->nullable()->constrained($usersTable)->nullOnDelete();
                $blueprint->string('event_type', 40)->index();
                $blueprint->string('threat_level', 20)->default('low')->index();
                $blueprint->string('method', 10)->nullable();
                $blueprint->string('path', 2048)->nullable();
                $blueprint->text('full_url')->nullable();
                $blueprint->string('rule_label')->nullable();
                $blueprint->text('evidence')->nullable();
                $blueprint->string('user_agent', 512)->nullable();
                $blueprint->string('referer', 512)->nullable();
                $blueprint->boolean('was_blocked')->default(false);
                $blueprint->string('action_taken', 40)->nullable();
                $blueprint->json('meta')->nullable();
                $blueprint->timestamps();

                $blueprint->index(['ip_address', 'created_at']);
                $blueprint->index(['threat_level', 'created_at']);
                $blueprint->index('created_at');
            });
        }
    }

    public function down(): void
    {
        $table = config('security.table_names.security_logs', 'security_logs');
        Schema::dropIfExists($table);
    }
};
