<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('security.table_names.blocked_ips', 'blocked_ips');
        $usersTable = config('security.table_names.users', 'users');

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $blueprint) use ($usersTable) {
                $blueprint->id();
                $blueprint->string('ip_address', 45);
                $blueprint->string('local_ip', 45)->nullable();
                $blueprint->string('device_id', 100)->nullable()->index();
                $blueprint->string('block_scope', 20)->default('ip');
                $blueprint->string('reason')->nullable();
                $blueprint->text('notes')->nullable();
                $blueprint->string('source', 20)->default('manual');
                $blueprint->foreignId('blocked_by')->nullable()->constrained($usersTable)->nullOnDelete();
                $blueprint->timestamp('blocked_at')->nullable();
                $blueprint->timestamp('expires_at')->nullable();
                $blueprint->boolean('is_active')->default(true);
                $blueprint->unsignedInteger('hit_count')->default(0);
                $blueprint->timestamp('last_hit_at')->nullable();
                $blueprint->timestamps();

                $blueprint->index(['is_active', 'ip_address']);
                $blueprint->index('expires_at');
            });
        }
    }

    public function down(): void
    {
        $table = config('security.table_names.blocked_ips', 'blocked_ips');
        Schema::dropIfExists($table);
    }
};
