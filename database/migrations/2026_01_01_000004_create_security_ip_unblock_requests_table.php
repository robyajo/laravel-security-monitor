<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('security.table_names.ip_unblock_requests', 'ip_unblock_requests');
        $usersTable = config('security.table_names.users', 'users');
        $blockedIpsTable = config('security.table_names.blocked_ips', 'blocked_ips');

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $blueprint) use ($usersTable, $blockedIpsTable) {
                $blueprint->id();
                $blueprint->string('ticket_number', 40)->unique();
                $blueprint->string('ip_address', 45)->index();
                $blueprint->string('local_ip', 45)->nullable();
                $blueprint->string('device_id', 100)->nullable()->index();
                $blueprint->string('name', 100);
                $blueprint->string('email', 150);
                $blueprint->string('phone', 30)->nullable();
                $blueprint->text('reason');
                $blueprint->string('status', 20)->default('pending')->index();
                $blueprint->text('admin_notes')->nullable();
                $blueprint->foreignId('resolved_by')->nullable()->constrained($usersTable)->nullOnDelete();
                $blueprint->timestamp('resolved_at')->nullable();
                $blueprint->foreignId('blocked_ip_id')->nullable()->constrained($blockedIpsTable)->nullOnDelete();
                $blueprint->text('user_agent')->nullable();
                $blueprint->timestamps();

                $blueprint->index(['status', 'created_at']);
            });
        }
    }

    public function down(): void
    {
        $table = config('security.table_names.ip_unblock_requests', 'ip_unblock_requests');
        Schema::dropIfExists($table);
    }
};
