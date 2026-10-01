<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = config('security.table_names.login_attempts', 'login_attempts');

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $blueprint) {
                $blueprint->id();
                $blueprint->string('email')->nullable();
                $blueprint->string('ip_address', 45)->nullable();
                $blueprint->unsignedInteger('attempts')->default(0);
                $blueprint->unsignedInteger('lockout_level')->default(0);
                $blueprint->timestamp('locked_until')->nullable();
                $blueprint->timestamp('last_attempt_at')->nullable();
                $blueprint->timestamps();

                $blueprint->unique(['email', 'ip_address']);
                $blueprint->index('locked_until');
                $blueprint->index('last_attempt_at');
            });
        }
    }

    public function down(): void
    {
        $table = config('security.table_names.login_attempts', 'login_attempts');
        Schema::dropIfExists($table);
    }
};
