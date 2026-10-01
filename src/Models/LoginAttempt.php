<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Berisi hitungan percobaan login gagal per kombinasi email + IP, dipakai oleh
 * LoginThrottleService untuk menerapkan cooldown bertingkat
 * (3x salah → 1 menit, 3x salah lagi → 2 menit, dan seterusnya).
 *
 * @property int $id
 * @property string|null $email
 * @property string|null $ip_address
 * @property int $attempts
 * @property int $lockout_level
 * @property Carbon|null $locked_until
 * @property Carbon|null $last_attempt_at
 */
class LoginAttempt extends Model
{
    public function getTable()
    {
        return config('security.table_names.login_attempts', parent::getTable());
    }

    protected $fillable = [
        'email',
        'ip_address',
        'attempts',
        'lockout_level',
        'locked_until',
        'last_attempt_at',
    ];

    protected $casts = [
        'attempts' => 'integer',
        'lockout_level' => 'integer',
        'locked_until' => 'datetime',
        'last_attempt_at' => 'datetime',
    ];

    /**
     * Hanya record yang sedang terkunci.
     *
     * @param  Builder<LoginAttempt>  $query
     * @return Builder<LoginAttempt>
     */
    public function scopeLocked(Builder $query): Builder
    {
        return $query->whereNotNull('locked_until')
            ->where('locked_until', '>', now());
    }

    public function isLocked(): bool
    {
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }

    /**
     * Sisa detik sampai blokir sementara berakhir.
     */
    public function secondsRemaining(): int
    {
        if (! $this->isLocked()) {
            return 0;
        }

        return max(0, (int) now()->diffInSeconds($this->locked_until, false));
    }
}
