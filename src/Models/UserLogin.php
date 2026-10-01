<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property string|null $session_id
 * @property string $ip_address
 * @property string|null $local_ip
 * @property string|null $device_id
 * @property string|null $user_agent
 * @property string $device_type
 * @property string $operating_system
 * @property string $browser
 * @property string|null $city
 * @property string|null $region
 * @property string|null $country
 * @property string|null $country_code
 * @property float|null $latitude
 * @property float|null $longitude
 * @property string|null $isp
 * @property Carbon $login_at
 * @property Carbon|null $last_activity_at
 * @property Carbon|null $logout_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class UserLogin extends Model
{
    public function getTable()
    {
        return config('security.table_names.user_logins', parent::getTable());
    }

    protected $fillable = [
        'user_id',
        'session_id',
        'ip_address',
        'local_ip',
        'device_id',
        'user_agent',
        'device_type',
        'operating_system',
        'browser',
        'city',
        'region',
        'country',
        'country_code',
        'latitude',
        'longitude',
        'isp',
        'login_at',
        'last_activity_at',
        'logout_at',
    ];

    protected $casts = [
        'login_at' => 'datetime',
        'last_activity_at' => 'datetime',
        'logout_at' => 'datetime',
        'latitude' => 'float',
        'longitude' => 'float',
    ];

    /**
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(config('security.user_model', 'App\\Models\\User'));
    }

    /**
     * Filter login records that were active in the last $minutes minutes.
     *
     * @param  Builder<UserLogin>  $query
     * @return Builder<UserLogin>
     */
    public function scopeActive(Builder $query, int $minutes = 5): Builder
    {
        return $query->where('last_activity_at', '>=', now()->subMinutes($minutes))
            ->whereNull('logout_at');
    }

    /**
     * Determine if this login is currently considered online.
     */
    public function isOnline(int $minutes = 5): bool
    {
        if ($this->logout_at !== null) {
            return false;
        }

        return $this->last_activity_at !== null && $this->last_activity_at->gte(now()->subMinutes($minutes));
    }

    /**
     * Format location string.
     */
    public function formattedLocation(): string
    {
        $parts = array_filter([$this->city, $this->region, $this->country]);

        return ! empty($parts) ? implode(', ', $parts) : 'Lokasi Tidak Diketahui';
    }
}
