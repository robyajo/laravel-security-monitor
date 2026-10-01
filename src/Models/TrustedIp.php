<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $user_id
 * @property string $ip_address
 * @property string|null $local_ip
 * @property string|null $device_id
 * @property string|null $device_name
 * @property string|null $operating_system
 * @property string|null $browser
 * @property string|null $location
 * @property bool $is_active
 * @property Carbon|null $verified_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class TrustedIp extends Model
{
    public function getTable()
    {
        return config('security.table_names.trusted_ips', parent::getTable());
    }

    protected $fillable = [
        'user_id',
        'ip_address',
        'local_ip',
        'device_id',
        'device_name',
        'operating_system',
        'browser',
        'location',
        'is_active',
        'verified_at',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'verified_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(
            config('security.user_model', 'App\\Models\\User'),
        );
    }

    /**
     * @param  Builder<TrustedIp>  $query
     * @return Builder<TrustedIp>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    /**
     * Check if a specific IP / device is trusted for a user.
     */
    public static function isTrusted(
        string $ip,
        int $userId,
        ?string $deviceId = null,
        ?string $localIp = null,
    ): bool {
        return static::query()
            ->where('user_id', $userId)
            ->where('is_active', true)
            ->where(function (Builder $query) use ($ip, $deviceId, $localIp) {
                $query->where('ip_address', $ip);
                if ($deviceId) {
                    $query->orWhere('device_id', $deviceId);
                }
                if ($localIp) {
                    $query->orWhere('local_ip', $localIp);
                }
            })
            ->exists();
    }

    /**
     * Check if an IP / device is trusted by any user.
     */
    public static function isAnyTrusted(
        string $ip,
        ?string $deviceId = null,
        ?string $localIp = null,
    ): bool {
        return static::query()
            ->where('is_active', true)
            ->where(function (Builder $query) use ($ip, $deviceId, $localIp) {
                $query->where('ip_address', $ip);
                if ($deviceId) {
                    $query->orWhere('device_id', $deviceId);
                }
                if ($localIp) {
                    $query->orWhere('local_ip', $localIp);
                }
            })
            ->exists();
    }
}
