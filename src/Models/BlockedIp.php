<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $ip_address
 * @property string|null $local_ip
 * @property string|null $device_id
 * @property string $block_scope
 * @property string|null $reason
 * @property string|null $notes
 * @property string $source
 * @property int|null $blocked_by
 * @property Carbon|null $blocked_at
 * @property Carbon|null $expires_at
 * @property bool $is_active
 * @property int $hit_count
 * @property Carbon|null $last_hit_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class BlockedIp extends Model
{
    public function getTable()
    {
        return config('security.table_names.blocked_ips', parent::getTable());
    }

    protected $fillable = [
        'ip_address',
        'local_ip',
        'device_id',
        'block_scope',
        'reason',
        'notes',
        'source',
        'blocked_by',
        'blocked_at',
        'expires_at',
        'is_active',
        'hit_count',
        'last_hit_at',
    ];

    protected $casts = [
        'is_active' => 'boolean',
        'hit_count' => 'integer',
        'blocked_at' => 'datetime',
        'expires_at' => 'datetime',
        'last_hit_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<Model, $this>
     */
    public function blockedBy(): BelongsTo
    {
        return $this->belongsTo(
            config('security.user_model', 'App\\Models\\User'),
            'blocked_by',
        );
    }

    /**
     * Only currently enforced blocks (active and not expired).
     *
     * @param  Builder<BlockedIp>  $query
     * @return Builder<BlockedIp>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query
            ->where('is_active', true)
            ->where(function (Builder $query) {
                $query
                    ->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * @param  Builder<BlockedIp>  $query
     * @return Builder<BlockedIp>
     */
    public function scopeExpired(Builder $query): Builder
    {
        return $query
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());
    }

    public function isPermanent(): bool
    {
        return $this->expires_at === null;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * Whether this record currently blocks traffic.
     */
    public function isEnforced(): bool
    {
        return $this->is_active && ! $this->isExpired();
    }

    /**
     * Human readable remaining duration of the block.
     */
    public function getRemainingAttribute(): string
    {
        if ($this->isPermanent()) {
            return 'Permanen';
        }

        if ($this->isExpired()) {
            return 'Kedaluwarsa';
        }

        return $this->expires_at->diffForHumans(now(), [
            'syntax' => Carbon::DIFF_ABSOLUTE,
            'parts' => 2,
        ]);
    }
}
