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
 * @property int|null $user_id
 * @property string $event_type
 * @property string $threat_level
 * @property string|null $method
 * @property string|null $path
 * @property string|null $full_url
 * @property string|null $rule_label
 * @property string|null $evidence
 * @property string|null $user_agent
 * @property string|null $referer
 * @property bool $was_blocked
 * @property string|null $action_taken
 * @property array<string, mixed>|null $meta
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class SecurityLog extends Model
{
    public function getTable()
    {
        return config('security.table_names.security_logs', parent::getTable());
    }

    public const LEVELS = ['low', 'medium', 'high', 'critical'];

    /**
     * Numeric weight per level, used for sorting and severity comparison.
     *
     * @var array<string, int>
     */
    public const LEVEL_WEIGHTS = [
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    protected $fillable = [
        'ip_address',
        'local_ip',
        'device_id',
        'user_id',
        'event_type',
        'threat_level',
        'method',
        'path',
        'full_url',
        'rule_label',
        'evidence',
        'user_agent',
        'referer',
        'was_blocked',
        'action_taken',
        'meta',
    ];

    protected $casts = [
        'was_blocked' => 'boolean',
        'meta' => 'array',
    ];

    /**
     * Severity weight of a level name (unknown levels count as the lowest).
     */
    public static function weightOf(?string $level): int
    {
        return self::LEVEL_WEIGHTS[$level] ?? 0;
    }

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
     * @param  Builder<SecurityLog>  $query
     * @return Builder<SecurityLog>
     */
    public function scopeLevel(Builder $query, string $level): Builder
    {
        return $query->where('threat_level', $level);
    }

    /**
     * Logs whose level is at least as severe as the given level.
     *
     * @param  Builder<SecurityLog>  $query
     * @return Builder<SecurityLog>
     */
    public function scopeAtLeast(Builder $query, string $level): Builder
    {
        $minimum = self::LEVEL_WEIGHTS[$level] ?? 1;
        $levels = array_keys(
            array_filter(
                self::LEVEL_WEIGHTS,
                fn (int $weight) => $weight >= $minimum,
            ),
        );

        return $query->whereIn('threat_level', $levels);
    }

    /**
     * @param  Builder<SecurityLog>  $query
     * @return Builder<SecurityLog>
     */
    public function scopeEventType(Builder $query, string $type): Builder
    {
        return $query->where('event_type', $type);
    }

    /**
     * Severity weight of this log entry (higher is worse).
     */
    public function severity(): int
    {
        return self::LEVEL_WEIGHTS[$this->threat_level] ?? 0;
    }

    public function isCritical(): bool
    {
        return $this->threat_level === 'critical';
    }

    /**
     * Label used for the UI badges.
     */
    public function levelLabel(): string
    {
        return match ($this->threat_level) {
            'critical' => 'Kritis',
            'high' => 'Tinggi',
            'medium' => 'Sedang',
            default => 'Rendah',
        };
    }
}
