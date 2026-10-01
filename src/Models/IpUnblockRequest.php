<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $ticket_number
 * @property string $ip_address
 * @property string|null $local_ip
 * @property string|null $device_id
 * @property string $name
 * @property string $email
 * @property string|null $phone
 * @property string $reason
 * @property string $status
 * @property string|null $admin_notes
 * @property int|null $resolved_by
 * @property Carbon|null $resolved_at
 * @property int|null $blocked_ip_id
 * @property string|null $user_agent
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class IpUnblockRequest extends Model
{
    public function getTable()
    {
        return config('security.table_names.ip_unblock_requests', parent::getTable());
    }

    protected $fillable = [
        'ticket_number',
        'ip_address',
        'local_ip',
        'device_id',
        'name',
        'email',
        'phone',
        'reason',
        'status',
        'admin_notes',
        'resolved_by',
        'resolved_at',
        'blocked_ip_id',
        'user_agent',
    ];

    protected $casts = [
        'resolved_at' => 'datetime',
    ];

    /**
     * @return BelongsTo<User, $this>
     */
    public function resolver(): BelongsTo
    {
        return $this->belongsTo(config('security.user_model', 'App\\Models\\User'), 'resolved_by');
    }

    /**
     * @return BelongsTo<BlockedIp, $this>
     */
    public function blockedIp(): BelongsTo
    {
        return $this->belongsTo(BlockedIp::class, 'blocked_ip_id');
    }

    /**
     * @param  Builder<IpUnblockRequest>  $query
     * @return Builder<IpUnblockRequest>
     */
    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', 'pending');
    }

    /**
     * @param  Builder<IpUnblockRequest>  $query
     * @return Builder<IpUnblockRequest>
     */
    public function scopeApproved(Builder $query): Builder
    {
        return $query->where('status', 'approved');
    }

    /**
     * @param  Builder<IpUnblockRequest>  $query
     * @return Builder<IpUnblockRequest>
     */
    public function scopeRejected(Builder $query): Builder
    {
        return $query->where('status', 'rejected');
    }

    public function isPending(): bool
    {
        return $this->status === 'pending';
    }

    public function isApproved(): bool
    {
        return $this->status === 'approved';
    }

    public function isRejected(): bool
    {
        return $this->status === 'rejected';
    }
}
