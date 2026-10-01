<?php

namespace Internal\SecurityMonitor\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;

trait HasSecurityRelations
{
    public function logins(): HasMany
    {
        return $this->hasMany(UserLogin::class, 'user_id');
    }

    public function trustedIps(): HasMany
    {
        return $this->hasMany(TrustedIp::class, 'user_id');
    }

    public function securityLogs(): HasMany
    {
        return $this->hasMany(SecurityLog::class, 'user_id');
    }

    public function blockedIps(): HasMany
    {
        return $this->hasMany(BlockedIp::class, 'blocked_by');
    }

    public function resolvedTickets(): HasMany
    {
        return $this->hasMany(IpUnblockRequest::class, 'resolved_by');
    }
}
