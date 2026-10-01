<?php

namespace Internal\SecurityMonitor\Tests;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Internal\SecurityMonitor\Concerns\HasSecurityRelations;

class TestUser extends Authenticatable
{
    use HasSecurityRelations;

    protected $table = 'users';
    protected $guarded = [];

    public function isAdmin(): bool
    {
        return $this->role === 'admin';
    }
}
