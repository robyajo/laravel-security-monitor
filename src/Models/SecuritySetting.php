<?php

namespace Internal\SecurityMonitor\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Persisted key-value settings for Laravel Security Monitor.
 *
 * @property int $id
 * @property string $key
 * @property string|null $value
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class SecuritySetting extends Model
{
    protected $table = 'security_settings';

    protected $fillable = [
        'key',
        'value',
    ];
}
