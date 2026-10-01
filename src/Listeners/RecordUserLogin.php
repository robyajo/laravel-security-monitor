<?php

namespace Internal\SecurityMonitor\Listeners;

use Illuminate\Contracts\Auth\Authenticatable;
use Internal\SecurityMonitor\Services\UserLoginService;
use Illuminate\Auth\Events\Login;
use Throwable;

class RecordUserLogin
{
    public function __construct(
        protected UserLoginService $loginService,
    ) {}

    public function handle(Login $event): void
    {
        if ($event->user instanceof User && request()) {
            try {
                $this->loginService->recordLogin($event->user, request());
            } catch (Throwable) {
                // Do not block user login if recording fails
            }
        }
    }
}
