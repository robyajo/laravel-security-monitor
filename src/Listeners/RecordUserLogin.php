<?php

namespace Internal\SecurityMonitor\Listeners;

use Illuminate\Auth\Events\Login;
use Internal\SecurityMonitor\Services\UserLoginService;
use Throwable;

class RecordUserLogin
{
    public function __construct(protected UserLoginService $loginService) {}

    public function handle(Login $event): void
    {
        $user = $event->user;
        $userModel = (string) config(
            'security.user_model',
            'App\\Models\\User',
        );

        // Hanya catat login untuk model user yang dikonfigurasi (bila kelasnya ada).
        if (class_exists($userModel) && ! ($user instanceof $userModel)) {
            return;
        }

        try {
            $this->loginService->recordLogin($user, request());
        } catch (Throwable) {
            // Do not block user login if recording fails
        }
    }
}
