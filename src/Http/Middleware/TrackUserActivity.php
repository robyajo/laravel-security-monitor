<?php

namespace Internal\SecurityMonitor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Internal\SecurityMonitor\Services\UserLoginService;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class TrackUserActivity
{
    public function __construct(
        protected UserLoginService $loginService,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if ($request->user()) {
            $userId = $request->user()->id;
            $cacheKey = "user_act_{$userId}";

            // Throttle database heartbeat write to once every 45 seconds per user
            if (! Cache::has($cacheKey)) {
                Cache::put($cacheKey, true, now()->addSeconds(45));

                try {
                    $this->loginService->updateActivity(
                        $userId,
                        (string) ($request->ip() ?? '127.0.0.1'),
                        $request->session()->getId(),
                    );
                } catch (Throwable) {
                    // Ignore tracking errors to avoid disrupting response
                }
            }
        }

        return $response;
    }
}
