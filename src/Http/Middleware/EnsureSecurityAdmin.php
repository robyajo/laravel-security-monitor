<?php

namespace Internal\SecurityMonitor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Memastikan request dilakukan oleh Administrator yang berwenang
 * mengelola fitur keamanan dan IP blocking.
 */
class EnsureSecurityAdmin
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user) {
            return $this->unauthorized($request);
        }

        if (Gate::has('manage-security-monitor')) {
            if (! Gate::allows('manage-security-monitor')) {
                return $this->forbidden($request);
            }
            return $next($request);
        }

        if (method_exists($user, 'isAdmin') && $user->isAdmin()) {
            return $next($request);
        }

        if (in_array($user->role ?? null, ['admin', 'superadmin'], true)) {
            return $next($request);
        }

        if (($user->is_admin ?? false) === true) {
            return $next($request);
        }

        return $this->forbidden($request);
    }

    protected function unauthorized(Request $request): Response
    {
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthenticated.',
            ], 401);
        }

        abort(401, 'Silakan login terlebih dahulu.');
    }

    protected function forbidden(Request $request): Response
    {
        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'success' => false,
                'message' => 'Hanya administrator yang diizinkan mengakses resource keamanan ini.',
            ], 403);
        }

        abort(403, 'Hanya administrator yang diizinkan mengakses resource keamanan ini.');
    }
}
