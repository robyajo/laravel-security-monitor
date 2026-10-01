<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Services\UserLoginService;

class UserSessionApiController extends Controller
{
    public function __construct(
        protected UserLoginService $loginService,
        protected SecurityMonitorService $securityService,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $perPage = min(100, max(10, (int) $request->input('per_page', 20)));

        $loginsQuery = UserLogin::query()->with('user')->latest('id');

        if ($search = $request->input('search')) {
            $loginsQuery->where(function ($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                    ->orWhere('browser', 'like', "%{$search}%")
                    ->orWhere('operating_system', 'like', "%{$search}%")
                    ->orWhere('device_id', 'like', "%{$search}%")
                    ->orWhereHas('user', function ($uq) use ($search) {
                        $uq->where('name', 'like', "%{$search}%")
                            ->orWhere('email', 'like', "%{$search}%");
                    });
            });
        }

        $logins = $loginsQuery->paginate($perPage);

        $trustedIps = TrustedIp::query()->with('user')->latest('id')->get();

        return response()->json([
            'success' => true,
            'data' => [
                'logins' => $logins,
                'trusted_ips' => $trustedIps,
                'online_count' => UserLogin::query()->active(5)->count(),
            ],
        ]);
    }

    public function realtime(Request $request): JsonResponse
    {
        $activeLogins = UserLogin::query()
            ->with('user')
            ->active(5)
            ->latest('last_activity_at')
            ->get();

        return response()->json([
            'success' => true,
            'online_count' => $activeLogins->count(),
            'active_users' => $activeLogins,
        ]);
    }

    public function show(Request $request, int|string $id): JsonResponse
    {
        $login = UserLogin::query()->with('user')->find($id);

        if (! $login) {
            return response()->json([
                'success' => false,
                'message' => 'Data sesi login tidak ditemukan.',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'data' => $login,
        ]);
    }

    public function destroy(Request $request, int|string $id): JsonResponse
    {
        $login = UserLogin::query()->find($id);

        if (! $login) {
            return response()->json([
                'success' => false,
                'message' => 'Data login tidak ditemukan.',
            ], 404);
        }

        $login->delete();

        return response()->json([
            'success' => true,
            'message' => 'Riwayat login berhasil dihapus.',
        ]);
    }

    public function destroySession(Request $request, string $sessionId): JsonResponse
    {
        $this->loginService->logoutSession($sessionId);

        return response()->json([
            'success' => true,
            'message' => 'Sesi berhasil diakhiri (logout).',
        ]);
    }

    public function storeMyIp(Request $request): JsonResponse
    {
        $user = $request->user();
        if (! $user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated.'], 401);
        }

        $ip = $this->securityService->resolveClientIp($request);
        $deviceId = $this->securityService->resolveDeviceId($request);
        $localIp = $this->securityService->resolveLocalIp($request);

        $trusted = TrustedIp::query()->updateOrCreate(
            [
                'user_id' => $user->getKey(),
                'ip_address' => $ip,
            ],
            [
                'local_ip' => $localIp,
                'device_id' => $deviceId,
                'device_name' => $request->input('device_name', 'Perangkat Saya'),
                'operating_system' => $request->header('User-Agent'),
                'is_active' => true,
                'verified_at' => now(),
            ]
        );

        return response()->json([
            'success' => true,
            'message' => "IP {$ip} berhasil ditambahkan sebagai IP terpercaya Anda.",
            'data' => $trusted,
        ]);
    }

    public function destroyTrustedIp(Request $request, int|string $id): JsonResponse
    {
        $trusted = TrustedIp::query()->find($id);

        if (! $trusted) {
            return response()->json([
                'success' => false,
                'message' => 'Data IP terpercaya tidak ditemukan.',
            ], 404);
        }

        $ip = $trusted->ip_address;
        $trusted->delete();

        return response()->json([
            'success' => true,
            'message' => "IP terpercaya {$ip} berhasil dihapus.",
        ]);
    }
}
