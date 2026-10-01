<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Internal\SecurityMonitor\Models\LoginAttempt;
use Internal\SecurityMonitor\Services\LoginThrottleService;
use Internal\SecurityMonitor\Services\ServerSecurityService;

class ServerSecurityApiController extends Controller
{
    public function __construct(
        protected ServerSecurityService $serverService,
        protected LoginThrottleService $throttleService,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $force = filter_var($request->input('refresh', false), FILTER_VALIDATE_BOOLEAN);
        $report = $this->serverService->scan($force);

        return response()->json([
            'success' => true,
            'data' => $report,
        ]);
    }

    public function storeBaseline(Request $request): JsonResponse
    {
        $baseline = $this->serverService->createBaseline();

        return response()->json([
            'success' => true,
            'message' => 'Baseline integritas berkas berhasil dibuat.',
            'data' => $baseline,
        ]);
    }

    public function destroyBaseline(Request $request): JsonResponse
    {
        $deleted = $this->serverService->deleteBaseline();

        return response()->json([
            'success' => $deleted,
            'message' => $deleted ? 'Baseline integritas berkas berhasil dihapus.' : 'Gagal menghapus baseline.',
        ]);
    }

    public function destroySuspiciousFile(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'file_path' => ['required', 'string'],
        ]);

        $result = $this->serverService->deleteSuspiciousFile($validated['file_path']);

        return response()->json($result, $result['success'] ? 200 : 422);
    }

    public function releaseLockout(Request $request, int|string $id): JsonResponse
    {
        $attempt = LoginAttempt::query()->find($id);

        if (! $attempt) {
            return response()->json([
                'success' => false,
                'message' => 'Data lockout tidak ditemukan.',
            ], 404);
        }

        $email = $attempt->email;
        $ip = $attempt->ip_address;
        $attempt->delete();

        return response()->json([
            'success' => true,
            'message' => "Lockout untuk {$email} ({$ip}) berhasil dibuka.",
        ]);
    }
}
