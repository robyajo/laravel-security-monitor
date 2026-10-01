<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Models\SecurityLog;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Throwable;

class BlockedIpApiController extends Controller
{
    public function __construct(
        protected SecurityMonitorService $service
    ) {}

    public function index(Request $request): JsonResponse
    {
        $query = BlockedIp::query()->latest('id');

        if ($search = $request->input('search')) {
            $query->where(function ($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                  ->orWhere('device_id', 'like', "%{$search}%")
                  ->orWhere('reason', 'like', "%{$search}%")
                  ->orWhere('notes', 'like', "%{$search}%");
            });
        }

        if ($request->has('is_active') && $request->input('is_active') !== null) {
            $query->where('is_active', filter_var($request->input('is_active'), FILTER_VALIDATE_BOOLEAN));
        }

        if ($status = $request->input('status')) {
            if ($status === 'active') {
                $query->active();
            } elseif ($status === 'expired') {
                $query->expired();
            } elseif ($status === 'permanent') {
                $query->whereNull('expires_at')->where('is_active', true);
            }
        }

        $perPage = min(100, max(10, (int) $request->input('per_page', 25)));
        $blockedIps = $query->paginate($perPage);

        return response()->json([
            'success' => true,
            'data' => $blockedIps,
            'stats' => [
                'total' => BlockedIp::query()->count(),
                'active' => BlockedIp::query()->active()->count(),
                'permanent' => BlockedIp::query()->whereNull('expires_at')->where('is_active', true)->count(),
                'total_hits' => (int) BlockedIp::query()->sum('hit_count'),
            ],
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip_address' => ['required', 'string', 'max:45'],
            'local_ip' => ['nullable', 'string', 'max:45'],
            'device_id' => ['nullable', 'string', 'max:100'],
            'block_scope' => ['nullable', 'string', 'in:ip,device'],
            'reason' => ['nullable', 'string', 'max:255'],
            'notes' => ['nullable', 'string'],
            'duration_hours' => ['nullable', 'integer', 'min:0'],
            'is_permanent' => ['nullable', 'boolean'],
        ]);

        $ip = trim($validated['ip_address']);

        // Don't block invalid IP syntax unless it is 0.0.0.0 or valid IP
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return response()->json([
                'success' => false,
                'message' => 'Alamat IP tidak valid.',
            ], 422);
        }

        $myIp = $this->service->resolveClientIp($request);
        if ($ip === $myIp) {
            return response()->json([
                'success' => false,
                'message' => 'Anda tidak dapat memblokir alamat IP Anda sendiri.',
            ], 422);
        }

        if ($this->service->isWhitelisted($ip)) {
            return response()->json([
                'success' => false,
                'message' => 'Alamat IP ini berada dalam daftar whitelist dan tidak dapat diblokir.',
            ], 422);
        }

        $duration = (int) ($validated['duration_hours'] ?? 24);
        $isPermanent = (bool) ($validated['is_permanent'] ?? ($duration === 0));

        $expiresAt = $isPermanent ? null : now()->addHours($duration);

        $block = BlockedIp::query()->updateOrCreate(
            ['ip_address' => $ip],
            [
                'local_ip' => $validated['local_ip'] ?? null,
                'device_id' => $validated['device_id'] ?? null,
                'block_scope' => $validated['block_scope'] ?? 'ip',
                'reason' => $validated['reason'] ?? 'Diblokir secara manual oleh administrator',
                'notes' => $validated['notes'] ?? null,
                'source' => 'manual',
                'blocked_by' => $request->user()?->getKey(),
                'blocked_at' => now(),
                'expires_at' => $expiresAt,
                'is_active' => true,
            ]
        );

        return response()->json([
            'success' => true,
            'message' => "Alamat IP {$ip} berhasil diblokir.",
            'data' => $block,
        ], 201);
    }

    public function show(Request $request, int|string $id): JsonResponse
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return response()->json([
                'success' => false,
                'message' => 'Data blokir IP tidak ditemukan.',
            ], 404);
        }

        $recentLogs = SecurityLog::query()
            ->where('ip_address', $block->ip_address)
            ->latest('id')
            ->limit(20)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $block,
            'recent_logs' => $recentLogs,
        ]);
    }

    public function toggle(Request $request, int|string $id): JsonResponse
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return response()->json([
                'success' => false,
                'message' => 'Data blokir IP tidak ditemukan.',
            ], 404);
        }

        $block->is_active = ! $block->is_active;
        $block->save();

        $statusText = $block->is_active ? 'diaktifkan' : 'dinonaktifkan';

        return response()->json([
            'success' => true,
            'message' => "Blokir untuk IP {$block->ip_address} berhasil {$statusText}.",
            'data' => $block,
        ]);
    }

    public function destroy(Request $request, int|string $id): JsonResponse
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return response()->json([
                'success' => false,
                'message' => 'Data blokir IP tidak ditemukan.',
            ], 404);
        }

        $ip = $block->ip_address;
        $block->delete();

        return response()->json([
            'success' => true,
            'message' => "Blokir IP {$ip} berhasil dihapus (unblocked).",
        ]);
    }
}
