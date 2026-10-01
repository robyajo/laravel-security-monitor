<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Str;
use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

class IpUnblockRequestApiController extends Controller
{
    public function __construct(
        protected SecurityMonitorService $service
    ) {}

    /**
     * Endpoint publik untuk klien yang terblokir mengajukan tiket banding.
     */
    public function submit(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:100'],
            'email' => ['required', 'email', 'max:150'],
            'phone' => ['nullable', 'string', 'max:30'],
            'reason' => ['required', 'string', 'max:1000'],
        ]);

        $ip = $this->service->resolveClientIp($request);
        $deviceId = $this->service->resolveDeviceId($request);
        $localIp = $this->service->resolveLocalIp($request);

        // Check if there is an active block
        $blockedRecord = $this->service->activeBlock($ip, $deviceId, $localIp);

        // Rate limit: 1 ticket per IP per 30 minutes
        $existingPending = IpUnblockRequest::query()
            ->where('ip_address', $ip)
            ->where('status', 'pending')
            ->where('created_at', '>=', now()->subMinutes(30))
            ->first();

        if ($existingPending) {
            return response()->json([
                'success' => false,
                'message' => 'Anda sudah memiliki tiket permohonan yang sedang diproses. Mohon tunggu review administrator.',
                'ticket_number' => $existingPending->ticket_number,
            ], 429);
        }

        $ticketNumber = 'TKT-'.strtoupper(Str::random(8));

        $ticket = IpUnblockRequest::create([
            'ticket_number' => $ticketNumber,
            'ip_address' => $ip,
            'local_ip' => $localIp,
            'device_id' => $deviceId,
            'name' => $validated['name'],
            'email' => $validated['email'],
            'phone' => $validated['phone'] ?? null,
            'reason' => $validated['reason'],
            'status' => 'pending',
            'blocked_ip_id' => $blockedRecord?->id,
            'user_agent' => Str::limit((string) $request->userAgent(), 500, ''),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Permohonan pembukaan blokir berhasil diajukan.',
            'ticket_number' => $ticketNumber,
            'data' => $ticket,
        ], 201);
    }

    /**
     * Endpoint publik untuk mengecek status tiket banding.
     */
    public function checkStatus(Request $request, string $ticketNumber): JsonResponse
    {
        $ticket = IpUnblockRequest::query()
            ->where('ticket_number', $ticketNumber)
            ->first();

        if (! $ticket) {
            return response()->json([
                'success' => false,
                'message' => 'Nomor tiket tidak ditemukan.',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'ticket_number' => $ticket->ticket_number,
                'status' => $ticket->status,
                'created_at' => $ticket->created_at->toIso8601String(),
                'resolved_at' => $ticket->resolved_at?->toIso8601String(),
                'admin_notes' => $ticket->admin_notes,
            ],
        ]);
    }

    /**
     * Endpoint admin untuk melihat daftar tiket permohonan.
     */
    public function index(Request $request): JsonResponse
    {
        $query = IpUnblockRequest::query()->latest('id');

        if ($status = $request->input('status')) {
            $query->where('status', $status);
        }

        if ($search = $request->input('search')) {
            $query->where(function ($q) use ($search) {
                $q->where('ticket_number', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%");
            });
        }

        $perPage = min(100, max(10, (int) $request->input('per_page', 20)));
        $tickets = $query->paginate($perPage);

        return response()->json([
            'success' => true,
            'data' => $tickets,
            'stats' => [
                'pending' => IpUnblockRequest::query()->pending()->count(),
                'approved' => IpUnblockRequest::query()->approved()->count(),
                'rejected' => IpUnblockRequest::query()->rejected()->count(),
            ],
        ]);
    }

    /**
     * Endpoint admin untuk menyetujui atau menolak permohonan.
     */
    public function respond(Request $request, int|string $id): JsonResponse
    {
        $ticket = IpUnblockRequest::query()->find($id);

        if (! $ticket) {
            return response()->json([
                'success' => false,
                'message' => 'Tiket tidak ditemukan.',
            ], 404);
        }

        $validated = $request->validate([
            'action' => ['required', 'string', 'in:approve,reject'],
            'admin_notes' => ['nullable', 'string', 'max:500'],
        ]);

        $action = $validated['action'];

        if ($action === 'approve') {
            $ticket->status = 'approved';
            $ticket->admin_notes = $validated['admin_notes'] ?? 'Permohonan disetujui.';
            $ticket->resolved_by = $request->user()?->getKey();
            $ticket->resolved_at = now();
            $ticket->save();

            // Automatically unblock the IP
            $this->service->unblockIp($ticket->ip_address, $ticket->device_id);

            return response()->json([
                'success' => true,
                'message' => "Permohonan tiket {$ticket->ticket_number} disetujui dan IP {$ticket->ip_address} berhasil dibuka blokirnya.",
                'data' => $ticket,
            ]);
        }

        $ticket->status = 'rejected';
        $ticket->admin_notes = $validated['admin_notes'] ?? 'Permohonan ditolak.';
        $ticket->resolved_by = $request->user()?->getKey();
        $ticket->resolved_at = now();
        $ticket->save();

        return response()->json([
            'success' => true,
            'message' => "Permohonan tiket {$ticket->ticket_number} ditolak.",
            'data' => $ticket,
        ]);
    }

    public function destroy(Request $request, int|string $id): JsonResponse
    {
        $ticket = IpUnblockRequest::query()->find($id);

        if (! $ticket) {
            return response()->json([
                'success' => false,
                'message' => 'Tiket tidak ditemukan.',
            ], 404);
        }

        $ticket->delete();

        return response()->json([
            'success' => true,
            'message' => 'Tiket berhasil dihapus.',
        ]);
    }
}
