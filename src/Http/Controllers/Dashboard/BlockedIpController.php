<?php

namespace Internal\SecurityMonitor\Http\Controllers\Dashboard;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Validation\ValidationException;
use Inertia\Inertia;
use Inertia\Response;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Blocked IP management page for the Inertia + React dashboard.
 */
class BlockedIpController extends Controller
{
    public function index(Request $request): Response
    {
        $query = BlockedIp::query()->latest('id');

        $search = (string) $request->query('search', '');
        $status = (string) $request->query('status', '');

        if ($search !== '') {
            $query->where(function ($q) use ($search): void {
                $q->where('ip_address', 'like', "%{$search}%")
                    ->orWhere('device_id', 'like', "%{$search}%")
                    ->orWhere('reason', 'like', "%{$search}%")
                    ->orWhere('notes', 'like', "%{$search}%");
            });
        }

        if ($status === 'active') {
            $query->active();
        } elseif ($status === 'expired') {
            $query->expired();
        } elseif ($status === 'permanent') {
            $query->whereNull('expires_at')->where('is_active', true);
        }

        return Inertia::render('security/blocked-ips', [
            'blocks' => $query->paginate(25)->withQueryString(),
            'stats' => [
                'total' => BlockedIp::query()->count(),
                'active' => BlockedIp::query()->active()->count(),
                'permanent' => BlockedIp::query()->whereNull('expires_at')->where('is_active', true)->count(),
                'hits' => (int) BlockedIp::query()->sum('hit_count'),
            ],
            'filters' => [
                'search' => $search,
                'status' => $status,
            ],
            'urls' => [
                'index' => route('security.dashboard.blocked-ips'),
                'store' => route('security.dashboard.blocked-ips.store'),
                'toggle' => route('security.dashboard.blocked-ips.toggle', ['id' => '__ID__']),
                'destroy' => route('security.dashboard.blocked-ips.destroy', ['id' => '__ID__']),
            ],
        ]);
    }

    public function store(Request $request, SecurityMonitorService $security): RedirectResponse
    {
        $validated = $request->validate([
            'ip_address' => ['required', 'string', 'max:45'],
            'reason' => ['nullable', 'string', 'max:255'],
            'notes' => ['nullable', 'string', 'max:1000'],
            'duration_hours' => ['nullable', 'integer', 'min:0'],
            'is_permanent' => ['nullable', 'boolean'],
        ]);

        $ip = trim($validated['ip_address']);

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            throw ValidationException::withMessages([
                'ip_address' => __('Invalid IP address.'),
            ]);
        }

        if ($ip === $security->resolveClientIp($request)) {
            throw ValidationException::withMessages([
                'ip_address' => __('You cannot block your own IP address.'),
            ]);
        }

        if ($security->isWhitelisted($ip)) {
            throw ValidationException::withMessages([
                'ip_address' => __('This IP is whitelisted and cannot be blocked.'),
            ]);
        }

        $duration = (int) ($validated['duration_hours'] ?? 24);
        $isPermanent = (bool) ($validated['is_permanent'] ?? ($duration === 0));

        BlockedIp::query()->updateOrCreate(
            ['ip_address' => $ip],
            [
                'block_scope' => 'ip',
                'reason' => $validated['reason'] ?? __('Blocked manually by administrator'),
                'notes' => $validated['notes'] ?? null,
                'source' => 'manual',
                'blocked_by' => $request->user()?->getKey(),
                'blocked_at' => now(),
                'expires_at' => $isPermanent ? null : now()->addHours($duration),
                'is_active' => true,
            ],
        );

        return back()->with('toast', [
            'type' => 'success',
            'message' => __('IP :ip has been blocked.', ['ip' => $ip]),
        ]);
    }

    public function toggle(int $id): RedirectResponse
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return back()->with('toast', [
                'type' => 'error',
                'message' => __('Blocked IP not found.'),
            ]);
        }

        $block->is_active = ! $block->is_active;
        $block->save();

        return back()->with('toast', [
            'type' => 'success',
            'message' => $block->is_active
                ? __('Block for :ip re-enabled.', ['ip' => $block->ip_address])
                : __('Block for :ip disabled.', ['ip' => $block->ip_address]),
        ]);
    }

    public function destroy(int $id): RedirectResponse
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return back()->with('toast', [
                'type' => 'error',
                'message' => __('Blocked IP not found.'),
            ]);
        }

        $ip = $block->ip_address;
        $block->delete();

        return back()->with('toast', [
            'type' => 'success',
            'message' => __('IP :ip has been unblocked.', ['ip' => $ip]),
        ]);
    }
}
