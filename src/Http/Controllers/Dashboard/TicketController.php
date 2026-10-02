<?php

namespace Internal\SecurityMonitor\Http\Controllers\Dashboard;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Inertia;
use Inertia\Response;
use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Unblock appeal tickets page for the Inertia + React dashboard.
 */
class TicketController extends Controller
{
    public function index(Request $request): Response
    {
        $query = IpUnblockRequest::query()->latest('id');

        $search = (string) $request->query('search', '');
        $status = (string) $request->query('status', '');

        if ($status !== '') {
            $query->where('status', $status);
        }

        if ($search !== '') {
            $query->where(function ($q) use ($search): void {
                $q->where('ticket_number', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%");
            });
        }

        return Inertia::render('security/tickets', [
            'tickets' => $query->paginate(20)->withQueryString(),
            'stats' => [
                'pending' => IpUnblockRequest::query()->pending()->count(),
                'approved' => IpUnblockRequest::query()->approved()->count(),
                'rejected' => IpUnblockRequest::query()->rejected()->count(),
            ],
            'filters' => [
                'search' => $search,
                'status' => $status,
            ],
            'urls' => [
                'index' => route('security.dashboard.tickets'),
                'respond' => route('security.dashboard.tickets.respond', ['id' => '__ID__']),
                'destroy' => route('security.dashboard.tickets.destroy', ['id' => '__ID__']),
            ],
        ]);
    }

    public function respond(Request $request, int $id, SecurityMonitorService $security): RedirectResponse
    {
        $ticket = IpUnblockRequest::query()->find($id);

        if (! $ticket) {
            return back()->with('toast', [
                'type' => 'error',
                'message' => __('Ticket not found.'),
            ]);
        }

        $validated = $request->validate([
            'action' => ['required', 'string', 'in:approve,reject'],
            'admin_notes' => ['nullable', 'string', 'max:500'],
        ]);

        $approve = $validated['action'] === 'approve';

        $ticket->status = $approve ? 'approved' : 'rejected';
        $ticket->admin_notes = $validated['admin_notes'] ?? ($approve ? __('Request approved.') : __('Request rejected.'));
        $ticket->resolved_by = $request->user()?->getKey();
        $ticket->resolved_at = now();
        $ticket->save();

        if ($approve) {
            $security->unblockIp($ticket->ip_address, $ticket->device_id);
        }

        return back()->with('toast', [
            'type' => 'success',
            'message' => $approve
                ? __('Ticket :ticket approved and IP unblocked.', ['ticket' => $ticket->ticket_number])
                : __('Ticket :ticket rejected.', ['ticket' => $ticket->ticket_number]),
        ]);
    }

    public function destroy(int $id): RedirectResponse
    {
        IpUnblockRequest::query()->whereKey($id)->delete();

        return back()->with('toast', [
            'type' => 'success',
            'message' => __('Ticket deleted.'),
        ]);
    }
}
