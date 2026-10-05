<?php

use Internal\SecurityMonitor\Models\IpUnblockRequest;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('Unblock Appeals')] class extends Component {
    use WithPagination;

    public string $search = '';

    public string $status = '';

    public int $perPage = 20;

    public bool $showRespondModal = false;

    public ?int $respondingId = null;

    public string $respondingAction = 'approve';

    public string $adminNotes = '';

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function updatedStatus(): void
    {
        $this->resetPage();
    }

    public function openRespond(int $id, string $action): void
    {
        $this->respondingId = $id;
        $this->respondingAction = $action === 'reject' ? 'reject' : 'approve';
        $this->adminNotes = '';
        $this->resetErrorBag();
        $this->showRespondModal = true;
    }

    public function closeRespondModal(): void
    {
        $this->showRespondModal = false;
        $this->reset(['respondingId', 'adminNotes']);
    }

    public function confirmRespond(): void
    {
        $this->validate([
            'adminNotes' => ['nullable', 'string', 'max:500'],
        ]);

        $ticket = IpUnblockRequest::query()->find($this->respondingId);

        if (! $ticket) {
            $this->showRespondModal = false;

            return;
        }

        $approve = $this->respondingAction === 'approve';

        $ticket->status = $approve ? 'approved' : 'rejected';
        $ticket->admin_notes = $this->adminNotes !== ''
            ? $this->adminNotes
            : ($approve ? __('Request approved.') : __('Request rejected.'));
        $ticket->resolved_by = auth()->id();
        $ticket->resolved_at = now();
        $ticket->save();

        if ($approve) {
            app(SecurityMonitorService::class)->unblockIp($ticket->ip_address, $ticket->device_id);
        }

        $this->showRespondModal = false;
        $this->reset(['respondingId', 'adminNotes']);

        session()->flash(
            'security_message',
            $approve
                ? __('Ticket :ticket approved and IP unblocked.', ['ticket' => $ticket->ticket_number])
                : __('Ticket :ticket rejected.', ['ticket' => $ticket->ticket_number]),
        );
    }

    public function destroy(int $id): void
    {
        IpUnblockRequest::query()->whereKey($id)->delete();

        session()->flash('security_message', __('Ticket deleted.'));
    }

    public function statusBadgeClass(?string $status): string
    {
        return match ($status) {
            'pending' => 'sec-badge-high',
            'approved' => 'sec-badge-success',
            'rejected' => 'sec-badge-critical',
            default => 'sec-badge-low',
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function with(): array
    {
        $query = IpUnblockRequest::query()->latest('id');

        if ($this->status !== '') {
            $query->where('status', $this->status);
        }

        if ($this->search !== '') {
            $search = $this->search;
            $query->where(function ($q) use ($search) {
                $q->where('ticket_number', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%");
            });
        }

        return [
            'tickets' => $query->paginate($this->perPage),
            'stats' => [
                'pending' => IpUnblockRequest::query()->pending()->count(),
                'approved' => IpUnblockRequest::query()->approved()->count(),
                'rejected' => IpUnblockRequest::query()->rejected()->count(),
            ],
        ];
    }
}; ?>

<div>
    <x-pages::security.layout :heading="__('Unblock Appeals')" :subheading="__('Review self-service unblock requests from blocked users')">
        <!-- Stat Cards -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Pending') }}</div>
                <div class="sec-stat-value" style="color: var(--sec-warning);">{{ number_format($stats['pending']) }}</div>
            </div>
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Approved') }}</div>
                <div class="sec-stat-value" style="color: var(--sec-success);">{{ number_format($stats['approved']) }}</div>
            </div>
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Rejected') }}</div>
                <div class="sec-stat-value sec-text-danger">{{ number_format($stats['rejected']) }}</div>
            </div>
        </div>

        <!-- Toolbar -->
        <div class="sec-toolbar">
            <div class="sec-toolbar-group">
                <input
                    type="search"
                    wire:model.live.debounce.300ms="search"
                    placeholder="{{ __('Search ticket, IP, name, email…') }}"
                    class="sec-input"
                    style="min-width: 260px;"
                />

                <select wire:model.live="status" class="sec-select">
                    <option value="">{{ __('All statuses') }}</option>
                    <option value="pending">{{ __('Pending') }}</option>
                    <option value="approved">{{ __('Approved') }}</option>
                    <option value="rejected">{{ __('Rejected') }}</option>
                </select>
            </div>
        </div>

        <!-- Appeals Table -->
        <div class="sec-card sec-card-flush">
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('Ticket') }}</th>
                            <th>{{ __('Applicant') }}</th>
                            <th>{{ __('IP') }}</th>
                            <th>{{ __('Status') }}</th>
                            <th>{{ __('Submitted') }}</th>
                            <th style="text-align: right;">{{ __('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($tickets as $ticket)
                            <tr>
                                <td class="sec-font-mono" style="font-weight: 600; font-size: 12px;">
                                    {{ $ticket->ticket_number }}
                                </td>
                                <td>
                                    <div style="font-weight: 600; font-size: 13px;">{{ $ticket->name }}</div>
                                    <div style="font-size: 11px; color: var(--sec-text-muted);">{{ $ticket->email }}</div>
                                </td>
                                <td class="sec-font-mono" style="font-size: 12px;">{{ $ticket->ip_address }}</td>
                                <td>
                                    <span class="sec-badge {{ $this->statusBadgeClass($ticket->status) }}">
                                        {{ $ticket->status }}
                                    </span>
                                </td>
                                <td style="font-size: 12px; color: var(--sec-text-muted); white-space: nowrap;">
                                    {{ $ticket->created_at?->diffForHumans() }}
                                </td>
                                <td style="text-align: right; white-space: nowrap;">
                                    @if ($ticket->isPending())
                                        <button
                                            type="button"
                                            class="sec-btn sec-btn-primary sec-btn-sm"
                                            wire:click="openRespond({{ $ticket->id }}, 'approve')"
                                        >
                                            {{ __('Approve') }}
                                        </button>
                                        <button
                                            type="button"
                                            class="sec-btn sec-btn-secondary sec-btn-sm"
                                            wire:click="openRespond({{ $ticket->id }}, 'reject')"
                                        >
                                            {{ __('Reject') }}
                                        </button>
                                    @else
                                        <button
                                            type="button"
                                            class="sec-btn sec-btn-ghost sec-btn-sm"
                                            wire:click="destroy({{ $ticket->id }})"
                                            wire:confirm="{{ __('Delete this ticket?') }}"
                                            title="{{ __('Delete ticket') }}"
                                        >
                                            🗑️
                                        </button>
                                    @endif
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--sec-text-muted); padding: 36px;">
                                    {{ __('No appeal tickets found.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            @if ($tickets->hasPages())
                <div style="padding: 16px 20px; border-top: 1px solid var(--sec-border-light);">
                    {{ $tickets->links() }}
                </div>
            @endif
        </div>

        <!-- Respond Modal -->
        @if ($showRespondModal)
            <div class="sec-modal-backdrop" wire:keydown.escape="closeRespondModal">
                <div class="sec-modal-box">
                    <div class="sec-modal-header">
                        <h3 class="sec-card-title">
                            {{ $respondingAction === 'approve' ? __('Approve appeal') : __('Reject appeal') }}
                        </h3>
                        <p class="sec-card-subtitle">
                            {{ $respondingAction === 'approve'
                                ? __('The blocked IP/device will be unblocked automatically.')
                                : __('The block will remain active.') }}
                        </p>
                    </div>

                    <form wire:submit="confirmRespond">
                        <div class="sec-modal-body">
                            <div>
                                <label style="display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px;">{{ __('Admin notes') }}</label>
                                <textarea
                                    wire:model="adminNotes"
                                    rows="3"
                                    class="sec-textarea"
                                    placeholder="{{ __('Optional notes shown to the applicant…') }}"
                                ></textarea>
                                @error('adminNotes')
                                    <div style="color: var(--sec-danger); font-size: 11px; margin-top: 4px;">{{ $message }}</div>
                                @enderror
                            </div>
                        </div>

                        <div class="sec-modal-footer">
                            <button type="button" class="sec-btn sec-btn-secondary" wire:click="closeRespondModal">
                                {{ __('Cancel') }}
                            </button>
                            <button
                                type="submit"
                                class="sec-btn {{ $respondingAction === 'approve' ? 'sec-btn-primary' : 'sec-btn-danger' }}"
                            >
                                {{ $respondingAction === 'approve' ? __('Approve & unblock') : __('Reject') }}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        @endif
    </x-pages::security.layout>
</div>
