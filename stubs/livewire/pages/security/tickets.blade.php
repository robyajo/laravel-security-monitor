<?php

use Flux\Flux;
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

        Flux::toast(
            variant: 'success',
            text: $approve
                ? __('Ticket :ticket approved and IP unblocked.', ['ticket' => $ticket->ticket_number])
                : __('Ticket :ticket rejected.', ['ticket' => $ticket->ticket_number]),
        );
    }

    public function destroy(int $id): void
    {
        IpUnblockRequest::query()->whereKey($id)->delete();

        Flux::toast(variant: 'success', text: __('Ticket deleted.'));
    }

    public function statusColor(?string $status): string
    {
        return match ($status) {
            'pending' => 'amber',
            'approved' => 'green',
            'rejected' => 'red',
            default => 'zinc',
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

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('Unblock Appeals')" :subheading="__('Review self-service unblock requests from blocked users')">
        <div class="grid auto-rows-min gap-4 md:grid-cols-3">
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Pending') }}</flux:text>
                <flux:heading size="lg" class="text-amber-600 dark:text-amber-400">{{ number_format($stats['pending']) }}</flux:heading>
            </flux:card>
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Approved') }}</flux:text>
                <flux:heading size="lg" class="text-green-600 dark:text-green-400">{{ number_format($stats['approved']) }}</flux:heading>
            </flux:card>
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Rejected') }}</flux:text>
                <flux:heading size="lg" class="text-red-600 dark:text-red-400">{{ number_format($stats['rejected']) }}</flux:heading>
            </flux:card>
        </div>

        <div class="mt-5 flex flex-wrap items-end gap-3">
            <flux:input
                wire:model.live.debounce.300ms="search"
                icon="magnifying-glass"
                :placeholder="__('Search ticket, IP, name, email…')"
                class="w-full sm:w-72"
            />

            <flux:select wire:model.live="status" class="w-44">
                <flux:select.option value="">{{ __('All statuses') }}</flux:select.option>
                <flux:select.option value="pending">{{ __('Pending') }}</flux:select.option>
                <flux:select.option value="approved">{{ __('Approved') }}</flux:select.option>
                <flux:select.option value="rejected">{{ __('Rejected') }}</flux:select.option>
            </flux:select>
        </div>

        <flux:card class="mt-5 p-0!">
            <flux:table :paginate="$tickets">
                <flux:table.columns>
                    <flux:table.column>{{ __('Ticket') }}</flux:table.column>
                    <flux:table.column>{{ __('Applicant') }}</flux:table.column>
                    <flux:table.column>{{ __('IP') }}</flux:table.column>
                    <flux:table.column>{{ __('Status') }}</flux:table.column>
                    <flux:table.column>{{ __('Submitted') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                    @forelse ($tickets as $ticket)
                        <flux:table.row :key="$ticket->id">
                            <flux:table.cell class="font-mono text-xs">{{ $ticket->ticket_number }}</flux:table.cell>
                            <flux:table.cell class="text-xs">
                                <div class="font-medium">{{ $ticket->name }}</div>
                                <div class="text-zinc-500">{{ $ticket->email }}</div>
                            </flux:table.cell>
                            <flux:table.cell class="font-mono text-xs">{{ $ticket->ip_address }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:badge :color="$this->statusColor($ticket->status)" size="sm">{{ $ticket->status }}</flux:badge>
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $ticket->created_at?->diffForHumans() }}</flux:table.cell>
                            <flux:table.cell>
                                <div class="flex items-center justify-end gap-1">
                                    @if ($ticket->isPending())
                                        <flux:button size="sm" variant="primary" icon="check" wire:click="openRespond({{ $ticket->id }}, 'approve')">
                                            {{ __('Approve') }}
                                        </flux:button>
                                        <flux:button size="sm" variant="outline" icon="x-mark" wire:click="openRespond({{ $ticket->id }}, 'reject')">
                                            {{ __('Reject') }}
                                        </flux:button>
                                    @else
                                        <flux:button
                                            size="sm"
                                            variant="ghost"
                                            icon="trash"
                                            wire:click="destroy({{ $ticket->id }})"
                                            wire:confirm="{{ __('Delete this ticket?') }}"
                                        />
                                    @endif
                                </div>
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="6" class="text-center text-sm text-zinc-500">
                                {{ __('No appeal tickets found.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>
    </x-pages::security.layout>

    <flux:modal name="respond-ticket-modal" wire:model="showRespondModal" class="max-w-lg">
        <form wire:submit="confirmRespond" class="space-y-6">
            <div>
                <flux:heading size="lg">
                    {{ $respondingAction === 'approve' ? __('Approve appeal') : __('Reject appeal') }}
                </flux:heading>
                <flux:subheading>
                    {{ $respondingAction === 'approve'
                        ? __('The blocked IP/device will be unblocked automatically.')
                        : __('The block will remain active.') }}
                </flux:subheading>
            </div>

            <flux:textarea wire:model="adminNotes" :label="__('Admin notes')" rows="3" :placeholder="__('Optional notes shown to the applicant…')" />

            <div class="flex justify-end gap-3">
                <flux:modal.close>
                    <flux:button variant="outline">{{ __('Cancel') }}</flux:button>
                </flux:modal.close>
                <flux:button
                    :variant="$respondingAction === 'approve' ? 'primary' : 'danger'"
                    type="submit"
                >
                    {{ $respondingAction === 'approve' ? __('Approve & unblock') : __('Reject') }}
                </flux:button>
            </div>
        </form>
    </flux:modal>
</div>
