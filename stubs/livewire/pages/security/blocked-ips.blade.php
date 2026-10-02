<?php

use Flux\Flux;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('Blocked IPs')] class extends Component {
    use WithPagination;

    public string $search = '';

    public string $status = '';

    public int $perPage = 25;

    public bool $showBlockModal = false;

    public string $ipAddress = '';

    public string $reason = '';

    public string $notes = '';

    public int $durationHours = 24;

    public bool $permanent = false;

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function updatedStatus(): void
    {
        $this->resetPage();
    }

    public function openBlockModal(): void
    {
        $this->reset(['ipAddress', 'reason', 'notes', 'permanent']);
        $this->durationHours = 24;
        $this->resetErrorBag();
        $this->showBlockModal = true;
    }

    public function block(SecurityMonitorService $security): void
    {
        $this->validate([
            'ipAddress' => ['required', 'string', 'max:45'],
            'reason' => ['nullable', 'string', 'max:255'],
            'notes' => ['nullable', 'string', 'max:1000'],
            'durationHours' => ['required', 'integer', 'min:0'],
            'permanent' => ['boolean'],
        ]);

        $ip = trim($this->ipAddress);

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->addError('ipAddress', __('Invalid IP address.'));

            return;
        }

        if ($ip === $security->resolveClientIp(request())) {
            $this->addError('ipAddress', __('You cannot block your own IP address.'));

            return;
        }

        if ($security->isWhitelisted($ip)) {
            $this->addError('ipAddress', __('This IP is whitelisted and cannot be blocked.'));

            return;
        }

        $isPermanent = $this->permanent || $this->durationHours === 0;

        BlockedIp::query()->updateOrCreate(
            ['ip_address' => $ip],
            [
                'block_scope' => 'ip',
                'reason' => $this->reason !== '' ? $this->reason : __('Blocked manually by administrator'),
                'notes' => $this->notes !== '' ? $this->notes : null,
                'source' => 'manual',
                'blocked_by' => auth()->id(),
                'blocked_at' => now(),
                'expires_at' => $isPermanent ? null : now()->addHours($this->durationHours),
                'is_active' => true,
            ],
        );

        $this->showBlockModal = false;
        $this->reset(['ipAddress', 'reason', 'notes']);

        Flux::toast(variant: 'success', text: __('IP :ip has been blocked.', ['ip' => $ip]));
    }

    public function toggle(int $id): void
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return;
        }

        $block->is_active = ! $block->is_active;
        $block->save();

        Flux::toast(
            variant: 'success',
            text: $block->is_active
                ? __('Block for :ip re-enabled.', ['ip' => $block->ip_address])
                : __('Block for :ip disabled.', ['ip' => $block->ip_address]),
        );
    }

    public function unblock(int $id): void
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return;
        }

        $ip = $block->ip_address;
        $block->delete();

        Flux::toast(variant: 'success', text: __('IP :ip has been unblocked.', ['ip' => $ip]));
    }

    /**
     * @return array<string, mixed>
     */
    public function with(): array
    {
        $query = BlockedIp::query()->latest('id');

        if ($this->search !== '') {
            $search = $this->search;
            $query->where(function ($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                    ->orWhere('device_id', 'like', "%{$search}%")
                    ->orWhere('reason', 'like', "%{$search}%")
                    ->orWhere('notes', 'like', "%{$search}%");
            });
        }

        if ($this->status === 'active') {
            $query->active();
        } elseif ($this->status === 'expired') {
            $query->expired();
        } elseif ($this->status === 'permanent') {
            $query->whereNull('expires_at')->where('is_active', true);
        }

        return [
            'blocks' => $query->paginate($this->perPage),
            'stats' => [
                'total' => BlockedIp::query()->count(),
                'active' => BlockedIp::query()->active()->count(),
                'permanent' => BlockedIp::query()->whereNull('expires_at')->where('is_active', true)->count(),
                'hits' => (int) BlockedIp::query()->sum('hit_count'),
            ],
        ];
    }
}; ?>

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('Blocked IPs')" :subheading="__('Manage quarantined IP addresses and devices')">
        <div class="grid auto-rows-min gap-4 md:grid-cols-4">
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Total blocks') }}</flux:text>
                <flux:heading size="lg">{{ number_format($stats['total']) }}</flux:heading>
            </flux:card>
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Active') }}</flux:text>
                <flux:heading size="lg" class="text-red-600 dark:text-red-400">{{ number_format($stats['active']) }}</flux:heading>
            </flux:card>
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Permanent') }}</flux:text>
                <flux:heading size="lg">{{ number_format($stats['permanent']) }}</flux:heading>
            </flux:card>
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Total hits') }}</flux:text>
                <flux:heading size="lg">{{ number_format($stats['hits']) }}</flux:heading>
            </flux:card>
        </div>

        <div class="mt-5 flex flex-wrap items-end justify-between gap-3">
            <div class="flex flex-wrap items-end gap-3">
                <flux:input
                    wire:model.live.debounce.300ms="search"
                    icon="magnifying-glass"
                    :placeholder="__('Search IP, device, reason…')"
                    class="w-full sm:w-72"
                />

                <flux:select wire:model.live="status" class="w-44">
                    <flux:select.option value="">{{ __('All statuses') }}</flux:select.option>
                    <flux:select.option value="active">{{ __('Active') }}</flux:select.option>
                    <flux:select.option value="expired">{{ __('Expired') }}</flux:select.option>
                    <flux:select.option value="permanent">{{ __('Permanent') }}</flux:select.option>
                </flux:select>
            </div>

            <flux:button variant="primary" icon="plus" wire:click="openBlockModal">
                {{ __('Block IP') }}
            </flux:button>
        </div>

        <flux:card class="mt-5 p-0!">
            <flux:table :paginate="$blocks">
                <flux:table.columns>
                    <flux:table.column>{{ __('IP address') }}</flux:table.column>
                    <flux:table.column>{{ __('Reason') }}</flux:table.column>
                    <flux:table.column>{{ __('Status') }}</flux:table.column>
                    <flux:table.column>{{ __('Expires') }}</flux:table.column>
                    <flux:table.column align="end">{{ __('Hits') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                    @forelse ($blocks as $block)
                        <flux:table.row :key="$block->id">
                            <flux:table.cell>
                                <div class="font-mono text-xs">{{ $block->ip_address }}</div>
                                @if ($block->device_id)
                                    <div class="mt-0.5 text-[10px] text-zinc-400">{{ $block->device_id }}</div>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="max-w-xs truncate text-xs" title="{{ $block->reason }}">
                                {{ \Illuminate\Support\Str::limit((string) $block->reason, 48) }}
                            </flux:table.cell>
                            <flux:table.cell>
                                @if ($block->isEnforced())
                                    <flux:badge color="red" size="sm">{{ __('Active') }}</flux:badge>
                                @elseif ($block->is_active)
                                    <flux:badge color="amber" size="sm">{{ __('Expired') }}</flux:badge>
                                @else
                                    <flux:badge color="zinc" size="sm">{{ __('Disabled') }}</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">
                                {{ $block->isPermanent() ? __('Never') : $block->remaining }}
                            </flux:table.cell>
                            <flux:table.cell align="end" class="tabular-nums">{{ number_format((int) $block->hit_count) }}</flux:table.cell>
                            <flux:table.cell>
                                <div class="flex items-center justify-end gap-1">
                                    <flux:button
                                        size="sm"
                                        variant="ghost"
                                        :icon="$block->is_active ? 'pause' : 'play'"
                                        wire:click="toggle({{ $block->id }})"
                                        :title="$block->is_active ? __('Disable block') : __('Enable block')"
                                    />
                                    <flux:button
                                        size="sm"
                                        variant="ghost"
                                        icon="lock-open"
                                        wire:click="unblock({{ $block->id }})"
                                        wire:confirm="{{ __('Remove this block entirely?') }}"
                                        :title="__('Unblock')"
                                    />
                                </div>
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="6" class="text-center text-sm text-zinc-500">
                                {{ __('No blocked IPs match the current filters.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>
    </x-pages::security.layout>

    <flux:modal name="block-ip-modal" wire:model="showBlockModal" class="max-w-lg">
        <form wire:submit="block" class="space-y-6">
            <div>
                <flux:heading size="lg">{{ __('Block an IP address') }}</flux:heading>
                <flux:subheading>{{ __('Requests from this address will receive a 403 response.') }}</flux:subheading>
            </div>

            <flux:input wire:model="ipAddress" :label="__('IP address')" placeholder="203.0.113.50" required />

            <flux:input wire:model="reason" :label="__('Reason')" :placeholder="__('e.g. Repeated directory scanning')" />

            <flux:textarea wire:model="notes" :label="__('Internal notes')" rows="2" />

            <div class="grid grid-cols-2 gap-4">
                <flux:input wire:model="durationHours" type="number" min="0" :label="__('Duration (hours)')" :description="__('0 = permanent')" />
                <div class="flex items-end">
                    <flux:switch wire:model="permanent" :label="__('Permanent block')" />
                </div>
            </div>

            <div class="flex justify-end gap-3">
                <flux:modal.close>
                    <flux:button variant="outline">{{ __('Cancel') }}</flux:button>
                </flux:modal.close>
                <flux:button variant="danger" type="submit">{{ __('Block IP') }}</flux:button>
            </div>
        </form>
    </flux:modal>
</div>
