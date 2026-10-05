<?php

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

    public function closeBlockModal(): void
    {
        $this->showBlockModal = false;
        $this->reset(['ipAddress', 'reason', 'notes']);
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

        session()->flash('security_message', __('IP :ip has been blocked.', ['ip' => $ip]));
    }

    public function toggle(int $id): void
    {
        $block = BlockedIp::query()->find($id);

        if (! $block) {
            return;
        }

        $block->is_active = ! $block->is_active;
        $block->save();

        session()->flash(
            'security_message',
            $block->is_active
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

        session()->flash('security_message', __('IP :ip has been unblocked.', ['ip' => $ip]));
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

<div>
    <x-pages::security.layout :heading="__('Blocked IPs')" :subheading="__('Manage quarantined IP addresses and devices')">
        <!-- Stat Grid -->
        <div class="sec-grid-4">
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Total blocks') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['total']) }}</div>
            </div>
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Active') }}</div>
                <div class="sec-stat-value sec-text-danger">{{ number_format($stats['active']) }}</div>
            </div>
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Permanent') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['permanent']) }}</div>
            </div>
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Total hits') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['hits']) }}</div>
            </div>
        </div>

        <!-- Toolbar -->
        <div class="sec-toolbar">
            <div class="sec-toolbar-group">
                <input
                    type="search"
                    wire:model.live.debounce.300ms="search"
                    placeholder="{{ __('Search IP, device, reason…') }}"
                    class="sec-input"
                    style="min-width: 240px;"
                />

                <select wire:model.live="status" class="sec-select">
                    <option value="">{{ __('All statuses') }}</option>
                    <option value="active">{{ __('Active') }}</option>
                    <option value="expired">{{ __('Expired') }}</option>
                    <option value="permanent">{{ __('Permanent') }}</option>
                </select>
            </div>

            <button type="button" class="sec-btn sec-btn-primary" wire:click="openBlockModal">
                <span>➕</span>
                <span>{{ __('Block IP') }}</span>
            </button>
        </div>

        <!-- Table Card -->
        <div class="sec-card sec-card-flush">
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('IP address') }}</th>
                            <th>{{ __('Reason') }}</th>
                            <th>{{ __('Status') }}</th>
                            <th>{{ __('Expires') }}</th>
                            <th style="text-align: right;">{{ __('Hits') }}</th>
                            <th style="text-align: right;">{{ __('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($blocks as $block)
                            <tr>
                                <td>
                                    <div class="sec-font-mono" style="font-weight: 600; font-size: 13px;">{{ $block->ip_address }}</div>
                                    @if ($block->device_id)
                                        <div style="font-size: 10px; color: var(--sec-text-muted); font-family: var(--sec-font-mono);">{{ $block->device_id }}</div>
                                    @endif
                                </td>
                                <td style="max-width: 250px;" title="{{ $block->reason }}">
                                    <span style="font-size: 12px;">{{ \Illuminate\Support\Str::limit((string) $block->reason, 45) }}</span>
                                </td>
                                <td>
                                    @if ($block->isEnforced())
                                        <span class="sec-badge sec-badge-critical">{{ __('Active') }}</span>
                                    @elseif ($block->is_active)
                                        <span class="sec-badge sec-badge-high">{{ __('Expired') }}</span>
                                    @else
                                        <span class="sec-badge sec-badge-low">{{ __('Disabled') }}</span>
                                    @endif
                                </td>
                                <td style="font-size: 12px; color: var(--sec-text-muted); white-space: nowrap;">
                                    {{ $block->isPermanent() ? __('Never') : $block->remaining }}
                                </td>
                                <td style="text-align: right;" class="sec-font-mono">
                                    {{ number_format((int) $block->hit_count) }}
                                </td>
                                <td style="text-align: right; white-space: nowrap;">
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="toggle({{ $block->id }})"
                                        title="{{ $block->is_active ? __('Disable block') : __('Enable block') }}"
                                    >
                                        {{ $block->is_active ? '⏸️' : '▶️' }}
                                    </button>
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="unblock({{ $block->id }})"
                                        wire:confirm="{{ __('Remove this block entirely?') }}"
                                        title="{{ __('Unblock IP') }}"
                                    >
                                        🔓
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--sec-text-muted); padding: 36px;">
                                    {{ __('No blocked IPs match the current filters.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            @if ($blocks->hasPages())
                <div style="padding: 16px 20px; border-top: 1px solid var(--sec-border-light);">
                    {{ $blocks->links() }}
                </div>
            @endif
        </div>

        <!-- Block IP Modal -->
        @if ($showBlockModal)
            <div class="sec-modal-backdrop" wire:keydown.escape="closeBlockModal">
                <div class="sec-modal-box">
                    <div class="sec-modal-header">
                        <h3 class="sec-card-title">{{ __('Block an IP address') }}</h3>
                        <p class="sec-card-subtitle">{{ __('Requests from this address will receive a 403 response.') }}</p>
                    </div>

                    <form wire:submit="block">
                        <div class="sec-modal-body">
                            <div>
                                <label style="display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px;">{{ __('IP address') }} *</label>
                                <input
                                    type="text"
                                    wire:model="ipAddress"
                                    placeholder="203.0.113.50"
                                    class="sec-input"
                                    style="width: 100%;"
                                    required
                                />
                                @error('ipAddress')
                                    <div style="color: var(--sec-danger); font-size: 11px; margin-top: 4px;">{{ $message }}</div>
                                @enderror
                            </div>

                            <div>
                                <label style="display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px;">{{ __('Reason') }}</label>
                                <input
                                    type="text"
                                    wire:model="reason"
                                    placeholder="{{ __('e.g. Repeated directory scanning') }}"
                                    class="sec-input"
                                    style="width: 100%;"
                                />
                            </div>

                            <div>
                                <label style="display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px;">{{ __('Internal notes') }}</label>
                                <textarea
                                    wire:model="notes"
                                    rows="2"
                                    class="sec-textarea"
                                    placeholder="{{ __('Optional internal audit notes…') }}"
                                ></textarea>
                            </div>

                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; align-items: center;">
                                <div>
                                    <label style="display: block; font-size: 12px; font-weight: 600; margin-bottom: 4px;">{{ __('Duration (hours)') }}</label>
                                    <input
                                        type="number"
                                        min="0"
                                        wire:model="durationHours"
                                        class="sec-input"
                                        style="width: 100%;"
                                    />
                                    <span style="font-size: 11px; color: var(--sec-text-muted);">0 = permanent</span>
                                </div>

                                <div style="padding-top: 18px;">
                                    <label style="display: inline-flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
                                        <input type="checkbox" wire:model="permanent" />
                                        <span>{{ __('Permanent block') }}</span>
                                    </label>
                                </div>
                            </div>
                        </div>

                        <div class="sec-modal-footer">
                            <button type="button" class="sec-btn sec-btn-secondary" wire:click="closeBlockModal">
                                {{ __('Cancel') }}
                            </button>
                            <button type="submit" class="sec-btn sec-btn-danger">
                                {{ __('Block IP') }}
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        @endif
    </x-pages::security.layout>
</div>
