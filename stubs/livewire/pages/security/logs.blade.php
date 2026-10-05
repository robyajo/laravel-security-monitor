<?php

use Internal\SecurityMonitor\Models\SecurityLog;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('Security Logs')] class extends Component {
    use WithPagination;

    public string $search = '';

    public string $level = '';

    public string $eventType = '';

    public int $perPage = 25;

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function updatedLevel(): void
    {
        $this->resetPage();
    }

    public function updatedEventType(): void
    {
        $this->resetPage();
    }

    public function updatedPerPage(): void
    {
        $this->resetPage();
    }

    public function delete(int $id): void
    {
        SecurityLog::query()->whereKey($id)->delete();

        session()->flash('security_message', __('Log entry deleted.'));
    }

    public function clearAll(): void
    {
        $count = SecurityLog::query()->count();
        SecurityLog::query()->truncate();

        $this->resetPage();

        session()->flash('security_message', __(':count log entries cleared.', ['count' => number_format($count)]));
    }

    public function levelClass(?string $level): string
    {
        return match ($level) {
            'critical' => 'sec-badge-critical',
            'high' => 'sec-badge-high',
            'medium' => 'sec-badge-medium',
            default => 'sec-badge-low',
        };
    }

    public function levelLabel(?string $level): string
    {
        return match ($level) {
            'critical' => __('Critical'),
            'high' => __('High'),
            'medium' => __('Medium'),
            'low' => __('Low'),
            default => __('Unknown'),
        };
    }

    /**
     * @return array<string, mixed>
     */
    public function with(): array
    {
        $query = SecurityLog::query()->latest('id');

        if ($this->search !== '') {
            $search = $this->search;
            $query->where(function ($q) use ($search) {
                $q->where('path', 'like', "%{$search}%")
                    ->orWhere('evidence', 'like', "%{$search}%")
                    ->orWhere('rule_label', 'like', "%{$search}%")
                    ->orWhere('user_agent', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%");
            });
        }

        if ($this->level !== '' && in_array($this->level, SecurityLog::LEVELS, true)) {
            $query->where('threat_level', $this->level);
        }

        if ($this->eventType !== '') {
            $query->where('event_type', $this->eventType);
        }

        return [
            'logs' => $query->paginate($this->perPage),
            'eventTypes' => SecurityLog::query()
                ->select('event_type')
                ->distinct()
                ->orderBy('event_type')
                ->pluck('event_type')
                ->all(),
        ];
    }
}; ?>

<div>
    <x-pages::security.layout :heading="__('Security Logs')" :subheading="__('Audit trail of detected threats and blocked requests')">
        <!-- Toolbar Filters -->
        <div class="sec-toolbar">
            <div class="sec-toolbar-group">
                <input
                    type="search"
                    wire:model.live.debounce.300ms="search"
                    placeholder="{{ __('Search IP, path, evidence…') }}"
                    class="sec-input"
                    style="min-width: 240px;"
                />

                <select wire:model.live="level" class="sec-select">
                    <option value="">{{ __('All levels') }}</option>
                    @foreach (\Internal\SecurityMonitor\Models\SecurityLog::LEVELS as $lvl)
                        <option value="{{ $lvl }}">{{ $this->levelLabel($lvl) }}</option>
                    @endforeach
                </select>

                <select wire:model.live="eventType" class="sec-select">
                    <option value="">{{ __('All events') }}</option>
                    @foreach ($eventTypes as $type)
                        <option value="{{ $type }}">{{ $type }}</option>
                    @endforeach
                </select>
            </div>

            <button
                type="button"
                class="sec-btn sec-btn-danger sec-btn-sm"
                wire:click="clearAll"
                wire:confirm="{{ __('Clear ALL security logs? This cannot be undone.') }}"
            >
                <span>🗑️</span>
                <span>{{ __('Clear logs') }}</span>
            </button>
        </div>

        <!-- Table Card -->
        <div class="sec-card sec-card-flush">
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('Level') }}</th>
                            <th>{{ __('Event') }}</th>
                            <th>{{ __('IP') }}</th>
                            <th>{{ __('Path') }}</th>
                            <th>{{ __('When') }}</th>
                            <th style="text-align: right;">{{ __('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($logs as $log)
                            <tr>
                                <td>
                                    <span class="sec-badge {{ $this->levelClass($log->threat_level) }}">
                                        {{ $this->levelLabel($log->threat_level) }}
                                    </span>
                                </td>
                                <td>
                                    <div style="font-weight: 600;">{{ $log->event_type }}</div>
                                    <div style="font-size: 11px; color: var(--sec-text-muted);">
                                        {{ \Illuminate\Support\Str::limit((string) $log->rule_label, 45) }}
                                    </div>
                                </td>
                                <td class="sec-font-mono" style="font-size: 12px; font-weight: 500;">
                                    {{ $log->ip_address }}
                                </td>
                                <td style="max-width: 260px;" title="{{ $log->path }}">
                                    <span style="font-size: 11px; font-weight: 600; color: var(--sec-text-muted);">{{ $log->method }}</span>
                                    <span style="font-size: 12px;">{{ \Illuminate\Support\Str::limit((string) $log->path, 40) }}</span>
                                </td>
                                <td style="font-size: 12px; color: var(--sec-text-muted); white-space: nowrap;">
                                    {{ $log->created_at?->diffForHumans() }}
                                </td>
                                <td style="text-align: right; white-space: nowrap;">
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="delete({{ $log->id }})"
                                        wire:confirm="{{ __('Delete this log entry?') }}"
                                        title="{{ __('Delete log entry') }}"
                                    >
                                        🗑️
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--sec-text-muted); padding: 36px;">
                                    {{ __('No security logs match the current filters.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            @if ($logs->hasPages())
                <div style="padding: 16px 20px; border-top: 1px solid var(--sec-border-light);">
                    {{ $logs->links() }}
                </div>
            @endif
        </div>
    </x-pages::security.layout>
</div>
