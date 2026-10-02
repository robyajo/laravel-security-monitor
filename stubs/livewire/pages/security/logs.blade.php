<?php

use Flux\Flux;
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

        Flux::toast(variant: 'success', text: __('Log entry deleted.'));
    }

    public function clearAll(): void
    {
        $count = SecurityLog::query()->count();
        SecurityLog::query()->truncate();

        $this->resetPage();

        Flux::toast(variant: 'success', text: __(':count log entries cleared.', ['count' => number_format($count)]));
    }

    public function levelColor(?string $level): string
    {
        return match ($level) {
            'critical' => 'red',
            'high' => 'orange',
            'medium' => 'amber',
            default => 'zinc',
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

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('Security Logs')" :subheading="__('Audit trail of detected threats and blocked requests')">
        <div class="flex flex-wrap items-end justify-between gap-3">
            <div class="flex flex-wrap items-end gap-3">
                <flux:input
                    wire:model.live.debounce.300ms="search"
                    icon="magnifying-glass"
                    :placeholder="__('Search IP, path, evidence…')"
                    class="w-full sm:w-72"
                />

                <flux:select wire:model.live="level" :placeholder="__('All levels')" class="w-40">
                    <flux:select.option value="">{{ __('All levels') }}</flux:select.option>
                    @foreach (\Internal\SecurityMonitor\Models\SecurityLog::LEVELS as $lvl)
                        <flux:select.option value="{{ $lvl }}">{{ $this->levelLabel($lvl) }}</flux:select.option>
                    @endforeach
                </flux:select>

                <flux:select wire:model.live="eventType" class="w-48">
                    <flux:select.option value="">{{ __('All events') }}</flux:select.option>
                    @foreach ($eventTypes as $type)
                        <flux:select.option value="{{ $type }}">{{ $type }}</flux:select.option>
                    @endforeach
                </flux:select>
            </div>

            <flux:button
                variant="danger"
                icon="trash"
                wire:click="clearAll"
                wire:confirm="{{ __('Clear ALL security logs? This cannot be undone.') }}"
            >
                {{ __('Clear logs') }}
            </flux:button>
        </div>

        <flux:card class="mt-5 p-0!">
            <flux:table :paginate="$logs">
                <flux:table.columns>
                    <flux:table.column>{{ __('Level') }}</flux:table.column>
                    <flux:table.column>{{ __('Event') }}</flux:table.column>
                    <flux:table.column>{{ __('IP') }}</flux:table.column>
                    <flux:table.column>{{ __('Path') }}</flux:table.column>
                    <flux:table.column>{{ __('When') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                    @forelse ($logs as $log)
                        <flux:table.row :key="$log->id">
                            <flux:table.cell>
                                <flux:badge :color="$this->levelColor($log->threat_level)" size="sm">
                                    {{ $this->levelLabel($log->threat_level) }}
                                </flux:badge>
                            </flux:table.cell>
                            <flux:table.cell class="text-xs">
                                <div class="font-medium">{{ $log->event_type }}</div>
                                <div class="text-zinc-500">{{ \Illuminate\Support\Str::limit((string) $log->rule_label, 48) }}</div>
                            </flux:table.cell>
                            <flux:table.cell class="font-mono text-xs">{{ $log->ip_address }}</flux:table.cell>
                            <flux:table.cell class="max-w-xs truncate text-xs" title="{{ $log->path }}">
                                <span class="text-zinc-500">{{ $log->method }}</span>
                                {{ \Illuminate\Support\Str::limit((string) $log->path, 48) }}
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $log->created_at?->diffForHumans() }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:button
                                    size="sm"
                                    variant="ghost"
                                    icon="trash"
                                    wire:click="delete({{ $log->id }})"
                                    wire:confirm="{{ __('Delete this log entry?') }}"
                                />
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="6" class="text-center text-sm text-zinc-500">
                                {{ __('No security logs match the current filters.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>
    </x-pages::security.layout>
</div>
