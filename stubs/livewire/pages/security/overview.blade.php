<?php

use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('Security Overview')] class extends Component {
    public string $range = 'week';

    /** @var array<string, int> */
    public array $stats = [];

    /** @var array<string, int> */
    public array $levels = [];

    /**
     * @var array{total: int, peak: array{label: string, total: int}, points: array<int, array<string, mixed>>}
     */
    public array $trend = ['total' => 0, 'peak' => ['label' => '-', 'total' => 0], 'points' => []];

    /** @var array<int, array<string, mixed>> */
    public array $attackers = [];

    public function mount(SecurityMonitorService $security): void
    {
        $this->load($security);
    }

    public function updatedRange(SecurityMonitorService $security): void
    {
        $this->load($security);
    }

    protected function load(SecurityMonitorService $security): void
    {
        $this->stats = $security->stats();
        $this->levels = $security->levelBreakdown();
        $this->trend = $security->attackTrend($this->range);
        $this->attackers = $security->topAttackers(5)
            ->map(fn ($row) => (array) $row)
            ->all();
    }

    public function levelLabel(string $level): string
    {
        return match ($level) {
            'critical' => __('Critical'),
            'high' => __('High'),
            'medium' => __('Medium'),
            default => __('Low'),
        };
    }

    public function levelColor(string $level): string
    {
        return match ($level) {
            'critical' => 'red',
            'high' => 'orange',
            'medium' => 'amber',
            default => 'zinc',
        };
    }
}; ?>

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('Security Overview')" :subheading="__('Ringkasan ancaman, blokir, dan aktivitas keamanan terbaru')">
        @php($maxTrend = max(1, collect($trend['points'])->max('total') ?? 1))

        <div class="grid auto-rows-min gap-4 md:grid-cols-2 xl:grid-cols-4">
            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Logs today') }}</flux:text>
                <flux:heading size="xl">{{ number_format($stats['logs_today'] ?? 0) }}</flux:heading>
                <flux:text class="text-xs text-zinc-400">{{ __(':count total recorded', ['count' => number_format($stats['total_logs'] ?? 0)]) }}</flux:text>
            </flux:card>

            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Critical threats today') }}</flux:text>
                <flux:heading size="xl" class="text-red-600 dark:text-red-400">{{ number_format($stats['critical_today'] ?? 0) }}</flux:heading>
                <flux:text class="text-xs text-zinc-400">{{ __('Requires immediate review') }}</flux:text>
            </flux:card>

            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Active blocks') }}</flux:text>
                <flux:heading size="xl">{{ number_format($stats['active_blocks'] ?? 0) }}</flux:heading>
                <flux:text class="text-xs text-zinc-400">{{ __(':count total blocks', ['count' => number_format($stats['total_blocks'] ?? 0)]) }}</flux:text>
            </flux:card>

            <flux:card class="space-y-1">
                <flux:text class="text-sm text-zinc-500">{{ __('Unique IPs today') }}</flux:text>
                <flux:heading size="xl">{{ number_format($stats['unique_ips_today'] ?? 0) }}</flux:heading>
                <flux:text class="text-xs text-zinc-400">{{ __(':count blocked attempts', ['count' => number_format($stats['blocked_attempts_today'] ?? 0)]) }}</flux:text>
            </flux:card>
        </div>

        <div class="grid gap-4 lg:grid-cols-2">
            <flux:card class="space-y-4">
                <div class="flex items-center justify-between gap-4">
                    <div>
                        <flux:heading>{{ __('Attack trend') }}</flux:heading>
                        <flux:text class="text-sm text-zinc-500">{{ __('Total :total · Peak :peak (:count)', ['total' => number_format($trend['total']), 'peak' => $trend['peak']['label'], 'count' => number_format($trend['peak']['total'])]) }}</flux:text>
                    </div>

                    <flux:select wire:model.live="range" size="sm" class="w-32">
                        <flux:select.option value="week">{{ __('7 days') }}</flux:select.option>
                        <flux:select.option value="month">{{ __('30 days') }}</flux:select.option>
                        <flux:select.option value="year">{{ __('12 months') }}</flux:select.option>
                    </flux:select>
                </div>

                <div class="flex h-40 items-end gap-1.5">
                    @foreach ($trend['points'] as $point)
                        <div class="group relative flex flex-1 flex-col items-center justify-end gap-1">
                            <div class="w-full rounded-t bg-red-500/70 transition group-hover:bg-red-500"
                                 style="height: {{ max(2, (int) round(((int) $point['total'] / $maxTrend) * 130)) }}px"
                                 title="{{ $point['tooltip'] }} · {{ $point['total'] }}"></div>
                            <span class="text-[10px] text-zinc-400">{{ $point['label'] }}</span>
                        </div>
                    @endforeach
                </div>
            </flux:card>

            <flux:card class="space-y-4">
                <flux:heading>{{ __('Threats by severity (24h)') }}</flux:heading>

                @php($levelTotal = max(1, array_sum($levels)))

                <div class="space-y-3">
                    @foreach (\Internal\SecurityMonitor\Models\SecurityLog::LEVELS as $level)
                        @php($count = $levels[$level] ?? 0)
                        <div class="space-y-1">
                            <div class="flex items-center justify-between text-sm">
                                <flux:badge :color="$this->levelColor($level)" size="sm">{{ $this->levelLabel($level) }}</flux:badge>
                                <span class="font-medium tabular-nums">{{ number_format($count) }}</span>
                            </div>
                            <div class="h-2 w-full overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
                                <div class="h-full rounded-full bg-current {{ $level === 'critical' ? 'text-red-500' : ($level === 'high' ? 'text-orange-500' : ($level === 'medium' ? 'text-amber-500' : 'text-zinc-400')) }}"
                                     style="width: {{ (int) round(($count / $levelTotal) * 100) }}%"></div>
                            </div>
                        </div>
                    @endforeach
                </div>
            </flux:card>
        </div>

        <flux:card class="space-y-3">
            <flux:heading>{{ __('Top attackers (24h)') }}</flux:heading>

            <flux:table>
                <flux:table.columns>
                    <flux:table.column>{{ __('IP address') }}</flux:table.column>
                    <flux:table.column>{{ __('Hits') }}</flux:table.column>
                    <flux:table.column>{{ __('Highest level') }}</flux:table.column>
                    <flux:table.column>{{ __('Last seen') }}</flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                    @forelse ($attackers as $attacker)
                        <flux:table.row>
                            <flux:table.cell class="font-mono text-xs">{{ $attacker['ip_address'] }}</flux:table.cell>
                            <flux:table.cell class="tabular-nums">{{ number_format((int) $attacker['hits']) }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:badge :color="$this->levelColor((string) $attacker['level'])" size="sm">
                                    {{ $this->levelLabel((string) $attacker['level']) }}
                                </flux:badge>
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ \Illuminate\Support\Carbon::parse($attacker['last_seen'])->diffForHumans() }}</flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="4" class="text-center text-sm text-zinc-500">
                                {{ __('No threats recorded in the last 24 hours.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>
    </x-pages::security.layout>
</div>
