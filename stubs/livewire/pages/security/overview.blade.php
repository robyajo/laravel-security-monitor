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

    public function levelClass(string $level): string
    {
        return match ($level) {
            'critical' => 'sec-badge-critical',
            'high' => 'sec-badge-high',
            'medium' => 'sec-badge-medium',
            default => 'sec-badge-low',
        };
    }

    public function trendBarHeight(mixed $total, int $maxTrend): string
    {
        return max(4, (int) round(((int) $total / $maxTrend) * 120)).'px';
    }

    public function severityPercent(int $count, int $levelTotal): string
    {
        return (int) round(($count / $levelTotal) * 100).'%';
    }

    public function severityColor(string $level): string
    {
        return match ($level) {
            'critical' => 'var(--sec-danger)',
            'high' => 'var(--sec-warning)',
            'medium' => '#d97706',
            default => 'var(--sec-text-subtle)',
        };
    }
}; ?>

<div>
    <x-pages::security.layout :heading="__('Security Overview')" :subheading="__('Ringkasan ancaman, blokir, dan aktivitas keamanan terbaru')">
        @php($maxTrend = max(1, collect($trend['points'])->max('total') ?? 1))

        <!-- Stats Grid -->
        <div class="sec-grid-4">
            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Logs today') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['logs_today'] ?? 0) }}</div>
                <div class="sec-stat-desc">{{ __(':count total recorded', ['count' => number_format($stats['total_logs'] ?? 0)]) }}</div>
            </div>

            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Critical threats today') }}</div>
                <div class="sec-stat-value sec-text-danger">{{ number_format($stats['critical_today'] ?? 0) }}</div>
                <div class="sec-stat-desc">{{ __('Requires immediate review') }}</div>
            </div>

            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Active blocks') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['active_blocks'] ?? 0) }}</div>
                <div class="sec-stat-desc">{{ __(':count total blocks', ['count' => number_format($stats['total_blocks'] ?? 0)]) }}</div>
            </div>

            <div class="sec-stat-card">
                <div class="sec-stat-label">{{ __('Unique IPs today') }}</div>
                <div class="sec-stat-value">{{ number_format($stats['unique_ips_today'] ?? 0) }}</div>
                <div class="sec-stat-desc">{{ __(':count blocked attempts', ['count' => number_format($stats['blocked_attempts_today'] ?? 0)]) }}</div>
            </div>
        </div>

        <!-- Middle Charts Grid -->
        <div class="sec-grid-2">
            <!-- Attack Trend Chart -->
            <div class="sec-card">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                    <div>
                        <h3 class="sec-card-title">{{ __('Attack trend') }}</h3>
                        <p class="sec-card-subtitle">
                            {{ __('Total :total · Peak :peak (:count)', ['total' => number_format($trend['total']), 'peak' => $trend['peak']['label'], 'count' => number_format($trend['peak']['total'])]) }}
                        </p>
                    </div>

                    <select wire:model.live="range" class="sec-select">
                        <option value="week">{{ __('7 days') }}</option>
                        <option value="month">{{ __('30 days') }}</option>
                        <option value="year">{{ __('12 months') }}</option>
                    </select>
                </div>

                <div class="sec-chart-box">
                    @foreach ($trend['points'] as $point)
                        <div class="sec-chart-col">
                            <div class="sec-chart-bar"
                                 {!! 'style="height: ' . $this->trendBarHeight($point['total'], $maxTrend) . ';"' !!}
                                 title="{{ $point['tooltip'] }} · {{ $point['total'] }}"></div>
                            <span class="sec-chart-label">{{ $point['label'] }}</span>
                        </div>
                    @endforeach
                </div>
            </div>

            <!-- Severity Breakdown -->
            <div class="sec-card">
                <h3 class="sec-card-title" style="margin-bottom: 16px;">{{ __('Threats by severity (24h)') }}</h3>

                @php($levelTotal = max(1, array_sum($levels)))

                <div style="display: flex; flex-direction: column; gap: 14px;">
                    @foreach (\Internal\SecurityMonitor\Models\SecurityLog::LEVELS as $level)
                        @php($count = $levels[$level] ?? 0)
                        <div>
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <span class="sec-badge {{ $this->levelClass($level) }}">{{ $this->levelLabel($level) }}</span>
                                <span class="sec-font-mono" style="font-size: 13px; font-weight: 600;">{{ number_format($count) }}</span>
                            </div>
                            <div style="height: 6px; width: 100%; background: var(--sec-border-light); border-radius: 9999px; overflow: hidden;">
                                <div {!! 'style="height: 100%; border-radius: 9999px; width: ' . $this->severityPercent($count, $levelTotal) . '; background: ' . $this->severityColor($level) . ';"' !!}></div>
                            </div>
                        </div>
                    @endforeach
                </div>
            </div>
        </div>

        <!-- Top Attackers Table -->
        <div class="sec-card sec-card-flush">
            <div class="sec-card-header">
                <h3 class="sec-card-title">{{ __('Top attackers (24h)') }}</h3>
            </div>

            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('IP address') }}</th>
                            <th>{{ __('Hits') }}</th>
                            <th>{{ __('Highest level') }}</th>
                            <th>{{ __('Last seen') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($attackers as $attacker)
                            <tr>
                                <td class="sec-font-mono" style="font-weight: 600;">{{ $attacker['ip_address'] }}</td>
                                <td class="sec-font-mono">{{ number_format((int) $attacker['hits']) }}</td>
                                <td>
                                    <span class="sec-badge {{ $this->levelClass((string) $attacker['level']) }}">
                                        {{ $this->levelLabel((string) $attacker['level']) }}
                                    </span>
                                </td>
                                <td style="color: var(--sec-text-muted);">
                                    {{ \Illuminate\Support\Carbon::parse($attacker['last_seen'])->diffForHumans() }}
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="4" style="text-align: center; color: var(--sec-text-muted); padding: 32px;">
                                    {{ __('No threats recorded in the last 24 hours.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>
    </x-pages::security.layout>
</div>
