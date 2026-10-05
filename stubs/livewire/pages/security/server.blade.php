<?php

use Internal\SecurityMonitor\Models\LoginAttempt;
use Internal\SecurityMonitor\Services\ServerSecurityService;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('Server Audit')] class extends Component {
    /** @var array<string, mixed> */
    public array $report = [];

    /** @var array<string, string> */
    public array $environment = [];

    /** @var array<string, mixed> */
    public array $baseline = [];

    /** @var array{modified: array<int, string>, missing: array<int, string>, added: array<int, string>} */
    public array $integrity = ['modified' => [], 'missing' => [], 'added' => []];

    /** @var array<int, array<string, mixed>> */
    public array $suspicious = [];

    /** @var array<int, array<string, mixed>> */
    public array $lockouts = [];

    public function mount(): void
    {
        $this->load();
    }

    public function refresh(): void
    {
        app(ServerSecurityService::class)->forget();
        $this->load(force: true);

        session()->flash('security_message', __('Server audit refreshed.'));
    }

    public function createBaseline(): void
    {
        app(ServerSecurityService::class)->createBaseline(auth()->id());
        $this->load(force: true);

        session()->flash('security_message', __('Integrity baseline created.'));
    }

    public function deleteBaseline(): void
    {
        app(ServerSecurityService::class)->deleteBaseline();
        $this->load(force: true);

        session()->flash('security_message', __('Integrity baseline deleted.'));
    }

    public function deleteFile(string $path): void
    {
        $result = app(ServerSecurityService::class)->deleteSuspiciousFile($path, auth()->id());

        $this->load(force: true);

        session()->flash(
            'security_message',
            $result['message'] ?? __('Suspicious file action performed.'),
        );
    }

    public function releaseLockout(int $id): void
    {
        $attempt = LoginAttempt::query()->find($id);

        if (! $attempt) {
            return;
        }

        app(ServerSecurityService::class)->releaseLockout($attempt);
        $this->load(force: true);

        session()->flash('security_message', __('Lockout released.'));
    }

    public function statusBadgeClass(?string $status): string
    {
        return match ($status) {
            'critical' => 'sec-badge-critical',
            'warning' => 'sec-badge-high',
            'ok' => 'sec-badge-success',
            default => 'sec-badge-low',
        };
    }

    protected function load(bool $force = false): void
    {
        $server = app(ServerSecurityService::class);

        $this->report = $server->scan($force);
        $this->environment = $server->environmentInfo();
        $this->baseline = $server->baselineSummary();
        $this->integrity = $server->integrityReport();
        $this->suspicious = $server->suspiciousFiles($force);
        $this->lockouts = $server->activeLockouts();
    }
}; ?>

<div>
    <x-pages::security.layout :heading="__('Server Audit')" :subheading="__('Integrity, webshell scanner, and environment hygiene')">
        @php($summary = $report['summary'] ?? [])

        <!-- Header Controls & Top Stats -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;">
            <div class="sec-grid-4" style="flex: 1; margin-bottom: 0;">
                <div class="sec-stat-card">
                    <div class="sec-stat-label">{{ __('Health score') }}</div>
                    <div class="sec-stat-value">
                        {{ $summary['score'] ?? 0 }}<span style="font-size: 14px; color: var(--sec-text-subtle);">/100</span>
                    </div>
                </div>
                <div class="sec-stat-card">
                    <div class="sec-stat-label">{{ __('Critical') }}</div>
                    <div class="sec-stat-value sec-text-danger">{{ $summary['critical'] ?? 0 }}</div>
                </div>
                <div class="sec-stat-card">
                    <div class="sec-stat-label">{{ __('Warnings') }}</div>
                    <div class="sec-stat-value" style="color: var(--sec-warning);">{{ $summary['warning'] ?? 0 }}</div>
                </div>
                <div class="sec-stat-card">
                    <div class="sec-stat-label">{{ __('Passed checks') }}</div>
                    <div class="sec-stat-value" style="color: var(--sec-success);">{{ $summary['ok'] ?? 0 }}</div>
                </div>
            </div>

            <div>
                <button type="button" class="sec-btn sec-btn-primary" wire:click="refresh">
                    <span>🔄</span>
                    <span>{{ __('Refresh') }}</span>
                </button>
            </div>
        </div>

        <!-- Middle Section: Baseline & Environment -->
        <div class="sec-grid-2">
            <!-- Integrity Baseline -->
            <div class="sec-card">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <h3 class="sec-card-title">{{ __('Integrity baseline') }}</h3>
                        <p class="sec-card-subtitle">
                            @if ($baseline['exists'] ?? false)
                                {{ __(':files files tracked · created :when', ['files' => number_format($baseline['files'] ?? 0), 'when' => $baseline['created_at'] ?? '-']) }}
                            @else
                                {{ __('No baseline created yet (:watched files watched).', ['watched' => number_format($baseline['watched'] ?? 0)]) }}
                            @endif
                        </p>
                    </div>

                    <div style="display: flex; gap: 8px;">
                        <button type="button" class="sec-btn sec-btn-secondary sec-btn-sm" wire:click="createBaseline" wire:confirm="{{ __('Create a new integrity baseline from current files?') }}">
                            {{ __('Create') }}
                        </button>
                        @if ($baseline['exists'] ?? false)
                            <button type="button" class="sec-btn sec-btn-danger sec-btn-sm" wire:click="deleteBaseline" wire:confirm="{{ __('Delete the stored baseline?') }}">
                                {{ __('Delete') }}
                            </button>
                        @endif
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; text-align: center; margin-bottom: 16px;">
                    <div style="padding: 12px; background: var(--sec-warning-bg); border: 1px solid var(--sec-warning-border); border-radius: var(--sec-radius-sm);">
                        <div style="font-size: 20px; font-weight: 700; color: var(--sec-warning);">{{ count($integrity['modified']) }}</div>
                        <div style="font-size: 11px; font-weight: 600; color: var(--sec-text-muted);">{{ __('Modified') }}</div>
                    </div>
                    <div style="padding: 12px; background: var(--sec-danger-bg); border: 1px solid var(--sec-danger-border); border-radius: var(--sec-radius-sm);">
                        <div style="font-size: 20px; font-weight: 700; color: var(--sec-danger);">{{ count($integrity['missing']) }}</div>
                        <div style="font-size: 11px; font-weight: 600; color: var(--sec-text-muted);">{{ __('Missing') }}</div>
                    </div>
                    <div style="padding: 12px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: var(--sec-radius-sm);">
                        <div style="font-size: 20px; font-weight: 700; color: #0284c7;">{{ count($integrity['added']) }}</div>
                        <div style="font-size: 11px; font-weight: 600; color: var(--sec-text-muted);">{{ __('New') }}</div>
                    </div>
                </div>

                @php($integrityIssues = array_slice(array_merge(
                    array_map(fn ($f) => ['type' => 'modified', 'file' => $f], $integrity['modified']),
                    array_map(fn ($f) => ['type' => 'missing', 'file' => $f], $integrity['missing']),
                    array_map(fn ($f) => ['type' => 'added', 'file' => $f], $integrity['added']),
                ), 0, 8))

                @if (! empty($integrityIssues))
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        @foreach ($integrityIssues as $issue)
                            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; padding: 6px 8px; background: var(--sec-card-hover); border-radius: var(--sec-radius-sm);">
                                <span class="sec-font-mono" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 80%;" title="{{ $issue['file'] }}">
                                    {{ $issue['file'] }}
                                </span>
                                <span class="sec-badge {{ $issue['type'] === 'missing' ? 'sec-badge-critical' : ($issue['type'] === 'modified' ? 'sec-badge-high' : 'sec-badge-low') }}">
                                    {{ $issue['type'] }}
                                </span>
                            </div>
                        @endforeach
                    </div>
                @endif
            </div>

            <!-- Environment -->
            <div class="sec-card">
                <h3 class="sec-card-title" style="margin-bottom: 14px;">{{ __('Environment') }}</h3>
                <div style="display: flex; flex-direction: column;">
                    @foreach ($environment as $key => $value)
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--sec-border-light); font-size: 13px;">
                            <span style="color: var(--sec-text-muted);">{{ \Illuminate\Support\Str::headline($key) }}</span>
                            <span class="sec-font-mono" style="font-weight: 600; max-width: 60%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{{ $value }}">
                                {{ $value }}
                            </span>
                        </div>
                    @endforeach
                </div>
            </div>
        </div>

        <!-- Suspicious Files & Webshells -->
        <div class="sec-card sec-card-flush">
            <div class="sec-card-header">
                <h3 class="sec-card-title">{{ __('Suspicious files & webshells') }}</h3>
            </div>
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('File') }}</th>
                            <th>{{ __('Threat') }}</th>
                            <th>{{ __('Reason') }}</th>
                            <th style="text-align: right;">{{ __('Size') }}</th>
                            <th style="text-align: right;">{{ __('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($suspicious as $file)
                            <tr>
                                <td class="sec-font-mono" style="font-size: 12px; font-weight: 600;">{{ $file['path'] }}</td>
                                <td>
                                    <span class="sec-badge {{ $this->statusBadgeClass($file['threat_level'] ?? 'info') }}">
                                        {{ $file['threat_level'] ?? 'info' }}
                                    </span>
                                </td>
                                <td style="max-width: 280px; font-size: 12px; color: var(--sec-text-muted);" title="{{ $file['reason'] ?? '' }}">
                                    {{ \Illuminate\Support\Str::limit((string) ($file['reason'] ?? ''), 60) }}
                                </td>
                                <td style="text-align: right; font-size: 12px;" class="sec-font-mono">{{ $file['size'] ?? '-' }}</td>
                                <td style="text-align: right;">
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="deleteFile('{{ $file['path'] }}')"
                                        wire:confirm="{{ __('Permanently delete this file?') }}"
                                        title="{{ __('Delete file') }}"
                                    >
                                        🗑️
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="5" style="text-align: center; color: var(--sec-text-muted); padding: 32px;">
                                    {{ __('No suspicious files detected.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Active Lockouts (if any) -->
        @if (! empty($lockouts))
            <div class="sec-card sec-card-flush">
                <div class="sec-card-header">
                    <h3 class="sec-card-title">{{ __('Active login lockouts') }}</h3>
                </div>
                <div class="sec-table-wrap">
                    <table class="sec-table">
                        <thead>
                            <tr>
                                <th>{{ __('Email') }}</th>
                                <th>{{ __('IP') }}</th>
                                <th>{{ __('Level') }}</th>
                                <th>{{ __('Remaining') }}</th>
                                <th style="text-align: right;">{{ __('Action') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($lockouts as $lockout)
                                <tr>
                                    <td style="font-size: 12px;">{{ $lockout['email'] }}</td>
                                    <td class="sec-font-mono" style="font-size: 12px;">{{ $lockout['ip_address'] }}</td>
                                    <td>
                                        <span class="sec-badge sec-badge-high">{{ $lockout['lockout_level'] }}</span>
                                    </td>
                                    <td style="font-size: 12px; color: var(--sec-text-muted);">{{ $lockout['remaining'] }}s</td>
                                    <td style="text-align: right;">
                                        <button
                                            type="button"
                                            class="sec-btn sec-btn-secondary sec-btn-sm"
                                            wire:click="releaseLockout({{ $lockout['id'] }})"
                                        >
                                            {{ __('Release') }}
                                        </button>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            </div>
        @endif

        <!-- Security Checks Categorized -->
        <div class="sec-card">
            <h3 class="sec-card-title" style="margin-bottom: 16px;">{{ __('Security checks') }}</h3>

            <div style="display: flex; flex-direction: column; gap: 20px;">
                @foreach (($report['categories'] ?? []) as $category)
                    <div>
                        <h4 style="font-size: 14px; font-weight: 600; color: var(--sec-text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin: 0 0 10px 0;">
                            {{ $category['label'] }}
                        </h4>
                        <div style="display: flex; flex-direction: column; gap: 8px;">
                            @foreach (($category['checks'] ?? []) as $check)
                                <div style="display: flex; justify-content: space-between; align-items: flex-start; padding: 12px 14px; background: var(--sec-card-hover); border-radius: var(--sec-radius-sm); gap: 12px;">
                                    <div style="display: flex; flex-direction: column; gap: 4px;">
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <span class="sec-badge {{ $this->statusBadgeClass($check['status'] ?? 'info') }}">
                                                {{ $check['status'] ?? 'info' }}
                                            </span>
                                            <span style="font-size: 14px; font-weight: 600;">{{ $check['label'] ?? '' }}</span>
                                        </div>
                                        @if (! empty($check['detail']))
                                            <div style="font-size: 12px; color: var(--sec-text-muted);">{{ $check['detail'] }}</div>
                                        @endif
                                        @if (! empty($check['recommendation']))
                                            <div style="font-size: 12px; color: var(--sec-warning); font-weight: 500;">
                                                → {{ $check['recommendation'] }}
                                            </div>
                                        @endif
                                    </div>
                                    @if (($check['value'] ?? null) !== null)
                                        <span class="sec-badge sec-badge-low sec-font-mono" style="font-size: 11px;">
                                            {{ $check['value'] }}
                                        </span>
                                    @endif
                                </div>
                            @endforeach
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    </x-pages::security.layout>
</div>
