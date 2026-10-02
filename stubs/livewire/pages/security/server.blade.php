<?php

use Flux\Flux;
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

        Flux::toast(variant: 'success', text: __('Server audit refreshed.'));
    }

    public function createBaseline(): void
    {
        app(ServerSecurityService::class)->createBaseline(auth()->id());
        $this->load(force: true);

        Flux::toast(variant: 'success', text: __('Integrity baseline created.'));
    }

    public function deleteBaseline(): void
    {
        app(ServerSecurityService::class)->deleteBaseline();
        $this->load(force: true);

        Flux::toast(variant: 'success', text: __('Integrity baseline deleted.'));
    }

    public function deleteFile(string $path): void
    {
        $result = app(ServerSecurityService::class)->deleteSuspiciousFile($path, auth()->id());

        $this->load(force: true);

        Flux::toast(
            variant: ($result['success'] ?? false) ? 'success' : 'danger',
            text: $result['message'] ?? __('Unable to delete the file.'),
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

        Flux::toast(variant: 'success', text: __('Lockout released.'));
    }

    public function statusColor(?string $status): string
    {
        return match ($status) {
            'critical' => 'red',
            'warning' => 'amber',
            'ok' => 'green',
            default => 'zinc',
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

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('Server Audit')" :subheading="__('Integrity, webshell scanner, and environment hygiene')">
        @php($summary = $report['summary'] ?? [])

        <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="grid flex-1 auto-rows-min gap-4 md:grid-cols-4">
                <flux:card class="space-y-1">
                    <flux:text class="text-sm text-zinc-500">{{ __('Health score') }}</flux:text>
                    <flux:heading size="xl">{{ $summary['score'] ?? 0 }}<span class="text-base text-zinc-400">/100</span></flux:heading>
                </flux:card>
                <flux:card class="space-y-1">
                    <flux:text class="text-sm text-zinc-500">{{ __('Critical') }}</flux:text>
                    <flux:heading size="xl" class="text-red-600 dark:text-red-400">{{ $summary['critical'] ?? 0 }}</flux:heading>
                </flux:card>
                <flux:card class="space-y-1">
                    <flux:text class="text-sm text-zinc-500">{{ __('Warnings') }}</flux:text>
                    <flux:heading size="xl" class="text-amber-600 dark:text-amber-400">{{ $summary['warning'] ?? 0 }}</flux:heading>
                </flux:card>
                <flux:card class="space-y-1">
                    <flux:text class="text-sm text-zinc-500">{{ __('Passed checks') }}</flux:text>
                    <flux:heading size="xl" class="text-green-600 dark:text-green-400">{{ $summary['ok'] ?? 0 }}</flux:heading>
                </flux:card>
            </div>

            <flux:button variant="primary" icon="arrow-path" wire:click="refresh">
                {{ __('Refresh') }}
            </flux:button>
        </div>

        <div class="grid gap-4 lg:grid-cols-2">
            <flux:card class="space-y-4">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <flux:heading>{{ __('Integrity baseline') }}</flux:heading>
                        <flux:text class="text-sm text-zinc-500">
                            @if ($baseline['exists'] ?? false)
                                {{ __(':files files tracked · created :when', ['files' => number_format($baseline['files'] ?? 0), 'when' => $baseline['created_at'] ?? '-']) }}
                            @else
                                {{ __('No baseline created yet (:watched files watched).', ['watched' => number_format($baseline['watched'] ?? 0)]) }}
                            @endif
                        </flux:text>
                    </div>

                    <div class="flex gap-2">
                        <flux:button size="sm" variant="filled" wire:click="createBaseline" wire:confirm="{{ __('Create a new integrity baseline from the current files?') }}">
                            {{ __('Create') }}
                        </flux:button>
                        @if ($baseline['exists'] ?? false)
                            <flux:button size="sm" variant="danger" wire:click="deleteBaseline" wire:confirm="{{ __('Delete the stored baseline?') }}">
                                {{ __('Delete') }}
                            </flux:button>
                        @endif
                    </div>
                </div>

                <div class="grid grid-cols-3 gap-3 text-center">
                    <div class="rounded-lg bg-amber-50 p-3 dark:bg-amber-950/40">
                        <div class="text-lg font-semibold tabular-nums">{{ count($integrity['modified']) }}</div>
                        <flux:text class="text-xs">{{ __('Modified') }}</flux:text>
                    </div>
                    <div class="rounded-lg bg-red-50 p-3 dark:bg-red-950/40">
                        <div class="text-lg font-semibold tabular-nums">{{ count($integrity['missing']) }}</div>
                        <flux:text class="text-xs">{{ __('Missing') }}</flux:text>
                    </div>
                    <div class="rounded-lg bg-sky-50 p-3 dark:bg-sky-950/40">
                        <div class="text-lg font-semibold tabular-nums">{{ count($integrity['added']) }}</div>
                        <flux:text class="text-xs">{{ __('New') }}</flux:text>
                    </div>
                </div>

                @php($integrityIssues = array_slice(array_merge(
                    array_map(fn ($f) => ['type' => 'modified', 'file' => $f], $integrity['modified']),
                    array_map(fn ($f) => ['type' => 'missing', 'file' => $f], $integrity['missing']),
                    array_map(fn ($f) => ['type' => 'added', 'file' => $f], $integrity['added']),
                ), 0, 8))

                @if (! empty($integrityIssues))
                    <div class="space-y-1">
                        @foreach ($integrityIssues as $issue)
                            <div class="flex items-center justify-between gap-2 text-xs">
                                <span class="truncate font-mono" title="{{ $issue['file'] }}">{{ $issue['file'] }}</span>
                                <flux:badge :color="$issue['type'] === 'missing' ? 'red' : ($issue['type'] === 'modified' ? 'amber' : 'sky')" size="sm">
                                    {{ $issue['type'] }}
                                </flux:badge>
                            </div>
                        @endforeach
                    </div>
                @endif
            </flux:card>

            <flux:card class="space-y-3">
                <flux:heading>{{ __('Environment') }}</flux:heading>
                <div class="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
                    @foreach ($environment as $key => $value)
                        <div class="flex items-center justify-between gap-2 border-b border-zinc-100 py-1 dark:border-zinc-800">
                            <span class="text-zinc-500">{{ \Illuminate\Support\Str::headline($key) }}</span>
                            <span class="truncate font-medium" title="{{ $value }}">{{ $value }}</span>
                        </div>
                    @endforeach
                </div>
            </flux:card>
        </div>

        <flux:card class="space-y-3">
            <flux:heading>{{ __('Suspicious files & webshells') }}</flux:heading>

            <flux:table>
                <flux:table.columns>
                    <flux:table.column>{{ __('File') }}</flux:table.column>
                    <flux:table.column>{{ __('Threat') }}</flux:table.column>
                    <flux:table.column>{{ __('Reason') }}</flux:table.column>
                    <flux:table.column align="end">{{ __('Size') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                    @forelse ($suspicious as $file)
                        <flux:table.row :key="$file['id'] ?? $file['path']">
                            <flux:table.cell class="font-mono text-xs">{{ $file['path'] }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:badge :color="$this->statusColor($file['threat_level'] ?? 'info')" size="sm">
                                    {{ $file['threat_level'] ?? 'info' }}
                                </flux:badge>
                            </flux:table.cell>
                            <flux:table.cell class="max-w-sm truncate text-xs text-zinc-500" title="{{ $file['reason'] ?? '' }}">
                                {{ \Illuminate\Support\Str::limit((string) ($file['reason'] ?? ''), 64) }}
                            </flux:table.cell>
                            <flux:table.cell align="end" class="text-xs">{{ $file['size'] ?? '-' }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:button
                                    size="sm"
                                    variant="ghost"
                                    icon="trash"
                                    wire:click="deleteFile('{{ $file['path'] }}')"
                                    wire:confirm="{{ __('Permanently delete this file?') }}"
                                />
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="5" class="text-center text-sm text-zinc-500">
                                {{ __('No suspicious files detected.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>

        @if (! empty($lockouts))
            <flux:card class="space-y-3">
                <flux:heading>{{ __('Active login lockouts') }}</flux:heading>
                <flux:table>
                    <flux:table.columns>
                        <flux:table.column>{{ __('Email') }}</flux:table.column>
                        <flux:table.column>{{ __('IP') }}</flux:table.column>
                        <flux:table.column>{{ __('Level') }}</flux:table.column>
                        <flux:table.column>{{ __('Remaining') }}</flux:table.column>
                        <flux:table.column></flux:table.column>
                    </flux:table.columns>
                    <flux:table.rows>
                        @foreach ($lockouts as $lockout)
                            <flux:table.row :key="$lockout['id']">
                                <flux:table.cell class="text-xs">{{ $lockout['email'] }}</flux:table.cell>
                                <flux:table.cell class="font-mono text-xs">{{ $lockout['ip_address'] }}</flux:table.cell>
                                <flux:table.cell>{{ $lockout['lockout_level'] }}</flux:table.cell>
                                <flux:table.cell class="text-xs">{{ $lockout['remaining'] }}s</flux:table.cell>
                                <flux:table.cell>
                                    <flux:button size="sm" variant="ghost" icon="lock-open" wire:click="releaseLockout({{ $lockout['id'] }})">
                                        {{ __('Release') }}
                                    </flux:button>
                                </flux:table.cell>
                            </flux:table.row>
                        @endforeach
                    </flux:table.rows>
                </flux:table>
            </flux:card>
        @endif

        <flux:card class="space-y-4">
            <flux:heading>{{ __('Security checks') }}</flux:heading>

            @foreach (($report['categories'] ?? []) as $category)
                <div class="space-y-2">
                    <flux:subheading>{{ $category['label'] }}</flux:subheading>
                    <div class="space-y-2">
                        @foreach (($category['checks'] ?? []) as $check)
                            <div class="flex items-start justify-between gap-3 rounded-lg border border-zinc-100 p-3 dark:border-zinc-800">
                                <div class="space-y-0.5">
                                    <div class="flex items-center gap-2">
                                        <flux:badge :color="$this->statusColor($check['status'] ?? 'info')" size="sm">
                                            {{ $check['status'] ?? 'info' }}
                                        </flux:badge>
                                        <span class="text-sm font-medium">{{ $check['label'] ?? '' }}</span>
                                    </div>
                                    @if (! empty($check['detail']))
                                        <flux:text class="text-xs text-zinc-500">{{ $check['detail'] }}</flux:text>
                                    @endif
                                    @if (! empty($check['recommendation']))
                                        <flux:text class="text-xs text-amber-600 dark:text-amber-400">→ {{ $check['recommendation'] }}</flux:text>
                                    @endif
                                </div>
                                @if (($check['value'] ?? null) !== null)
                                    <flux:badge color="zinc" size="sm" class="font-mono">{{ $check['value'] }}</flux:badge>
                                @endif
                            </div>
                        @endforeach
                    </div>
                </div>
            @endforeach
        </flux:card>
    </x-pages::security.layout>
</div>
