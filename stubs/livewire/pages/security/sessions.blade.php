<?php

use Illuminate\Support\Str;
use Internal\SecurityMonitor\Models\TrustedIp;
use Internal\SecurityMonitor\Models\UserLogin;
use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Internal\SecurityMonitor\Services\UserLoginService;
use Livewire\Attributes\Title;
use Livewire\Component;
use Livewire\WithPagination;

new #[Title('User Sessions')] class extends Component {
    use WithPagination;

    public string $search = '';

    public int $perPage = 20;

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function deleteLogin(int $id): void
    {
        UserLogin::query()->whereKey($id)->delete();

        session()->flash('security_message', __('Login history entry deleted.'));
    }

    public function destroySession(string $sessionId): void
    {
        app(UserLoginService::class)->logoutSession($sessionId);

        session()->flash('security_message', __('Session terminated.'));
    }

    public function deleteTrusted(int $id): void
    {
        $trusted = TrustedIp::query()->find($id);
        $ip = $trusted?->ip_address;

        $trusted?->delete();

        session()->flash('security_message', __('Trusted IP :ip removed.', ['ip' => $ip ?? '']));
    }

    public function saveMyIp(): void
    {
        $user = auth()->user();

        if (! $user) {
            return;
        }

        $security = app(SecurityMonitorService::class);
        $ip = $security->resolveClientIp(request());
        $userAgent = (string) request()->userAgent();

        TrustedIp::query()->updateOrCreate(
            [
                'user_id' => $user->getKey(),
                'ip_address' => $ip,
            ],
            [
                'local_ip' => $security->resolveLocalIp(request()),
                'device_id' => $security->resolveDeviceId(request()),
                'device_name' => Str::limit($userAgent, 100) ?: __('My device'),
                'operating_system' => $userAgent,
                'is_active' => true,
                'verified_at' => now(),
            ],
        );

        session()->flash('security_message', __('IP :ip saved as trusted.', ['ip' => $ip]));
    }

    /**
     * @return array<string, mixed>
     */
    public function with(): array
    {
        $query = UserLogin::query()->with('user')->latest('id');

        if ($this->search !== '') {
            $search = $this->search;
            $query->where(function ($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                    ->orWhere('browser', 'like', "%{$search}%")
                    ->orWhere('operating_system', 'like', "%{$search}%")
                    ->orWhere('device_id', 'like', "%{$search}%")
                    ->orWhereHas('user', function ($uq) use ($search) {
                        $uq->where('name', 'like', "%{$search}%")
                            ->orWhere('email', 'like', "%{$search}%");
                    });
            });
        }

        return [
            'logins' => $query->paginate($this->perPage),
            'trustedIps' => TrustedIp::query()->with('user')->latest('id')->get(),
            'onlineCount' => UserLogin::query()->active(5)->count(),
        ];
    }
}; ?>

<div>
    <x-pages::security.layout :heading="__('User Sessions')" :subheading="__('Active sessions, login history, and trusted devices')">
        <!-- Toolbar & Counter -->
        <div class="sec-toolbar">
            <div class="sec-toolbar-group">
                <div class="sec-stat-card" style="padding: 10px 16px; min-width: 140px;">
                    <div class="sec-stat-label" style="margin-bottom: 2px;">{{ __('Online now') }}</div>
                    <div class="sec-stat-value" style="font-size: 20px; color: var(--sec-success); margin-bottom: 0;">
                        {{ number_format($onlineCount) }}
                    </div>
                </div>

                <input
                    type="search"
                    wire:model.live.debounce.300ms="search"
                    placeholder="{{ __('Search user, IP, browser…') }}"
                    class="sec-input"
                    style="min-width: 260px;"
                />
            </div>

            <button type="button" class="sec-btn sec-btn-primary" wire:click="saveMyIp">
                <span>🛡️</span>
                <span>{{ __('Trust this device') }}</span>
            </button>
        </div>

        <!-- Logins Table -->
        <div class="sec-card sec-card-flush">
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('User') }}</th>
                            <th>{{ __('IP') }}</th>
                            <th>{{ __('Device') }}</th>
                            <th>{{ __('Location') }}</th>
                            <th>{{ __('Last activity') }}</th>
                            <th style="text-align: right;">{{ __('Actions') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($logins as $login)
                            <tr>
                                <td>
                                    <div style="font-weight: 600;">{{ $login->user->name ?? __('Deleted user') }}</div>
                                    <div style="font-size: 11px; color: var(--sec-text-muted);">{{ $login->user->email ?? '' }}</div>
                                </td>
                                <td>
                                    <div class="sec-font-mono" style="font-size: 12px; font-weight: 600;">{{ $login->ip_address }}</div>
                                    @if ($login->isOnline())
                                        <span class="sec-badge sec-badge-success" style="margin-top: 4px;">{{ __('Online') }}</span>
                                    @endif
                                </td>
                                <td style="font-size: 12px;">
                                    <div>{{ $login->browser ?: __('Unknown') }}</div>
                                    <div style="font-size: 11px; color: var(--sec-text-muted);">{{ $login->operating_system ?: '' }}</div>
                                </td>
                                <td style="font-size: 12px; color: var(--sec-text-muted);">{{ $login->formattedLocation() }}</td>
                                <td style="font-size: 12px; color: var(--sec-text-muted); white-space: nowrap;">
                                    {{ $login->last_activity_at?->diffForHumans() ?? '-' }}
                                </td>
                                <td style="text-align: right; white-space: nowrap;">
                                    @if ($login->session_id && $login->isOnline())
                                        <button
                                            type="button"
                                            class="sec-btn sec-btn-ghost sec-btn-sm"
                                            wire:click="destroySession('{{ $login->session_id }}')"
                                            wire:confirm="{{ __('Force logout this session?') }}"
                                            title="{{ __('Terminate session') }}"
                                        >
                                            🚪
                                        </button>
                                    @endif
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="deleteLogin({{ $login->id }})"
                                        title="{{ __('Delete history entry') }}"
                                    >
                                        🗑️
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="6" style="text-align: center; color: var(--sec-text-muted); padding: 36px;">
                                    {{ __('No login records found.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            @if ($logins->hasPages())
                <div style="padding: 16px 20px; border-top: 1px solid var(--sec-border-light);">
                    {{ $logins->links() }}
                </div>
            @endif
        </div>

        <!-- Trusted IPs Card -->
        <div class="sec-card sec-card-flush">
            <div class="sec-card-header">
                <h3 class="sec-card-title">{{ __('Trusted IPs') }}</h3>
            </div>
            <div class="sec-table-wrap">
                <table class="sec-table">
                    <thead>
                        <tr>
                            <th>{{ __('IP') }}</th>
                            <th>{{ __('User') }}</th>
                            <th>{{ __('Device') }}</th>
                            <th>{{ __('Verified') }}</th>
                            <th style="text-align: right;">{{ __('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($trustedIps as $trusted)
                            <tr>
                                <td class="sec-font-mono" style="font-size: 12px; font-weight: 600;">{{ $trusted->ip_address }}</td>
                                <td style="font-size: 12px;">{{ $trusted->user->name ?? __('Deleted user') }}</td>
                                <td style="font-size: 12px; color: var(--sec-text-muted);">{{ $trusted->device_name ?: '-' }}</td>
                                <td style="font-size: 12px; color: var(--sec-text-muted); white-space: nowrap;">
                                    {{ $trusted->verified_at?->diffForHumans() ?? '-' }}
                                </td>
                                <td style="text-align: right;">
                                    <button
                                        type="button"
                                        class="sec-btn sec-btn-ghost sec-btn-sm"
                                        wire:click="deleteTrusted({{ $trusted->id }})"
                                        wire:confirm="{{ __('Remove this trusted IP?') }}"
                                        title="{{ __('Remove trusted IP') }}"
                                    >
                                        🗑️
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="5" style="text-align: center; color: var(--sec-text-muted); padding: 24px;">
                                    {{ __('No trusted IPs yet.') }}
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>
    </x-pages::security.layout>
</div>
