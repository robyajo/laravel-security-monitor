<?php

use Flux\Flux;
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

        Flux::toast(variant: 'success', text: __('Login history entry deleted.'));
    }

    public function destroySession(string $sessionId): void
    {
        app(UserLoginService::class)->logoutSession($sessionId);

        Flux::toast(variant: 'success', text: __('Session terminated.'));
    }

    public function deleteTrusted(int $id): void
    {
        $trusted = TrustedIp::query()->find($id);
        $ip = $trusted?->ip_address;

        $trusted?->delete();

        Flux::toast(variant: 'success', text: __('Trusted IP :ip removed.', ['ip' => $ip ?? '']));
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

        Flux::toast(variant: 'success', text: __('IP :ip saved as trusted.', ['ip' => $ip]));
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

<div class="flex h-full w-full flex-1 flex-col gap-6">
    <x-pages::security.layout :heading="__('User Sessions')" :subheading="__('Active sessions, login history, and trusted devices')">
        <div class="flex flex-wrap items-end justify-between gap-3">
            <div class="flex flex-wrap items-end gap-3">
                <flux:card class="px-4! py-3!">
                    <flux:text class="text-sm text-zinc-500">{{ __('Online now') }}</flux:text>
                    <flux:heading size="lg" class="text-green-600 dark:text-green-400">{{ number_format($onlineCount) }}</flux:heading>
                </flux:card>

                <flux:input
                    wire:model.live.debounce.300ms="search"
                    icon="magnifying-glass"
                    :placeholder="__('Search user, IP, browser…')"
                    class="w-full sm:w-72"
                />
            </div>

            <flux:button variant="primary" icon="shield-check" wire:click="saveMyIp">
                {{ __('Trust this device') }}
            </flux:button>
        </div>

        <flux:card class="mt-5 p-0!">
            <flux:table :paginate="$logins">
                <flux:table.columns>
                    <flux:table.column>{{ __('User') }}</flux:table.column>
                    <flux:table.column>{{ __('IP') }}</flux:table.column>
                    <flux:table.column>{{ __('Device') }}</flux:table.column>
                    <flux:table.column>{{ __('Location') }}</flux:table.column>
                    <flux:table.column>{{ __('Last activity') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>

                <flux:table.rows>
                    @forelse ($logins as $login)
                        <flux:table.row :key="$login->id">
                            <flux:table.cell class="text-xs">
                                <div class="font-medium">{{ $login->user->name ?? __('Deleted user') }}</div>
                                <div class="text-zinc-500">{{ $login->user->email ?? '' }}</div>
                            </flux:table.cell>
                            <flux:table.cell>
                                <div class="font-mono text-xs">{{ $login->ip_address }}</div>
                                @if ($login->isOnline())
                                    <flux:badge color="green" size="sm" class="mt-0.5">{{ __('Online') }}</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell class="text-xs">
                                <div>{{ $login->browser ?: __('Unknown') }}</div>
                                <div class="text-zinc-500">{{ $login->operating_system ?: '' }}</div>
                            </flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $login->formattedLocation() }}</flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $login->last_activity_at?->diffForHumans() ?? '-' }}</flux:table.cell>
                            <flux:table.cell>
                                <div class="flex items-center justify-end gap-1">
                                    @if ($login->session_id && $login->isOnline())
                                        <flux:button
                                            size="sm"
                                            variant="ghost"
                                            icon="arrow-right-start-on-rectangle"
                                            wire:click="destroySession('{{ $login->session_id }}')"
                                            wire:confirm="{{ __('Force logout this session?') }}"
                                            :title="__('Terminate session')"
                                        />
                                    @endif
                                    <flux:button
                                        size="sm"
                                        variant="ghost"
                                        icon="trash"
                                        wire:click="deleteLogin({{ $login->id }})"
                                        :title="__('Delete history entry')"
                                    />
                                </div>
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="6" class="text-center text-sm text-zinc-500">
                                {{ __('No login records found.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>

        <flux:card class="space-y-3">
            <flux:heading>{{ __('Trusted IPs') }}</flux:heading>

            <flux:table>
                <flux:table.columns>
                    <flux:table.column>{{ __('IP') }}</flux:table.column>
                    <flux:table.column>{{ __('User') }}</flux:table.column>
                    <flux:table.column>{{ __('Device') }}</flux:table.column>
                    <flux:table.column>{{ __('Verified') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                    @forelse ($trustedIps as $trusted)
                        <flux:table.row :key="$trusted->id">
                            <flux:table.cell class="font-mono text-xs">{{ $trusted->ip_address }}</flux:table.cell>
                            <flux:table.cell class="text-xs">{{ $trusted->user->name ?? __('Deleted user') }}</flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $trusted->device_name ?: '-' }}</flux:table.cell>
                            <flux:table.cell class="text-xs text-zinc-500">{{ $trusted->verified_at?->diffForHumans() ?? '-' }}</flux:table.cell>
                            <flux:table.cell>
                                <flux:button
                                    size="sm"
                                    variant="ghost"
                                    icon="trash"
                                    wire:click="deleteTrusted({{ $trusted->id }})"
                                    wire:confirm="{{ __('Remove this trusted IP?') }}"
                                />
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="5" class="text-center text-sm text-zinc-500">
                                {{ __('No trusted IPs yet.') }}
                            </flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </flux:card>
    </x-pages::security.layout>
</div>
