{{--
    Security Monitor — sub-layout dashboard Livewire Starter Kit.

    Dirender sebagai komponen Blade biasa (<x-pages::security.layout>) di dalam
    halaman page-component Livewire. Menyediakan navigasi antar modul keamanan
    plus judul/subjudul halaman.

    Dipublikasikan oleh: php artisan vendor:publish --tag=starterkit-livewire
--}}
@props(['heading' => null, 'subheading' => null])

<div class="flex items-start max-md:flex-col">
    <div class="me-10 w-full pb-4 md:w-[220px]">
        <flux:navlist aria-label="{{ __('Security Monitor') }}">
            <flux:navlist.item :href="route('security.dashboard.overview')" :current="request()->routeIs('security.dashboard.overview')" wire:navigate>
                {{ __('Overview') }}
            </flux:navlist.item>
            <flux:navlist.item :href="route('security.dashboard.logs')" :current="request()->routeIs('security.dashboard.logs')" wire:navigate>
                {{ __('Security Logs') }}
            </flux:navlist.item>
            <flux:navlist.item :href="route('security.dashboard.blocked-ips')" :current="request()->routeIs('security.dashboard.blocked-ips')" wire:navigate>
                {{ __('Blocked IPs') }}
            </flux:navlist.item>
            <flux:navlist.item :href="route('security.dashboard.server')" :current="request()->routeIs('security.dashboard.server')" wire:navigate>
                {{ __('Server Audit') }}
            </flux:navlist.item>
            <flux:navlist.item :href="route('security.dashboard.sessions')" :current="request()->routeIs('security.dashboard.sessions')" wire:navigate>
                {{ __('Sessions') }}
            </flux:navlist.item>
            <flux:navlist.item :href="route('security.dashboard.tickets')" :current="request()->routeIs('security.dashboard.tickets')" wire:navigate>
                {{ __('Appeals') }}
            </flux:navlist.item>
        </flux:navlist>
    </div>

    <flux:separator class="md:hidden" />

    <div class="flex-1 self-stretch max-md:pt-6">
        <flux:heading>{{ $heading ?? '' }}</flux:heading>
        <flux:subheading>{{ $subheading ?? '' }}</flux:subheading>

        <div class="mt-5 w-full">
            {{ $slot }}
        </div>
    </div>
</div>
