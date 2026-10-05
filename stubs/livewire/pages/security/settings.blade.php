<?php

use Internal\SecurityMonitor\Services\SecurityMonitorService;
use Livewire\Attributes\Title;
use Livewire\Component;

new #[Title('Security Settings')] class extends Component {
    public string $auto_block_scope = 'device';
    public string $instant_block_scope = 'device';
    public bool $auto_block_enabled = true;
    public int $auto_block_threshold = 3;
    public int $auto_block_window = 10;
    public int $auto_block_duration = 24;
    public bool $instant_block_enabled = true;
    public int $instant_block_duration = 720;
    public bool $block_enforcement = true;

    public bool $saved = false;

    public function mount(SecurityMonitorService $security): void
    {
        $settings = $security->getSettings();

        $this->auto_block_scope = (string) ($settings['auto_block_scope'] ?? 'device');
        $this->instant_block_scope = (string) ($settings['instant_block_scope'] ?? 'device');
        $this->auto_block_enabled = (bool) ($settings['auto_block_enabled'] ?? true);
        $this->auto_block_threshold = (int) ($settings['auto_block_threshold'] ?? 3);
        $this->auto_block_window = (int) ($settings['auto_block_window'] ?? 10);
        $this->auto_block_duration = (int) ($settings['auto_block_duration'] ?? 24);
        $this->instant_block_enabled = (bool) ($settings['instant_block_enabled'] ?? true);
        $this->instant_block_duration = (int) ($settings['instant_block_duration'] ?? 720);
        $this->block_enforcement = (bool) ($settings['block_enforcement'] ?? true);
    }

    public function save(SecurityMonitorService $security): void
    {
        $this->validate([
            'auto_block_scope' => ['required', 'string', 'in:device,ip'],
            'instant_block_scope' => ['required', 'string', 'in:device,ip'],
            'auto_block_enabled' => ['boolean'],
            'auto_block_threshold' => ['required', 'integer', 'min:1', 'max:100'],
            'auto_block_window' => ['required', 'integer', 'min:1', 'max:1440'],
            'auto_block_duration' => ['required', 'integer', 'min:0', 'max:8760'],
            'instant_block_enabled' => ['boolean'],
            'instant_block_duration' => ['required', 'integer', 'min:0', 'max:8760'],
            'block_enforcement' => ['boolean'],
        ]);

        $security->updateSettings([
            'auto_block_scope' => $this->auto_block_scope,
            'instant_block_scope' => $this->instant_block_scope,
            'auto_block_enabled' => $this->auto_block_enabled,
            'auto_block_threshold' => $this->auto_block_threshold,
            'auto_block_window' => $this->auto_block_window,
            'auto_block_duration' => $this->auto_block_duration,
            'instant_block_enabled' => $this->instant_block_enabled,
            'instant_block_duration' => $this->instant_block_duration,
            'block_enforcement' => $this->block_enforcement,
        ]);

        $this->saved = true;
        session()->flash('security_message', __('Pengaturan keamanan berhasil disimpan dan langsung diterapkan.'));
    }
}; ?>

<div>
    <style>
        .sec-scope-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
        }
        .sec-scope-box {
            cursor: pointer;
            border: 2px solid var(--sec-border);
            border-radius: var(--sec-radius);
            padding: 18px;
            background: var(--sec-card);
            display: flex;
            flex-direction: column;
            gap: 10px;
            transition: all 0.2s ease-in-out;
        }
        .sec-scope-box:hover {
            border-color: var(--sec-border-light);
            background: var(--sec-card-hover);
        }
        .sec-scope-box.active-primary {
            border-color: var(--sec-primary);
            background: rgba(59, 130, 246, 0.08);
        }
        .sec-scope-box.active-warning {
            border-color: var(--sec-warning);
            background: rgba(245, 158, 11, 0.08);
        }
        .sec-scope-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .sec-scope-title-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .sec-scope-title {
            font-weight: 700;
            font-size: 15px;
            color: var(--sec-text);
        }
        .sec-scope-desc {
            font-size: 13px;
            color: var(--sec-text-muted);
            line-height: 1.5;
            margin: 0;
        }
        .sec-param-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--sec-border);
        }
    </style>

    <x-pages::security.layout :heading="__('Security Settings')" :subheading="__('Konfigurasi lingkup isolasi pemblokiran otomatis (IP router vs Perangkat), ambang batas ancaman, dan kebijakan karantina')">

        @if ($saved)
            <div class="sec-alert sec-alert-success" style="margin-bottom: 24px;">
                <span>✅ {{ __('Pengaturan keamanan berhasil disimpan dan langsung diterapkan!') }}</span>
            </div>
        @endif

        <form wire:submit.prevent="save" style="display: flex; flex-direction: column; gap: 24px;">

            <!-- 1. Lingkup Pemblokiran Otomatis (Auto Block Scope) -->
            <div class="sec-card">
                <div class="sec-card-header">
                    <div>
                        <h2 class="sec-card-title">🎯 {{ __('Lingkup Pemblokiran Otomatis (Auto Block Scope)') }}</h2>
                        <p class="sec-card-desc">{{ __('Pilih apakah pemblokiran otomatis saat mencapai ambang batas hanya mengisolasi perangkat penyerang atau seluruh IP publik router.') }}</p>
                    </div>
                </div>

                <div class="sec-card-body sec-scope-grid">
                    <!-- Option: Device -->
                    <label class="sec-scope-box {{ $auto_block_scope === 'device' ? 'active-primary' : '' }}">
                        <div class="sec-scope-header">
                            <div class="sec-scope-title-wrap">
                                <input type="radio" wire:model.live="auto_block_scope" value="device" style="accent-color: var(--sec-primary); width: 18px; height: 18px;">
                                <span class="sec-scope-title">📱 {{ __('Isolasi Perangkat Saja') }}</span>
                            </div>
                            <span class="sec-badge sec-badge-success">{{ __('Default / Rekomendasi') }}</span>
                        </div>
                        <p class="sec-scope-desc">
                            {{ __('Hanya memblokir perangkat spesifik penyerang berdasarkan Device ID / Fingerprint / LAN IP. Pengguna lain atau rekan kantor dalam satu jaringan WiFi / IP publik yang sama TETAP AMAN dan TIDAK IKUT TERBLOKIR.') }}
                        </p>
                    </label>

                    <!-- Option: IP -->
                    <label class="sec-scope-box {{ $auto_block_scope === 'ip' ? 'active-warning' : '' }}">
                        <div class="sec-scope-header">
                            <div class="sec-scope-title-wrap">
                                <input type="radio" wire:model.live="auto_block_scope" value="ip" style="accent-color: var(--sec-warning); width: 18px; height: 18px;">
                                <span class="sec-scope-title">🌐 {{ __('Seluruh IP Router Publik') }}</span>
                            </div>
                            <span class="sec-badge sec-badge-high">{{ __('Hati-hati') }}</span>
                        </div>
                        <p class="sec-scope-desc">
                            {{ __('Memblokir seluruh alamat IP router publik. PERINGATAN: Semua pengguna lain, tamu, atau rekan kerja yang menggunakan koneksi WiFi/NAT router yang sama akan otomatis ikut terblokir jika satu perangkat terdeteksi.') }}
                        </p>
                    </label>
                </div>
            </div>

            <!-- 2. Lingkup Pemblokiran Instan (Instant Block Scope) -->
            <div class="sec-card">
                <div class="sec-card-header">
                    <div>
                        <h2 class="sec-card-title">⚡ {{ __('Lingkup Pemblokiran Instan (Zero Tolerance Scope)') }}</h2>
                        <p class="sec-card-desc">{{ __('Lingkup isolasi untuk serangan berbahaya yang memicu blokir instan pada percobaan pertama (upload webshell, path traversal /etc/passwd, probe .env/.git).') }}</p>
                    </div>
                </div>

                <div class="sec-card-body sec-scope-grid">
                    <!-- Option: Device -->
                    <label class="sec-scope-box {{ $instant_block_scope === 'device' ? 'active-primary' : '' }}">
                        <div class="sec-scope-header">
                            <div class="sec-scope-title-wrap">
                                <input type="radio" wire:model.live="instant_block_scope" value="device" style="accent-color: var(--sec-primary); width: 18px; height: 18px;">
                                <span class="sec-scope-title">📱 {{ __('Isolasi Perangkat Saja') }}</span>
                            </div>
                            <span class="sec-badge sec-badge-success">{{ __('Default / Rekomendasi') }}</span>
                        </div>
                        <p class="sec-scope-desc">
                            {{ __('Mengisolasi perangkat pelaku serangan fatal tanpa memutus koneksi pengguna umum lainnya di WiFi yang sama.') }}
                        </p>
                    </label>

                    <!-- Option: IP -->
                    <label class="sec-scope-box {{ $instant_block_scope === 'ip' ? 'active-warning' : '' }}">
                        <div class="sec-scope-header">
                            <div class="sec-scope-title-wrap">
                                <input type="radio" wire:model.live="instant_block_scope" value="ip" style="accent-color: var(--sec-warning); width: 18px; height: 18px;">
                                <span class="sec-scope-title">🌐 {{ __('Seluruh IP Router Publik') }}</span>
                            </div>
                            <span class="sec-badge sec-badge-high">{{ __('Ketat') }}</span>
                        </div>
                        <p class="sec-scope-desc">
                            {{ __('Blokir total seluruh IP publik. Cocok jika server berada di jaringan privat atau tidak melayani pengguna umum dari jaringan NAT/WiFi publik.') }}
                        </p>
                    </label>
                </div>
            </div>

            <!-- 3. Parameter Pemblokiran Otomatis -->
            <div class="sec-card">
                <div class="sec-card-header">
                    <div>
                        <h2 class="sec-card-title">⏱️ {{ __('Parameter Ambang Batas Otomatis (Auto Block Parameters)') }}</h2>
                        <p class="sec-card-desc">{{ __('Aturan ambang batas jumlah pelanggaran sebelum tindakan karantina dijalankan.') }}</p>
                    </div>
                </div>

                <div class="sec-card-body" style="display: flex; flex-direction: column; gap: 18px;">
                    <div class="sec-param-row">
                        <div>
                            <div style="font-weight: 600; color: var(--sec-text);">{{ __('Aktifkan Pemblokiran Otomatis') }}</div>
                            <div style="font-size: 13px; color: var(--sec-text-muted);">{{ __('Secara otomatis memblokir pelanggar yang melewati ambang batas ancaman.') }}</div>
                        </div>
                        <input type="checkbox" wire:model="auto_block_enabled" style="width: 20px; height: 20px; accent-color: var(--sec-primary);">
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                        <div>
                            <label class="sec-label" style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; color: var(--sec-text);">
                                {{ __('Ambang Batas Pelanggaran (Threshold)') }}
                            </label>
                            <input type="number" wire:model="auto_block_threshold" min="1" max="100" class="sec-input" style="width: 100%;">
                            <span style="font-size: 12px; color: var(--sec-text-subtle);">{{ __('Jumlah pelanggaran (default: 3 kali)') }}</span>
                        </div>

                        <div>
                            <label class="sec-label" style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; color: var(--sec-text);">
                                {{ __('Jendela Waktu Evaluasi (Menit)') }}
                            </label>
                            <input type="number" wire:model="auto_block_window" min="1" max="1440" class="sec-input" style="width: 100%;">
                            <span style="font-size: 12px; color: var(--sec-text-subtle);">{{ __('Jendela akumulasi log (default: 10 menit)') }}</span>
                        </div>

                        <div>
                            <label class="sec-label" style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; color: var(--sec-text);">
                                {{ __('Durasi Masa Blokir (Jam)') }}
                            </label>
                            <input type="number" wire:model="auto_block_duration" min="0" max="8760" class="sec-input" style="width: 100%;">
                            <span style="font-size: 12px; color: var(--sec-text-subtle);">{{ __('Lama masa karantina (default: 24 jam, 0 = permanen)') }}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 4. Parameter Pemblokiran Instan & Penegakan -->
            <div class="sec-card">
                <div class="sec-card-header">
                    <div>
                        <h2 class="sec-card-title">🛡️ {{ __('Penegakan Blokir & Durasi Instan') }}</h2>
                        <p class="sec-card-desc">{{ __('Pengaturan penegakan HTTP 403 Forbidden dan masa karantina zero-tolerance.') }}</p>
                    </div>
                </div>

                <div class="sec-card-body" style="display: flex; flex-direction: column; gap: 18px;">
                    <div class="sec-param-row">
                        <div>
                            <div style="font-weight: 600; color: var(--sec-text);">{{ __('Penegakan Blokir (Block Enforcement)') }}</div>
                            <div style="font-size: 13px; color: var(--sec-text-muted);">{{ __('Tolak permintaan klien yang terblokir dengan HTTP 403 Forbidden. Jika dimatikan, pelanggaran tetap dicatat tapi tidak ada permintaan yang ditolak.') }}</div>
                        </div>
                        <input type="checkbox" wire:model="block_enforcement" style="width: 20px; height: 20px; accent-color: var(--sec-primary);">
                    </div>

                    <div class="sec-param-row">
                        <div>
                            <div style="font-weight: 600; color: var(--sec-text);">{{ __('Aktifkan Pemblokiran Instan (Zero Tolerance)') }}</div>
                            <div style="font-size: 13px; color: var(--sec-text-muted);">{{ __('Langsung blokir penyerang pada percobaan pertama serangan fatal.') }}</div>
                        </div>
                        <input type="checkbox" wire:model="instant_block_enabled" style="width: 20px; height: 20px; accent-color: var(--sec-primary);">
                    </div>

                    <div style="max-width: 320px;">
                        <label class="sec-label" style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; color: var(--sec-text);">
                            {{ __('Durasi Masa Blokir Instan (Jam)') }}
                        </label>
                        <input type="number" wire:model="instant_block_duration" min="0" max="8760" class="sec-input" style="width: 100%;">
                        <span style="font-size: 12px; color: var(--sec-text-subtle);">{{ __('Default: 720 jam (30 hari). 0 = permanen.') }}</span>
                    </div>
                </div>
            </div>

            <!-- Submit Button Bar -->
            <div style="display: flex; justify-content: flex-end; align-items: center; gap: 12px; padding: 16px 0;">
                <button type="submit" class="sec-btn sec-btn-primary" style="padding: 10px 24px; font-size: 14px; font-weight: 600; cursor: pointer;">
                    <span wire:loading.remove wire:target="save">💾 {{ __('Simpan Pengaturan') }}</span>
                    <span wire:loading wire:target="save">⏳ {{ __('Menyimpan...') }}</span>
                </button>
            </div>

        </form>
    </x-pages::security.layout>
</div>
