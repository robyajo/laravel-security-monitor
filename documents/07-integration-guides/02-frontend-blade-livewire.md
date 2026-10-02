# 02. Integrasi Frontend Blade & Livewire

Jika aplikasi host Anda menggunakan template berbasis Blade atau Livewire, integrasi dengan **`robyajo/laravel-security-monitor`** sangat cepat dan intuitif.

---

## 1. Menyesuaikan Halaman Tampilan Blokir (`errors.blocked`)

Jika request bukan panggilan JSON API, middleware `BlockIpAddress` secara otomatis memeriksa apakah berkas view Blade `errors.blocked` tersedia di aplikasi Anda (`resources/views/errors/blocked.blade.php`).

Jika ada, paket akan me-render view tersebut dengan meneruskan variabel:

- `$ip`: Alamat IP klien yang diblokir.
- `$deviceId`: Fingerprint perangkat klien (jika ada).
- `$localIp`: IP lokal klien.
- `$reason`: Alasan pemblokiran (nama aturan atau catatan admin).
- `$message`: Pesan deskriptif.
- `$referenceId`: ID referensi unik (misal: `SEC-9A8B7C6D`).
- `$supportEmail`: Alamat email bantuan dari konfigurasi.

### Contoh Template Blade Cantik: `resources/views/errors/blocked.blade.php`

```blade
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>403 - Akses Ditolak | Sistem Keamanan</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
        .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; max-width: 520px; width: 100%; padding: 32px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
        .badge { display: inline-block; background: #ef4444; color: #fff; font-size: 12px; font-weight: bold; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase; margin-bottom: 16px; }
        h1 { font-size: 22px; margin: 0 0 12px 0; color: #f1f5f9; }
        p { font-size: 14px; line-height: 1.6; color: #94a3b8; margin: 0 0 20px 0; }
        .meta-box { background: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-family: monospace; font-size: 13px; }
        .meta-row { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .meta-row:last-child { margin-bottom: 0; }
        .meta-label { color: #64748b; }
        .meta-value { color: #38bdf8; font-weight: bold; }
        .btn { display: block; width: 100%; text-align: center; background: #2563eb; color: #fff; text-decoration: none; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 14px; transition: background 0.2s; }
        .btn:hover { background: #1d4ed8; }
        .footer { font-size: 12px; text-align: center; color: #64748b; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Akses Ditolak (403)</span>
        <h1>Perlindungan Keamanan Aktif</h1>
        <p>{{ $message }}</p>

        <div class="meta-box">
            <div class="meta-row">
                <span class="meta-label">ID Referensi:</span>
                <span class="meta-value">{{ $referenceId }}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Alamat IP:</span>
                <span class="meta-value">{{ $ip }}</span>
            </div>
            <div class="meta-row">
                <span class="meta-label">Indikasi:</span>
                <span class="meta-value" style="color: #f87171">{{ $reason }}</span>
            </div>
        </div>

        <a href="mailto:{{ $supportEmail }}?subject=Buka%20Blokir%20{{ $referenceId }}" class="btn">
            Hubungi Tim Keamanan IT
        </a>

        <div class="footer">
            Pusat Keamanan Siber &bullet; {{ config('app.name') }}
        </div>
    </div>
</body>
</html>
```

---

## 2. Dashboard Monitoring Livewire Starter Kit Siap Pakai

Jika aplikasi host Anda dibangun di atas **Laravel Livewire Starter Kit** (Livewire + Flux UI), Anda tidak perlu membangun panel monitoring dari nol. Paket menyediakan enam halaman Livewire siap pakai yang dapat dipublikasikan dengan satu perintah:

```bash
php artisan vendor:publish --tag=starterkit-livewire
```

Perintah tersebut menyalin berkas berikut ke aplikasi Anda:

| Berkas yang Dipublikasikan                             | Deskripsi                                                   |
| :----------------------------------------------------- | :---------------------------------------------------------- |
| `resources/views/pages/security/overview.blade.php`    | Statistik, tren serangan, dan top attacker.                 |
| `resources/views/pages/security/logs.blade.php`        | Tabel log keamanan dengan filter dan aksi bersihkan/hapus.  |
| `resources/views/pages/security/blocked-ips.blade.php` | Manajemen karantina IP (blokir manual, toggle, unblock).    |
| `resources/views/pages/security/server.blade.php`      | Audit integritas, pemindai webshell, baseline, dan lockout. |
| `resources/views/pages/security/sessions.blade.php`    | Sesi pengguna aktif, riwayat login, dan IP terpercaya.      |
| `resources/views/pages/security/tickets.blade.php`     | Review tiket banding (approve/reject + auto-unblock).       |
| `resources/views/pages/security/layout.blade.php`      | Sub-layout navigasi antar modul keamanan.                   |

Setelah dipublikasikan, aktifkan dashboard melalui `.env`:

```dotenv
SECURITY_DASHBOARD_ENABLED=true
SECURITY_DASHBOARD_PREFIX=security
```

Panel dapat diakses pada `/security`. Halaman-halaman tersebut merupakan **single-file Livewire component** (`pages::security.*`) sehingga otomatis memakai layout starter kit (`layouts::app`).

> 🔒 **Wajib Login**: Rute dashboard memakai middleware `web` + `auth`, dan secara bawaan juga `security.admin` (Gate `manage-security-monitor`). Untuk mengizinkan semua pengguna yang sudah login (tanpa syarat admin), kosongkan `security.dashboard.admin_middleware` pada `config/security.php`.

### Menambahkan Tautan di Sidebar Starter Kit

Untuk memunculkan tautan ke panel, tambahkan item berikut pada `resources/views/layouts/app/sidebar.blade.php` di dalam `<flux:sidebar.nav>`:

```blade
<flux:sidebar.item icon="shield-check" :href="route('security.dashboard.overview')" :current="request()->routeIs('security.dashboard.*')" wire:navigate>
    {{ __('Security Monitor') }}
</flux:sidebar.item>
```
