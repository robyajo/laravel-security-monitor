# 02. Panduan Instalasi & Migrasi

Halaman ini memandu proses instalasi paket **`robyajo/laravel-security-monitor`** ke dalam aplikasi Laravel Anda.

> 🌟 **Nol Ketergantungan NPM (Zero NPM)**: Paket ini murni PHP Composer library standar seperti paket Spatie. Anda **tidak perlu** menginstal dependensi npm atau menjalankan build tools frontend.

---

## 1. Persyaratan Sistem

Pastikan lingkungan server Anda memenuhi spesifikasi minimum berikut:
- **PHP**: `^8.2`, `^8.3`, atau `^8.4`
- **Laravel**: `^10.0`, `^11.0`, `^12.0`, atau `^13.0`
- **Ekstensi PHP**: `pdo`, `mbstring`, `json`, `filter`, `openssl` (tanpa memerlukan ekstensi `gd` atau `imagick` berkat implementasi pure SVG CAPTCHA).

---

## 2. Pemasangan via Composer

### Menggunakan Packagist (Publik)
Jika paket sudah diterbitkan di Packagist:
```bash
composer require robyajo/laravel-security-monitor
```

### Menggunakan Repositori Lokal / Private Git (Monorepo atau Path)
Jika Anda menggunakan paket ini secara internal sebelum publikasi ke Packagist, tambahkan konfigurasi repositori pada berkas `composer.json` proyek Laravel Anda:

```json
"repositories": [
    {
        "type": "path",
        "url": "../laravel-security-monitor",
        "options": {
            "symlink": true
        }
    }
]
```

Kemudian pasang paket:
```bash
composer require robyajo/laravel-security-monitor:@dev
```

---

## 3. Publikasi Aset Otomatis (`security:install`)

Paket menyediakan perintah Artisan interaktif satu langkah untuk mempublikasikan seluruh berkas konfigurasi, migrasi, dan berkas konfigurasi Nginx:

```bash
php artisan security:install
```

### Opsi Perintah:
| Opsi | Fungsi |
| :--- | :--- |
| `--force` | Menimpa berkas `config/security.php`, migrasi, dan `nginx.conf` yang sudah ada sebelumnya. |
| `--without-nginx` | Melewatkan publikasi berkas `nginx.conf` jika server tidak menggunakan Nginx. |

---

## 4. Publikasi Aset Manual via Vendor Publish

Jika Anda ingin mempublikasikan aset secara bertahap atau terpisah:

### 1. Publikasikan Konfigurasi Saja
```bash
php artisan vendor:publish --tag=security-config
```
Berkas akan ditempatkan di: `config/security.php`.

### 2. Publikasikan Migrasi Saja
```bash
php artisan vendor:publish --tag=security-migrations
```
Berkas migrasi akan disalin ke folder `database/migrations/`.

### 3. Publikasikan Template Nginx WAF Hardened Saja
```bash
php artisan vendor:publish --tag=security-nginx
```
Berkas akan ditempatkan di root proyek: `nginx.conf`.

---

## 5. Menjalankan Migrasi Database

Jalankan perintah migrasi Laravel untuk membuat tabel-tabel pendukung paket:

```bash
php artisan migrate
```

Tabel-tabel yang dibuat secara default:
1. `blocked_ips`: Menyimpan daftar karantina IP dan perangkat aktif/kedaluwarsa beserta hit counter.
2. `security_logs`: Log audit ancaman keamanan, pola yang terdeteksi, bukti payload, dan aksi mitigasi.
3. `login_attempts`: Pelacakan kegagalan login bertingkat (*stepped lockout*) per kombinasi email & IP.
4. `ip_unblock_requests`: Tiket banding pembukaan blokir yang diajukan oleh pengguna publik.
5. `user_logins`: Rekam jejak riwayat login pengguna, detail perangkat/browser, sesi aktif, dan waktu aktivitas terakhir.
6. `trusted_ips`: Daftar alamat IP terpercaya per pengguna untuk otorisasi akses khusus.

---

## 6. Mendaftarkan Trait ke Model User (Standar Spatie)

Buka model pengguna aplikasi Anda (biasanya `app/Models/User.php`) dan sertakan trait `HasSecurityRelations`:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Internal\SecurityMonitor\Concerns\HasSecurityRelations;

class User extends Authenticatable
{
    use HasSecurityRelations;

    // ... sisa model Anda
}
```

Metode relasi Eloquent yang otomatis tersedia:
- `$user->logins()`: Mengambil seluruh riwayat login (`HasMany` ke `UserLogin`).
- `$user->trustedIps()`: Mengambil daftar IP terpercaya milik pengguna (`HasMany` ke `TrustedIp`).
- `$user->securityLogs()`: Mengambil audit ancaman yang diasosiasikan dengan akun ini (`HasMany` ke `SecurityLog`).
- `$user->blockedIps()`: Mengambil daftar entri blokir yang dieksekusi oleh user admin ini (`HasMany` ke `BlockedIp`).
- `$user->resolvedTickets()`: Mengambil daftar tiket banding yang diselesaikan oleh user admin ini (`HasMany` ke `IpUnblockRequest`).

---

## 7. Mendaftarkan Middleware Keamanan ke Core Laravel

Paket menyediakan 4 middleware terisolasi:

| Alias | Kelas Middleware | Peran |
| :--- | :--- | :--- |
| `security.block` | `Internal\SecurityMonitor\Http\Middleware\BlockIpAddress` | Menolak request dari IP/perangkat yang sedang terblokir aktif (HTTP 403). |
| `security.detect`| `Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats` | Menginspeksi payload request terhadap tanda-tanda serangan siber dan mengaktifkan auto-block/instant block. |
| `security.admin` | `Internal\SecurityMonitor\Http\Middleware\EnsureSecurityAdmin` | Memastikan hanya user dengan wewenang admin yang dapat mengakses REST API admin. |
| `security.activity`| `Internal\SecurityMonitor\Http\Middleware\TrackUserActivity` | Memperbarui heartbeat aktivitas login pengguna di database (ter-throttle 45 detik). |

### Pendaftaran pada Laravel 11 / 12 / 13 (`bootstrap/app.php`)

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;
use Internal\SecurityMonitor\Http\Middleware\BlockIpAddress;
use Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats;
use Internal\SecurityMonitor\Http\Middleware\TrackUserActivity;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Pasang di lapisan global
        $middleware->append(BlockIpAddress::class);
        $middleware->append(DetectSecurityThreats::class);

        // Pasang di grup web untuk pelacakan aktivitas user login
        $middleware->web(append: [
            TrackUserActivity::class,
        ]);
    })
    ->create();
```

### Pendaftaran pada Laravel 10 (`app/Http/Kernel.php`)

Buka `app/Http/Kernel.php` dan tambahkan ke array `$middleware`:

```php
protected $middleware = [
    // ...
    \Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class,
    \Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class,
];
```

> **Tips Opsi Otomatis (Zero-Touch)**: Jika Anda mengatur `SECURITY_AUTO_REGISTER_MIDDLEWARE=true` di berkas `.env`, paket akan otomatis menyuntikkan `BlockIpAddress` dan `DetectSecurityThreats` ke Kernel HTTP aplikasi secara otomatis saat booting.
