# Laravel Security Monitor (Bulwark)

[![Tests](https://img.shields.io/badge/tests-62%20passed%20(261%20assertions)-brightgreen.svg)]()
[![PHP Version](https://img.shields.io/badge/php-%5E8.2%20%7C%20%5E8.3%20%7C%20%5E8.4-blue.svg)]()
[![Laravel Version](https://img.shields.io/badge/laravel-%5E10.0%20%7C%20%5E11.0%20%7C%20%5E12.0%20%7C%20%5E13.0-red.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Laravel Security Monitor** adalah paket keamanan komprehensif (*Self-Hosted WAF & Threat Engine*) berbasis **Headless REST API** untuk ekosistem Laravel. Paket ini dirancang khusus untuk memproteksi aplikasi web internal dari serangan siber tingkat lanjut, injeksi payload pentest, eksploitasi webshell, dan brute force tanpa mengikat aplikasi ke template frontend tertentu (React, Vue, Inertia, Blade, Livewire, ataupun Mobile Apps).

---

## 🌟 Fitur Utama

1. **Self-Hosted WAF & Zero-Tolerance Threat Detection**:
   - Deteksi instan tanpa batas ambang (*zero-tolerance*) untuk null-byte upload (`.php%00.jpg`), ekstensi ganda (`.php.jpg`), path traversal (`../../../public/`), probe file sensitif (`.htaccess`, `.env`, `.git`), dan SSTI canary (`{{7*7}}`).
   - Deteksi komprehensif untuk SQL Injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI), Command Injection, dan Scanner User-Agents.
   - Pola regex yang diperketat dan kebal terhadap serangan ReDoS (*Regular Expression Denial of Service*).

2. **Isolasi Perangkat Granular (Device-Level Quarantine)**:
   - Dukungan isolasi di tingkat perangkat menggunakan `device_id` (WebRTC/fingerprint) dan `local_ip`.
   - Memastikan perangkat penyerang terblokir tanpa mengganggu pengguna sah lain yang berbagi alamat IP publik yang sama (seperti kantor atau router Wi-Fi publik).

3. **Tiket Banding & Permohonan Buka Blokir (Appeal Tickets)**:
   - Endpoint publik REST API bagi pengguna yang terblokir untuk mengajukan tiket permohonan buka blokir beserta status pelacakannya.
   - Antarmuka persetujuan admin yang secara otomatis mencabut karantina IP/perangkat dan memasukkannya ke whitelist.

4. **Multi-Tier Stepped Login Lockout**:
   - Sistem pencegahan *credential stuffing* & *brute force* berjenjang (1 menit, 5 menit, 15 menit, 1 jam, hingga 24 jam).
   - Pencatatan otomatis riwayat kegagalan otentikasi ke log audit keamanan.

5. **Pure SVG CAPTCHA (Zero Dependency)**:
   - Generator CAPTCHA berbasis matriks vektor SVG murni tanpa memerlukan ekstensi PHP GD atau Imagick.
   - Token tantangan sekali pakai (*stateless one-time challenge*) yang aman secara kriptografis.

6. **Server Integrity & Webshell Scanner**:
   - Pembuatan dan verifikasi baseline hash SHA-256 untuk berkas-berkas aplikasi inti.
   - Pemindaian berkas mencurigakan / webshell (ekstensi ganda, skrip di direktori publik/upload, polyglot media).
   - Fitur penghapusan berkas berbahaya yang aman dengan proteksi path traversal dan berkas sistem vital.
   - Audit konfigurasi keamanan server (`APP_DEBUG`, secure session cookie, Fortify 2FA).

7. **Streaming Access Log Scanner**:
   - Pemindai berkas log mentah Apache / Nginx secara *streaming* berdaya hemat memori untuk menangkap penyerang yang ditolak oleh web server sebelum request mencapai proses PHP Laravel.

8. **Headless & Arsitektur Terkopel Longgar**:
   - 100% REST API JSON murni.
   - Model `User` dan nama tabel database sepenuhnya dapat dikonfigurasi melalui `config/security.php`.
   - Trait `HasSecurityRelations` untuk kemudahan integrasi relasi Eloquent.

---

## 📋 Persyaratan Sistem

- PHP: `^8.2`, `^8.3`, atau `^8.4`
- Laravel: `^10.0`, `^11.0`, `^12.0`, atau `^13.0`

---

## 🚀 Instalasi

### 1. Pasang Paket via Composer

Tambahkan repositori paket internal pada `composer.json` proyek Anda, lalu jalankan:

```bash
composer require internal/laravel-security-monitor
```

### 2. Publikasikan Konfigurasi & Migrasi

Publikasikan berkas konfigurasi `config/security.php`:

```bash
php artisan vendor:publish --tag=security-config
```

Publikasikan berkas migrasi database:

```bash
php artisan vendor:publish --tag=security-migrations
```

Jalankan migrasi database:

```bash
php artisan migrate
```

---

## ⚙️ Konfigurasi & Integrasi

### 1. Tambahkan Trait ke Model User

Buka model `App\Models\User.php` dan tambahkan trait `HasSecurityRelations`:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Internal\SecurityMonitor\Concerns\HasSecurityRelations;

class User extends Authenticatable
{
    use HasSecurityRelations;

    // ...
}
```

Trait ini menyediakan relasi Eloquent bawaan:
- `$user->logins()`: Riwayat login pengguna (`UserLogin`).
- `$user->trustedIps()`: Daftar IP terpercaya pengguna (`TrustedIp`).
- `$user->securityLogs()`: Riwayat event keamanan pengguna (`SecurityLog`).
- `$user->blockedIps()`: Riwayat pemblokiran yang dilakukan oleh pengguna (`BlockedIp`).
- `$user->resolvedTickets()`: Tiket permohonan buka blokir yang diselesaikan admin (`IpUnblockRequest`).

### 2. Daftarkan Middleware

#### Pada Laravel 11 / 12 / 13 (`bootstrap/app.php`)

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Daftarkan penegakan WAF dan blokir IP secara global
        $middleware->append(\Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class);
        $middleware->append(\Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class);

        // Lacak aktivitas sesi pengguna di grup web
        $middleware->web(append: [
            \Internal\SecurityMonitor\Http\Middleware\TrackUserActivity::class,
        ]);

        // Alias middleware keamanan
        $middleware->alias([
            'security.block' => \Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class,
            'security.detect' => \Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class,
            'security.admin' => \Internal\SecurityMonitor\Http\Middleware\EnsureSecurityAdmin::class,
            'security.activity' => \Internal\SecurityMonitor\Http\Middleware\TrackUserActivity::class,
        ]);
    })
    ->create();
```

#### Pada Laravel 10 (`app/Http/Kernel.php`)

```php
protected $middleware = [
    // ...
    \Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class,
    \Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class,
];

protected $middlewareGroups = [
    'web' => [
        // ...
        \Internal\SecurityMonitor\Http\Middleware\TrackUserActivity::class,
    ],
];

protected $middlewareAliases = [
    'security.block' => \Internal\SecurityMonitor\Http\Middleware\BlockIpAddress::class,
    'security.detect' => \Internal\SecurityMonitor\Http\Middleware\DetectSecurityThreats::class,
    'security.admin' => \Internal\SecurityMonitor\Http\Middleware\EnsureSecurityAdmin::class,
    'security.activity' => \Internal\SecurityMonitor\Http\Middleware\TrackUserActivity::class,
];
```

---

## 📡 Headless REST API Reference

Semua rute REST API didaftarkan secara default dengan prefix `/api/security` (dapat diubah melalui `config('security.routes.prefix')`).

### 1. Endpoint Publik

| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/captcha` | Menghasilkan SVG CAPTCHA dan mengembalikan gambar vector langsung beserta `X-Captcha-Token` |
| `POST` | `/api/security/captcha/verify` | Memvalidasi jawaban CAPTCHA (`phrase` & `token`) |
| `POST` | `/api/security/unblock-tickets/submit` | Mengirim permohonan banding pembukaan blokir IP/perangkat |
| `GET` | `/api/security/unblock-tickets/check/{ticketNumber}` | Memeriksa status tiket permohonan banding |

#### Contoh Payload Pengajuan Tiket:
```json
POST /api/security/unblock-tickets/submit
{
  "name": "Budi Santoso",
  "email": "budi@example.com",
  "phone": "081234567890",
  "reason": "Alamat IP kantor saya terblokir saat mengakses dashboard.",
  "device_id": "client-uuid-1234",
  "local_ip": "192.168.1.50"
}
```

### 2. Endpoint Pengguna Terautentikasi (`auth`)

| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `POST` | `/api/security/trusted-ips/save-my-ip` | Menyimpan alamat IP saat ini sebagai IP terpercaya pengguna |

### 3. Endpoint Manajemen Admin (`auth` + `security.admin`)

#### Log Keamanan & Analitik Serangan
| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/logs` | Mendapatkan log ancaman (paginasi, filter event/level/tanggal, statistik, tren 24 jam/7 hari) |
| `DELETE` | `/api/security/logs/clear` | Mengosongkan seluruh log audit keamanan |
| `DELETE` | `/api/security/logs/{id}` | Menghapus satu entri log keamanan tertentu |

#### Daftar Blokir IP & Perangkat
| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/blocked-ips` | Mendapatkan daftar IP yang diblokir (aktif & kedaluwarsa) |
| `POST` | `/api/security/blocked-ips` | Memblokir IP atau perangkat secara manual |
| `GET` | `/api/security/blocked-ips/{id}` | Melihat detail data pemblokiran |
| `PATCH` | `/api/security/blocked-ips/{id}/toggle` | Mengaktifkan / menonaktifkan status blokir |
| `DELETE` | `/api/security/blocked-ips/{id}` | Mencabut blokir dan menghapus entri |

#### Audit Server & Integritas Berkas
| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/server` | Laporan komprehensif audit keamanan server & integritas berkas |
| `POST` | `/api/security/server/baseline` | Membuat baseline hash SHA-256 berkas aplikasi baru |
| `DELETE` | `/api/security/server/baseline` | Menghapus baseline integritas |
| `DELETE` | `/api/security/server/suspicious-files` | Menghapus berkas mencurigakan/webshell yang terdeteksi |
| `DELETE` | `/api/security/lockouts/{id}` | Membuka kunci akun yang terkena lockout login berjenjang |

#### Sesi Pengguna & IP Terpercaya
| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/user-sessions` | Riwayat sesi login seluruh pengguna |
| `GET` | `/api/security/user-sessions/realtime` | Daftar pengguna yang aktif secara real-time |
| `DELETE` | `/api/security/user-sessions/{id}` | Menghapus log sesi pengguna |
| `DELETE` | `/api/security/user-sessions/session/{sessionId}` | Memutus sesi pengguna tertentu (*force logout*) |
| `DELETE` | `/api/security/trusted-ips/{id}` | Menghapus IP dari daftar terpercaya |

#### Pengelolaan Tiket Banding
| Metode | URI | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/security/unblock-tickets` | Daftar seluruh tiket permohonan banding |
| `POST` | `/api/security/unblock-tickets/{id}/respond` | Menyetujui atau menolak tiket (buka blokir & whitelist) |
| `DELETE` | `/api/security/unblock-tickets/{id}` | Menghapus arsip tiket |

---

## 🛡️ Validation Rules Bawaan

Paket menyediakan aturan validasi siap pakai untuk request form aplikasi Anda:

### 1. `SafeImageFile`
Memvalidasi unggahan gambar dan mencegah serangan *polyglot image* (gambar JPEG/PNG sah yang diinjeksi kode `<?php`), ekstensi ganda berbahaya, dan SVG bereksekusi JavaScript/XSS:

```php
use Internal\SecurityMonitor\Rules\SafeImageFile;

$request->validate([
    'avatar' => ['required', 'file', new SafeImageFile(maxKilobytes: 2048)],
]);
```

### 2. `SafeAssetPath`
Memvalidasi string path aset gambar/ikon agar terbebas dari path traversal, probe direktori sensitif, dan file `.htaccess`:

```php
use Internal\SecurityMonitor\Rules\SafeAssetPath;

$request->validate([
    'icon_path' => ['required', 'string', new SafeAssetPath],
]);
```

### 3. `ValidCaptcha`
Memvalidasi verifikasi CAPTCHA SVG tanpa dependensi:

```php
use Internal\SecurityMonitor\Rules\ValidCaptcha;

$request->validate([
    'captcha' => ['required', new ValidCaptcha],
]);
```

---

## 💻 Perintah Artisan CLI

Paket ini menyertakan perintah Artisan lengkap untuk otomasi di server produksi:

### 1. Pemindaian Log Akses Web Server (`security:scan-logs`)
Memindai berkas log Apache atau Nginx, mendeteksi pola serangan, dan memblokir IP penyerang secara otomatis:

```bash
# Pratinjau temuan tanpa memodifikasi database (dry-run)
php artisan security:scan-logs --file=/var/log/nginx/access.log --dry-run

# Pindai, impor ke log keamanan, dan blokir IP penyerang zero-tolerance
php artisan security:scan-logs --file=/var/log/nginx/access.log --import --block
```

### 2. Manajemen Baseline Integritas Berkas (`security:baseline`)
```bash
# Menampilkan status verifikasi integritas berkas
php artisan security:baseline

# Membuat baseline baru
php artisan security:baseline --create

# Menghapus baseline
php artisan security:baseline --destroy
```

### 3. Membuka Blokir IP (`security:unblock-ip`)
```bash
php artisan security:unblock-ip 198.51.100.50
```

### 4. Pembersihan Log Kedaluwarsa (`security:prune-logs`)
```bash
# Menghapus log lebih tua dari durasi retensi terkonfigurasi (default: 90 hari)
php artisan security:prune-logs

# Menghapus log lebih tua dari 30 hari
php artisan security:prune-logs --days=30
```

### 5. Pembersihan Data Residu Pentest (`security:purge-injected-data`)
Mendeteksi dan menghapus payload injeksi sisa pengujian keamanan (seperti `{{7*7}}`, `.htaccess`, path traversal) dari tabel aplikasi:

```bash
# Mode simulasi (hanya mendeteksi data tercemar)
php artisan security:purge-injected-data

# Hapus data yang terindikasi
php artisan security:purge-injected-data --force
```

---

## 🧪 Menjalankan Pengujian (Testing)

Paket ini dilengkapi dengan pengujian menyeluruh menggunakan **Pest PHP** dan **Orchestra Testbench**:

```bash
./vendor/bin/pest
```

Hasil uji: **62 passed (261 assertions)** mencakup:
- `DetectorTuningTest`: Verifikasi akurasi pola deteksi dan ketahanan ReDoS.
- `InstantBlockTest`: Verifikasi zero-tolerance instant blocking pada percobaan pertama.
- `PolyglotImageTest`: Uji penolakan polyglot image ber-tag PHP dan SVG XSS.
- `SecurityAdminApiTest`: Pengujian lengkap otorisasi, mutasi data, dan respons JSON REST API.
- `DeviceLevelBlockingTest`: Uji isolasi perangkat pada IP publik bersama.
- `ServerSecurityTest`: Audit keamanan lingkungan, baseline SHA-256, dan webshell sanitizer.
- `AccessLogScanTest`: Uji parser streaming log akses web server.
- `SecurityMonitorTest`: Uji ambang batas auto-blocking dan rotasi log.

---

## 📄 Lisensi

Paket ini dilisensikan di bawah lisensi terbuka [MIT](LICENSE).
