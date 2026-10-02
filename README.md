# Laravel Security Monitor (Bulwark)

[![Run Tests](https://github.com/robyajo/laravel-security-monitor/actions/workflows/run-tests.yml/badge.svg)](https://github.com/robyajo/laravel-security-monitor/actions/workflows/run-tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/robyajo/laravel-security-monitor.svg)](https://packagist.org/packages/robyajo/laravel-security-monitor)
[![Total Downloads](https://img.shields.io/packagist/dt/robyajo/laravel-security-monitor.svg)](https://packagist.org/packages/robyajo/laravel-security-monitor)
[![PHP Version](https://img.shields.io/badge/php-%5E8.2%20%7C%20%5E8.3%20%7C%20%5E8.4%20%7C%20%5E8.5-blue.svg)](https://www.php.net/supported-versions.php)
[![Laravel Version](https://img.shields.io/badge/laravel-%5E10.0%20%7C%20%5E11.0%20%7C%20%5E12.0%20%7C%20%5E13.0-red.svg)](https://laravel.com/docs/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Laravel Security Monitor** (Bulwark) adalah paket keamanan komprehensif (_Self-Hosted WAF & Threat Engine_) berbasis **Headless REST API** untuk ekosistem Laravel. Paket ini murni PHP Composer library (Zero-NPM / standar Spatie) yang dirancang khusus untuk memproteksi aplikasi web internal dari serangan siber tingkat lanjut, injeksi payload pentest, eksploitasi webshell, dan brute force tanpa mengikat aplikasi ke template frontend tertentu.

> 📚 **Portal Dokumentasi Resmi Lengkap**: Tersedia 25 bab dokumentasi mendalam di direktori [`documents/`](./documents/README.md) serta portal interaktif offline [`documents/index.html`](./documents/index.html).

---

## 🌟 Fitur Utama

1. **Self-Hosted WAF & Zero-Tolerance Threat Detection**:
    - Deteksi instan tanpa batas ambang (_zero-tolerance_) untuk null-byte upload (`.php%00.jpg`), ekstensi ganda (`.php.jpg`), path traversal (`../../../public/`), probe file sensitif (`.htaccess`, `.env`, `.git`), dan SSTI canary (`{{7*7}}`).
    - Deteksi komprehensif untuk SQL Injection, Cross-Site Scripting (XSS), Local File Inclusion (LFI), Command Injection, dan Scanner User-Agents.
    - Pola regex yang diperketat dan kebal terhadap serangan ReDoS (_Regular Expression Denial of Service_).

2. **Isolasi Perangkat Granular (Device-Level Quarantine)**:
    - Dukungan isolasi di tingkat perangkat menggunakan `device_id` (WebRTC/fingerprint) dan `local_ip`.
    - Memastikan perangkat penyerang terblokir tanpa mengganggu pengguna sah lain yang berbagi alamat IP publik yang sama (seperti kantor atau router Wi-Fi publik).

3. **Tiket Banding & Permohonan Buka Blokir (Appeal Tickets)**:
    - Endpoint publik REST API bagi pengguna yang terblokir untuk mengajukan tiket permohonan buka blokir beserta status pelacakannya.
    - Antarmuka persetujuan admin yang secara otomatis mencabut karantina IP/perangkat dan memasukkannya ke whitelist.

4. **Multi-Tier Stepped Login Lockout**:
    - Sistem pencegahan _credential stuffing_ & _brute force_ berjenjang (1 menit, 5 menit, 15 menit, 1 jam, hingga 24 jam).
    - Pencatatan otomatis riwayat kegagalan otentikasi ke log audit keamanan.

5. **Pure SVG CAPTCHA (Zero Dependency)**:
    - Generator CAPTCHA berbasis matriks vektor SVG murni tanpa memerlukan ekstensi PHP GD atau Imagick.
    - Token tantangan sekali pakai (_stateless one-time challenge_) yang aman secara kriptografis.

6. **Server Integrity & Webshell Scanner**:
    - Pembuatan dan verifikasi baseline hash SHA-256 untuk berkas-berkas aplikasi inti.
    - Pemindaian berkas mencurigakan / webshell (ekstensi ganda, skrip di direktori publik/upload, polyglot media).
    - Fitur penghapusan berkas berbahaya yang aman dengan proteksi path traversal dan berkas sistem vital.
    - Audit konfigurasi keamanan server (`APP_DEBUG`, secure session cookie, Fortify 2FA).

7. **Streaming Access Log Scanner**:
    - Pemindai berkas log mentah Apache / Nginx secara _streaming_ berdaya hemat memori untuk menangkap penyerang yang ditolak oleh web server sebelum request mencapai proses PHP Laravel.

8. **Headless & Arsitektur Terkopel Longgar**:
    - 100% REST API JSON murni.
    - Model `User` dan nama tabel database sepenuhnya dapat dikonfigurasi melalui `config/security.php`.
    - Trait `HasSecurityRelations` untuk kemudahan integrasi relasi Eloquent.

---

## 📋 Persyaratan Sistem

- PHP: `^8.2`, `^8.3`, `^8.4`, atau `^8.5`
- Laravel: `^10.0`, `^11.0`, `^12.0`, atau `^13.0`

---

## 🚀 Instalasi

### 1. Pasang Paket via Composer

```bash
composer require robyajo/laravel-security-monitor:^1.1
```

> **Penting — jangan pakai `@dev` di produksi.** Menulis
> `composer require robyajo/laravel-security-monitor:@dev` memaksa Composer
> mengambil branch default `dev-main` (kode yang belum dirilis), bukan tag rilis
> stabil. Selalu pakai constraint rilis (mis. `^1.1`) atau tanpa constraint sama
> sekali. Flag `@dev` hanya diperlukan saat mengembangkan paket ini lewat
> _path repository_ lokal.

### 2. Publikasikan Aset Otomatis (`security:install`)

Gunakan perintah satu langkah untuk mempublikasikan dan menerapkan seluruh aset keamanan secara otomatis:

```bash
php artisan security:install
```

#### Aset yang Didapat Pengguna Setelah Menjalankan Perintah Ini:

1. 📄 **`config/security.php`**: Konfigurasi lengkap WAF, ambang batas blokir, IP whitelist, stepped login lockout, SVG Captcha, dan log scanner.
2. 🗄️ **`database/migrations/` (6 tabel)**: Menyiapkan tabel `blocked_ips`, `security_logs`, `login_attempts`, `ip_unblock_requests`, `user_logins`, dan `trusted_ips`.
3. 🌐 **`nginx.conf`**: Konfigurasi produksi Nginx Hardened WAF (Dual-zone rate limit, single-PHP execution `/index.php`, storage sandboxing).
4. 🛡️ **`public/.htaccess`**: Hardening web server Apache & LiteSpeed (Blokir dotfiles, double extension `.php.jpg`, file backup dump `.sql`, dan matikan directory listing).
    > _Catatan Keamanan_: Jika `public/.htaccess` lama sudah ada, installer otomatis membuat cadangan `public/.htaccess.backup-YYYYMMDD_HHMMSS` dan menyisipkan aturan keamanan di bawah tanpa merusak rewrite rules aplikasi Anda.
5. 🚫 **`resources/views/errors/blocked.blade.php`**: Halaman 403 default yang menampilkan alasan blokir, kode referensi, dan **formulir banding** yang terhubung langsung ke endpoint publik tiket banding. Dapat disesuaikan sesuai branding aplikasi Anda.
6. ⚙️ **Penyematan Variabel ke `.env` & `.env.example`**: Installer secara otomatis menambahkan blok konfigurasi lengkap disertai **penjelasan fungsi berbahasa Indonesia** untuk setiap variabel (`SECURITY_*` dan `CAPTCHA_*`) langsung ke berkas `.env` dan `.env.example` aplikasi Anda.
7. 📊 **(Opsional) Dashboard monitoring Starter Kit**: Tampilan monitoring Livewire (`resources/views/pages/security/`) atau React (`resources/js/pages/security/`), wajib login. Dipublikasikan bila Anda menambahkan opsi `--with-dashboard` atau `--with-react-dashboard`.

#### Opsi Perintah `security:install`:

| Opsi                     | Keterangan                                                                                         |
| :----------------------- | :------------------------------------------------------------------------------------------------- |
| `--force`                | Menimpa seluruh berkas konfigurasi, migrasi, `nginx.conf`, `public/.htaccess`, dan halaman blokir. |
| `--without-nginx`        | Melewatkan pembuatan berkas `nginx.conf`.                                                          |
| `--without-htaccess`     | Melewatkan pembaruan berkas `public/.htaccess`.                                                    |
| `--without-views`        | Melewatkan publikasi halaman blokir `errors/blocked.blade.php`.                                    |
| `--with-dashboard`       | Mempublikasikan tampilan dashboard monitoring Livewire (wajib login).                              |
| `--with-react-dashboard` | Mempublikasikan tampilan dashboard monitoring React/Inertia (wajib login).                         |
| `--with-htaccess`        | Memaksa pembaruan berkas `public/.htaccess`.                                                       |
| `--without-env`          | Melewatkan penyematan variabel konfigurasi ke berkas `.env` dan `.env.example`.                    |

#### Publikasi Aset Secara Parsial (Manual):

```bash
# 1. Konfigurasi saja
php artisan vendor:publish --tag=security-config

# 2. Migrasi database saja
php artisan vendor:publish --tag=security-migrations

# 3. Konfigurasi server Nginx saja
php artisan vendor:publish --tag=security-nginx

# 4. Aturan hardening Apache .htaccess saja
php artisan vendor:publish --tag=security-htaccess --force

# 5. Halaman blokir default saja
php artisan vendor:publish --tag=security-views --force

# 6. Dashboard monitoring Livewire + konfigurasi
php artisan vendor:publish --tag=starterkit-livewire --force

# 7. Dashboard monitoring React/Inertia + konfigurasi
php artisan vendor:publish --tag=starterkit-react --force

# 8. Seluruh aset sekaligus
php artisan vendor:publish --tag=security-all --force
```

Jalankan migrasi database:

```bash
php artisan migrate
```

### 3. Dashboard Monitoring Starter Kit (Opsional)

Paket ini tetap **100% headless** secara default, namun menyediakan panel monitoring siap pakai untuk **starter kit resmi Laravel** yang dapat dipublikasikan ke dalam aplikasi host. Pilih salah satu sesuai stack frontend aplikasi Anda.

#### a. Livewire Starter Kit (Flux UI)

```bash
php artisan vendor:publish --tag=starterkit-livewire
```

Perintah tersebut menyalin **`resources/views/pages/security/*.blade.php`** (enam halaman Livewire single-file component) beserta blok konfigurasi `dashboard` pada `config/security.php`.

#### b. React Starter Kit (Inertia + React + shadcn/ui)

```bash
php artisan vendor:publish --tag=starterkit-react
```

Perintah tersebut menyalin:

1. **`resources/js/pages/security/*.tsx`** — enam halaman Inertia/React: _Overview_, _Security Logs_, _Blocked IPs_, _Server Audit_, _User Sessions_, dan _Unblock Appeals_.
2. **`resources/js/components/security/*.tsx`** — komponen pendukung (navigasi & paginasi).
3. **`config/security.php`** — menyertakan blok konfigurasi `dashboard`.

> ℹ️ Halaman React dikirim melalui controller Inertia bawaan paket (data di-render server-side), sehingga **tidak** bergantung pada REST API `/api/*`. Setelah publikasi, jalankan `npm run build` (atau `npm run dev`).

#### Mengaktifkan Dashboard

```dotenv
SECURITY_DASHBOARD_ENABLED=true
SECURITY_DASHBOARD_DRIVER=livewire   # atau "react"
SECURITY_DASHBOARD_PREFIX=security
```

Setelah diaktifkan, panel dapat diakses pada **`/security`**.

> 🔒 **Wajib Login**: Seluruh halaman dashboard dilindungi middleware `web` + `auth`. Secara bawaan, akses juga dibatasi oleh middleware `security.admin` (Gate `manage-security-monitor`) sehingga hanya administrator yang diizinkan. Keduanya dapat dikustomisasi melalui kunci `security.dashboard.middleware` dan `security.dashboard.admin_middleware` di `config/security.php`.

Saat menjalankan `security:install`, tambahkan opsi `--with-dashboard` (Livewire) atau `--with-react-dashboard` (React) untuk mempublikasikan dashboard sekaligus.

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

| Metode | URI                                                  | Deskripsi                                                                                   |
| :----- | :--------------------------------------------------- | :------------------------------------------------------------------------------------------ |
| `GET`  | `/api/security/captcha`                              | Menghasilkan SVG CAPTCHA dan mengembalikan gambar vector langsung beserta `X-Captcha-Token` |
| `POST` | `/api/security/captcha/verify`                       | Memvalidasi jawaban CAPTCHA (`phrase` & `token`)                                            |
| `POST` | `/api/security/unblock-tickets/submit`               | Mengirim permohonan banding pembukaan blokir IP/perangkat                                   |
| `GET`  | `/api/security/unblock-tickets/check/{ticketNumber}` | Memeriksa status tiket permohonan banding                                                   |

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

| Metode | URI                                    | Deskripsi                                                   |
| :----- | :------------------------------------- | :---------------------------------------------------------- |
| `POST` | `/api/security/trusted-ips/save-my-ip` | Menyimpan alamat IP saat ini sebagai IP terpercaya pengguna |

### 3. Endpoint Manajemen Admin (`auth` + `security.admin`)

#### Log Keamanan & Analitik Serangan

| Metode   | URI                        | Deskripsi                                                                                     |
| :------- | :------------------------- | :-------------------------------------------------------------------------------------------- |
| `GET`    | `/api/security/logs`       | Mendapatkan log ancaman (paginasi, filter event/level/tanggal, statistik, tren 24 jam/7 hari) |
| `DELETE` | `/api/security/logs/clear` | Mengosongkan seluruh log audit keamanan                                                       |
| `DELETE` | `/api/security/logs/{id}`  | Menghapus satu entri log keamanan tertentu                                                    |

#### Daftar Blokir IP & Perangkat

| Metode   | URI                                     | Deskripsi                                                 |
| :------- | :-------------------------------------- | :-------------------------------------------------------- |
| `GET`    | `/api/security/blocked-ips`             | Mendapatkan daftar IP yang diblokir (aktif & kedaluwarsa) |
| `POST`   | `/api/security/blocked-ips`             | Memblokir IP atau perangkat secara manual                 |
| `GET`    | `/api/security/blocked-ips/{id}`        | Melihat detail data pemblokiran                           |
| `PATCH`  | `/api/security/blocked-ips/{id}/toggle` | Mengaktifkan / menonaktifkan status blokir                |
| `DELETE` | `/api/security/blocked-ips/{id}`        | Mencabut blokir dan menghapus entri                       |

#### Audit Server & Integritas Berkas

| Metode   | URI                                     | Deskripsi                                                      |
| :------- | :-------------------------------------- | :------------------------------------------------------------- |
| `GET`    | `/api/security/server`                  | Laporan komprehensif audit keamanan server & integritas berkas |
| `POST`   | `/api/security/server/baseline`         | Membuat baseline hash SHA-256 berkas aplikasi baru             |
| `DELETE` | `/api/security/server/baseline`         | Menghapus baseline integritas                                  |
| `DELETE` | `/api/security/server/suspicious-files` | Menghapus berkas mencurigakan/webshell yang terdeteksi         |
| `DELETE` | `/api/security/lockouts/{id}`           | Membuka kunci akun yang terkena lockout login berjenjang       |

#### Sesi Pengguna & IP Terpercaya

| Metode   | URI                                               | Deskripsi                                       |
| :------- | :------------------------------------------------ | :---------------------------------------------- |
| `GET`    | `/api/security/user-sessions`                     | Riwayat sesi login seluruh pengguna             |
| `GET`    | `/api/security/user-sessions/realtime`            | Daftar pengguna yang aktif secara real-time     |
| `DELETE` | `/api/security/user-sessions/{id}`                | Menghapus log sesi pengguna                     |
| `DELETE` | `/api/security/user-sessions/session/{sessionId}` | Memutus sesi pengguna tertentu (_force logout_) |
| `DELETE` | `/api/security/trusted-ips/{id}`                  | Menghapus IP dari daftar terpercaya             |

#### Pengelolaan Tiket Banding

| Metode   | URI                                          | Deskripsi                                               |
| :------- | :------------------------------------------- | :------------------------------------------------------ |
| `GET`    | `/api/security/unblock-tickets`              | Daftar seluruh tiket permohonan banding                 |
| `POST`   | `/api/security/unblock-tickets/{id}/respond` | Menyetujui atau menolak tiket (buka blokir & whitelist) |
| `DELETE` | `/api/security/unblock-tickets/{id}`         | Menghapus arsip tiket                                   |

---

## 🛡️ Validation Rules Bawaan

Paket menyediakan aturan validasi siap pakai untuk request form aplikasi Anda:

### 1. `SafeImageFile`

Memvalidasi unggahan gambar dan mencegah serangan _polyglot image_ (gambar JPEG/PNG sah yang diinjeksi kode `<?php`), ekstensi ganda berbahaya, dan SVG bereksekusi JavaScript/XSS:

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

---

## 🌐 Konfigurasi Web Server Hardened

Paket ini menyertakan template konfigurasi hardened siap pakai untuk web server **Nginx** maupun **Apache / LiteSpeed / cPanel**.

### 1. Nginx Hardened WAF (`nginx.conf`)

Diterbitkan via `php artisan vendor:publish --tag=security-nginx`:

1. **Dua Zona Rate Limiting Terpisah**:
    - `auth_limit`: 5 request/menit (burst 5) untuk endpoint sensitif (`/login`, `/register`, `/forgot-password`, `/reset-password`, dll.).
    - `general_limit`: 30 request/detik (burst 50) untuk rute umum aplikasi.
2. **Proteksi Aset Statis Vite / Frontend**:
    - Direktori `/build/` dibebaskan dari rate-limiting agar chunk parallel JS tidak memicu HTTP 429 atau `NS_ERROR_CORRUPTED_CONTENT`.
3. **Strict Single-PHP Execution**:
    - **Hanya `/index.php`** yang boleh dieksekusi oleh PHP-FPM. Berkas skrip lain yang berada di direktori publik langsung ditolak dengan **HTTP 403**.
4. **Pencegahan Double Extension & Ekstensi Berbahaya**:
    - Menolak ekstensi ganda (`.php.jpg`, `.phtml.zip`, dll.).
5. **Sandboxing Direktori Storage / Upload**:
    - Folder `/storage/` dimatikan dari eksekusi PHP dengan header `X-Content-Type-Options: nosniff` dan CSP sandbox.
6. **Blokir Dotfiles & Berkas Backup**:
    - Menolak akses berkas `.env`, `.git`, `.htaccess`, `.sql`, `.bak`, dan `.log`.

### 2. Apache & LiteSpeed Hardened (`public/.htaccess`)

Diterapkan otomatis via `php artisan security:install` atau `php artisan vendor:publish --tag=security-htaccess`:

1. **Front Controller & Authorization Header**: Routing Laravel standar, pemeliharaan header `Authorization` dan `X-XSRF-Token`.
2. **Blokir Akses ke Dotfile (`<FilesMatch "^\.">`)**:
    - Menutup akses ke `.htaccess`, `.env`, `.git`, `.htpasswd` (kompatibel Apache 2.4+ `Require all denied` dan Apache 2.2 `Deny from all`).
3. **Blokir Serangan Ekstensi Ganda (Double Extension Webshell)**:
    - Menolak berkas berbahaya seperti `shell.php.jpg` atau trik null-byte `wne.php%00.jpg`:
    ```apache
    <FilesMatch "\.(php[0-9]?|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|scr)\.[a-z0-9]+$">
        Require all denied
    </FilesMatch>
    ```
4. **Blokir Berkas Backup, Dump Database, dan Log Sensitif**:
    - Menutup berkas `.sql`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, `.log`, `.ini`, `.conf`, `.yml`, `.yaml`.
5. **Matikan Directory Listing**:
    - `Options -Indexes` mencegah browser menampilkan daftar berkas di dalam folder publik/storage.

## 🧪 Menjalankan Pengujian (Testing)

Paket ini dilengkapi dengan pengujian menyeluruh menggunakan **Pest PHP** dan **Orchestra Testbench**:

```bash
./vendor/bin/pest
```

Hasil uji: **82 passed (333 assertions)** 100% Passed mencakup:

- `DetectorTuningTest`: Verifikasi akurasi pola deteksi dan ketahanan ReDoS.
- `InstantBlockTest`: Verifikasi zero-tolerance instant blocking pada percobaan pertama.
- `PolyglotImageTest`: Uji penolakan polyglot image ber-tag PHP dan SVG XSS.
- `SecurityAdminApiTest`: Pengujian lengkap otorisasi, mutasi data, dan respons JSON REST API.
- `DeviceLevelBlockingTest`: Uji isolasi perangkat pada IP publik bersama.
- `ServerSecurityTest`: Audit keamanan lingkungan, baseline SHA-256, dan webshell sanitizer.
- `AccessLogScanTest`: Uji parser streaming log akses web server.
- `SecurityMonitorTest`: Uji ambang batas auto-blocking dan rotasi log.
- `NginxPublishTest`: Verifikasi publikasi konfigurasi hardened virtual host Nginx.
- `HtaccessPublishTest`: Verifikasi publikasi, penambahan aturan otomatis, dan pencadangan `.htaccess` Apache.

---

## ❤️ Dukungan (Support)

Jika paket ini bermanfaat untuk proyek Anda, Anda dapat mendukung pengembangan
berkelanjutannya melalui:

- 🇮🇩 **Saweria**: <https://saweria.co/robykartis>

Dukungan Anda sangat membantu agar paket ini tetap terawat, aman, dan terus
diperbarui. Terima kasih! 🙏

---

## 📄 Lisensi

Paket ini dilisensikan di bawah lisensi terbuka [MIT](LICENSE).
