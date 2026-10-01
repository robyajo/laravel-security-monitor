# 01. Pengenalan & Filosofi Arsitektur

## Latar Belakang

Dalam pengembangan aplikasi berbasis Laravel modern di lingkungan enterprise dan instansi pemerintah, tantangan keamanan web tidak lagi terbatas pada pencegahan SQL Injection dasar. Laporan audit pentest (penetration testing) dan serangan siber nyata sering kali mengeksploitasi celah tingkat lanjut:

1. **Uji Penetrasi Agresif & Residual Payload**: Pentester kerap menyuntikkan payload SSTI (`{{7*7}}`), path traversal (`../../../public/`), dan probe file `.env` atau `.htaccess` yang tersimpan di basis data lalu merusak tampilan pengguna normal.
2. **Unggahan Gambar Polyglot & Webshell**: Mengunggah berkas gambar valid (JPEG/PNG) yang disisipi tag PHP (`<?php ... ?>`) atau SVG berisi kode JavaScript XSS untuk melewati validasi `mimes:jpg,png`.
3. **Penyalahgunaan IP Bersama (Shared NAT/Router)**: Ketika seorang penyerang berada di jaringan Wi-Fi publik, kantor, atau kampus yang sama dengan ratusan pengguna sah, pemblokiran berbasis IP publik akan menyebabkan *collateral damage*—seluruh kantor kehilangan akses ke aplikasi.
4. **Credential Stuffing & DoS Regex (ReDoS)**: Serangan brute-force menggunakan botnet terdistribusi serta pengiriman string panjang berpola untuk memicu kegagalan komputasi CPU akibat regex backtracking berulang (*Catastrophic Backtracking*).

**`robyajo/laravel-security-monitor`** (Bulwark) dibangun dari pengalaman lapangan menangani insiden nyata tersebut, dikemas menjadi paket mandiri, modular, dan berperforma tinggi.

---

## Standar Desain Spatie: 100% Pure PHP & Nol Ketergantungan NPM (Zero NPM)

Berbeda dengan paket aplikasi yang mengikat pengguna ke antarmuka atau bundler JavaScript tertentu, paket ini mengikuti **standar emas paket Laravel seperti Spatie** (misal: `spatie/laravel-permission`, `spatie/laravel-activitylog`, `spatie/laravel-honeypot`):

> 🌟 **Nol Dependensi NPM / Node.js**: Paket ini adalah **100% Murni PHP untuk Laravel**. Anda **TIDAK PERNAH** memerlukan `npm install`, `node`, `vite build`, atau bundler frontend apa pun untuk menjalankan paket ini.

Setelah paket dipasang melalui `composer require robyajo/laravel-security-monitor`, pengembang **bebas menerapkannya di mana saja** di seluruh ekosistem Laravel:
- ✅ **Aplikasi Laravel Blade Murni**: Bekerja langsung dengan view HTML standar dan sesi cookie.
- ✅ **Aplikasi API Backend Murni (Headless)**: Menyuplai REST API JSON untuk aplikasi mobile (Flutter/React Native) atau SPA frontend terpisah.
- ✅ **Aplikasi Laravel Livewire / Alpine.js**: Validasi form dan lockout bekerja instan tanpa build step.
- ✅ **Aplikasi Panel Admin (Filament / Nova / Backpack)**: Dapat dipasangi trait, monitoring log, dan action unblock.
- ✅ **Aplikasi Inertia / React / Vue**: Jika aplikasi host kebetulan memakai Inertia/React, API JSON paket langsung dapat dikonsumsi tanpa benturan dependensi.

---

## Bagaimana Paket Masuk dan Menyatu ke Core Laravel?

Sama seperti paket Spatie terpopuler, paket ini menyatu secara elegan ke dalam titik-titik inti (*Core Hooks*) framework Laravel:

```mermaid
graph TD
    Composer[composer require robyajo/laravel-security-monitor] --> Discovery[1. Laravel Package Auto-Discovery<br/>SecurityMonitorServiceProvider + Facade]
    
    Discovery --> Hook1[2. Core Eloquent: HasSecurityRelations Trait<br/>User::logins(), User::trustedIps()]
    Discovery --> Hook2[3. Core Auth Events: Event::listen<br/>Failed & Login Events Otomatis Diawasi]
    Discovery --> Hook3[4. Core HTTP Kernel: Middleware Aliases<br/>security.block, security.detect, security.admin]
    Discovery --> Hook4[5. Core Authorization: Gate<br/>Gate::define('manage-security-monitor')]
    Discovery --> Hook5[6. Core Artisan CLI: Console Commands<br/>security:install, security:scan-logs, dll]
    Discovery --> Hook6[7. Core Scheduler: Schedule Runner<br/>Prune log harian & liveness heartbeat]
    Discovery --> Hook7[8. Core Validation: ValidationRule<br/>SafeImageFile, SafeAssetPath, ValidCaptcha]
    Discovery --> Hook8[9. Pure Vector Math: Zero-Dep Captcha<br/>Tanpa GD, tanpa Imagick, tanpa client JS]
```

### 1. Package Auto-Discovery
Di dalam `composer.json`, paket mendeklarasikan ServiceProvider dan Facade bawaan:
```json
"extra": {
    "laravel": {
        "providers": [
            "Internal\\SecurityMonitor\\SecurityMonitorServiceProvider"
        ],
        "aliases": {
            "SecurityMonitor": "Internal\\SecurityMonitor\\Facades\\SecurityMonitor"
        }
    }
}
```
Laravel otomatis memuat provider ini saat proses booting. Pengembang tidak perlu mengedit `config/app.php` secara manual.

### 2. Integrasi Model Eloquent via Trait (Mirip `HasRoles` Spatie)
Sama seperti menambahkan `use HasRoles;` pada paket Spatie Permission, pengembang cukup menambahkan satu baris ke model `User` miliknya:
```php
use Internal\SecurityMonitor\Concerns\HasSecurityRelations;

class User extends Authenticatable
{
    use HasSecurityRelations;
}
```
Ini langsung membuka relasi `$user->logins()`, `$user->trustedIps()`, `$user->securityLogs()`, dan `$user->blockedIps()`.

### 3. Mengaitkan Event Otentikasi Bawaan Laravel
Tanpa perlu memodifikasi controller login aplikasi Anda, `SecurityMonitorServiceProvider` secara otomatis mendaftarkan listener ke event inti Laravel:
- `\Illuminate\Auth\Events\Failed` ➔ Otomatis mencatat kegagalan dan menghitung stepped lockout.
- `\Illuminate\Auth\Events\Login` ➔ Otomatis mereset hitungan lockout dan merekam sesi login aktif.

### 4. Middleware Pipeline & Kernel
Paket mendaftarkan 4 alias middleware resmi:
- `'security.block'` ➔ `BlockIpAddress`
- `'security.detect'` ➔ `DetectSecurityThreats`
- `'security.admin'` ➔ `EnsureSecurityAdmin`
- `'security.activity'` ➔ `TrackUserActivity`

Pengembang dapat memasangnya di mana saja: sebagai middleware global, di grup `web`, grup `api`, atau pada rute individual.

### 5. Registrasi Gate Otorisasi Bawaan
Paket mendefinisikan gate `'manage-security-monitor'` yang langsung terhubung ke sistem otorisasi standar Laravel (`@can`, `$user->can()`, `Gate::allows()`).

### 6. Artisan Console Commands
Menyediakan 6 perintah CLI bawaan yang otomatis tersedia di `php artisan`:
- `security:install`, `security:scan-logs`, `security:baseline`, `security:unblock-ip`, `security:prune-logs`, `security:purge-injected-data`.

### 7. Task Scheduler Otomatis
Mengaitkan tugas pembersihan log usang harian dan pemeriksaan detak jantung (*heartbeat*) langsung ke `Illuminate\Console\Scheduling\Schedule` bawaan Laravel.

### 8. Validation Rules Bawaan
Menyediakan aturan validasi form Laravel murni:
- `SafeImageFile`: Memeriksa biner gambar terhadap tag PHP polyglot dan SVG XSS.
- `SafeAssetPath`: Memeriksa string path terhadap path traversal.
- `ValidCaptcha`: Memvalidasi tantangan CAPTCHA.

---

## 4 Filosofi Arsitektur Utama

1. **Headless Only (Pure REST API)**:
   Tidak ada template HTML/CSS bawaan yang dipaksakan. Seluruh respon dikembalikan dalam JSON REST API murni atau fallback view Blade standar jika diinginkan.
2. **Loose Coupling & Decoupled Models**:
   Nama tabel dan model `User` 100% dinamis melalui `config/security.php`.
3. **Kekebalan Mutlak ReDoS (ReDoS Immunity)**:
   Pola regex linear yang lolos uji beban 100KB+ adversarial string dengan eksekusi sub-milidetik.
4. **Isolasi Perangkat Granular (Device-Level Quarantine)**:
   Mendukung isolasi penyerang pada jaringan IP publik bersama (NAT) via `X-Device-Id` dan `X-Local-Ip`.
