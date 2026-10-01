# Laravel Security Monitor (Bulwark)
## Dokumentasi Resmi & Panduan Penggunaan Lengkap

> **Versi Paket**: `1.0.0` | **PHP**: `^8.2 | ^8.3 | ^8.4` | **Laravel**: `^10.0 | ^11.0 | ^12.0 | ^13.0` | **Lisensi**: `MIT`

Selamat datang di dokumentasi resmi **`robyajo/laravel-security-monitor`** (Bulwark). Dokumentasi ini dirancang untuk memberikan panduan komprehensif mulai dari konsep arsitektur, instalasi, konfigurasi, integrasi REST API headless, modul keamanan tingkat lanjut, otomasi Artisan CLI, hingga hardening web server Nginx di lingkungan produksi.

---

## 🧭 Daftar Isi Dokumentasi

Dokumentasi ini disusun secara modular ke dalam 7 bagian utama:

### 1. [Memulai (Getting Started)](./01-getting-started/)
- [01. Pengenalan & Filosofi Arsitektur](./01-getting-started/01-introduction.md) — Mengapa paket ini dibuat, filosofi headless WAF, ReDoS safety, dan perbandingan dengan paket lain.
- [02. Panduan Instalasi & Migrasi](./01-getting-started/02-installation.md) — Langkah instalasi Composer, publikasi aset otomatis (`security:install`), konfigurasi tag, dan migrasi database.
- [03. Konfigurasi Lengkap & Environment Variable](./01-getting-started/03-configuration.md) — Penjelasan baris-per-baris seluruh kunci pada `config/security.php` dan 30+ variabel `.env`.

### 2. [Arsitektur Inti (Core Architecture)](./02-core-architecture/)
- [01. Threat Detection Engine & Zero-Tolerance WAF](./02-core-architecture/01-threat-detection-engine.md) — Mekanisme inspeksi HTTP request, perbedaan blokir instan vs ambang batas progresif, dan standar keamanan ReDoS.
- [02. Karantina Berbasis Perangkat (Device-Level Quarantine)](./02-core-architecture/02-device-quarantine.md) — Solusi isolasi perangkat pada IP publik bersama (kantor/Wi-Fi publik) tanpa memblokir seluruh router.
- [03. Resolusi Reverse Proxy & Deteksi IP Klien](./02-core-architecture/03-reverse-proxy-resolution.md) — Resolusi IP di belakang Cloudflare, Nginx reverse proxy, dan AWS ALB tanpa risiko spoofing header.
- [04. Model Database & Dynamic Decoupling](./02-core-architecture/04-models-and-database.md) — Kustomisasi nama tabel, integrasi model `User` dinamis, dan penggunaan trait `HasSecurityRelations`.

### 3. [Modul Keamanan (Security Modules)](./03-security-modules/)
- [01. Stepped Login Lockout & Brute-Force Defense](./03-security-modules/01-stepped-login-throttling.md) — Proteksi bertingkat (1 mnt, 5 mnt, 15 mnt, hingga 24 jam), event listeners, dan rilis lockout.
- [02. Zero-Dependency SVG CAPTCHA](./03-security-modules/02-svg-captcha.md) — Generator CAPTCHA vektor SVG murni tanpa ekstensi PHP GD/Imagick, tantangan kriptografis stateless, dan aturan validasi.
- [03. Server Integrity & Webshell Scanner](./03-security-modules/03-server-security-and-webshells.md) — Baseline hash SHA-256 berkas inti, deteksi webshell di folder publik/storage, dan pembersih berkas yang aman.
- [04. Streaming Access Log Scanner](./03-security-modules/04-access-log-streaming.md) — Pemindai berkas log Apache/Nginx hemat memori (< 15MB) untuk menangkap serangan sebelum mencapai PHP.
- [05. Sistem Tiket Banding Pembukaan Blokir (Appeal Tickets)](./03-security-modules/05-appeal-tickets-system.md) — Alur pengajuan tiket publik bagi pengguna yang terblokir, rate limiting, dan persetujuan admin.
- [06. Pelacakan Sesi & Pengguna Realtime](./03-security-modules/06-session-and-activity-tracking.md) — Pemantauan user online realtime, heartbeat ter-throttle, pemutusan paksa sesi, dan IP terpercaya.

### 4. [Referensi REST API Headless (API Reference)](./04-rest-api-reference/)
- [01. Konvensi & Spesifikasi API](./04-rest-api-reference/01-api-overview.md) — Format envelope JSON, autentikasi, middleware, otorisasi Gate, dan status code.
- [02. Endpoint Publik](./04-rest-api-reference/02-public-endpoints.md) — Dokumentasi endpoint Captcha (`GET /captcha`, `POST /captcha/verify`) dan Tiket Banding (`POST /submit`, `GET /check/{ticket}`).
- [03. Endpoint Pengguna Terautentikasi](./04-rest-api-reference/03-user-endpoints.md) — Simpan IP terpercaya saya (`POST /trusted-ips/save-my-ip`).
- [04. Endpoint Administrator](./04-rest-api-reference/04-admin-endpoints.md) — Manajemen log keamanan, pengelolaan blokir IP, audit server, baseline SHA-256, sesi pengguna, dan tiket banding.

### 5. [CLI & Otomasi (Artisan & Automation)](./05-cli-and-automation/)
- [01. Referensi Perintah Artisan CLI](./05-cli-and-automation/01-artisan-commands.md) — `security:install`, `security:scan-logs`, `security:baseline`, `security:unblock-ip`, `security:prune-logs`, `security:purge-injected-data`.
- [02. Tugas Terjadwal (Cron & Scheduler)](./05-cli-and-automation/02-scheduled-tasks.md) — Pembersihan log berkala, liveness heartbeat, auto-scan log akses web server, dan konfigurasi crontab.

### 6. [Hardening Web Server (Web Server Hardening)](./06-webserver-hardening/)
- [01. Konfigurasi Nginx Hardened WAF (`nginx.conf`)](./06-webserver-hardening/01-nginx-hardened-waf.md) — Dual rate limiting, bypass aset Vite (`NS_ERROR_CORRUPTED_CONTENT`), eksekusi tunggal `/index.php`, dan sandbox storage.
- [02. Checklist Keamanan Produksi](./06-webserver-hardening/02-production-checklist.md) — Checklist sebelum peluncuran, izin direktori, tuning database, dan prosedur darurat.

### 7. [Panduan Integrasi (Integration Guides)](./07-integration-guides/)
- [01. Integrasi Frontend React / Inertia](./07-integration-guides/01-frontend-react-inertia.md) — Axios interceptor penanganan HTTP 403, modal permohonan buka blokir, dan komponen SVG Captcha di React.
- [02. Integrasi Frontend Blade & Livewire](./07-integration-guides/02-frontend-blade-livewire.md) — Kustomisasi `resources/views/errors/blocked.blade.php`, komponen Captcha Blade, dan proteksi form.
- [03. Pembuatan Aturan Kustom & Whitelist Subnet](./07-integration-guides/03-custom-rules-and-whitelist.md) — Menambahkan signature kustom, whitelist subnet CIDR kantor, dan kustomisasi skema.

---

## ⚡ Ringkasan Cepat Arsitektur

```mermaid
flowchart TD
    Client([HTTP Request]) --> Nginx[Nginx Hardened WAF<br/>Dual-Zone Rate Limit & FastCGI Filter]
    Nginx -->|Lolos Pemeriksaan| PHP[Laravel Front Controller<br/>public/index.php]
    
    subgraph LSM ["Laravel Security Monitor (Bulwark)"]
        PHP --> BlockMW[Middleware: BlockIpAddress]
        BlockMW -->|IP / Device Terdaftar Aktif| Ret403[HTTP 403: Akses Ditolak<br/>+ Reference ID]
        BlockMW -->|Lolos| ThreatMW[Middleware: DetectSecurityThreats]
        
        ThreatMW --> Inspect[Engine Inspeksi Payload<br/>URI, Query, Body, Header, Filename]
        Inspect -->|Cocok Zero-Tolerance| InstBlock[Blokir Instan 30 Hari<br/>+ Catat SecurityLog]
        InstBlock --> Ret403
        
        Inspect -->|Skor Ancaman >= Ambang Batas| AutoBlock[Auto-Block 24 Jam<br/>+ Catat SecurityLog]
        AutoBlock --> Ret403
        
        Inspect -->|Tidak Ada Ancaman / Lolos| AppController[Controller Aplikasi Host]
    end
    
    Ret403 --> Appeal[Form Tiket Banding<br/>/api/security/unblock-tickets/submit]
    Appeal --> Admin[Admin Review & Unblock API<br/>/api/security/unblock-tickets/{id}/respond]
    Admin -->|Disetujui| LiftBlock[Buka Blokir Otomatis]
```

---

## 💻 Portal Dokumentasi Interaktif

Paket ini menyediakan portal dokumentasi interaktif offline berbasis HTML murni dan CSS modern di:
👉 **[`documents/index.html`](./index.html)**

Anda dapat membuka berkas tersebut langsung di browser apa pun untuk menikmati navigasi visual, pencarian cepat, tema gelap/terang, dan salin kode sekali klik.
