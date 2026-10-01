# 03. Konfigurasi Lengkap & Environment Variable

Seluruh perilaku **`robyajo/laravel-security-monitor`** dikontrol melalui berkas konfigurasi `config/security.php`. Konfigurasi ini dirancang agar dapat disesuaikan tanpa perlu mengubah kode sumber paket, cukup melalui berkas `.env`.

---

## 1. Daftar Variabel Lingkungan (`.env`)

Berikut adalah daftar lengkap seluruh variabel lingkungan yang didukung:

| Variabel `.env` | Tipe | Nilai Bawaan | Keterangan & Dampak |
| :--- | :---: | :---: | :--- |
| `SECURITY_MONITOR_ENABLED` | bool | `true` | Sakelar utama untuk pemindaian ancaman di middleware. Jika `false`, inspeksi ditiadakan. |
| `SECURITY_BLOCK_ENFORCEMENT`| bool | `true` | Penegakan blokir aktif. Jika `false`, IP terblokir tetap dicatat tetapi request tidak ditolak. |
| `SECURITY_BLOCKED_LOG_INTERVAL`| int | `10` | Jeda waktu (detik) pencatatan log untuk IP yang terus-menerus mencoba mengakses saat terblokir. |
| `SECURITY_AUTO_BLOCK_ENABLED`| bool | `true` | Mengaktifkan pemblokiran otomatis berbasis akumulasi skor ancaman berulang. |
| `SECURITY_AUTO_BLOCK_THRESHOLD`| int | `3` | Jumlah kejadian ancaman yang harus dicapai dalam kurun waktu sebelum IP diblokir. |
| `SECURITY_AUTO_BLOCK_WINDOW` | int | `10` | Rentang jendela waktu evaluasi auto-block (dalam menit). |
| `SECURITY_AUTO_BLOCK_DURATION`| int | `24` | Durasi pemblokiran otomatis (dalam jam). Masukkan `0` jika ingin memblokir permanen. |
| `SECURITY_INSTANT_BLOCK_ENABLED`| bool | `true` | Mengaktifkan blokir langsung pada percobaan pertama untuk signature berbahaya zero-tolerance. |
| `SECURITY_INSTANT_BLOCK_DURATION`| int | `720` | Durasi blokir instan (dalam jam; bawaan: 720 jam = 30 hari). Masukkan `0` untuk permanen. |
| `SECURITY_MAX_INSPECT_LENGTH`| int | `4000` | Batas maksimum panjang karakter string payload yang diinspeksi untuk mencegah ReDoS pada payload raksasa. |
| `SECURITY_BLOCK_SUSPICIOUS` | bool | `false` | Tolak langsung (HTTP 403) request yang memicu ancaman berlevel `critical` tanpa menunggu akumulasi. |
| `SECURITY_LOG_RETENTION_DAYS`| int | `90` | Masa simpan riwayat log keamanan (hari) sebelum dibersihkan otomatis oleh cron scheduler. |
| `SECURITY_ACCESS_LOG_PATHS` | string | `null` | Jalur absolut ke berkas access log web server Nginx/Apache (dipisahkan koma). |
| `SECURITY_ACCESS_LOG_MAX_LINES`| int | `500000` | Batas maksimum baris log yang dianalisis dalam satu kali eksekusi streaming scanner. |
| `SECURITY_ACCESS_LOG_AUTO_SCAN`| bool | `false` | Mengaktifkan tugas cron harian otomatis untuk memindai berkas log web server. |
| `SECURITY_ACCESS_LOG_AUTO_SCAN_HOURS`| int | `24` | Rentang waktu mundur (jam) yang dipindai oleh pemindai otomatis terjadwal. |
| `SECURITY_LOGIN_LOCKOUT_ENABLED`| bool | `true` | Mengaktifkan penguncian bertingkat (*stepped login lockout*) terhadap brute force. |
| `SECURITY_LOGIN_LOCKOUT_THRESHOLD`| int | `3` | Jumlah kegagalan otentikasi berturut-turut sebelum akun/IP dikunci sementara. |
| `SECURITY_LOGIN_LOCKOUT_BASE_MINUTES`| int | `1` | Durasi awal penguncian pada tier pertama (menit). |
| `SECURITY_LOGIN_LOCKOUT_MAX_MINUTES`| int | `30` | Batas maksimum durasi penguncian berjenjang (menit). |
| `SECURITY_LOGIN_LOCKOUT_DECAY_MINUTES`| int | `60` | Waktu tanpa percobaan gagal (menit) sebelum penghitung kegagalan direset ke nol. |
| `SECURITY_SERVER_SCAN_CACHE_MINUTES`| int | `10` | Durasi cache hasil pemindaian integritas dan berkas server (menit). |
| `SECURITY_SERVER_SCAN_MAX_FILES`| int | `20000` | Batas maksimum berkas yang diperiksa saat audit baseline integritas. |
| `SECURITY_RECENT_CHANGES_DAYS`| int | `7` | Rentang hari berkas baru/dimodifikasi yang dimasukkan ke laporan audit server. |
| `SECURITY_DISK_WARNING_PERCENT`| int | `20` | Ambang batas sisa kapasitas disk (%) untuk memicu peringatan (*warning*). |
| `SECURITY_DISK_CRITICAL_PERCENT`| int | `10` | Ambang batas sisa kapasitas disk (%) untuk memicu status genting (*critical*). |
| `SECURITY_MAX_ADMIN_ACCOUNTS`| int | `5` | Jumlah maksimum akun administrator yang wajar sebelum auditor memunculkan peringatan. |
| `SECURITY_LOG_SIZE_WARNING_MB`| int | `100` | Peringatan audit jika berkas `storage/logs/laravel.log` melebihi ukuran ini (MB). |
| `SECURITY_USER_MODEL` | string | `App\Models\User` | FQCN kelas Model Pengguna otentikasi di aplikasi host Anda. |
| `SECURITY_USERS_TABLE` | string | `users` | Nama tabel database untuk data pengguna. |
| `SECURITY_BLOCKED_IPS_TABLE`| string | `blocked_ips` | Nama tabel untuk karantina IP dan perangkat. |
| `SECURITY_LOGS_TABLE` | string | `security_logs` | Nama tabel untuk riwayat audit log keamanan. |
| `SECURITY_LOGIN_ATTEMPTS_TABLE`| string | `login_attempts` | Nama tabel untuk penghitung kegagalan login. |
| `SECURITY_IP_UNBLOCK_REQUESTS_TABLE`| string | `ip_unblock_requests` | Nama tabel untuk permohonan tiket banding buka blokir. |
| `SECURITY_USER_LOGINS_TABLE`| string | `user_logins` | Nama tabel untuk sesi dan riwayat login pengguna. |
| `SECURITY_TRUSTED_IPS_TABLE`| string | `trusted_ips` | Nama tabel untuk daftar IP terpercaya milik pengguna. |
| `SECURITY_ROUTES_ENABLED` | bool | `true` | Mengaktifkan rute headless REST API di bawah `/api/security/*`. |
| `SECURITY_ROUTES_PREFIX` | string | `api/security` | Awalan prefix URI untuk seluruh rute API paket. |
| `SECURITY_SCHEDULE_ENABLED` | bool | `true` | Mengaktifkan registrasi jadwal tugas cron otomatis (prune & heartbeat). |
| `SECURITY_PRUNE_SCHEDULE` | string | `02:30` | Jam eksekusi harian pembersihan log usang (format `HH:mm`). |
| `CAPTCHA_ENABLED` | bool | `true` | Sakelar aktivasi fitur generator pure SVG CAPTCHA. |
| `CAPTCHA_ON_LOGIN` | bool | `true` | Mewajibkan CAPTCHA pada proses login. |
| `CAPTCHA_LENGTH` | int | `5` | Jumlah karakter alfanumerik pada gambar CAPTCHA. |
| `CAPTCHA_DIFFICULTY` | string | `medium` | Tingkat distorsi noise dan garis interferensi: `low`, `medium`, `high`. |
| `CAPTCHA_TTL_SECONDS` | int | `300` | Masa berlaku token tantangan CAPTCHA (dalam detik, default 5 menit). |
| `SECURITY_SUPPORT_EMAIL` | string | `security@example.com` | Alamat email dukungan yang ditampilkan pada layar respon blokir. |
| `SECURITY_AUTO_REGISTER_MIDDLEWARE`| bool | `false` | Mendaftarkan middleware global secara otomatis saat boot aplikasi. |

---

## 2. Struktur Konfigurasi Inti (`config/security.php`)

### A. Whitelist Jaringan & IP Lokal
Konfigurasi `whitelist` memastikan IP internal, proxy terpercaya, dan subnet kantor tidak pernah diblokir meskipun melakukan pengujian pentest:

```php
'whitelist' => array_values(array_filter(array_map(
    'trim',
    explode(',', (string) env('SECURITY_WHITELIST', '127.0.0.1,::1'))
))),
```

### B. Signature Zero-Tolerance (`instant_block`)
Menentukan pola serangan mutlak yang langsung memblokir pelaku pada request pertama:

```php
'instant_block' => [
    'enabled' => (bool) env('SECURITY_INSTANT_BLOCK_ENABLED', true),
    'duration_hours' => (int) env('SECURITY_INSTANT_BLOCK_DURATION', 720), // 30 hari
    'skip_whitelisted' => true,
    'signatures' => [
        [
            'id' => 'webshell_upload',
            'label' => 'Percobaan upload webshell (null byte / double extension)',
            'target' => 'any',
            'patterns' => [
                '/\.php(?:[\x00\0]|%00)\.[a-z0-9_-]+/i',
                '/\.php\.(?:jpe?g|png|gif|webp|svg|bmp|ico|pdf|zip|rar|tar|gz|7z|docx?|xlsx?)/i',
            ],
        ],
        // ... signatures lainnya
    ],
],
```

### C. Pola Aturan WAF Reguler (`rules`)
Pola aturan untuk SQLi, XSS, Path Traversal, Command Injection, dan SSRF yang diakumulasikan ke dalam penilaian ancaman bersyarat:

```php
'rules' => [
    [
        'id' => 'sql_injection',
        'label' => 'Indikasi SQL Injection',
        'level' => 'critical',
        'patterns' => [
            '/\bunion\s+(?:all\s+)?select\b/i',
            '/\bselect\b.+\bfrom\b.+\bwhere\b/is',
            // ...
        ],
    ],
    // ...
],
```

---

## 3. Preset Konfigurasi Lingkungan

### 🛠 Preset Pengembangan Lokal (`.env.local`)
Pada lingkungan development lokal, Anda dapat melonggarkan blokir agar tidak mengganggu proses pengujian dan debugging:

```dotenv
SECURITY_MONITOR_ENABLED=true
SECURITY_BLOCK_ENFORCEMENT=false
SECURITY_AUTO_BLOCK_ENABLED=false
SECURITY_INSTANT_BLOCK_ENABLED=false
SECURITY_BLOCK_SUSPICIOUS=false
CAPTCHA_ENABLED=false
SECURITY_WHITELIST=127.0.0.1,::1,192.168.*.*
```

### 🚀 Preset Produksi (`.env.production`)
Di server produksi, seluruh perlindungan diaktifkan penuh dengan pembersihan log berkala dan toleransi ketat:

```dotenv
SECURITY_MONITOR_ENABLED=true
SECURITY_BLOCK_ENFORCEMENT=true
SECURITY_AUTO_BLOCK_ENABLED=true
SECURITY_AUTO_BLOCK_THRESHOLD=3
SECURITY_AUTO_BLOCK_WINDOW=10
SECURITY_AUTO_BLOCK_DURATION=24
SECURITY_INSTANT_BLOCK_ENABLED=true
SECURITY_INSTANT_BLOCK_DURATION=720
SECURITY_BLOCK_SUSPICIOUS=false
SECURITY_LOG_RETENTION_DAYS=90
SECURITY_ACCESS_LOG_AUTO_SCAN=true
SECURITY_ACCESS_LOG_PATHS=/var/log/nginx/access.log
SECURITY_LOGIN_LOCKOUT_ENABLED=true
SECURITY_SCHEDULE_ENABLED=true
CAPTCHA_ENABLED=true
CAPTCHA_ON_LOGIN=true
SECURITY_SUPPORT_EMAIL=security@domain-anda.com
```
