# 04. Model Database & Dynamic Decoupling

Salah satu prinsip desain fundamental dari **`robyajo/laravel-security-monitor`** adalah **Loose Coupling** (keterikatan longgar). Paket ini tidak pernah mengasumsikan model `User` bawaan Laravel atau nama tabel yang paten, melainkan menyelesaikan semuanya secara dinamis melalui konfigurasi.

---

## 1. Konvensi Nama Tabel Dinamis

Semua model Eloquent paket meng-override metode `getTable()` untuk membaca nama tabel dari konfigurasi `config/security.php`:

```php
public function getTable(): string
{
    return config('security.table_names.blocked_ips', parent::getTable());
}
```

Hal ini memungkinkan Anda mengubah nama tabel di berkas `.env` jika terdapat benturan nama (*table name conflict*) dengan aplikasi eksisting Anda:

```dotenv
SECURITY_BLOCKED_IPS_TABLE=waf_blocked_ips
SECURITY_LOGS_TABLE=waf_audit_logs
SECURITY_LOGIN_ATTEMPTS_TABLE=auth_lockouts
SECURITY_IP_UNBLOCK_REQUESTS_TABLE=waf_appeal_tickets
SECURITY_USER_LOGINS_TABLE=auth_user_sessions
SECURITY_TRUSTED_IPS_TABLE=auth_trusted_devices
```

---

## 2. Rincian Model Eloquent

### A. `BlockedIp` (`Internal\SecurityMonitor\Models\BlockedIp`)
Menyimpan data entitas yang sedang diblokir atau pernah diblokir.

| Kolom | Tipe Data | Deskripsi |
| :--- | :--- | :--- |
| `id` | BigIncrements | Primary key |
| `ip_address` | String(45) | Alamat IPv4 atau IPv6 |
| `local_ip` | String(45), nullable | Alamat IP LAN lokal perangkat |
| `device_id` | String(100), nullable | UUID / Fingerprint perangkat |
| `block_scope`| Enum('ip', 'device') | Cakupan blokir: seluruh IP publik atau perangkat tertentu |
| `reason` | String(255) | Alasan pemblokiran (nama signature / catatan admin) |
| `notes` | Text, nullable | Catatan internal pengelola sistem |
| `source` | Enum('manual', 'auto', 'instant') | Asal pemblokiran (admin atau deteksi otomatis WAF) |
| `blocked_by` | BigInteger, nullable | ID user admin yang melakukan blokir (jika manual) |
| `blocked_at` | DateTime | Waktu pemblokiran dimulai |
| `expires_at` | DateTime, nullable | Waktu kedaluwarsa (`null` = blokir permanen) |
| `is_active` | Boolean | Status aktifasi blokir (`true` = diblokir, `false` = nonaktif) |
| `hit_count` | UnsignedBigInteger | Berapa kali entitas ini mencoba mengakses saat diblokir |
| `last_hit_at`| DateTime, nullable | Waktu percobaan akses terakhir saat terblokir |

**Eloquent Scopes Tersedia**:
- `BlockedIp::active()`: Mengambil entri yang `is_active = true` dan belum kedaluwarsa (`expires_at > now()` atau `expires_at is null`).
- `BlockedIp::expired()`: Mengambil entri yang masa berlakunya telah habis.
- `BlockedIp::permanent()`: Mengambil entri blokir yang permanen (`expires_at is null`).

---

### B. `SecurityLog` (`Internal\SecurityMonitor\Models\SecurityLog`)
Menyimpan rekam jejak setiap ancaman keamanan yang terdeteksi oleh WAF.

| Kolom | Tipe Data | Deskripsi |
| :--- | :--- | :--- |
| `id` | BigIncrements | Primary key |
| `event_type` | String(50) | Tipe kejadian: `threat_detected`, `blocked_attempt`, `admin_bypass`, dll. |
| `threat_level`| Enum('low', 'medium', 'high', 'critical') | Tingkat bahaya ancaman |
| `rule_id` | String(50) | Pengenal aturan (misal `sql_injection`, `webshell_upload`) |
| `rule_label` | String(100) | Label deskriptif bahasa manusia |
| `ip_address` | String(45) | IP klien |
| `device_id` | String(100), nullable | Fingerprint perangkat klien |
| `local_ip` | String(45), nullable | IP lokal perangkat |
| `user_id` | BigInteger, nullable | ID user yang terautentikasi (jika ada) |
| `user_agent` | Text, nullable | User-Agent klien |
| `method` | String(10) | HTTP Method (`GET`, `POST`, `PUT`, dll.) |
| `path` | String(255) | Request URI path |
| `query_string`| Text, nullable | Parameter URL mentah |
| `evidence` | Text, nullable | Potongan payload atau string bukti serangan |
| `was_blocked`| Boolean | Apakah request ini berujung pada penolakan akses |
| `action_taken`| String(50), nullable | Tindakan yang diambil (`instant_block`, `auto_blocked`, `rejected`) |
| `created_at` | DateTime | Waktu pencatatan |

---

### C. `LoginAttempt` (`Internal\SecurityMonitor\Models\LoginAttempt`)
Melacak kegagalan otentikasi untuk mitigasi brute force bertingkat (*stepped lockout*).

| Kolom | Tipe Data | Deskripsi |
| :--- | :--- | :--- |
| `id` | BigIncrements | Primary key |
| `email` | String(150), nullable | Email akun yang dicoba |
| `ip_address` | String(45) | IP sumber kegagalan |
| `device_id` | String(100), nullable | Fingerprint perangkat |
| `attempts` | Integer | Jumlah kegagalan berturut-turut pada tier saat ini |
| `level` | Integer | Tingkatan penalti lockout (1 s/d 6+) |
| `locked_until`| DateTime, nullable | Waktu berakhirnya penguncian |
| `last_attempt_at`| DateTime | Waktu percobaan gagal terakhir |

---

### D. `IpUnblockRequest` (`Internal\SecurityMonitor\Models\IpUnblockRequest`)
Menyimpan tiket banding yang diajukan oleh pengguna publik yang terblokir.

| Kolom | Tipe Data | Deskripsi |
| :--- | :--- | :--- |
| `id` | BigIncrements | Primary key |
| `ticket_number` | String(30), unique | Nomor tiket unik (format `TKT-XXXXXXXX`) |
| `ip_address` | String(45) | IP pemohon |
| `local_ip` | String(45), nullable | IP lokal pemohon |
| `device_id` | String(100), nullable | Device ID pemohon |
| `name` | String(100) | Nama lengkap pemohon |
| `email` | String(150) | Email aktif pemohon untuk konfirmasi |
| `phone` | String(30), nullable | Nomor kontak pemohon |
| `reason` | Text | Penjelasan alasan permohonan banding |
| `status` | Enum('pending', 'approved', 'rejected') | Status tiket saat ini |
| `admin_notes`| Text, nullable | Catatan dari administrator saat merespons |
| `resolved_by`| BigInteger, nullable | ID user administrator yang memproses |
| `resolved_at`| DateTime, nullable | Waktu penyelesaian tiket |
| `blocked_ip_id`| BigInteger, nullable | Foreign key ke tabel `blocked_ips` |

**Eloquent Scopes**: `pending()`, `approved()`, `rejected()`.

---

### E. `UserLogin` & `TrustedIp`
- **`UserLogin`**: Menyimpan riwayat setiap login yang berhasil, mencatat user agent yang diparse (nama browser, sistem operasi), sesi aktif (`session_id`), dan stempel waktu aktivitas terakhir (`last_activity_at`).
  - Scope `active(int $minutes = 5)`: Mengambil pengguna yang memiliki aktivitas dalam N menit terakhir (realtime online users).
- **`TrustedIp`**: Menyimpan daftar IP dan perangkat terpercaya per pengguna yang telah diverifikasi.

---

## 3. Integrasi Trait `HasSecurityRelations`

Untuk menghubungkan model `User` aplikasi Anda dengan model-model di atas, cukup gunakan trait `Internal\SecurityMonitor\Concerns\HasSecurityRelations`:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Internal\SecurityMonitor\Concerns\HasSecurityRelations;

class User extends Authenticatable
{
    use HasSecurityRelations;
}
```

Metode yang tersedia:
```php
$user = User::find(1);

// Riwayat sesi login
$logins = $user->logins;

// Daftar IP terpercaya
$trustedIps = $user->trustedIps;

// Log keamanan yang terkait
$securityLogs = $user->securityLogs;

// Entri IP yang diblokir oleh admin ini
$blockedByMe = $user->blockedIps;

// Tiket banding yang diselesaikan oleh admin ini
$resolvedTickets = $user->resolvedTickets;
```
