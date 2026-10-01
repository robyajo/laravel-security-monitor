# 04. Endpoint Administrator REST API

Seluruh endpoint pada dokumen ini dilindungi oleh middleware ganda: **`auth`** (pengguna harus login) dan **`security.admin`** (`EnsureSecurityAdmin`).

---

## 1. Log Keamanan (Security Logs)

### A. Ambil Daftar Log Keamanan (Index & Statistik)
Mengambil data log terpaginasi lengkap dengan rincian statistik, level breakdown, top attacker, dan tren ancaman.

- **Metode**: `GET`
- **URI**: `/api/security/logs`
- **Query Parameters**:
  - `page` *(int)*: Nomor halaman (default: 1).
  - `per_page` *(int)*: Jumlah per halaman (default: 25, maks: 100).
  - `search` *(string)*: Cari berdasarkan IP, path, evidence, rule label, atau user agent.
  - `level` *(string)*: Filter tingkat ancaman (`low`, `medium`, `high`, `critical`).
  - `event_type` *(string)*: Filter jenis event (`threat_detected`, `blocked_attempt`, dll).
  - `was_blocked` *(bool)*: Filter apakah request berujung blokir (`true` atau `false`).
  - `range` *(string)*: Rentang agregasi grafik tren (`week`, `month`, `year`).

#### Contoh Respons Berhasil (HTTP 200):
```json
{
    "success": true,
    "data": {
        "current_page": 1,
        "data": [
            {
                "id": 142,
                "event_type": "threat_detected",
                "threat_level": "critical",
                "rule_id": "ssti",
                "rule_label": "Percobaan Server-Side Template Injection (SSTI)",
                "ip_address": "198.51.100.77",
                "device_id": "dev-01",
                "method": "GET",
                "path": "/search",
                "query_string": "q=%7B%7B7*7%7D%7D",
                "evidence": "q={{7*7}}",
                "was_blocked": true,
                "action_taken": "instant_block",
                "created_at": "2026-10-02T00:25:00.000000Z"
            }
        ],
        "total": 142
    },
    "stats": {
        "total_threats": 142,
        "blocked_threats": 89,
        "critical_threats": 34
    },
    "level_breakdown": {
        "critical": 34,
        "high": 45,
        "medium": 50,
        "low": 13
    },
    "top_attackers": [
        { "ip_address": "198.51.100.77", "hits": 24 }
    ],
    "trend": [
        { "date": "2026-09-25", "count": 12 },
        { "date": "2026-09-26", "count": 19 }
    ]
}
```

### B. Bersihkan Seluruh Log (Clear All Logs)
- **Metode**: `DELETE`
- **URI**: `/api/security/logs/clear`

---

## 2. Pengelolaan Karantina IP (Blocked IPs)

### A. Ambil Daftar IP yang Diblokir
- **Metode**: `GET`
- **URI**: `/api/security/blocked-ips`
- **Query Parameters**:
  - `search` *(string)*: Cari IP, device ID, catatan, atau alasan.
  - `status` *(string)*: `active`, `expired`, atau `permanent`.
  - `per_page` *(int)*: Jumlah per halaman (maks: 100).

### B. Blokir IP / Perangkat Baru Secara Manual
- **Metode**: `POST`
- **URI**: `/api/security/blocked-ips`
- **Body JSON**:
  ```json
  {
      "ip_address": "203.0.113.50",
      "device_id": "device-uuid-optional",
      "local_ip": "192.168.1.55",
      "block_scope": "ip",
      "reason": "Scanning celah direktori admin berulang kali",
      "notes": "Tiket insiden #SEC-8812",
      "duration_hours": 48,
      "is_permanent": false
  }
  ```
- **Validasi Khusus**:
  - Tidak dapat memblokir IP sendiri (`resolveClientIp`).
  - Tidak dapat memblokir IP yang berada dalam whitelist.

### C. Detail Blokir IP Beserta Log Terkait
- **Metode**: `GET`
- **URI**: `/api/security/blocked-ips/{id}`
- Mengembalikan entri `BlockedIp` beserta 20 entri `SecurityLog` terakhir dari IP tersebut.

### D. Beralih Status Aktif/Nonaktif (Toggle)
- **Metode**: `PATCH`
- **URI**: `/api/security/blocked-ips/{id}/toggle`

### E. Hapus Blokir (Unblock)
- **Metode**: `DELETE`
- **URI**: `/api/security/blocked-ips/{id}`

---

## 3. Audit Server & Baseline Integritas

### A. Ambil Laporan Audit Server
- **Metode**: `GET`
- **URI**: `/api/security/server?refresh=true`
- **Informasi yang Dikembalikan**:
  - `environment`: Status `APP_DEBUG`, HTTPS enforcement, session secure cookie, disk free space %.
  - `integrity`: Laporan baseline SHA-256 (berkas dimodifikasi, hilang, atau baru).
  - `suspicious_files`: Daftar berkas berbahaya (webshell, skrip PHP di folder public/storage).
  - `scheduler`: Status heartbeat cron Laravel.
  - `lockouts`: Daftar akun yang sedang terkunci akibat kegagalan login.

### B. Buat Baseline Integritas Baru (SHA-256)
- **Metode**: `POST`
- **URI**: `/api/security/server/baseline`

### C. Hapus Baseline Integritas
- **Metode**: `DELETE`
- **URI**: `/api/security/server/baseline`

### D. Hapus Berkas Mencurigakan (Safe Deletion)
- **Metode**: `DELETE`
- **URI**: `/api/security/server/suspicious-files`
- **Body JSON**:
  ```json
  {
      "file_path": "public/uploads/shell.php"
  }
  ```
- **Proteksi**: Menolak path traversal (`..`), menolak penghapusan berkas di luar `base_path()`, dan melindungi berkas vital (`public/index.php`, `.env`, dll).

### E. Lepaskan Lockout Login Pengguna
- **Metode**: `DELETE`
- **URI**: `/api/security/lockouts/{id}`

---

## 4. Sesi Pengguna & IP Terpercaya (User Sessions)

### A. Daftar Sesi Pengguna & Online Count
- **Metode**: `GET`
- **URI**: `/api/security/user-sessions`
- Mengembalikan riwayat login pengguna (`logins`), daftar `trusted_ips`, dan jumlah pengguna aktif saat ini (`online_count`).

### B. Pemantauan Realtime Pengguna Aktif
- **Metode**: `GET`
- **URI**: `/api/security/user-sessions/realtime`

### C. Putus Paksa Sesi Pengguna (Force Logout)
- **Metode**: `DELETE`
- **URI**: `/api/security/user-sessions/session/{sessionId}`

### D. Hapus IP Terpercaya
- **Metode**: `DELETE`
- **URI**: `/api/security/trusted-ips/{id}`

---

## 5. Manajemen Tiket Banding (Appeal Tickets)

### A. Daftar Tiket Banding
- **Metode**: `GET`
- **URI**: `/api/security/unblock-tickets?status=pending`

### B. Tanggapi Tiket (Approve / Reject)
- **Metode**: `POST`
- **URI**: `/api/security/unblock-tickets/{id}/respond`
- **Body JSON**:
  ```json
  {
      "action": "approve",
      "admin_notes": "Blokir dibuka setelah validasi identitas via WhatsApp dinas."
  }
  ```
- **Aksi Otomatis**: Jika `action` adalah `approve`, sistem langsung memanggil `unblockIp()` untuk membuka karantina pada IP/perangkat terkait.

### C. Hapus Arsip Tiket
- **Metode**: `DELETE`
- **URI**: `/api/security/unblock-tickets/{id}`
