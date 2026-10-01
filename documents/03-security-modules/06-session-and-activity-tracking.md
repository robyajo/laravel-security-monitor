# 06. Pelacakan Sesi & Pengguna Realtime

Mengetahui siapa saja yang sedang aktif menggunakan aplikasi, dari perangkat apa, dan dari lokasi IP mana adalah bagian penting dari audit keamanan organisasi.

Modul `UserLoginService` dan middleware `TrackUserActivity` menyediakan pemantauan aktivitas pengguna secara *realtime* tanpa membebani performa basis data.

---

## 1. Throttled Activity Heartbeat

Jika setiap request HTTP pengguna yang terotentikasi langsung menulis ke tabel database untuk memperbarui status `last_activity_at`, database akan mengalami lonjakan penulisan I/O (*write amplification*) pada aplikasi yang memiliki banyak pengguna aktif.

Middleware `TrackUserActivity` menerapkan mekanisme **Cache Throttle**:
1. Saat request pengguna masuk, sistem memeriksa cache key: `user_act_{userId}`.
2. Jika key sudah ada di cache, request langsung diteruskan tanpa menyentuh tabel database.
3. Jika key belum ada, sistem memperbarui `last_activity_at` di tabel `user_logins` dan menyimpan cache key tersebut selama **45 detik**.
4. Dengan cara ini, penulisan ke database dibatasi **maksimal 1 kali per 45 detik per pengguna**.

---

## 2. Pengguna Aktif Realtime (`active_users`)

Sistem menganggap seorang pengguna sedang daring (*online*) jika memiliki aktivitas dalam kurun waktu **5 menit terakhir** (`active(5)`).

### Mengambil Data via REST API
```http
GET /api/security/user-sessions/realtime
Authorization: Bearer <admin-token>
```

**Respons JSON**:
```json
{
    "success": true,
    "online_count": 3,
    "active_users": [
        {
            "id": 12,
            "user_id": 4,
            "ip_address": "103.11.22.45",
            "browser": "Chrome 128.0",
            "operating_system": "Windows 11",
            "device_name": "Laptop Kantor",
            "last_activity_at": "2026-10-02T00:15:30Z",
            "user": {
                "id": 4,
                "name": "Budi Santoso",
                "email": "budi@pekanbaru.go.id"
            }
        }
    ]
}
```

---

## 3. Pemutusan Paksa Sesi Pengguna (Force Logout)

Jika administrator mendeteksi adanya sesi mencurigakan (misalnya login dari IP luar negeri yang tidak dikenali), admin dapat memutus sesi tersebut secara paksa:

```http
DELETE /api/security/user-sessions/session/{sessionId}
Authorization: Bearer <admin-token>
```

Layanan `UserLoginService::logoutSession($sessionId)` akan:
1. Menghapus sesi tersebut dari storage session Laravel (driver `file`, `database`, `redis`, atau `memcached`).
2. Menghapus entri `user_logins` terkait.
3. Mengharuskan pengguna tersebut melakukan login ulang pada perangkat yang bersangkutan.

---

## 4. Alamat IP Terpercaya (Trusted IPs)

Pengguna dapat mendaftarkan alamat IP rumah atau kantor mereka sebagai IP terpercaya melalui endpoint:

```http
POST /api/security/trusted-ips/save-my-ip
Authorization: Bearer <user-token>
Content-Type: application/json

{
    "device_name": "PC Rumah"
}
```

IP yang telah terdaftar di tabel `trusted_ips` dapat digunakan oleh aplikasi host untuk:
- Melewati kewajiban tantangan Two-Factor Authentication (2FA) berulang.
- Mengirimkan notifikasi peringatan jika akun diakses dari IP yang *bukan* IP terpercaya.
- Menjadi pertimbangan otomatis saat mengevaluasi skor ancaman.
