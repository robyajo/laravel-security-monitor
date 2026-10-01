# 03. Endpoint Pengguna Terautentikasi

Endpoint pada bagian ini mewajibkan pengguna telah melakukan autentikasi (`auth` middleware) melalui sesi cookie web (Laravel Sanctum/Breeze) atau Bearer token.

---

## 1. Simpan IP Saya sebagai IP Terpercaya (Save My IP)

Memungkinkan pengguna yang sedang login untuk mendaftarkan alamat IP dan perangkat yang sedang mereka gunakan ke dalam daftar `trusted_ips` milik mereka.

- **Metode**: `POST`
- **URI**: `/api/security/trusted-ips/save-my-ip`
- **Headers**:
  - `Authorization: Bearer <user-token>`
  - `Content-Type: application/json`
  - `Accept: application/json`
  - `X-Device-Id`: *Opsional, UUID fingerprint perangkat*
  - `X-Local-Ip`: *Opsional, IP LAN lokal*
- **Body JSON**:
  ```json
  {
      "device_name": "MacBook Pro M3 Kantor"
  }
  ```

### Contoh Request cURL:
```bash
curl -X POST "https://domain-anda.com/api/security/trusted-ips/save-my-ip" \
     -H "Authorization: Bearer 1|abc123xyz..." \
     -H "Content-Type: application/json" \
     -H "Accept: application/json" \
     -d '{"device_name": "Laptop Kerja Utama"}'
```

### Contoh Respons Berhasil (HTTP 200 OK):
```json
{
    "success": true,
    "message": "IP 103.11.22.45 berhasil ditambahkan sebagai IP terpercaya Anda.",
    "data": {
        "id": 8,
        "user_id": 4,
        "ip_address": "103.11.22.45",
        "local_ip": "192.168.1.15",
        "device_id": "dev-uuid-001",
        "device_name": "Laptop Kerja Utama",
        "operating_system": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
        "is_active": true,
        "verified_at": "2026-10-02T00:30:00.000000Z"
    }
}
```

---

## 2. Manfaat & Penggunaan di Aplikasi Host

Setelah IP terdaftar di tabel `trusted_ips`:
1. Aplikasi host dapat memeriksa keterpercayaan IP melalui relasi Eloquent atau service:
   ```php
   use Internal\SecurityMonitor\Services\UserLoginService;

   $isTrusted = app(UserLoginService::class)->isIpTrusted(
       ip: $request->ip(),
       userId: $user->id,
       deviceId: $request->header('X-Device-Id')
   );
   ```
2. Melewati kewajiban tantangan Two-Factor Authentication (2FA) berulang pada perangkat yang sama.
3. Memberikan alert keamanan lewat email jika terjadi login dari perangkat asing yang belum terdaftar.
