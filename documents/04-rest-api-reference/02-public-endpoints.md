# 02. Endpoint REST API Publik

Endpoint berikut dapat diakses oleh publik tanpa memerlukan token autentikasi. Endpoint ini dirancang khusus untuk memfasilitasi mekanisme pemulihan mandiri bagi pengguna yang terblokir (Tiket Banding).

---

## 1. Pengajuan Tiket Banding Buka Blokir (Submit Appeal Ticket)

Memungkinkan klien yang terblokir mengajukan permohonan banding kepada administrator.

- **Metode**: `POST`
- **URI**: `/api/security/unblock-tickets/submit`
- **Headers**:
    - `Content-Type: application/json`
    - `Accept: application/json`
    - `X-Device-Id`: _Opsional, UUID fingerprint perangkat_
    - `X-Local-Ip`: _Opsional, IP LAN lokal perangkat_
- **Body JSON**:
    ```json
    {
        "name": "Budi Santoso",
        "email": "budi.santoso@pekanbaru.go.id",
        "phone": "081234567890",
        "reason": "Saya sedang mencoba mengunggah dokumen PDF laporan dinas, namun tiba-tiba koneksi terputus dan muncul pesan terblokir dengan referensi SEC-9A8B7C6D."
    }
    ```

### Aturan Validasi:

- `name`: Wajib, string, maks 100 karakter.
- `email`: Wajib, format email valid, maks 150 karakter.
- `phone`: Opsional, string, maks 30 karakter.
- `reason`: Wajib, string, maks 1000 karakter.

### Contoh Respons Berhasil (HTTP 201 Created):

```json
{
    "success": true,
    "message": "Permohonan pembukaan blokir berhasil diajukan.",
    "ticket_number": "TKT-AB82C71E",
    "data": {
        "id": 5,
        "ticket_number": "TKT-AB82C71E",
        "ip_address": "103.11.22.45",
        "name": "Budi Santoso",
        "email": "budi.santoso@pekanbaru.go.id",
        "status": "pending",
        "created_at": "2026-10-02T00:20:00.000000Z"
    }
}
```

### Contoh Respons Terkena Cooldown (HTTP 429 Too Many Requests):

```json
{
    "success": false,
    "message": "Anda sudah memiliki tiket permohonan yang sedang diproses. Mohon tunggu review administrator.",
    "ticket_number": "TKT-AB82C71E"
}
```

---

## 2. Cek Status Tiket Banding (Check Ticket Status)

Melihat status permohonan banding menggunakan nomor tiket unik.

- **Metode**: `GET`
- **URI**: `/api/security/unblock-tickets/check/{ticketNumber}`
- **Headers**:
    - `Accept: application/json`

### Contoh Request:

```bash
curl -X GET "https://domain-anda.com/api/security/unblock-tickets/check/TKT-AB82C71E"
```

### Contoh Respons Berhasil (HTTP 200):

```json
{
    "success": true,
    "data": {
        "ticket_number": "TKT-AB82C71E",
        "status": "approved",
        "created_at": "2026-10-02T00:20:00.000000Z",
        "resolved_at": "2026-10-02T00:35:10.000000Z",
        "admin_notes": "Identitas staf terverifikasi, blokir perangkat telah dicabut."
    }
}
```

### Nilai Status Kemungkinan:

- `pending`: Tiket baru masuk dan belum diperiksa administrator.
- `approved`: Permohonan disetujui, blokir pada IP/perangkat telah dicabut.
- `rejected`: Permohonan ditolak oleh administrator, blokir tetap dipertahankan.
