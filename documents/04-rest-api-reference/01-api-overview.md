# 01. Konvensi & Spesifikasi Headless REST API

Seluruh fungsionalitas manajemen paket **`robyajo/laravel-security-monitor`** diekspos melalui antarmuka REST API JSON standar tanpa keterikatan antarmuka pengguna (headless). Hal ini memungkinkan paket diintegrasikan ke dashboard apa pun: React, Vue, Livewire, Filament, Inertia, Blade kustom, ataupun aplikasi seluler.

---

## 1. Konvensi URL & Awalan Rute

Secara default, seluruh endpoint berada di bawah prefix:

```
/api/security/*
```

Prefix ini dapat diubah melalui berkas `.env` menggunakan variabel:

```dotenv
SECURITY_ROUTES_PREFIX=api/v1/security
```

---

## 2. Format Respon Standar (JSON Envelope)

Seluruh respons dari endpoint API dikembalikan dalam format envelope JSON konsisten:

### A. Respons Berhasil (Success Envelope)

```json
{
    "success": true,
    "message": "Operasi berhasil dieksekusi.",
    "data": { ... },
    "stats": { ... }
}
```

### B. Respons Kesalahan Validasi (HTTP 422)

```json
{
    "message": "Data yang diberikan tidak valid.",
    "errors": {
        "ip_address": ["Alamat IP tidak valid."]
    }
}
```

### C. Respons Ditolak / Dilarang (HTTP 403)

```json
{
    "success": false,
    "message": "Akses ditolak. Alamat IP atau perangkat Anda diblokir karena terdeteksi aktivitas mencurigakan.",
    "reason": "Percobaan Server-Side Template Injection (SSTI)",
    "ip_address": "198.51.100.77",
    "device_id": "dev-uuid-001",
    "local_ip": "192.168.1.15",
    "block_scope": "device",
    "reference_id": "SEC-A1B2C3D4",
    "expires_at": "2026-11-01T00:00:00Z",
    "blocked": true
}
```

---

## 3. Autentikasi & Otorisasi

Endpoint API dibagi menjadi 3 tingkat akses:

| Kategori Akses               | Middleware yang Digunakan | Penjelasan                                                                 |
| :--------------------------- | :------------------------ | :------------------------------------------------------------------------- |
| **Publik (Public)**          | `api`                     | Dapat diakses oleh siapa saja tanpa autentikasi (Pengajuan Tiket Banding). |
| **Pengguna (Authenticated)** | `auth`                    | Memerlukan login pengguna sah (misal menyimpan IP terpercaya sendiri).     |
| **Administrator (Admin)**    | `auth` + `security.admin` | Hanya dapat diakses oleh user berwewenang administrator.                   |

### Evaluasi Hak Akses Administrator (`EnsureSecurityAdmin`)

Middleware `EnsureSecurityAdmin` mengevaluasi hak akses dengan urutan sebagai berikut:

1. Memeriksa Gate Laravel: `Gate::allows('manage-security-monitor')`.
2. Jika gate belum didefinisikan secara kustom, memeriksa metode `$user->isAdmin()`.
3. Memeriksa apakah kolom peran `$user->role` bernilai `'admin'` atau `'superadmin'`.
4. Memeriksa apakah kolom boolean `$user->is_admin === true`.
5. Jika seluruh kondisi di atas tidak terpenuhi, request ditolak dengan **HTTP 403 Forbidden**.

---

## 4. Kode Status HTTP (HTTP Status Codes)

| Kode                  | Arti                   | Penggunaan di Paket                                                   |
| :-------------------- | :--------------------- | :-------------------------------------------------------------------- |
| **200 OK**            | Permintaan Berhasil    | Pengambilan data (GET), toggle status, hapus entri.                   |
| **201 Created**       | Data Berhasil Dibuat   | Blokir IP baru (POST), pengajuan tiket banding.                       |
| **401 Unauthorized**  | Belum Login            | Token tidak disertakan atau sesi telah habis.                         |
| **403 Forbidden**     | Akses Ditolak          | Pengguna non-admin mengakses API admin, atau klien yang diblokir WAF. |
| **404 Not Found**     | Data Tidak Ditemukan   | ID blokir, log, atau nomor tiket tidak ditemukan di database.         |
| **422 Unprocessable** | Validasi Gagal         | Format IP salah, mencoba memblokir IP sendiri atau IP whitelist.      |
| **429 Rate Limited**  | Terlalu Banyak Request | Mengajukan lebih dari 1 tiket banding dalam 30 menit.                 |
