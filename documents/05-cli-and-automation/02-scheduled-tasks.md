# 02. Tugas Terjadwal (Cron & Scheduler)

`SecurityMonitorServiceProvider` menyertakan registrasi otomatis ke sistem scheduler bawaan Laravel (`Illuminate\Console\Scheduling\Schedule`). Tugas-tugas ini beroperasi secara otonom di latar belakang untuk menjaga higienitas basis data dan integritas server.

---

## 1. Tugas Terjadwal Bawaan

Jika `SECURITY_SCHEDULE_ENABLED=true` (default), tugas berikut otomatis aktif:

### A. Pembersihan Log Kedaluwarsa Harian (`security:prune-logs`)
- **Jadwal**: Harian pada jam yang ditentukan oleh `SECURITY_PRUNE_SCHEDULE` (default: **02:30 pagi**).
- **Aksi**: Menghapus entri `security_logs` yang lebih tua dari `SECURITY_LOG_RETENTION_DAYS` (default: 90 hari) agar ukuran database tidak membengkak seiring waktu.

### B. Scheduler Heartbeat (`security-heartbeat`)
- **Jadwal**: Setiap menit (`everyMinute()`).
- **Aksi**: Menuliskan stempel waktu ISO-8601 ke cache dengan key `ServerSecurityService::HEARTBEAT_KEY`.
- **Fungsi**: Laporan audit server (`/api/security/server`) menggunakan heartbeat ini untuk mendeteksi apakah cron server Anda berjalan normal atau mati/macet.

### C. Pemindaian Log Akses Web Server Otomatis
- **Jadwal**: Harian pada pukul **03:00 pagi**.
- **Aktivasi**: Aktif jika `SECURITY_ACCESS_LOG_AUTO_SCAN=true`.
- **Aksi**: Menjalankan:
  ```bash
  php artisan security:scan-logs --import --min-level=high --since="24 hours ago"
  ```
  Menyerap seluruh temuan ancaman dari log web server ke basis data audit keamanan.

---

## 2. Mengonfigurasi Crontab Server Produksi

Agar tugas terjadwal Laravel dapat berjalan, pastikan baris cron Laravel telah terpasang di server Anda:

Buka crontab pengguna web (misal `www-data` atau `cpanel`):
```bash
crontab -e
```

Tambahkan baris berikut:
```cron
* * * * * cd /var/www/aplikasi-anda && php artisan schedule:run >> /dev/null 2>&1
```

---

## 3. Menjalankan Scheduler Secara Lokal / Docker

Untuk menguji tugas terjadwal di lingkungan pengembangan lokal:
```bash
php artisan schedule:work
```
Perintah ini akan menjalankan scheduler di latar belakang setiap 60 detik tanpa perlu mengatur crontab sistem operasi.
