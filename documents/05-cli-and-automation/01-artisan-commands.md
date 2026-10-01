# 01. Referensi Perintah Artisan CLI

Paket menyertakan kumpulan perintah Artisan CLI untuk administrasi, otomasi pemindaian, dan pemeliharaan server secara mandiri.

---

## 1. `security:install`
Menginisialisasi paket, mempublikasikan konfigurasi, migrasi, dan konfigurasi Nginx hardened WAF.

```bash
php artisan security:install [options]
```

### Opsi:
- `--force`: Menimpa berkas yang sudah ada sebelumnya.
- `--without-nginx`: Melewatkan publikasi berkas `nginx.conf`.

---

## 2. `security:scan-logs`
Memindai berkas log web server (Apache/Nginx) secara streaming, mendeteksi serangan yang ditolak di level web server, mengimpor ke tabel log keamanan, atau langsung memblokir IP penyerang zero-tolerance.

```bash
php artisan security:scan-logs [options]
```

### Opsi:
- `--file=*`: Berkas log yang diperiksa (dapat ditentukan lebih dari satu kali, misal: `--file=/var/log/nginx/access.log --file=/var/log/nginx/access.log.1`).
- `--ip=`: Memfilter analisis hanya untuk satu alamat IP penyerang tertentu.
- `--since=`: Membatasi baris sejak waktu tertentu (misal: `"2 days ago"` atau `"2026-10-01 00:00"`).
- `--until=`: Membatasi baris hingga waktu tertentu.
- `--min-level=`: Saring level ancaman minimal (`low`, `medium`, `high`, `critical`).
- `--top=20`: Jumlah IP penyerang teratas yang ditampilkan di tabel ringkasan.
- `--samples`: Menampilkan contoh URI request yang mencurigakan untuk setiap IP.
- `--json`: Mengeluarkan hasil analisis dalam format JSON murni (cocok untuk pipeline SIEM / alerting).
- `--import`: Menyimpan temuan ke tabel database `security_logs`.
- `--block`: Memblokir otomatis IP yang memicu signature zero-tolerance.
- `--dry-run`: Mode simulasi: menampilkan apa saja yang akan diblokir/diimpor tanpa mengubah data apa pun di database.

### Contoh Skenario:
```bash
# 1. Analisis cepat 24 jam terakhir tanpa ubah database
php artisan security:scan-logs --since="24 hours ago" --samples

# 2. Tangkap penyerang dan blokir langsung di database
php artisan security:scan-logs --since="6 hours ago" --import --block
```

---

## 3. `security:baseline`
Membuat, mengaudit, atau menghapus baseline hash SHA-256 integritas berkas aplikasi.

```bash
php artisan security:baseline [options]
```

### Opsi:
- *(tanpa opsi)*: Membuat baseline baru jika belum ada, atau menampilkan ringkasan baseline yang tersimpan.
- `--check`: Membandingkan kondisi berkas saat ini dengan baseline tanpa menulis apa pun ke disk (mode audit).
- `--prune`: Menghapus berkas baseline yang tersimpan di `storage/app/security-baseline.json`.
- `--force`: Membuat baseline baru dan menimpa baseline lama tanpa meminta konfirmasi interaktif.

### Contoh Output Audit:
```text
Baseline SHA-256 dibuat: 2026-10-01 10:00:00 (1.420 berkas)
Status Audit:
  - Berkas dimodifikasi : 0
  - Berkas hilang       : 0
  - Berkas baru         : 1 (public/uploads/backdoor.php) [PERINGATAN!]
```

---

## 4. `security:unblock-ip`
Membuka blokir alamat IP yang terkena karantina WAF. Berfungsi sebagai **Escape Hatch** darurat jika administrator tidak sengaja memblokir IP mereka sendiri.

```bash
php artisan security:unblock-ip [ip] [options]
```

### Argumen & Opsi:
- `ip`: Alamat IP yang ingin dibuka blokirnya (misal: `198.51.100.50`).
- `--all`: Membuka blokir seluruh IP yang sedang aktif sekaligus.
- `--list`: Menampilkan daftar seluruh IP yang sedang diblokir aktif saat ini.

### Contoh:
```bash
# Buka blokir satu IP
php artisan security:unblock-ip 198.51.100.50

# Lihat siapa saja yang sedang diblokir
php artisan security:unblock-ip --list

# Buka seluruh blokir saat insiden darurat
php artisan security:unblock-ip --all
```

---

## 5. `security:prune-logs`
Membersihkan riwayat log keamanan yang telah melewati batas retensi waktu.

```bash
php artisan security:prune-logs [options]
```

### Opsi:
- `--days=`: Mengesampingkan konfigurasi retensi hari (default: `SECURITY_LOG_RETENTION_DAYS`, biasanya 90 hari).

### Contoh:
```bash
# Bersihkan log yang lebih tua dari 30 hari
php artisan security:prune-logs --days=30
```

---

## 6. `security:purge-injected-data`
Mendeteksi dan menghapus residu payload pentest atau injeksi yang tersimpan di dalam tabel aplikasi (misal `{{7*7}}`, `.htaccess`, `../../../public/`).

```bash
php artisan security:purge-injected-data [options]
```

### Opsi:
- *(tanpa `--force`)*: Menjalankan mode simulasi (hanya mendeteksi dan menampilkan daftar baris data yang tercemar tanpa menghapusnya).
- `--force`: Menghapus baris data tercemar yang ditemukan.
- `--marker=*`: Marker teks spesifik yang dicari (dapat diulang, default: canary pentest umum).
- `--model=*`: Membatasi pencarian pada model Eloquent tertentu.
