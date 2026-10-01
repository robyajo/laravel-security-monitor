# 04. Streaming Access Log Scanner

Sebagian besar serangan siber (seperti scanning direktori WordPress, probing `phpmyadmin`, pemindaian berkas `.git`, dan brute force HTTP dasar) ditolak langsung oleh web server (Nginx/Apache) dengan status HTTP 404 atau 403 **sebelum request sempat diteruskan ke proses PHP Laravel**.

Akibatnya, request tersebut tidak pernah melewati middleware Laravel dan tidak tercatat di tabel `security_logs`.

Layanan `AccessLogScannerService` memecahkan masalah ini dengan membaca dan menganalisis berkas log akses mentah (*raw access logs*) web server secara streaming.

---

## 1. Arsitektur Hemat Memori (PHP Generator Stream)

Berkas log akses produksi pada aplikasi sibuk sering kali berukuran ratusan megabyte hingga beberapa gigabyte dengan jutaan baris entri. Jika dibaca sekaligus menggunakan `file_get_contents()` atau `file()`, proses PHP akan langsung mengalami *Memory Exhaustion Fatal Error*.

`AccessLogScannerService` dirancang menggunakan **PHP Generators (`yield`)**:
- Baris berkas log dibaca satu per satu dari disk menggunakan pointer `fgets()`.
- Hanya satu baris yang berada di RAM pada satu waktu.
- Pemindai dapat memproses berkas log berisi 500.000+ baris dengan konsumsi memori stabil di bawah **15 MB RAM**!

---

## 2. Format Log yang Didukung

Pemindai mendukung format log web server standar industri:
- **Nginx Standard Combined Log Format**:
  `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
- **Apache Combined Log Format**
- Mendukung berkas log terkompresi `.gz` jika dikonfigurasikan.

---

## 3. Eksekusi via Artisan CLI (`security:scan-logs`)

Anda dapat menjalankan pemindai sewaktu-waktu menggunakan perintah:

### A. Pratinjau Temuan Tanpa Mengubah Database (Dry-Run)
```bash
php artisan security:scan-logs --file=/var/log/nginx/access.log --dry-run
```

### B. Memindai dan Mengimpor ke Tabel `security_logs`
```bash
php artisan security:scan-logs --file=/var/log/nginx/access.log --import
```

### C. Memindai, Mengimpor, dan Otomatis Memblokir IP Penyerang Zero-Tolerance
```bash
php artisan security:scan-logs --file=/var/log/nginx/access.log --import --block
```
Setiap IP yang ditemukan mencoba melakukan serangan zero-tolerance (misal mengunggah webshell, probe `.env`, atau path traversal) akan langsung dimasukkan ke tabel `blocked_ips` dan ditolak oleh aplikasi.

### D. Memfilter Aktivitas Berdasarkan Rentang Waktu atau IP Tertentu
```bash
# Hanya memindai aktivitas dalam 2 hari terakhir
php artisan security:scan-logs --since="2 days ago"

# Memeriksa rekam jejak satu IP spesifik
php artisan security:scan-logs --ip=104.207.74.38 --samples
```

---

## 4. Otomasi Terjadwal Harian (Daily Scheduler)

Anda dapat mengaktifkan pemindaian otomatis harian di latar belakang dengan menambahkan variabel berikut ke berkas `.env`:

```dotenv
SECURITY_ACCESS_LOG_AUTO_SCAN=true
SECURITY_ACCESS_LOG_AUTO_SCAN_HOURS=24
SECURITY_ACCESS_LOG_PATHS=/var/log/nginx/access.log,/var/log/nginx/error.log
```

Ketika opsi ini aktif, `SecurityMonitorServiceProvider` akan secara otomatis menjadwalkan perintah:
```bash
php artisan security:scan-logs --import --min-level=high --since="24 hours ago"
```
dieksekusi setiap hari pada pukul **03:00 pagi**.
