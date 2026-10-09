# 02. Checklist Keamanan Produksi

Gunakan daftar periksa (*checklist*) ini sebelum meluncurkan aplikasi ke lingkungan produksi untuk memastikan seluruh lapisan keamanan telah terpasang dengan benar.

---

## 1. Verifikasi Konfigurasi Lingkungan (`.env`)

- [ ] `APP_DEBUG=false`: Wajib dimatikan agar pesan stack trace dan kredensial database tidak bocor saat terjadi error.
- [ ] `APP_ENV=production`.
- [ ] `SESSION_SECURE_COOKIE=true`: Memastikan cookie sesi hanya dikirim melalui koneksi terenkripsi HTTPS.
- [ ] `SECURITY_MONITOR_ENABLED=true`: Sakelar WAF aktif.
- [ ] `SECURITY_BLOCK_ENFORCEMENT=true`: Penolakan HTTP 403 aktif untuk IP yang terblokir.
- [ ] `SECURITY_INSTANT_BLOCK_ENABLED=true`: Blokir langsung 30 hari untuk zero-tolerance attack.
- [ ] `SECURITY_LOGIN_LOCKOUT_ENABLED=true`: Proteksi stepped brute force aktif.
- [ ] `SECURITY_SUPPORT_EMAIL`: Diisi alamat email resmi helpdesk/keamanan instansi Anda.

---

## 2. Integritas Berkas & Baseline

- [ ] **Buat Baseline SHA-256 Pertama Kali**:
  Segera setelah deployment rilis selesai dijalankan:
  ```bash
  php artisan security:baseline --force
  ```
  Ini mengunci hash berkas inti resmi (`app/`, `config/`, `routes/`, `public/index.php`, `bootstrap/app.php`).

---

## 3. Hak Akses Berkas & Direktori (Permissions)

Terapkan prinsip *Least Privilege* pada sistem operasi Linux:
```bash
# Berikan kepemilikan kepada pengguna web server
sudo chown -R www-data:www-data /var/www/aplikasi-anda

# Setel izin direktori standar (755) dan berkas (644)
find /var/www/aplikasi-anda -type d -exec chmod 755 {} \;
find /var/www/aplikasi-anda -type f -exec chmod 644 {} \;

# Folder storage dan cache WAJIB writable (775)
chmod -R 775 /var/www/aplikasi-anda/storage
chmod -R 775 /var/www/aplikasi-anda/bootstrap/cache
```

---

## 4. Crontab & Otomasi Pemeliharaan

- [ ] Pastikan cron runner Laravel berjalan setiap menit:
  ```bash
  * * * * * cd /var/www/aplikasi-anda && php artisan schedule:run >> /dev/null 2>&1
  ```
- [ ] Pastikan cron pembersih log usang harian aktif (`security:prune-logs` pada jam 02:30).

---

## 5. Web Server Nginx Hardening

- [ ] Salin template `nginx.conf` yang telah dipublikasikan ke `/etc/nginx/sites-available/`.
- [ ] Pastikan dua direktif `limit_req_zone` diletakkan di dalam blok `http { ... }`.
- [ ] Sesuaikan path socket PHP-FPM (`/var/run/php/php8.3-fpm.sock` atau sesuai versi PHP server).
- [ ] Jika berada di balik Reverse Proxy / Cloudflare, aktifkan direktif `set_real_ip_from` dan `real_ip_recursive on;`.
- [ ] Pastikan `server_tokens off;` aktif untuk menyembunyikan versi Nginx.
- [ ] Jalankan uji sintaks Nginx:
  ```bash
  sudo nginx -t
  ```
- [ ] Reload Nginx:
  ```bash
  sudo systemctl reload nginx
  ```

---

## 6. Prosedur Darurat Buka Blokir (Emergency Runbook)

Jika karena suatu insiden tak terduga, IP kantor pusat atau IP pimpinan terblokir oleh WAF:
1. Hubungkan ke server melalui SSH.
2. Jalankan perintah unblock instan:
   ```bash
   php artisan security:unblock-ip 103.11.22.33
   ```
   Atau jika darurat skala luas:
   ```bash
   php artisan security:unblock-ip --all
   ```
3. Tambahkan IP tersebut ke variabel `SECURITY_WHITELIST` di berkas `.env` agar tidak terulang kembali.
