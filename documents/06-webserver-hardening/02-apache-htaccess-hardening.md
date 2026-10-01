# 02. Hardening Apache Web Server (.htaccess)

Halaman ini mendokumentasikan aturan keamanan berkas **`public/.htaccess`** yang disediakan oleh **Laravel Security Monitor (Bulwark)** untuk server yang menggunakan **Apache HTTP Server**, **LiteSpeed**, atau lingkungan shared hosting seperti **cPanel**.

Aturan hardening ini dirancang untuk mencegah eksploitasi di tingkat web server sebelum permintaan diproses oleh PHP runtime, mencakup pencegahan eksekusi webshell, bypass ekstensi ganda, eksposur dotfile, hingga kebocoran berkas dump database.

---

## 1. Berkas Lengkap `public/.htaccess` Hardened

Berikut adalah konfigurasi lengkap berkas `.htaccess` yang dipublikasikan oleh paket:

```apache
<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>

    RewriteEngine On

    # Handle Authorization Header
    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    # Handle X-XSRF-Token Header
    RewriteCond %{HTTP:x-xsrf-token} .
    RewriteRule .* - [E=HTTP_X_XSRF_TOKEN:%{HTTP:X-XSRF-Token}]

    # Redirect Trailing Slashes If Not A Folder...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]

    # Send Requests To Front Controller...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>

# ---------------------------------------------------------------------------
# Hardening keamanan (lihat DOCS/security-monitor.md)
# Melindungi dari: upload webshell (wne.php%00.jpg), double extension
# (shell.php.jpg), pembacaan .htaccess/.env, dan eksposur berkas backup.
# ---------------------------------------------------------------------------

# Blokir akses ke dotfile (.htaccess, .env, .git, .htpasswd, ...)
<FilesMatch "^\.">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

# Jangan pernah menyajikan berkas dengan double extension (shell.php.jpg)
<FilesMatch "\.(php[0-9]?|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|scr)\.[a-z0-9]+$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

# Blokir berkas backup / dump / log bila ikut tersalin ke folder publik
<FilesMatch "\.(sql|bak|old|orig|save|swp|log|ini|conf|yml|yaml)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>

# Matikan directory listing
Options -Indexes
```

---

## 2. Bedah Aturan Keamanan (Line-by-Line Analysis)

### A. Blokir Akses ke Dotfile (`^\.`)
```apache
<FilesMatch "^\.">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>
```
- **Tujuan**: Mencegah browser atau penyerang mengunduh berkas tersembunyi yang diawali tanda titik (`.`).
- **Ancaman yang Ditangkal**:
  - Pembacaan konfigurasi sensitif `.env` jika document root salah diarahkan ke root proyek alih-alih `public/`.
  - Pembacaan berkas kontrol versi `.git/config`, `.gitignore`, dan `.gitlab-ci.yml`.
  - Pembacaan atau verifikasi keberadaan `.htaccess` dan `.htpasswd`.
- **Kompatibilitas Ganda**: Menggunakan `mod_authz_core.c` (Apache 2.4+) dengan fallback ke `mod_access_compat` (Apache 2.2 / legacy LiteSpeed).

### B. Proteksi Serangan Ekstensi Ganda (Double Extension Bypass)
```apache
<FilesMatch "\.(php[0-9]?|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|scr)\.[a-z0-9]+$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>
```
- **Tujuan**: Memblokir berkas berbahaya yang disamarkan dengan ekstensi ganda, misalnya:
  - `avatar.php.jpg` atau `document.phtml.png`
  - Webshell polyglot atau trik null-byte (`wne.php%00.jpg`)
  - Skrip executable Windows/Linux (`payload.sh.txt`, `trojan.exe.pdf`)
- **Mengapa ini Penting di Apache?**: Pada beberapa konfigurasi Apache dengan handler MIME ganda (`AddHandler` atau `SetHandler`), berkas bernama `shell.php.jpg` dapat dieksekusi oleh modul PHP karena mengandung substring `.php`. Aturan ini menjamin Apache langsung menolak permintaan dengan **HTTP 403 Forbidden**.

### C. Blokir Berkas Backup, Dump Database, dan Log Sensitif
```apache
<FilesMatch "\.(sql|bak|old|orig|save|swp|log|ini|conf|yml|yaml)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>
```
- **Tujuan**: Mencegah kebocoran data (*data leakage*) jika developer atau skrip deployment tidak sengaja meninggalkan berkas backup di folder publik.
- **Ekstensi yang Ditutup**:
  - Database dump: `.sql`
  - Backup teks/editor: `.bak`, `.old`, `.orig`, `.save`, `.swp` (Vim swap file)
  - Log server & aplikasi: `.log`
  - Konfigurasi: `.ini`, `.conf`, `.yml`, `.yaml`

### D. Menonaktifkan Directory Listing
```apache
Options -Indexes
```
- **Tujuan**: Memastikan Apache tidak menampilkan daftar isi folder (*directory indexing*) jika folder tidak memiliki berkas `index.php` atau `index.html` (misalnya folder `public/storage/uploads/`).
- **Efek**: Pengunjung yang membuka direktori langsung akan menerima respons **HTTP 403 Forbidden** alih-alih melihat daftar berkas yang diunggah.

---

## 3. Cara Menerapkan ke Aplikasi Laravel Anda

### Opsi 1: Otomatis via `security:install` (Direkomendasikan)
Saat Anda menjalankan:
```bash
php artisan security:install
```
Perintah ini akan mendeteksi keberadaan berkas `public/.htaccess`:
- Jika berkas sudah ada, installer akan membuat cadangan otomatis:
  ```
  public/.htaccess.backup-20261002_010000
  ```
  dan menyisipkan blok hardening ke berkas yang ada tanpa menghapus aturan rewrite kustom Anda.
- Jika ingin menimpa total dengan berkas bersih bawaan paket:
  ```bash
  php artisan security:install --force
  ```

### Opsi 2: Manual via Vendor Publish Tag
Anda juga dapat mempublikasikannya langsung menggunakan tag Artisan Laravel:
```bash
php artisan vendor:publish --tag=security-htaccess --force
```

---

## 4. Verifikasi dan Pengujian

Setelah berkas `.htaccess` diperbarui, Anda dapat menguji efektivitas aturan keamanan langsung menggunakan `curl`:

### 1. Uji Blokir Dotfile (.env / .git)
```bash
curl -I http://localhost:8000/.env
# Respons yang diharapkan: HTTP/1.1 403 Forbidden
```

### 2. Uji Blokir Double Extension
```bash
curl -I http://localhost:8000/storage/avatar.php.jpg
# Respons yang diharapkan: HTTP/1.1 403 Forbidden
```

### 3. Uji Blokir Berkas Backup / Dump SQL
```bash
curl -I http://localhost:8000/backup.sql
# Respons yang diharapkan: HTTP/1.1 403 Forbidden
```

### 4. Uji Matikan Directory Listing
```bash
curl -I http://localhost:8000/storage/
# Respons yang diharapkan: HTTP/1.1 403 Forbidden
```

---

## 5. Catatan Konfigurasi VirtualHost Apache

Pastikan virtual host Apache Anda telah mengizinkan override dari berkas `.htaccess` dengan direktif `AllowOverride All`:

```apache
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/html/example/public

    <Directory /var/www/html/example/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/example_error.log
    CustomLog ${APACHE_LOG_DIR}/example_access.log combined
</VirtualHost>
```

> 💡 **LiteSpeed / OpenLiteSpeed**: LiteSpeed secara native mendukung sintaks `.htaccess` Apache dan akan langsung menerapkan aturan-aturan di atas saat berkas disimpan.
