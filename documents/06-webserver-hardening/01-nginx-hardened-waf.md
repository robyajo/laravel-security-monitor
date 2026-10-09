# 01. Konfigurasi Nginx Hardened WAF (`nginx.conf`)

Keamanan sebuah aplikasi web harus menerapkan prinsip **Pertahanan Berlapis (Defense in Depth)**. WAF di tingkat aplikasi PHP sangat kuat dalam memahami logika bisnis, namun penyerang dapat menghabiskan sumber daya CPU server sebelum request sempat diproses oleh PHP.

Paket ini menyertakan template konfigurasi Nginx siap pakai (`stubs/nginx.conf.stub` atau dipublikasikan melalui `php artisan security:install`), yang dirancang khusus untuk memblokir serangan di lapisan web server Nginx tercepat.

---

## 1. Dua Zona Rate Limiting Terpisah (Dual-Zone Limiting)

Meletakkan rate limit yang seragam di seluruh aplikasi adalah kesalahan fatal:
- Membatasi 5 request/menit untuk seluruh URL akan merusak halaman web normal yang memuat puluhan file CSS/JS.
- Mengizinkan 30 request/detik untuk seluruh URL akan membuat form login rentan dibobol serangan *brute force*.

Konfigurasi ini membaginya menjadi dua zona di dalam blok `http { ... }`:

```nginx
# 1. Zona Otentikasi: Sangat ketat (5 request per menit)
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;

# 2. Zona Umum: Longgar untuk navigasi aplikasi normal (30 request per detik)
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=30r/s;
```

### Penerapan pada Lokasi URL:
```nginx
# Endpoint sensitif dibatasi oleh auth_limit dengan burst=5
location ~* ^/(login|register|forgot-password|reset-password|two-factor-challenge|livewire|oauth) {
    limit_req zone=auth_limit burst=5 nodelay;
    try_files $uri $uri/ /index.php?$query_string;
}

# Seluruh rute lain menggunakan general_limit dengan burst=50
location / {
    limit_req zone=general_limit burst=50 nodelay;
    try_files $uri $uri/ /index.php?$query_string;
}
```

---

## 2. Pembebasan Aset Statis Frontend Vite (Asset Bypass)

### Masalah `NS_ERROR_CORRUPTED_CONTENT`:
Aplikasi Laravel modern yang menggunakan **Vite** (React, Vue, Inertia, Livewire) memecah kode JavaScript menjadi puluhan chunk berkas kecil (`.js` dan `.css`). Ketika browser membuka halaman pertama kali, browser akan mengunduh 30–50 chunk secara paralel dalam milidetik yang sama.

Jika folder build terkena rate limiting, sebagian chunk akan ditolak dengan status HTTP 429 atau koneksi diputus paksa. Browser Firefox memunculkan error legendaris: `NS_ERROR_CORRUPTED_CONTENT`, dan tampilan aplikasi menjadi blank/rusak!

### Solusi Hardening:
```nginx
location ^~ /build/ {
    # 1. WAJIB bebas dari direktif limit_req
    # 2. Kembalikan 404 murni jika file tidak ada (jangan lempar ke PHP)
    try_files $uri =404;

    # 3. Cache permanen 1 tahun karena Vite menyematkan hash unik pada nama file
    access_log off;
    expires 1y;
    add_header Cache-Control "public, max-age=31536000, immutable" always;
    add_header X-Content-Type-Options "nosniff" always;
}
```

> [!WARNING]
> Jangan menambahkan direktif `error_page 404 /index.php;` di level server jika menggunakan aturan di atas! Jika ada file chunk statis yang hilang, `error_page 404 /index.php;` akan mencegatnya dan merender respons HTML 404 dari Laravel, yang merusak browser saat mengeksekusi script.

---

## 3. Strict Single-PHP Execution (Hanya `/index.php` via Exact Match)

Mayoritas eksploitasi webshell bekerja dengan cara:
1. Penyerang berhasil mengunggah skrip PHP ke folder `public/uploads/backdoor.php`.
2. Penyerang mengakses `https://domain.com/uploads/backdoor.php` di browser.
3. Nginx mencocokkan blok `location ~ \.php$` dan meneruskannya ke PHP-FPM, sehingga kode berbahaya dieksekusi.

### Proteksi Mutlak di Level Nginx:
Dalam aplikasi Laravel murni, **TIDAK ADA BERKAS PHP YANG BOLEH DIEKSEKUSI SELAIN `public/index.php`**!

```nginx
# 1. BLOKIR SEMUA percobaan eksekusi berkas .php langsung
location ~ \.php$ {
    return 403;
}

# 2. HANYA index.php yang diizinkan masuk ke PHP-FPM (Exact Match '=')
location = /index.php {
    limit_req zone=general_limit burst=50 nodelay;
    fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    include fastcgi_params;

    # Buffer FastCGI Tuning (Mencegah 502 Bad Gateway)
    fastcgi_buffers 16 16k;
    fastcgi_buffer_size 32k;
    fastcgi_busy_buffers_size 64k;
    fastcgi_read_timeout 60s;

    fastcgi_hide_header X-Powered-By;
}
```
Karena Nginx selalu memprioritaskan exact match (`= /index.php`) sebelum regex (`~ \.php$`), `index.php` tetap berjalan mulus, sementara seluruh berkas `.php` lain ditolak langsung dengan status **HTTP 403** tanpa pernah menyentuh PHP-FPM.

---

## 4. Buffer Tuning (Mencegah Error 502 Bad Gateway & 400 Bad Request)

Aplikasi Laravel skala menengah hingga besar (terutama dengan Session, Inertia, Livewire, JWT/Sanctum Bearer Token) kerap mengalami masalah buffer default Nginx:

1. **502 Bad Gateway (`upstream sent too big header`)**:
   Laravel mengembalikan header cookie sesi, CSRF, dan header debug yang melebihi buffer bawaan FastCGI (4k/8k). Diatasi dengan:
   ```nginx
   fastcgi_buffers 16 16k;
   fastcgi_buffer_size 32k;
   fastcgi_busy_buffers_size 64k;
   ```
2. **400 Bad Request / 414 Request-URI Too Large**:
   Header permintaan browser membawa Authorization token yang panjang. Diatasi dengan menaikkan buffer client header di level server:
   ```nginx
   client_header_buffer_size 16k;
   large_client_header_buffers 4 32k;
   client_body_buffer_size 128k;
   ```

---

## 5. Pemulihan IP Asli (*Real IP Behind Reverse Proxy / Cloudflare*)

Jika aplikasi Anda berada di balik Cloudflare, AWS ALB, Kubernetes Ingress, atau Reverse Proxy internal:
- Tanpa modul Real IP, Nginx akan membaca IP proxy sebagai IP client.
- Hal ini menyebabkan `limit_req_zone` menghitung semua pengguna sebagai **satu IP tunggal**, sehingga memicu rate-limit massal.
- Perintah blokir WAF (`deny <ip>` atau `php artisan security:block-ip`) dapat memutus seluruh traffic yang melewati proxy.

Aktifkan pemulihan IP asli di dalam blok `server`:
```nginx
set_real_ip_from 127.0.0.1;
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For; # atau CF-Connecting-IP jika Cloudflare
real_ip_recursive on;           # Mencegah IP spoofing pada multi-hop proxy
```

---

## 6. Sandboxing Folder Storage & Upload

Folder `storage/app/public` (atau symlink `/storage/` di webroot) adalah tempat berkas unggahan pengguna disimpan. Folder ini diisolasi penuh:

```nginx
location ^~ /storage/ {
    location ~* \.(php[0-9]?|phtml|pht|phar|pl|py|sh|bash|cgi|exe|dll|bat|cmd|htm|html|shtml)$ {
        return 403;
    }

    # Cegah MIME confusion / sniffing pada file gambar polyglot
    add_header X-Content-Type-Options "nosniff" always;
    # Sandboxing untuk aset statis agar tidak mengeksekusi JavaScript
    add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; sandbox" always;

    try_files $uri =404;
}
```
Header `nosniff` dan `CSP sandbox` memastikan bahwa jika seseorang mengunggah file gambar palsu yang berisi JavaScript atau HTML (SVG XSS), browser pengunjung tidak akan mengeksekusi script tersebut.

---

## 7. Blokir Ekstensi Ganda & Berkas Sensitif

```nginx
# Blokir double extension (misal: image.php.jpg atau dokumen.phtml.zip)
location ~* \.(php[0-9]?|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|scr)\. {
    return 403;
}

# Blokir berkas rahasia, cadangan database, konfigurasi, dan dump
location ~* \.(sql|bak|old|orig|save|swp|log|env|ini|conf|yml|yaml)$ {
    return 403;
}

# Blokir dotfiles (.env, .git, .htaccess) kecuali .well-known untuk sertifikat SSL
location ~ /\.(?!well-known).* {
    deny all;
}
```

---

## 8. Timeouts Anti-Slowloris & Restriksi Method HTTP

```nginx
# Batasi timeout untuk mencegah Slowloris DoS yang menahan koneksi terbuka lambat
client_body_timeout 15s;
client_header_timeout 15s;
keepalive_timeout 65;
send_timeout 15s;

# Tolak method HTTP berisiko (misal TRACE/TRACK) untuk mencegah Cross-Site Tracing (XST)
if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$ ) {
    return 405;
}
```

---

## 9. Header Keamanan & Penyamaran Server

```nginx
# Sembunyikan versi Nginx di header HTTP dan halaman error
server_tokens off;

# Header keamanan wajib dengan flag 'always'
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

---

## 10. Konfigurasi Lengkap Produksi

Template siap pakai di atas telah dikemas secara terintegrasi di dalam [`stubs/nginx.conf.stub`](file:///Users/robykartis/Documents/KOMINFO/GITHUB/PHP/laravel-security/laravel-security-monitor/stubs/nginx.conf.stub) dan dapat dipublikasikan ke aplikasi Laravel Anda melalui:

```bash
php artisan security:install
# atau secara spesifik:
php artisan vendor:publish --tag=security-nginx --force
```
File hasil publish akan berada di `nginx.conf` di root direktori aplikasi host Anda, siap disalin ke `/etc/nginx/sites-available/`.
