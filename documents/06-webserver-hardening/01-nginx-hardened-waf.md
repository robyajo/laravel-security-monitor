# 01. Konfigurasi Nginx Hardened WAF (`nginx.conf`)

Keamanan sebuah aplikasi web harus menerapkan prinsip **Pertahanan Berlapis (Defense in Depth)**. WAF di tingkat aplikasi PHP sangat kuat dalam memahami logika bisnis, namun penyerang dapat menghabiskan sumber daya CPU server sebelum request sempat diproses oleh PHP.

Paket ini menyertakan template konfigurasi Nginx siap pakai (`stubs/nginx.conf.stub` atau dipublikasikan melalui `php artisan security:install`), yang dirancang khusus untuk memblokir serangan di lapisan web server Nginx tercepat.

---

## 1. Dua Zona Rate Limiting Terpisah (Dual-Zone Limiting)

Meletakkan rate limit yang seragam di seluruh aplikasi adalah kesalahan fatal. Mengapa?
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
    add_header Cache-Control "public, max-age=31536000, immutable";
}
```

---

## 3. Strict Single-PHP Execution (Hanya `/index.php`)

Mayoritas eksploitasi webshell bekerja dengan cara:
1. Penyerang berhasil mengunggah skrip PHP ke folder `public/uploads/backdoor.php`.
2. Penyerang mengakses `https://domain.com/uploads/backdoor.php` di browser.
3. Nginx mencocokkan blok `location ~ \.php$` dan meneruskannya ke PHP-FPM, sehingga kode berbahaya dieksekusi.

### Proteksi Mutlak di Level Nginx:
Dalam aplikasi Laravel murni, **TIDAK ADA BERKAS PHP YANG BOLEH DIEKSEKUSI SELAIN `public/index.php`**!

```nginx
# 1. BLOKIR KERAS seluruh percobaan eksekusi berkas .php di subfolder publik
location ~* ^/(?!index\.php$).*\.(php|phtml|php[34578]|phar|sh|pl|cgi|py)$ {
    deny all;
    return 403;
}

# 2. HANYA index.php yang diizinkan masuk ke PHP-FPM
location = /index.php {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
    fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    include fastcgi_params;
}
```
Dengan aturan ini, meskipun seorang penyerang berhasil meletakkan file backdoor di direktori mana pun di webroot, berkas tersebut **tidak akan pernah bisa dieksekusi oleh PHP-FPM** karena Nginx langsung menolaknya dengan HTTP 403!

---

## 4. Sandboxing Folder Storage & Upload

Folder `storage/app/public` (atau link simbolik `/storage/` di webroot) adalah tempat berkas unggahan pengguna disimpan. Folder ini diisolasi penuh:

```nginx
location ^~ /storage/ {
    # 1. Matikan eksekusi FastCGI secara mutlak
    # 2. Berikan header isolasi keamanan browser
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; sandbox" always;
    
    try_files $uri =404;
}
```
Header `nosniff` dan `CSP sandbox` memastikan bahwa jika seseorang mengunggah file gambar palsu yang berisi JavaScript atau HTML (SVG XSS), browser pengunjung tidak akan mengeksekusi script tersebut.

---

## 5. Blokir Ekstensi Ganda & Berkas Sensitif

```nginx
# Blokir double extension (misal: image.php.jpg atau dokumen.phtml.zip)
location ~* \.(php|phtml|phar)\.[a-zA-Z0-9]+$ {
    deny all;
    return 403;
}

# Blokir berkas rahasia, cadangan database, dan dotfiles
location ~* \.(env|git|htaccess|sql|bak|log|ini|conf)$ {
    deny all;
    return 403;
}
```
