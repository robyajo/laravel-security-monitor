# 03. Pembuatan Aturan Kustom & Whitelist Subnet

Setiap aplikasi memiliki karakteristik lalu lintas data dan kebutuhan bisnis yang unik. Anda dapat memperluas aturan deteksi WAF bawaan dan mengonfigurasi pengecualian subnet (CIDR) secara fleksibel melalui `config/security.php`.

---

## 1. Mendaftarkan Signature Zero-Tolerance Kustom

Jika aplikasi Anda memiliki endpoint khusus yang kerap diserang atau Anda ingin langsung memblokir percobaan pencarian berkas tertentu (misalnya probe terhadap `/wp-login.php` atau `/actuator/health`), tambahkan ke array `instant_block.signatures` di `config/security.php`:

```php
'instant_block' => [
    'enabled' => true,
    'duration_hours' => 720, // 30 hari
    'signatures' => [
        // Signature bawaan paket...

        // Tambahkan aturan kustom Anda:
        [
            'id' => 'wordpress_probe_custom',
            'label' => 'Percobaan probing CMS WordPress pada aplikasi non-WP',
            'target' => 'path', // Hanya periksa URI path
            'patterns' => [
                '#^/wp-(?:login|admin|content|includes)#i',
                '#^/xmlrpc\.php#i',
            ],
        ],
        [
            'id' => 'spring_actuator_probe',
            'label' => 'Percobaan akses Spring Boot Actuator',
            'target' => 'path',
            'patterns' => [
                '#^/actuator(?:/.*)?$#i',
            ],
        ],
    ],
],
```

---

## 2. Menambahkan Aturan WAF Reguler Kustom

Untuk pola serangan yang ingin diakumulasikan ke dalam penilaian ambang batas bertingkat (auto-block 3 kali dalam 10 menit), tambahkan ke array `rules`:

```php
'rules' => [
    // Aturan bawaan paket...

    [
        'id' => 'custom_log4j_jndi',
        'label' => 'Indikasi Eksploitasi Log4j / JNDI Injection',
        'level' => 'critical',
        'patterns' => [
            '/\$\{jndi:(?:ldap|rmi|dns):/i',
        ],
    ],
],
```

---

## 3. Whitelist Subnet Jaringan (CIDR) & Proxy Internal

Untuk memastikan bahwa alamat IP jaringan kantor lokal, VPN kantor, atau subnet monitoring tidak akan pernah diblokir meskipun melakukan pengujian penetrasi:

### Pada Berkas `.env`:
Pisahkan beberapa IP atau subnet dengan tanda koma:
```dotenv
SECURITY_WHITELIST="127.0.0.1,::1,192.168.1.0/24,10.10.0.0/16,103.11.22.33"
```

### Logika Pemeriksaan Subnet:
Metode `SecurityMonitorService::isWhitelisted()` secara otomatis mendukung:
1. **Pencocokan Alamat IPv4 / IPv6 Tunggal**: (misal `127.0.0.1`, `::1`).
2. **Pencocokan Notasi CIDR Subnet**: (misal `192.168.1.0/24` atau `10.0.0.0/8`).
3. **Pencocokan Wildcard Sederhana**: (misal `192.168.*.*`).
4. **Pengecekan Admin Bypass**: Pengguna yang terotentikasi sebagai administrator sistem secara otomatis memiliki hak bypass dan tidak akan pernah diblokir saat menguji sistem.

---

## 4. Pengecualian Jalur URI (`exclude_paths`)

Jika ada rute webhook pihak ketiga (seperti Midtrans, Xendit, Stripe, atau integrasi API mitra) yang mengirimkan payload terenkripsi mentah atau payload yang mirip pola teks tertentu, daftarkan jalurnya di `exclude_paths`:

```php
'exclude_paths' => [
    'api/webhooks/*',
    'api/payment-callback/*',
    'livewire/upload-file',
],
```
Request yang cocok dengan pola di atas akan dilewati dari inspeksi konten body WAF untuk mencegah kesalahan deteksi (*false positive*).
