# 03. Resolusi Reverse Proxy & Deteksi IP Klien

Dalam infrastruktur server produksi modern, aplikasi Laravel hampir selalu berjalan di belakang lapisan reverse proxy, Content Delivery Network (CDN), atau load balancer:
- **Cloudflare** (CDN, DDoS protection, WAF)
- **Nginx Ingress / HAProxy** (Load balancer internal)
- **AWS Application Load Balancer (ALB)**

Jika penanganan header proxy tidak dilakukan dengan benar, sistem keamanan dapat salah mendeteksi seluruh pengunjung sebagai IP lokal proxy (`127.0.0.1` atau `10.0.0.x`), atau lebih buruk lagi, penyerang dapat memalsukan IP mereka menggunakan header `X-Forwarded-For` palsu (*Header Spoofing*).

---

## 1. Urutan Prioritas Resolusi IP

Metode `SecurityMonitorService::resolveClientIp(Request $request)` melakukan resolusi alamat IP klien nyata (*Real Client IP*) dengan urutan prioritas yang aman:

1. **`CF-Connecting-IP`**: Header standar dari Cloudflare. Ini adalah header paling tepercaya jika domain Anda menggunakan proxy Cloudflare, karena Cloudflare membersihkan dan menimpa header ini di level edge network mereka.
2. **`X-Real-IP`**: Ditetapkan oleh reverse proxy Nginx terpercaya (`proxy_set_header X-Real-IP $remote_addr;`).
3. **`X-Forwarded-For`**: Berisi rantai alamat IP yang dipisahkan koma (`client, proxy1, proxy2`). Paket memindai daftar ini dari kiri ke kanan dan mengambil **alamat IP publik pertama yang valid** (mengabaikan rentang IP privat RFC1918 seperti `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
4. **`$request->ip()`**: Fallback ke mekanisme bawaan Laravel (menggunakan `REMOTE_ADDR` dari PHP Server Environment).

---

## 2. Pencegahan Pemalsuan Header (Header Spoofing)

Penyerang dapat dengan mudah mengirimkan request dengan header HTTP buatan:
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-For: 8.8.8.8
```

Jika server Laravel Anda terhubung langsung ke internet tanpa konfigurasi proxy terpercaya, Laravel dapat tertipu dan mengira penyerang berasal dari `8.8.8.8`.

### Solusi Wajib: Konfigurasi `TrustProxies` di Laravel

#### Pada Laravel 11 / 12 / 13 (`bootstrap/app.php`):
Konfigurasikan proxy terpercaya pada `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware) {
    // Jika berada di belakang Cloudflare atau Reverse Proxy lokal:
    $middleware->trustProxies(at: [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.1',
    ]);
})
```

Atau jika seluruh lalu lintas dijamin masuk melalui Cloudflare, gunakan wildcard:
```php
$middleware->trustProxies(at: '*');
```

#### Pada Laravel 10 (`app/Http/Middleware/TrustProxies.php`):
Setel properti `$proxies`:
```php
protected $proxies = '*';
protected $headers = Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST | Request::HEADER_X_FORWARDED_PORT | Request::HEADER_X_FORWARDED_PROTO;
```

---

## 3. Resolusi Identitas Perangkat (`device_id` & `local_ip`)

Selain alamat IP publik, `SecurityMonitorService` mengekstrak parameter identitas perangkat melalui metode:

- **`resolveDeviceId(Request $request)`**:
  1. Header `X-Device-Id`
  2. Input parameter `device_id`
  3. Header cookie sesi
- **`resolveLocalIp(Request $request)`**:
  1. Header `X-Local-Ip`
  2. Input parameter `local_ip`

Parameter ini memastikan bahwa fitur karantina granular (*Device-Level Quarantine*) dapat beroperasi mulus baik di lingkungan komunikasi langsung maupun di balik berbagai lapisan proxy.
