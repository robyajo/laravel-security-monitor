# 02. Zero-Dependency SVG CAPTCHA

Mayoritas paket CAPTCHA PHP tradisional bergantung pada ekstensi biner seperti **GD** (`ext-gd`) atau **ImageMagick** (`ext-imagick`). Ketergantungan ini sering kali menyulitkan proses deployment di lingkungan container minimal (Docker Alpine, AWS Lambda, serverless PHP) dan rawan eksploitasi kerentanan memori biner C (ImageTragick/libpng flaws).

Paket ini menyertakan generator **Pure SVG CAPTCHA** yang dibangun 100% menggunakan manipulasi string dan rumus vektor matematika PHP murni tanpa memerlukan ekstensi pengolah gambar apa pun!

---

## 1. Keunggulan Arsitektur Pure SVG

1. **Nol Dependensi Sistem (Zero Dependency)**:
   - Tidak butuh `php-gd`, `php-imagick`, FreeType, atau font sistem operasi eksternal.
   - Siap dijalankan di PHP murni apa pun (`php-cli`, Docker minimal, Alpine Linux, Windows, macOS).
2. **Kualitas Tajam di Segala Resolusi (Crisp & Scalable)**:
   - Berbasis XML SVG, tampilan CAPTCHA tetap tajam sempurna pada layar Retina/HiDPI tanpa buram (*anti-aliased vector paths*).
3. **Keamanan Anti-OCR Kriptografis**:
   - Algoritma menyertakan distorsi koordinat Bézier, kurva sinus acak, rotasi glif per karakter, garis interferensi silang, dan partikel noise titik acak.
   - Tidak dapat diurai oleh parser OCR dasar.

---

## 2. Penggunaan Validasi Form (`ValidCaptcha`)

Paket menyediakan aturan validasi Laravel bawaan `Internal\SecurityMonitor\Rules\ValidCaptcha`:

```php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Internal\SecurityMonitor\Rules\ValidCaptcha;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required', 'string'],
            'captcha' => ['required', new ValidCaptcha], // Validasi CAPTCHA otomatis
        ]);

        // ... Lanjutkan proses login
    }
}
```

---

## 3. Endpoint REST API Captcha

### A. Mengambil Gambar SVG Tantangan
```http
GET /api/security/captcha?form=login
```

**Header Respons**:
```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml; charset=utf-8
Cache-Control: no-store, no-cache, must-revalidate, max-age=0
X-Content-Type-Options: nosniff
```
Respons adalah payload markup XML SVG langsung yang dapat langsung ditampilkan di tag `<img>` browser.

### B. Verifikasi Stateless via API (Klien Mobile / SPA)
```http
POST /api/security/captcha/verify
Content-Type: application/json

{
    "captcha": "AB7X9",
    "form": "login"
}
```

**Respons JSON**:
```json
{
    "success": true,
    "valid": true,
    "message": "Captcha valid."
}
```

---

## 4. Contoh Integrasi di Frontend

### Menampilkan di Tag `<img>` (HTML / Blade / React)
```html
<div class="captcha-wrapper">
    <img id="captcha-img" src="/api/security/captcha?form=login" alt="Security CAPTCHA" />
    <button type="button" onclick="refreshCaptcha()">🔄 Ganti Kode</button>
</div>

<script>
function refreshCaptcha() {
    document.getElementById('captcha-img').src = '/api/security/captcha?form=login&t=' + Date.now();
}
</script>
```
Setiap kali gambar dimuat ulang dengan parameter query acak (`&t=...`), sesi akan diperbarui dengan kode tantangan yang baru.
