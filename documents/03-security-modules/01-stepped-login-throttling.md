# 01. Stepped Login Lockout & Brute-Force Defense

Serangan *credential stuffing* dan *brute force* menggunakan kamus kata sandi otomatis adalah salah satu vektor ancaman paling persisten terhadap endpoint otentikasi. Sistem pembatas bawaan Laravel (`RateLimiter`) umumnya hanya menyediakan penundaan statis (misal 60 detik setelah 5 kegagalan). Pola ini mudah diakali oleh bot otomatis yang memprogram jeda request per 61 detik.

Paket ini menyediakan mesin proteksi login bertingkat (**Stepped Login Lockout**) dengan algoritma *exponential penalty backoff*.

---

## 1. Mekanisme Penalti Bertingkat (Tiered Penalties)

Setiap kali terjadi kegagalan otentikasi (ditangkap secara otomatis oleh listener `LogFailedLoginAttempt` dari event Laravel `\Illuminate\Auth\Events\Failed`), sistem mencatat kegagalan pada tabel `login_attempts` untuk kombinasi `email` dan `ip_address`.

Ketika jumlah kegagalan mencapai ambang batas (`SECURITY_LOGIN_LOCKOUT_THRESHOLD`, default: 3 kali), durasi penguncian akan meningkat secara eksponensial sesuai level penalti:

| Tingkat (Level) | Durasi Penguncian | Skenario |
| :---: | :--- | :--- |
| **Level 1** | **1 Menit** | 3 kali salah memasukkan password pertama kali (kesalahan manusiawi biasa). |
| **Level 2** | **5 Menit** | Masih salah password setelah jeda 1 menit berakhir. |
| **Level 3** | **15 Menit** | Indikasi tebakan berulang terarah. |
| **Level 4** | **30 Menit** | Indikasi serangan brute force bot. |
| **Level 5** | **60 Menit (1 Jam)** | Serangan berlanjut tanpa henti. |
| **Level 6+** | **1440 Menit (24 Jam)** | Karantina penuh akun/IP dari otentikasi. |

### Jendela Peluruhan (Decay Window)
Jika seorang pengguna sah berhasil login atau tidak melakukan percobaan apa pun selama durasi `SECURITY_LOGIN_LOCKOUT_DECAY_MINUTES` (default: 60 menit), level penalti akan meluruh dan direset kembali ke level nol.

---

## 2. Event Listeners Bawaan

Paket secara otomatis mendaftarkan listener pada event otentikasi Laravel:

1. **`LogFailedLoginAttempt`** (mendengarkan `\Illuminate\Auth\Events\Failed`):
   - Memanggil `LoginThrottleService::registerFailure($email, $ip)`.
   - Mengakumulasikan hitungan kegagalan dan memperbarui `locked_until` jika mencapai batas tier.
   - Mencatat log audit ke tabel `security_logs`.
2. **`ResetLoginAttempts`** (mendengarkan `\Illuminate\Auth\Events\Login`):
   - Ketika pengguna berhasil login, listener ini langsung memanggil `LoginThrottleService::registerSuccess($email, $ip)`.
   - Menghapus riwayat kegagalan dan mereset status penguncian untuk email & IP tersebut.

---

## 3. Integrasi Pemeriksaan Status Lockout di Controller Login

Jika Anda membangun form login kustom atau API login headless, Anda dapat memeriksa status lockout sebelum memvalidasi kredensial:

```php
use Internal\SecurityMonitor\Services\LoginThrottleService;

class AuthController extends Controller
{
    public function login(Request $request, LoginThrottleService $throttle)
    {
        $email = (string) $request->input('email');
        $ip = (string) $request->ip();

        // 1. Periksa status penguncian
        $status = $throttle->status($email, $ip);

        if ($status['locked']) {
            return response()->json([
                'success' => false,
                'message' => $throttle->lockoutMessage($status['seconds_remaining']),
                'seconds_remaining' => $status['seconds_remaining'],
                'level' => $status['level'],
            ], 429);
        }

        // 2. Lanjutkan proses otentikasi normal...
    }
}
```

---

## 4. Membuka Kunci Akun Secara Manual (Release Lockout)

Administrator dapat membuka akun yang terkunci melalui:

### A. Headless REST API
```http
DELETE /api/security/lockouts/{id}
Authorization: Bearer <admin-token>
```
Endpoint ini menghapus entri dari `login_attempts` sehingga pengguna dapat langsung mencoba login kembali.

### B. Memanggil Service Secara Terprogram
```php
app(LoginThrottleService::class)->release('user@domain.com', '198.51.100.5');
```
