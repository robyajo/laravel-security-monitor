# 03. Server Integrity & Webshell Scanner

Ketika sebuah aplikasi web berhasil disusupi oleh penyerang, hal pertama yang biasanya mereka lakukan adalah menyisipkan *webshell* (backdoor script) atau mengubah berkas inti aplikasi untuk mempertahankan akses (*persistence*).

Layanan `ServerSecurityService` menyediakan audit integritas berkas berbasis hash kriptografis serta pemindai berkas mencurigakan untuk mendeteksi ancaman tersebut sebelum dimanfaatkan lebih jauh.

---

## 1. Verifikasi Integritas Berkas (SHA-256 Baseline)

Fitur ini bekerja mirip dengan audit integritas pada Git atau tripwire:
1. **Pembuatan Baseline**: Administrator membuat baseline hash resmi saat kode aplikasi pertama kali dideploy. Seluruh berkas pada direktori penting dihitung hash SHA-256-nya dan disimpan dalam format JSON terenkripsi/terlindungi di:
   `storage/app/security-baseline.json`.
2. **Jalur yang Diawasi (`integrity_paths`)**:
   Secara default memantau:
   - `app/`
   - `config/`
   - `routes/`
   - `public/index.php`
   - `bootstrap/app.php`
3. **Laporan Audit Integritas**:
   Sistem membandingkan kondisi berkas saat ini dengan baseline, mengelompokkannya menjadi:
   - **`modified`**: Berkas resmi yang isinya telah berubah setelah deployment (potensi modifikasi injeksi backdoor).
   - **`missing`**: Berkas resmi yang hilang/terhapus.
   - **`new`**: Berkas skrip baru yang tidak tercatat dalam rilis resmi deployment.

---

## 2. Pemindaian Berkas Mencurigakan (Webshell Scanner)

Pemindai menelusuri direktori publik (`public/` dan `storage/app/public/`) yang dapat diakses dari internet dan mencari:

### A. Ekstensi Skrip Terlarang di Webroot
Berkas dengan ekstensi dapat dieksekusi yang seharusnya tidak pernah berada di dalam folder aset atau unggahan publik:
- `.php`, `.phtml`, `.php5`, `.php7`, `.phar`, `.sh`, `.pl`, `.cgi`, `.py`

### B. Pola Nama Webshell Populer
Mendeteksi nama-nama berkas webshell yang sering digunakan penyerang:
- `b374k.php`, `c99.php`, `r57.php`, `wso.php`, `alfa.php`, `mini.php`, `shell.php`, `bypass.php`, `uploader.php`.

### C. Signature Kode Berbahaya di Dalam Berkas
Memindai konten teks berkas terhadap pola backdoor umum:
- `eval(base64_decode(`
- `eval(gzinflate(`
- `system($_GET[`
- `passthru($_POST[`
- `assert($_POST[`
- `preg_replace('/.*/e', ...)`

### D. Gambar Polyglot (Polyglot Image Detection)
Mendeteksi berkas gambar bertipe JPEG, PNG, atau GIF yang disisipi kode PHP di antara metadata EXIF atau payload biner gambar.

---

## 3. Pembersihan Berkas Berbahaya yang Aman (Safe Sanitizer)

Melalui REST API `DELETE /api/security/server/suspicious-files`, administrator dapat menghapus berkas mencurigakan langsung dari panel kontrol. 

Untuk memastikan fitur ini tidak dapat disalahgunakan oleh penyerang (*Defensive Design*), metode `ServerSecurityService::deleteSuspiciousFile()` menerapkan 3 lapisan pengamanan ketat:

1. **Anti Path-Traversal**:
   Menolak jalur berkas yang mengandung `..`, `\`, atau karakter null byte (`%00`).
2. **Strict Base Path Containment**:
   Memastikan jalur absolut berkas berada strictly di dalam `base_path()`. Berkas di luar folder proyek (seperti `/etc/passwd` atau `/var/log`) mustahil disentuh.
3. **Proteksi Berkas Sistem Vital (Protected System Files)**:
   Sistem menolak keras penghapusan berkas-berkas vital aplikasi, seperti:
   - `public/index.php`
   - `.env`
   - `composer.json`
   - `bootstrap/app.php`
4. **Audit Trail**:
   Setiap aksi penghapusan berkas secara otomatis dicatat ke dalam tabel `security_logs` lengkap dengan ID user admin yang mengeksekusi dan stempel waktu.
