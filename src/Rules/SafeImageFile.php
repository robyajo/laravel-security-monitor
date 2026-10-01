<?php

namespace Internal\SecurityMonitor\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;
use Throwable;

/**
 * Validates uploaded image files to prevent Polyglot Webshells and malicious payloads.
 *
 * Attackers craft files with valid JPEG/PNG headers that pass "image" or "mimes:jpg"
 * validation, but contain executable PHP code inside EXIF metadata or trailing bytes.
 * This rule strictly verifies the image structure and rejects any file containing
 * embedded PHP tags, malicious XML/SVG scripts, or executable tokens.
 */
class SafeImageFile implements ValidationRule
{
    /**
     * Allowed MIME types for image uploads.
     */
    protected const ALLOWED_MIMES = [
        'image/jpeg',
        'image/png',
        'image/webp',
        'image/gif',
        'image/svg+xml',
    ];

    /**
     * Dangerous tokens that must never appear anywhere in an uploaded image.
     */
    protected const DANGEROUS_PATTERNS = [
        '/<\?(php|=|\s)/i',
        '/<\?\s*\$/i',
        '/<script\b[^>]*>/i',
        '/__HALT_COMPILER\s*\(/i',
        '/\b(system|shell_exec|passthru|popen|proc_open|eval|assert)\s*\(/i',
    ];

    /**
     * Dangerous XML attributes/tags in SVG files (preventing Stored XSS).
     */
    protected const SVG_DANGEROUS_PATTERNS = [
        '/<script\b/i',
        '/javascript\s*:/i',
        '/\bon\w+\s*=/i', // onload=, onerror=, onclick=, etc.
        '/<(iframe|foreignObject|object|embed|applet)\b/i',
        '/xlink:href\s*=\s*["\']\s*javascript:/i',
        '/href\s*=\s*["\']\s*javascript:/i',
    ];

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if ($value === null || $value === '') {
            return;
        }

        if (! $value instanceof UploadedFile) {
            $fail('Berkas :attribute harus berupa berkas unggahan yang valid.');

            return;
        }

        if (! $value->isValid()) {
            $fail('Unggahan berkas :attribute gagal atau berkas rusak.');

            return;
        }

        // 1. Baca konten berkas untuk pemeriksaan polyglot.
        $content = '';
        try {
            /** @var mixed $rawFile */
            $rawFile = $value;
            if (is_object($rawFile) && property_exists($rawFile, 'tempFile') && is_resource($rawFile->tempFile)) {
                rewind($rawFile->tempFile);
                $content = (string) stream_get_contents($rawFile->tempFile);
            } elseif (method_exists($value, 'get')) {
                $content = (string) $value->get();
            } elseif (method_exists($value, 'getContent')) {
                $content = (string) $value->getContent();
            }
        } catch (Throwable) {
            // Abaikan dan gunakan fallback
        }

        if ($content === '') {
            $realPath = $value->getRealPath() ?: $value->getPathname();
            if ($realPath && is_readable($realPath)) {
                $content = (string) @file_get_contents($realPath);
            }
        }

        if ($content === '') {
            $fail('Gagal membaca isi berkas :attribute.');

            return;
        }

        // 2. Verifikasi ukuran wajar (maksimal 2MB untuk ikon/gambar).
        $size = strlen($content);
        if ($size <= 0 || $size > 2097152) {
            $fail('Ukuran berkas :attribute tidak boleh lebih dari 2MB.');

            return;
        }

        $clientExt = strtolower((string) $value->getClientOriginalExtension());
        $clientMime = strtolower((string) ($value->getClientMimeType() ?? ''));

        // 3. Pindai token PHP atau webshell berbahaya di seluruh byte file.
        foreach (self::DANGEROUS_PATTERNS as $pattern) {
            if (preg_match($pattern, $content) === 1) {
                $fail('Berkas :attribute ditolak: terdeteksi mengandung kode atau script yang tidak diizinkan.');

                return;
            }
        }

        // 4. Penanganan khusus SVG (XML-based).
        if ($clientExt === 'svg' || str_contains($clientMime, 'svg')) {
            foreach (self::SVG_DANGEROUS_PATTERNS as $pattern) {
                if (preg_match($pattern, $content) === 1) {
                    $fail('Berkas SVG :attribute ditolak: mengandung elemen script atau event handler berbahaya.');

                    return;
                }
            }

            return;
        }

        // 5. Validasi struktur raster image (JPEG/PNG/WEBP/GIF) dari byte string.
        $imageInfo = @getimagesizefromstring($content);

        if ($imageInfo === false) {
            $fail('Berkas :attribute bukan format gambar yang valid.');

            return;
        }

        $detectedMime = $imageInfo['mime'] ?? '';

        if (! in_array($detectedMime, self::ALLOWED_MIMES, true)) {
            $fail('Tipe gambar :attribute tidak didukung.');

            return;
        }

        // 6. Verifikasi integritas menggunakan GD jika ekstensi terpasang.
        if (extension_loaded('gd')) {
            $this->verifyImageIntegrityFromString($content, $fail);
        }
    }

    /**
     * Memastikan gambar dapat dirender oleh library GD tanpa korupsi stream.
     */
    protected function verifyImageIntegrityFromString(string $content, Closure $fail): void
    {
        try {
            $img = @imagecreatefromstring($content);

            if ($img === false) {
                $fail('Struktur berkas gambar rusak atau tidak dapat diproses.');

                return;
            }

            if (is_resource($img) || (is_object($img) && $img instanceof \GdImage)) {
                imagedestroy($img);
            }
        } catch (Throwable) {
            $fail('Struktur berkas gambar rusak atau tidak valid.');
        }
    }
}
