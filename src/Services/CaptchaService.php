<?php

namespace Internal\SecurityMonitor\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * Captcha mandiri (tanpa layanan pihak ketiga dan tanpa API key).
 *
 * Kode captcha digambar sebagai matriks titik di dalam SVG, sehingga teks kode
 * TIDAK pernah dikirim ke browser — berbeda dengan captcha berbasis
 * <text> yang bisa dibaca hanya dengan melihat source halaman.
 *
 * Kode disimpan di session dalam bentuk hash (sha1) dan bersifat sekali pakai.
 */
class CaptchaService
{
    /**
     * Kunci session tempat challenge disimpan.
     */
    public const SESSION_KEY = 'captcha_challenge';

    /**
     * Ukuran sel matriks (piksel) untuk satu titik glyph 5x7.
     */
    protected const CELL = 7;

    /**
     * Font matriks 5x7: setiap baris adalah 5 bit (bit kiri = piksel paling kiri).
     *
     * @var array<string, array<int, int>>
     */
    protected const FONT = [
        'A' => [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'B' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110],
        'C' => [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
        'D' => [0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110],
        'E' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
        'F' => [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000],
        'G' => [0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110],
        'H' => [0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
        'J' => [0b00001, 0b00001, 0b00001, 0b00001, 0b10001, 0b10001, 0b01110],
        'K' => [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
        'M' => [0b10001, 0b11011, 0b10101, 0b10001, 0b10001, 0b10001, 0b10001],
        'N' => [0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001],
        'P' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
        'Q' => [0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101],
        'R' => [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
        'T' => [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
        'U' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
        'V' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100],
        'W' => [0b10001, 0b10001, 0b10001, 0b10001, 0b10101, 0b11011, 0b10001],
        'X' => [0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001],
        'Y' => [0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100],
        'Z' => [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111],
        '2' => [0b01110, 0b10001, 0b00001, 0b00110, 0b01000, 0b10000, 0b11111],
        '3' => [0b11111, 0b00001, 0b00010, 0b00110, 0b00001, 0b10001, 0b01110],
        '4' => [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
        '6' => [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
        '7' => [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
        '8' => [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
        '9' => [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100],
    ];

    /**
     * Palet warna gelap agar kontras dengan latar terang.
     *
     * @var string[]
     */
    protected const COLORS = ['#0f172a', '#1e3a8a', '#7f1d1d', '#14532d', '#4c1d95', '#7c2d12'];

    public function enabled(): bool
    {
        return (bool) config('captcha.enabled', true);
    }

    /**
     * Apakah captcha dipakai pada form tertentu (mis. "login").
     */
    public function appliesTo(string $form = 'login'): bool
    {
        return $this->enabled() && (bool) config("captcha.for.{$form}", true);
    }

    /**
     * Buat kode baru, simpan di session, dan kembalikan SVG-nya.
     */
    public function generate(): string
    {
        $code = $this->randomCode();

        session()->put(self::SESSION_KEY, $this->challengeFor($code));

        return $this->render($code);
    }

    /**
     * Bentuk challenge untuk sebuah kode (hash + masa berlaku) tanpa menyentuh
     * session.
     *
     * Dipakai oleh generate() dan oleh pengujian, sehingga rumus hash tetap
     * hanya berada di satu tempat.
     *
     * @return array{hash: string, expires_at: int, issued_at: int}
     */
    public function challengeFor(string $code): array
    {
        return [
            'hash' => $this->hash($code),
            'expires_at' => now()->addSeconds($this->ttl())->timestamp,
            'issued_at' => now()->timestamp,
        ];
    }

    /**
     * Verifikasi jawaban pengguna. Kode selalu dibuang setelah diperiksa
     * (sekali pakai) sehingga tidak bisa dipakai ulang untuk request lain.
     */
    public function verify(?string $value): bool
    {
        $challenge = session(self::SESSION_KEY);
        $this->forget();

        if (! is_array($challenge)) {
            return false;
        }

        $expiresAt = (int) ($challenge['expires_at'] ?? 0);
        $hash = (string) ($challenge['hash'] ?? '');

        if ($hash === '' || $expiresAt < now()->timestamp) {
            return false;
        }

        if (! is_string($value) || trim($value) === '') {
            return false;
        }

        return hash_equals($hash, $this->hash($value));
    }

    /**
     * Hapus challenge yang tersimpan (dipakai setelah verifikasi).
     */
    public function forget(): void
    {
        session()->forget(self::SESSION_KEY);
    }

    public function ttl(): int
    {
        return max(60, (int) config('captcha.ttl_seconds', 300));
    }

    /**
     * URL gambar captcha (dengan penanda waktu agar tidak di-cache browser).
     */
    public function imageUrl(): string
    {
        return url('/captcha?t=').now()->timestamp;
    }

    protected function randomCode(): string
    {
        $charset = (string) config('captcha.charset', 'ABCDEFGHJKMNPQRTUVWXYZ2346789');
        $length = max(4, min(8, (int) config('captcha.length', 5)));
        $charset = $this->sanitizeCharset($charset);
        $max = strlen($charset) - 1;

        $code = '';

        for ($i = 0; $i < $length; $i++) {
            $code .= $charset[random_int(0, $max)];
        }

        return $code;
    }

    /**
     * Hanya sisakan karakter yang punya glyph di font matriks.
     */
    protected function sanitizeCharset(string $charset): string
    {
        $allowed = implode('', array_keys(self::FONT));
        $filtered = '';

        foreach (str_split(strtoupper($charset)) as $char) {
            if (str_contains($allowed, $char) && ! str_contains($filtered, $char)) {
                $filtered .= $char;
            }
        }

        return $filtered === '' ? 'ABCDEFGHJKMNPQRTUVWXYZ2346789' : $filtered;
    }

    protected function hash(string $code): string
    {
        return sha1(Str::upper(trim($code)).'|'.$this->salt());
    }

    /**
     * Salt dari APP_KEY agar hash tidak bisa ditebak tanpa kunci aplikasi.
     */
    protected function salt(): string
    {
        return (string) config('app.key', 'laravel-security-monitor-captcha');
    }

    /**
     * Render kode menjadi SVG matriks titik (tanpa teks yang bisa dibaca mesin).
     */
    protected function render(string $code): string
    {
        $width = max(160, (int) config('captcha.width', 220));
        $height = max(50, (int) config('captcha.height', 70));
        $chars = str_split($code);
        $count = max(1, count($chars));
        $difficulty = max(1, min(3, (int) config('captcha.difficulty', 2)));

        $cell = self::CELL;
        $glyphWidth = 5 * $cell;
        $slot = intdiv($width - 20, $count);
        $offsetX = max(8, intdiv($slot - $glyphWidth, 2));
        $baseline = intdiv($height - 7 * $cell, 2) + 6;

        $svg = sprintf(
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="Kode captcha">',
            $width,
            $height,
            $width,
            $height
        );

        $svg .= '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
            .'<stop offset="0%" stop-color="#f8fafc"/><stop offset="100%" stop-color="#e2e8f0"/>'
            .'</linearGradient></defs>';
        $svg .= sprintf('<rect width="100%%" height="100%%" rx="8" fill="url(#bg)"/>');

        // Garis noise di belakang glyph.
        $lines = [1 => 3, 2 => 5, 3 => 8][$difficulty];
        $svg .= $this->noiseLines($lines, $width, $height);

        foreach ($chars as $index => $char) {
            $rows = self::FONT[$char] ?? self::FONT['A'];
            $color = self::COLORS[array_rand(self::COLORS)];
            $originX = $offsetX + $index * $slot + random_int(-3, 3);
            $originY = $baseline + random_int(-4, 4);
            $rotation = random_int(-12, 12);

            $svg .= sprintf(
                '<g transform="rotate(%d %d %d)">',
                $rotation,
                $originX + intdiv($glyphWidth, 2),
                $originY + intdiv(7 * $cell, 2)
            );

            $svg .= $this->renderGlyph($rows, $originX, $originY, $cell, $color);
            $svg .= '</g>';
        }

        // Titik noise di depan glyph agar OCR makin sulit.
        $dots = [1 => 18, 2 => 34, 3 => 55][$difficulty];
        $svg .= $this->noiseDots($dots, $width, $height);

        return $svg.'</svg>';
    }

    /**
     * @param  array<int, int>  $rows
     */
    protected function renderGlyph(array $rows, int $originX, int $originY, int $cell, string $color): string
    {
        $shape = '';

        foreach ($rows as $row => $bits) {
            for ($column = 0; $column < 5; $column++) {
                // Bit paling kiri direpresentasikan oleh bit ke-4 (0b10000).
                if ((($bits >> (4 - $column)) & 1) === 0) {
                    continue;
                }

                $cx = $originX + ($column * $cell) + intdiv($cell, 2);
                $cy = $originY + ($row * $cell) + intdiv($cell, 2);
                $radius = intdiv($cell, 2) + random_int(0, 1);

                $shape .= sprintf(
                    '<circle cx="%d" cy="%d" r="%s" fill="%s"/>',
                    $cx,
                    $cy,
                    number_format($radius * 0.92, 2, '.', ''),
                    $color
                );
            }
        }

        return $shape;
    }

    protected function noiseLines(int $count, int $width, int $height): string
    {
        $svg = '';

        for ($i = 0; $i < $count; $i++) {
            $x1 = random_int(0, $width);
            $y1 = random_int(0, $height);
            $x2 = random_int(0, $width);
            $y2 = random_int(0, $height);
            $cx = random_int(0, $width);
            $cy = random_int(0, $height);

            $svg .= sprintf(
                '<path d="M %d %d Q %d %d %d %d" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round" opacity="%s"/>',
                $x1,
                $y1,
                $cx,
                $cy,
                $x2,
                $y2,
                self::COLORS[array_rand(self::COLORS)],
                number_format(random_int(8, 16) / 10, 1, '.', ''),
                number_format(random_int(25, 50) / 100, 2, '.', '')
            );
        }

        return $svg;
    }

    protected function noiseDots(int $count, int $width, int $height): string
    {
        $svg = '';

        for ($i = 0; $i < $count; $i++) {
            $svg .= sprintf(
                '<circle cx="%d" cy="%d" r="%s" fill="%s" opacity="%s"/>',
                random_int(0, $width),
                random_int(0, $height),
                number_format(random_int(6, 18) / 10, 1, '.', ''),
                self::COLORS[array_rand(self::COLORS)],
                number_format(random_int(20, 55) / 100, 2, '.', '')
            );
        }

        return $svg;
    }

    /**
     * Kapan challenge saat ini kedaluwarsa (untuk ditampilkan di UI).
     */
    public function expiresAt(): ?Carbon
    {
        $challenge = session(self::SESSION_KEY);
        $expiresAt = is_array($challenge) ? (int) ($challenge['expires_at'] ?? 0) : 0;

        return $expiresAt > 0 ? Carbon::createFromTimestamp($expiresAt) : null;
    }
}
