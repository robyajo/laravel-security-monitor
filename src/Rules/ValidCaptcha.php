<?php

namespace Internal\SecurityMonitor\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Internal\SecurityMonitor\Services\CaptchaService;

/**
 * Memvalidasi jawaban captcha pada form login.
 *
 * Kode captcha bersifat sekali pakai, sehingga setiap kali validasi dijalankan
 * (berhasil maupun gagal) challenge lama otomatis dibuang dan halaman harus
 * meminta gambar captcha baru.
 */
class ValidCaptcha implements ValidationRule
{
    public function __construct(protected ?string $form = 'login') {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $captcha = app(CaptchaService::class);

        if (! $captcha->appliesTo($this->form ?? 'login')) {
            return;
        }

        if (! $captcha->verify(is_string($value) ? $value : null)) {
            $fail('Kode captcha tidak sesuai atau sudah kedaluwarsa. Silakan masukkan kode yang tertera pada gambar.');
        }
    }
}
