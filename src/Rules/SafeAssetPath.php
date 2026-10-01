<?php

namespace Internal\SecurityMonitor\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * Validates the string value of an "icon" / asset field.
 *
 * The admin forms let an operator pick an icon from the media library, so the
 * value is normally a full URL (http://host/assets/icons/x.png) or a relative
 * path (icons/x.png). Anything that tries to walk the filesystem
 * ("../../../public/wne"), hide behind a dotfile (".htaccess") or smuggle an
 * executable extension (shell.php.jpg, x.php%00.jpg) is rejected here so the
 * payload can never be stored in the database and rendered back to clients.
 */
class SafeAssetPath implements ValidationRule
{
    /**
     * Extensions that may never appear in a stored asset path.
     */
    protected const BLOCKED_EXTENSIONS = [
        'php', 'php2', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht',
        'phar', 'phps', 'asp', 'aspx', 'ashx', 'asmx', 'jsp', 'jspx', 'cgi',
        'pl', 'py', 'rb', 'sh', 'bash', 'exe', 'dll', 'bat', 'cmd', 'com',
        'scr', 'js', 'mjs', 'html', 'htm', 'xhtml', 'shtml', 'svgz', 'htaccess',
    ];

    /**
     * Extensions accepted for icons.
     */
    protected const ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'bmp'];

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if ($value === null || $value === '') {
            return;
        }

        if (! is_string($value)) {
            $fail('Nilai :attribute tidak valid.');

            return;
        }

        $candidate = trim($value);

        // Null bytes (raw or encoded) are the classic extension bypass.
        if (preg_match('/(%00|%2500)/i', $candidate) === 1 || str_contains($candidate, "\0")) {
            $this->reject($fail);

            return;
        }

        // Backslashes are a traversal separator on Windows and never valid here.
        if (str_contains($candidate, '\\') || str_contains($candidate, '..')) {
            $this->reject($fail);

            return;
        }

        $isUrl = preg_match('#^https?://#i', $candidate) === 1;
        $path = $isUrl
            ? (string) (parse_url($candidate, PHP_URL_PATH) ?? '')
            : $candidate;

        $path = rawurldecode($path);

        if ($path === '') {
            $this->reject($fail);

            return;
        }

        // Absolute filesystem paths are only acceptable inside a full URL.
        if (str_starts_with($path, '/') && ! $isUrl) {
            $this->reject($fail);

            return;
        }

        // Dotfiles (.htaccess, .env) anywhere in the path.
        if (preg_match('#(^|/)\.#', ltrim($path, '/')) === 1) {
            $this->reject($fail);

            return;
        }

        if (preg_match('/[<>\'"{};|`$]/', $path) === 1) {
            $this->reject($fail);

            return;
        }

        // A double extension (logo.php.jpg) hides an executable file behind an
        // image suffix, so inspect every segment, not only the last one.
        if (preg_match('/\.('.implode('|', self::BLOCKED_EXTENSIONS).')(\b|[;.\s])/i', $path) === 1) {
            $this->reject($fail);

            return;
        }

        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));

        if (! in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            $fail('Nilai :attribute harus berupa berkas gambar ('.implode(', ', self::ALLOWED_EXTENSIONS).').');
        }
    }

    protected function reject(Closure $fail): void
    {
        $fail('Nilai :attribute tidak aman: hanya nama berkas gambar tanpa path traversal, dotfile, atau ekstensi yang dapat dieksekusi.');
    }
}
