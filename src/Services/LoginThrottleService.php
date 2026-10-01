<?php

namespace Internal\SecurityMonitor\Services;

use Internal\SecurityMonitor\Models\LoginAttempt;
use Internal\SecurityMonitor\Models\SecurityLog;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Throwable;

/**
 * Cooldown login bertingkat.
 *
 * Setiap "threshold" kegagalan (default 3x) menaikkan level blokir satu
 * langkah dan menambah durasi:
 *
 *   3x gagal  ->  1 menit
 *   6x gagal  ->  2 menit
 *   9x gagal  ->  3 menit   (dst, dibatasi "max_minutes")
 *
 * Riwayat kegagalan dianggap kadaluwarsa setelah "decay_minutes" tanpa
 * percobaan, supaya pengguna yang lupa sandi kemarin tidak langsung terkunci
 * lama hari ini. Login yang berhasil mengosongkan riwayat sepenuhnya.
 */
class LoginThrottleService
{
    public function __construct(protected SecurityMonitorService $security) {}

    public function enabled(): bool
    {
        return $this->config('enabled', true);
    }

    /**
     * Status blokir untuk kombinasi email + IP.
     *
     * @return array{locked: bool, seconds: int, level: int, attempts: int, threshold: int, message: string|null}
     */
    public function status(?string $email, ?string $ip): array
    {
        $threshold = (int) $this->config('threshold', 3);
        $empty = [
            'locked' => false,
            'seconds' => 0,
            'level' => 0,
            'attempts' => 0,
            'threshold' => $threshold,
            'message' => null,
        ];

        if (! $this->enabled()) {
            return $empty;
        }

        $record = $this->find($email, $ip);

        if ($record === null) {
            return $empty;
        }

        $this->decay($record);

        if (! $record->isLocked()) {
            return [
                'locked' => false,
                'seconds' => 0,
                'level' => $record->lockout_level,
                'attempts' => $record->attempts,
                'threshold' => $threshold,
                'message' => null,
            ];
        }

        $seconds = $record->secondsRemaining();

        return [
            'locked' => true,
            'seconds' => $seconds,
            'level' => $record->lockout_level,
            'attempts' => $record->attempts,
            'threshold' => $threshold,
            'message' => $this->lockoutMessage($seconds),
        ];
    }

    /**
     * Catat satu kegagalan login. Bila mencapai threshold, akun dikunci
     * sementara dan level kunci dinaikkan.
     *
     * @return array{locked: bool, seconds: int, level: int, attempts: int, threshold: int, message: string|null}
     */
    public function registerFailure(?string $email, ?string $ip): array
    {
        $threshold = (int) $this->config('threshold', 3);

        if (! $this->enabled()) {
            return [
                'locked' => false, 'seconds' => 0, 'level' => 0,
                'attempts' => 0, 'threshold' => $threshold, 'message' => null,
            ];
        }

        try {
            $record = $this->find($email, $ip) ?? new LoginAttempt([
                'email' => $email,
                'ip_address' => $ip,
            ]);

            $this->decay($record);

            $record->attempts = (int) $record->attempts + 1;
            $record->last_attempt_at = now();

            if ($record->attempts >= $threshold) {
                $record->lockout_level = (int) $record->lockout_level + 1;
                $record->attempts = 0;
                $record->locked_until = now()->addMinutes($this->minutesForLevel((int) $record->lockout_level));
            }

            $record->save();
        } catch (Throwable) {
            return [
                'locked' => false, 'seconds' => 0, 'level' => 0,
                'attempts' => 0, 'threshold' => $threshold, 'message' => null,
            ];
        }

        if ($record->isLocked()) {
            $this->recordLockout($record, $email, $ip);
        }

        return $this->status($email, $ip);
    }

    /**
     * Reset riwayat kegagalan setelah login berhasil.
     */
    public function registerSuccess(?string $email, ?string $ip): void
    {
        $record = $this->find($email, $ip);

        if ($record === null) {
            return;
        }

        try {
            $record->delete();
        } catch (Throwable) {
            // Mengosongkan riwayat tidak boleh menggagalkan proses login.
        }
    }

    /**
     * Buka paksa blokir untuk sebuah email + IP (aksi admin).
     */
    public function release(string $email, ?string $ip = null): int
    {
        return LoginAttempt::query()
            ->where('email', $email)
            ->when($ip !== null, fn ($query) => $query->where('ip_address', $ip))
            ->delete();
    }

    /**
     * Daftar blokir yang sedang aktif untuk ditampilkan di panel admin.
     *
     * @return Collection<int, LoginAttempt>
     */
    public function activeLockouts(): Collection
    {
        return LoginAttempt::query()
            ->locked()
            ->orderByDesc('locked_until')
            ->get();
    }

    /**
     * Durasi blokir (menit) untuk level tertentu.
     */
    public function minutesForLevel(int $level): int
    {
        $base = max(1, (int) $this->config('base_minutes', 1));
        $max = max($base, (int) $this->config('max_minutes', 30));

        return min($level * $base, $max);
    }

    public function lockoutMessage(int $seconds): string
    {
        $minutes = (int) ceil($seconds / 60);

        return sprintf(
            'Terlalu banyak percobaan login yang gagal. Demi keamanan, akun ini dikunci sementara. Silakan coba lagi dalam %d menit.',
            $minutes
        );
    }

    protected function config(string $key, mixed $default = null): mixed
    {
        return config('security.login_lockout.'.$key, $default);
    }

    protected function find(?string $email, ?string $ip): ?LoginAttempt
    {
        if ($email === null && $ip === null) {
            return null;
        }

        try {
            return LoginAttempt::query()
                ->where('email', $email)
                ->where('ip_address', $ip)
                ->first();
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Reset level kunci bila riwayat sudah terlalu lama.
     */
    protected function decay(LoginAttempt $record): void
    {
        if ($record->lockout_level === 0 && $record->attempts === 0) {
            return;
        }

        $decayMinutes = max(1, (int) $this->config('decay_minutes', 60));
        $lastAttempt = $record->last_attempt_at;

        if ($lastAttempt === null || $lastAttempt->diffInMinutes(now()) < $decayMinutes) {
            return;
        }

        // Blokir yang masih berjalan tidak dihapus oleh decay.
        if ($record->isLocked()) {
            return;
        }

        $record->attempts = 0;
        $record->lockout_level = 0;
        $record->save();
    }

    protected function recordLockout(LoginAttempt $record, ?string $email, ?string $ip): void
    {
        $this->security->log([
            'ip_address' => (string) ($ip ?? 'unknown'),
            'event_type' => 'login_lockout',
            'threat_level' => match (true) {
                $record->lockout_level >= 5 => 'critical',
                $record->lockout_level >= 3 => 'high',
                default => 'medium',
            },
            'method' => 'POST',
            'path' => '/login',
            'rule_label' => 'Akun terkunci sementara karena percobaan login gagal berulang',
            'evidence' => sprintf(
                'Akun %s dari IP %s dikunci %d menit (level %d).',
                Str::limit((string) $email, 120, ''),
                $ip ?? 'unknown',
                $this->minutesForLevel((int) $record->lockout_level),
                $record->lockout_level
            ),
            'user_agent' => Str::limit((string) request()?->userAgent(), 500, '') ?: null,
            'action_taken' => 'temporary_lockout',
            'meta' => [
                'lockout_level' => $record->lockout_level,
                'locked_until' => $record->locked_until?->toIso8601String(),
            ],
        ]);

        if ($record->lockout_level >= 3 && is_string($ip) && $ip !== '') {
            try {
                $this->security->autoBlockIfNeeded($ip);
            } catch (Throwable) {
                // Biarkan: blokir IP bersifat tambahan, bukan syarat utama.
            }
        }
    }

    /**
     * Ringkasan untuk panel keamanan.
     *
     * @return array<string, int>
     */
    public function stats(): array
    {
        return [
            'failed_today' => SecurityLog::query()
                ->where('event_type', 'login_failed')
                ->where('created_at', '>=', now()->startOfDay())
                ->count(),
            'lockouts_today' => SecurityLog::query()
                ->where('event_type', 'login_lockout')
                ->where('created_at', '>=', now()->startOfDay())
                ->count(),
            'active_lockouts' => LoginAttempt::query()->locked()->count(),
            'tracked_accounts' => LoginAttempt::query()->count(),
        ];
    }
}
