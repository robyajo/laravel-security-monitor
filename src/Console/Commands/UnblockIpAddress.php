<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;
use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Escape hatch so an administrator can never be permanently locked out of the
 * panel when their own IP gets blocked by the security monitor.
 */
class UnblockIpAddress extends Command
{
    protected $signature = 'security:unblock-ip
                            {ip? : Alamat IP yang akan dibuka blokirnya}
                            {--all : Buka blokir seluruh IP}
                            {--list : Tampilkan daftar IP yang sedang diblokir}';

    protected $description = 'Buka blokir alamat IP yang diblokir oleh Security Monitor';

    public function handle(SecurityMonitorService $service): int
    {
        if ($this->option('list') || (! $this->argument('ip') && ! $this->option('all'))) {
            return $this->listBlocks();
        }

        if ($this->option('all')) {
            $blocks = BlockedIp::query()->active()->get();

            if (! $this->confirm("Buka blokir untuk {$blocks->count()} IP?", true)) {
                return self::SUCCESS;
            }

            foreach ($blocks as $block) {
                $service->unblock($block);
            }

            $this->info("{$blocks->count()} blokir IP telah dibuka.");

            return self::SUCCESS;
        }

        $ip = (string) $this->argument('ip');
        $block = BlockedIp::query()->where('ip_address', $ip)->first();

        if ($block === null) {
            $this->warn("IP {$ip} tidak ada dalam daftar blokir.");

            return self::SUCCESS;
        }

        $service->unblock($block);

        $this->info("Blokir untuk IP {$ip} telah dibuka.");

        return self::SUCCESS;
    }

    protected function listBlocks(): int
    {
        $blocks = BlockedIp::query()
            ->active()
            ->orderByDesc('blocked_at')
            ->get(['ip_address', 'source', 'reason', 'expires_at', 'hit_count']);

        if ($blocks->isEmpty()) {
            $this->info('Tidak ada IP yang sedang diblokir.');

            return self::SUCCESS;
        }

        $this->table(
            ['IP', 'Sumber', 'Percobaan', 'Kedaluwarsa', 'Alasan'],
            $blocks->map(fn (BlockedIp $block) => [
                $block->ip_address,
                $block->source,
                $block->hit_count,
                $block->expires_at?->diffForHumans() ?? 'Permanen',
                mb_strimwidth((string) $block->reason, 0, 60, '…'),
            ])->all()
        );

        return self::SUCCESS;
    }
}
