<?php

namespace Internal\SecurityMonitor\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Removes the leftovers of an attack or penetration test from the database.
 *
 * Pentest scanners store their markers in every writable form field
 * ("{{7*7}}", "../../../public/wne", ".htaccess", "wne-ssti-blade", ...).
 * Those rows are then served to users and break the application,
 * so they must be cleaned up safely.
 */
class PurgeInjectedData extends Command
{
    protected $signature = 'security:purge-injected-data
                            {--force : Hapus data yang terdeteksi (tanpa opsi ini hanya menampilkan daftar)}
                            {--marker=* : Marker spesifik yang dicari, mis. --marker=wne (boleh diulang)}
                            {--model=* : Batasi ke model tertentu}';

    protected $description = 'Temukan dan hapus data hasil injeksi (payload pentest) di database';

    /**
     * Default injection markers when --marker is not supplied.
     *
     * @var string[]
     */
    protected array $defaultMarkers = [
        '..%2f', '../', '..\\', '%00', '\\0',
        '<?php', '<?=', '<script', 'javascript:', 'onerror=', 'onload=',
        '{{', '}}', '${', '<%=',
        'union select', 'etc/passwd', 'information_schema',
        '.htaccess', '.env', 'ssti', 'phpinfo', 'wne', 'c99', 'r57', 'shell.php',
    ];

    public function handle(): int
    {
        $force = (bool) $this->option('force');
        $markers = array_filter((array) $this->option('marker'));
        $markers = $markers === [] ? $this->defaultMarkers : $markers;

        // Targets can be defined in config('security.purge_targets')
        $allTargets = (array) config('security.purge_targets', []);

        // Filter only targets whose models exist
        $validTargets = [];
        foreach ($allTargets as $label => $target) {
            if (isset($target['model']) && class_exists($target['model'])) {
                $validTargets[$label] = $target;
            }
        }

        $only = array_filter((array) $this->option('model'));
        $targets = $only === []
            ? $validTargets
            : array_intersect_key($validTargets, array_flip($only));

        if ($targets === []) {
            $this->warn('Tidak ada target model yang dikonfigurasi di config("security.purge_targets").');
            $this->line('Tambahkan target pembersihan pada konfigurasi Anda, contoh:');
            $this->line('  "purge_targets" => [');
            $this->line('      "posts" => ["model" => \App\Models\Post::class, "columns" => ["title", "content"]],');
            $this->line('  ]');

            return self::SUCCESS;
        }

        $this->info($force ? 'Mode HAPUS dijalankan.' : 'Mode pratinjau (dry-run). Tambahkan --force untuk menghapus.');
        $this->newLine();

        $totalFound = 0;
        $totalDeleted = 0;

        foreach ($targets as $label => $target) {
            /** @var class-string<Model> $class */
            $class = $target['model'];
            $columns = (array) ($target['columns'] ?? []);

            if (empty($columns)) {
                continue;
            }

            $query = $class::query()->where(function ($query) use ($columns, $markers) {
                foreach ($columns as $column) {
                    foreach ($markers as $marker) {
                        $query->orWhere($column, 'like', '%'.$this->escapeLike($marker).'%');
                    }
                }
            });

            $rows = $query->get();

            if ($rows->isEmpty()) {
                $this->line("<fg=gray>{$label}: bersih</>");

                continue;
            }

            $totalFound += $rows->count();
            $this->warn("{$label}: {$rows->count()} baris mencurigakan");

            foreach ($rows as $row) {
                $this->line($this->describe($row, $columns, $markers));
            }

            if (! $force) {
                continue;
            }

            try {
                DB::transaction(fn () => $class::query()
                    ->whereIn('id', $rows->pluck('id')->all())
                    ->delete());

                $totalDeleted += $rows->count();
            } catch (Throwable $exception) {
                $this->error("Gagal menghapus data {$label}: {$exception->getMessage()}");
            }
        }

        $this->newLine();

        if ($totalFound === 0) {
            $this->info('Tidak ada data injeksi yang ditemukan.');

            return self::SUCCESS;
        }

        if ($force) {
            $this->info("Selesai. {$totalDeleted} dari {$totalFound} baris dihapus.");
            $this->comment('Jalankan "php artisan security:purge-injected-data" lagi untuk memastikan sudah bersih.');
        } else {
            $this->comment("{$totalFound} baris perlu dibersihkan. Jalankan ulang dengan --force untuk menghapusnya.");
        }

        return self::SUCCESS;
    }

    protected function describe(Model $row, array $columns, array $markers): string
    {
        foreach ($columns as $column) {
            $value = $row->getAttribute($column);

            if (! is_string($value) || $value === '') {
                continue;
            }

            foreach ($markers as $marker) {
                if (stripos($value, $marker) !== false) {
                    return sprintf(
                        '  #%s → %s.%s = %s',
                        $row->getKey(),
                        class_basename($row),
                        $column,
                        mb_strimwidth(str_replace(["\r", "\n"], ' ', $value), 0, 90, '…')
                    );
                }
            }
        }

        return '  #'.$row->getKey().' → '.class_basename($row);
    }

    protected function escapeLike(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', "\%", "\_"], $value);
    }
}
