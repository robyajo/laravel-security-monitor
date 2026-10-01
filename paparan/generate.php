<?php

declare(strict_types=1);

/**
 * Generator presentasi PowerPoint (.pptx) untuk
 * robyajo/laravel-security-monitor (Bulwark).
 *
 * Tanpa dependensi eksternal — hanya memakai ekstensi PHP:
 *   - zip  (ZipArchive)
 *   - dom  (validasi XML)
 *
 * Jalankan:
 *   php paparan/generate.php
 */

$outFile = __DIR__ . "/Laravel-Security-Monitor-Bulwark.pptx";

const SLIDE_W = 12192000; // 13.333 in (16:9)
const SLIDE_H = 6858000; // 7.5 in
const ML = 838200; // margin kiri
const CW = 10515600; // lebar konten

// ---------------------------------------------------------------------------
// Helper XML
// ---------------------------------------------------------------------------

function esc(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, "UTF-8");
}

function rPr(bool $bold, int $sz, ?string $color, bool $mono = false): string
{
    $attrs = ' lang="en-US" sz="' . $sz . '" dirty="0"';
    if ($bold) {
        $attrs .= ' b="1"';
    }

    $inner = "";
    if ($color !== null) {
        $inner .=
            '<a:solidFill><a:srgbClr val="' . $color . '"/></a:solidFill>';
    }
    if ($mono) {
        $inner .= '<a:latin typeface="Consolas"/><a:cs typeface="Consolas"/>';
    }

    return $inner === ""
        ? "<a:rPr" . $attrs . "/>"
        : "<a:rPr" . $attrs . ">" . $inner . "</a:rPr>";
}

/** Render teks; potongan di antara backtick dirender monospace. */
function runs(string $text, bool $bold, int $sz, string $color): string
{
    $parts = preg_split("/`([^`]+)`/", $text, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [
        $text,
    ];
    $xml = "";

    foreach ($parts as $i => $part) {
        if ($part === "") {
            continue;
        }

        $mono = $i % 2 === 1;
        $xml .=
            "<a:r>" .
            rPr(
                $bold,
                $mono ? max(1000, $sz - 100) : $sz,
                $mono ? "0EA5E9" : $color,
                $mono,
            ) .
            "<a:t>" .
            esc($part) .
            "</a:t></a:r>";
    }

    return $xml;
}

function bulletPara(string $text, int $lvl, int $sz, string $color): string
{
    $marL = $lvl === 0 ? 285750 : 571500;
    $char = $lvl === 0 ? "•" : "–";
    $pPr =
        '<a:pPr marL="' .
        $marL .
        '" indent="-285750">' .
        '<a:buFont typeface="Arial"/><a:buChar char="' .
        $char .
        '"/></a:pPr>';

    return "<a:p>" . $pPr . runs($text, false, $sz, $color) . "</a:p>";
}

function plainPara(
    string $text,
    bool $bold,
    int $sz,
    string $color,
    string $align = "l",
): string {
    $pPr = $align === "l" ? "<a:pPr/>" : '<a:pPr algn="' . $align . '"/>';

    return "<a:p>" . $pPr . runs($text, $bold, $sz, $color) . "</a:p>";
}

function textBox(
    int $id,
    string $name,
    int $x,
    int $y,
    int $cx,
    int $cy,
    string $paras,
    string $anchor = "t",
): string {
    $bodyPr =
        '<a:bodyPr wrap="square" lIns="0" rIns="0" tIns="0" bIns="0" anchor="' .
        $anchor .
        '">' .
        "<a:normAutofit/></a:bodyPr>";

    return '<p:sp><p:nvSpPr><p:cNvPr id="' .
        $id .
        '" name="' .
        esc($name) .
        '"/>' .
        '<p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>' .
        '<p:spPr><a:xfrm><a:off x="' .
        $x .
        '" y="' .
        $y .
        '"/><a:ext cx="' .
        $cx .
        '" cy="' .
        $cy .
        '"/></a:xfrm>' .
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr>' .
        "<p:txBody>" .
        $bodyPr .
        "<a:lstStyle/>" .
        $paras .
        "</p:txBody></p:sp>";
}

function rect(
    int $id,
    string $name,
    int $x,
    int $y,
    int $cx,
    int $cy,
    string $fill,
): string {
    return '<p:sp><p:nvSpPr><p:cNvPr id="' .
        $id .
        '" name="' .
        esc($name) .
        '"/>' .
        "<p:cNvSpPr/><p:nvPr/></p:nvSpPr>" .
        '<p:spPr><a:xfrm><a:off x="' .
        $x .
        '" y="' .
        $y .
        '"/><a:ext cx="' .
        $cx .
        '" cy="' .
        $cy .
        '"/></a:xfrm>' .
        '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>' .
        '<a:solidFill><a:srgbClr val="' .
        $fill .
        '"/></a:solidFill><a:ln><a:noFill/></a:ln></p:spPr>' .
        "<p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody></p:sp>";
}

function spTree(string $shapes): string
{
    return "<p:spTree>" .
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>' .
        '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/>' .
        '<a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>' .
        $shapes .
        "</p:spTree>";
}

function slideXml(string $shapes): string
{
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"' .
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"' .
        ' xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">' .
        "<p:cSld>" .
        spTree($shapes) .
        "</p:cSld>" .
        "<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>" .
        "</p:sld>";
}

// ---------------------------------------------------------------------------
// Tata letak slide
// ---------------------------------------------------------------------------

function titleSlide(array $s): string
{
    $shapes = rect(2, "BG", 0, 0, SLIDE_W, SLIDE_H, "0F172A");
    $shapes .= rect(3, "AccentBar", 0, 4750000, SLIDE_W, 91440, "06B6D4");
    $shapes .= textBox(
        4,
        "Title",
        ML,
        2000000,
        CW,
        1300000,
        plainPara($s["title"], true, 5400, "FFFFFF"),
        "b",
    );
    $shapes .= textBox(
        5,
        "Subtitle",
        ML,
        3350000,
        CW,
        1100000,
        plainPara($s["subtitle"], false, 2400, "22D3EE"),
        "t",
    );

    if (!empty($s["footer"])) {
        $shapes .= textBox(
            6,
            "Footer",
            ML,
            5900000,
            CW,
            500000,
            plainPara($s["footer"], false, 1400, "94A3B8"),
            "t",
        );
    }

    return slideXml($shapes);
}

function sectionSlide(array $s): string
{
    $shapes = rect(2, "BG", 0, 0, SLIDE_W, SLIDE_H, "0F172A");
    $shapes .= rect(3, "Accent", ML, 3300000, 1600200, 45720, "06B6D4");
    $shapes .= textBox(
        4,
        "Title",
        ML,
        3500000,
        CW,
        1300000,
        plainPara($s["title"], true, 4000, "FFFFFF"),
        "t",
    );

    return slideXml($shapes);
}

function contentSlide(array $s): string
{
    $shapes = rect(2, "TopBar", 0, 0, SLIDE_W, 182880, "0F172A");
    $shapes .= textBox(
        3,
        "Title",
        ML,
        420000,
        10000000,
        900000,
        plainPara($s["title"], true, 3200, "0F172A"),
        "t",
    );
    $shapes .= rect(4, "Underline", ML, 1330000, 685800, 27432, "06B6D4");

    $paras = "";
    foreach ($s["bullets"] as $b) {
        $lvl = 0;
        if (str_starts_with($b, "- ")) {
            $lvl = 1;
            $b = substr($b, 2);
        }
        $paras .= bulletPara($b, $lvl, $lvl === 0 ? 1700 : 1500, "1E293B");
    }

    $shapes .= textBox(5, "Body", ML, 1600200, CW, 4900000, $paras, "t");

    return slideXml($shapes);
}

// ---------------------------------------------------------------------------
// Konten presentasi
// ---------------------------------------------------------------------------

$slides = [
    [
        "kind" => "title",
        "title" => "Laravel Security Monitor",
        "subtitle" => "Bulwark — WAF & Threat Engine Headless untuk Laravel",
        "footer" =>
            "robyajo/laravel-security-monitor  ·  v1.0.6  ·  Lisensi MIT",
    ],
    [
        "kind" => "content",
        "title" => "Latar Belakang",
        "bullets" => [
            "Aplikasi web menghadapi serangan berkelanjutan: SQL Injection, XSS, RCE, webshell, dan brute force.",
            "WAF komersial mahal, bergantung pihak ketiga, dan menempatkan data sensitif di luar kendali kita.",
            "Serangan sering ditolak web server sebelum request sampai ke Laravel — tidak tercatat di aplikasi.",
            "Dibutuhkan solusi self-hosted yang ringan, tanpa dependensi frontend, dan siap produksi.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Solusi: Bulwark",
        "bullets" => [
            "Paket Composer murni PHP (100% Pure PHP, Zero NPM, tanpa build step frontend).",
            "Menggabungkan WAF self-hosted, threat detection engine, dan security auditing dalam satu paket.",
            "Arsitektur headless: seluruh fitur diekspos lewat REST API JSON.",
            "Sekali `composer require`, langsung terhubung ke inti Laravel (standar Spatie).",
            "Frontend-agnostic: Blade, Livewire, Inertia/React, Filament, hingga API murni.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Fitur Utama",
        "bullets" => [
            "Zero-Tolerance Threat Detection",
            "Device-Level Quarantine (isolasi perangkat pada IP publik bersama)",
            "Stepped Login Lockout (penalti bertingkat 1 menit – 24 jam)",
            "Pure SVG CAPTCHA (tanpa GD/Imagick)",
            "Server Integrity & Webshell Scanner",
            "Streaming Access Log Scanner",
            "Sistem Tiket Banding (appeal) mandiri",
            "Headless REST API + Perintah Artisan CLI",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Zero-Tolerance Threat Engine",
        "bullets" => [
            "Blokir instan pada percobaan pertama — tanpa menunggu ambang batas.",
            "Signature wajib: null-byte upload, ekstensi ganda, path traversal, probe `.env`/`.git`/`.htaccess`, SSTI canary.",
            "Deteksi progresif: SQLi, XSS, LFI, command injection, dan Scanner User-Agent (ambang geser).",
            "Regex kebal ReDoS — dilarang nested quantifier seperti `(a+)+`.",
            "Durasi blokir instan default 720 jam (30 hari), dapat dikonfigurasi.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Device-Level Quarantine",
        "bullets" => [
            "Masalah: satu IP publik dipakai banyak pengguna (kantor, Wi-Fi publik, NAT).",
            "Solusi: `block_scope = device` memakai `device_id` + `local_ip`.",
            "Perangkat penyerang diisolasi tanpa mengganggu pengguna sah di router yang sama.",
            "Dukungan reverse proxy: `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For` dengan proteksi anti-spoofing.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Stepped Login Lockout",
        "bullets" => [
            "Penalti eksponensial: 1 menit → 5 → 15 → 1 jam → 24 jam.",
            "Efektif mencegah brute force dan credential stuffing.",
            "Terhubung otomatis ke event inti Laravel: `Failed` dan `Login`.",
            "Pencabutan blokir manual tersedia lewat CLI dan API admin.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Pure SVG CAPTCHA Tanpa Dependensi",
        "bullets" => [
            "Dibuat murni dengan matematika vektor PHP — tanpa `ext-gd`, tanpa Imagick, tanpa library npm.",
            "Distorsi anti-OCR pada setiap tantangan.",
            "Token sekali pakai dengan verifikasi stateless.",
            "Validation Rule `ValidCaptcha` siap dipakai di form mana pun.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Server Integrity & Webshell Scanner",
        "bullets" => [
            "Baseline integritas SHA-256 untuk berkas inti (`app/`, `config/`, `routes/`, `public/index.php`).",
            "Melaporkan berkas yang berubah, hilang, dan berkas baru yang mencurigakan.",
            "Pemindai webshell di `public/` & `storage/` (b374k, c99, r57, wso, `eval(base64_decode()).`",
            "Penghapusan aman: anti path-traversal, dibatasi `base_path()`, berkas vital dilindungi.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Streaming Access Log Scanner",
        "bullets" => [
            "Membaca log Apache/Nginx baris-per-baris via generator — konsumsi RAM stabil di bawah 15 MB.",
            "Menangkap penyerang yang ditolak web server sebelum request mencapai PHP.",
            "Auto-block IP langsung dari log mentah.",
            "Dijadwalkan harian (cron) melalui Laravel Scheduler.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Appeal Tickets & Session Tracking",
        "bullets" => [
            "Endpoint publik untuk mengajukan banding buka blokir beserta pelacakan status.",
            "Rate-limit 30 menit untuk mencegah penyalahgunaan.",
            "Persetujuan admin otomatis mencabut karantina dan menambahkan ke whitelist.",
            "Pelacakan sesi aktif dengan heartbeat aktivitas yang di-throttle (45 detik).",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Arsitektur & Integrasi",
        "bullets" => [
            "Auto-discovery: `SecurityMonitorServiceProvider` + Facade `SecurityMonitor`.",
            "Trait `HasSecurityRelations` pada model `User` host.",
            "Middleware teraliasing: `security.block`, `security.detect`, `security.admin`, `security.activity`.",
            "Gate `manage-security-monitor` untuk otorisasi admin.",
            "Model & nama tabel dinamis via config — tidak ada `User` atau tabel yang di-hardcode.",
            "Zero-touch opsional: `SECURITY_AUTO_REGISTER_MIDDLEWARE=true`.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Headless REST API",
        "bullets" => [
            "Publik: captcha, verifikasi captcha, submit & cek status tiket banding.",
            "Pengguna terautentikasi: menyimpan IP saat ini sebagai IP terpercaya.",
            "Admin (`auth` + `security.admin`): logs, blocked-ips, server audit, sessions, tickets.",
            "Envelope JSON konsisten dengan status HTTP yang tepat.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "CLI Artisan & Automation",
        "bullets" => [
            "`security:install` — publikasi aset + hardening interaktif.",
            "`security:scan-logs` — pindai log akses dan auto-block.",
            "`security:baseline` — audit, buat, atau hapus baseline SHA-256.",
            "`security:unblock-ip` — cabut blokir darurat.",
            "`security:prune-logs` — bersihkan log kedaluwarsa (default 90 hari).",
            "`security:purge-injected-data` — bersihkan residu payload pentest dari database.",
            "Scheduler: prune log, heartbeat, dan pemindaian log harian.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Web Server Hardening",
        "bullets" => [
            "Nginx: dual rate-limit zone, eksekusi PHP hanya lewat `/index.php`, sandbox storage, blokir ekstensi ganda.",
            "Apache/LiteSpeed: proteksi dotfile, blokir ekstensi ganda, kunci berkas backup/log, matikan directory indexing.",
            "Publikasi template: `vendor:publish --tag=security-nginx` / `security-htaccess` / `security-all`.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Instalasi Cepat",
        "bullets" => [
            "`composer require robyajo/laravel-security-monitor`",
            "`php artisan security:install`",
            "`php artisan migrate`",
            "Tambahkan trait `HasSecurityRelations` ke model `User` dan daftarkan middleware.",
            "Opsional: `SECURITY_AUTO_REGISTER_MIDDLEWARE=true`.",
            "`php artisan security:baseline --create`",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Kualitas & Kompatibilitas",
        "bullets" => [
            "70 tes / 302 assertion (Pest PHP + Orchestra Testbench) — semuanya lulus.",
            "Matriks CI: Laravel 10–13 × PHP 8.2–8.5 (12 kombinasi, semuanya hijau).",
            "ReDoS-safe: setiap regex diuji terhadap payload 100KB+.",
            "Lisensi MIT, tanpa dependensi build frontend.",
        ],
    ],
    [
        "kind" => "content",
        "title" => "Roadmap",
        "bullets" => [
            "View default halaman 403 yang dapat dipublikasikan.",
            "Analitik statistik dan dashboard opsional.",
            "Integrasi notifikasi tambahan (Slack/Telegram).",
            "Dokumentasi berbahasa Inggris.",
            "Static analysis (PHPStan/Larastan) di pipeline CI.",
        ],
    ],
    [
        "kind" => "section",
        "title" => "Terima Kasih",
    ],
    [
        "kind" => "content",
        "title" => "Tautan",
        "bullets" => [
            "Repositori: `github.com/robyajo/laravel-security-monitor`",
            "Packagist: `packagist.org/packages/robyajo/laravel-security-monitor`",
            "Instalasi: `composer require robyajo/laravel-security-monitor`",
            "Dokumentasi: direktori `documents/` (25 bab) + portal `documents/index.html`",
        ],
    ],
];

// ---------------------------------------------------------------------------
// Part-part OOXML statis
// ---------------------------------------------------------------------------

$theme = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Bulwark Theme"><a:themeElements><a:clrScheme name="Bulwark"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="0F172A"/></a:dk2><a:lt2><a:srgbClr val="F8FAFC"/></a:lt2><a:accent1><a:srgbClr val="06B6D4"/></a:accent1><a:accent2><a:srgbClr val="3B82F6"/></a:accent2><a:accent3><a:srgbClr val="22C55E"/></a:accent3><a:accent4><a:srgbClr val="F59E0B"/></a:accent4><a:accent5><a:srgbClr val="EF4444"/></a:accent5><a:accent6><a:srgbClr val="8B5CF6"/></a:accent6><a:hlink><a:srgbClr val="3B82F6"/></a:hlink><a:folHlink><a:srgbClr val="8B5CF6"/></a:folHlink></a:clrScheme><a:fontScheme name="Bulwark"><a:majorFont><a:latin typeface="Segoe UI"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Segoe UI"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Bulwark"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="6350" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="12700" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="19050" cap="flat" cmpd="sng" algn="ctr"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>
XML;

$slideMaster = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles><p:titleStyle><a:lvl1pPr algn="l"><a:defRPr sz="4000" b="1"/></a:lvl1pPr></p:titleStyle><p:bodyStyle><a:lvl1pPr marL="285750" indent="-285750"><a:defRPr sz="1600"/></a:lvl1pPr></p:bodyStyle><p:otherStyle><a:defRPr sz="1800"/></p:otherStyle></p:txStyles></p:sldMaster>
XML;

$slideLayout = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1"><p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>
XML;

$presProps = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentationPr xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:showPr useTimings="0" showAnimation="1" showNarration="1" loop="0"/></p:presentationPr>
XML;

$tableStyles = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:tblStyleLst xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" def="{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}"/>
XML;

$coreXml = <<<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Laravel Security Monitor (Bulwark)</dc:title><dc:subject>WAF &amp; Threat Engine Headless untuk Laravel</dc:subject><dc:creator>Roby</dc:creator><cp:lastModifiedBy>Roby</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2026-10-02T00:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-02T00:00:00Z</dcterms:modified></cp:coreProperties>
XML;

$totalSlides = count($slides);

$appXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"' .
    ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">' .
    "<Application>Microsoft Office PowerPoint</Application>" .
    "<Company>robyajo</Company>" .
    "<Slides>" .
    $totalSlides .
    "</Slides>" .
    "</Properties>";

// Relasi & daftar slide
$sldIdLst = "";
$presentationRels = "";
for ($i = 0; $i < $totalSlides; $i++) {
    $num = $i + 1;
    $rid = $i + 2; // rId1 dipakai slideMaster
    $sldIdLst .= '<p:sldId id="' . (256 + $i) . '" r:id="rId' . $rid . '"/>';
    $presentationRels .=
        '<Relationship Id="rId' .
        $rid .
        '"' .
        ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide"' .
        ' Target="slides/slide' .
        $num .
        '.xml"/>';
}
$rPresProps = "rId" . ($totalSlides + 2);
$rTableStyles = "rId" . ($totalSlides + 3);
$rTheme = "rId" . ($totalSlides + 4);

$presentationRels =
    '<Relationship Id="rId1"' .
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster"' .
    ' Target="slideMasters/slideMaster1.xml"/>' .
    $presentationRels .
    '<Relationship Id="' .
    $rPresProps .
    '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps" Target="presProps.xml"/>' .
    '<Relationship Id="' .
    $rTableStyles .
    '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/tableStyles" Target="tableStyles.xml"/>' .
    '<Relationship Id="' .
    $rTheme .
    '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>';

$presentationXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
    '<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"' .
    ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"' .
    ' xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" saveSubsetFonts="1">' .
    '<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>' .
    "<p:sldIdLst>" .
    $sldIdLst .
    "</p:sldIdLst>" .
    '<p:sldSz cx="' .
    SLIDE_W .
    '" cy="' .
    SLIDE_H .
    '" type="screen16x9"/>' .
    '<p:notesSz cx="6858000" cy="9144000"/>' .
    "</p:presentation>";

// Content Types
$contentTypes =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' .
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' .
    '<Default Extension="xml" ContentType="application/xml"/>' .
    '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>' .
    '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>' .
    '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>';

for ($i = 0; $i < $totalSlides; $i++) {
    $num = $i + 1;
    $contentTypes .=
        '<Override PartName="/ppt/slides/slide' .
        $num .
        '.xml"' .
        ' ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>';
}

$contentTypes .=
    '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>' .
    '<Override PartName="/ppt/presProps.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presProps+xml"/>' .
    '<Override PartName="/ppt/tableStyles.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml"/>' .
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' .
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>' .
    "</Types>";

// ---------------------------------------------------------------------------
// Susun arsip
// ---------------------------------------------------------------------------

$parts = [
    "[Content_Types].xml" => $contentTypes,
    "_rels/.rels" =>
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>' .
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' .
        '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>' .
        "</Relationships>",
    "docProps/core.xml" => $coreXml,
    "docProps/app.xml" => $appXml,
    "ppt/presentation.xml" => $presentationXml,
    "ppt/_rels/presentation.xml.rels" =>
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
        $presentationRels .
        "</Relationships>",
    "ppt/presProps.xml" => $presProps,
    "ppt/tableStyles.xml" => $tableStyles,
    "ppt/theme/theme1.xml" => $theme,
    "ppt/slideMasters/slideMaster1.xml" => $slideMaster,
    "ppt/slideMasters/_rels/slideMaster1.xml.rels" =>
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>' .
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>' .
        "</Relationships>",
    "ppt/slideLayouts/slideLayout1.xml" => $slideLayout,
    "ppt/slideLayouts/_rels/slideLayout1.xml.rels" =>
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>' .
        "</Relationships>",
];

foreach ($slides as $i => $slide) {
    $num = $i + 1;
    $xml = match ($slide["kind"]) {
        "title" => titleSlide($slide),
        "section" => sectionSlide($slide),
        default => contentSlide($slide),
    };

    $parts["ppt/slides/slide" . $num . ".xml"] = $xml;
    $parts["ppt/slides/_rels/slide" . $num . ".xml.rels"] =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>' .
        "</Relationships>";
}

if (file_exists($outFile)) {
    unlink($outFile);
}

$zip = new ZipArchive();
if ($zip->open($outFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "Gagal membuat arsip: {$outFile}\n");
    exit(1);
}

foreach ($parts as $name => $content) {
    $zip->addFromString($name, $content);
}
$zip->close();

// ---------------------------------------------------------------------------
// Verifikasi
// ---------------------------------------------------------------------------

$check = new ZipArchive();
if ($check->open($outFile) !== true) {
    fwrite(STDERR, "Gagal membuka kembali arsip.\n");
    exit(1);
}

$errors = 0;
for ($i = 0; $i < $check->numFiles; $i++) {
    $name = $check->getNameIndex($i);
    if (!preg_match('/\.(xml|rels)$/', $name)) {
        continue;
    }

    $data = $check->getFromIndex($i);
    $doc = new DOMDocument();
    $prev = libxml_use_internal_errors(true);
    if (!$doc->loadXML($data)) {
        $errors++;
        fwrite(STDERR, "XML tidak valid: {$name}\n");
    }
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
}

$fileCount = $check->numFiles;

// Cek cakupan [Content_Types].xml untuk setiap part.
$ctXml = $check->getFromName("[Content_Types].xml");
$ctDoc = new DOMDocument();
$ctDoc->loadXML((string) $ctXml);

$defaults = [];
$overrides = [];
foreach ($ctDoc->getElementsByTagName("Default") as $el) {
    $defaults[strtolower($el->getAttribute("Extension"))] = true;
}
foreach ($ctDoc->getElementsByTagName("Override") as $el) {
    $overrides[ltrim($el->getAttribute("PartName"), "/")] = true;
}

$names = [];
for ($i = 0; $i < $check->numFiles; $i++) {
    $names[] = (string) $check->getNameIndex($i);
}
sort($names);

foreach ($names as $name) {
    if ($name === "[Content_Types].xml") {
        continue;
    }
    $ext = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
    if (!isset($overrides[$name]) && !isset($defaults[$ext])) {
        $errors++;
        fwrite(STDERR, "Part tanpa Content Type: {$name}\n");
    }
}

$check->close();

if ($errors > 0) {
    fwrite(STDERR, "Verifikasi gagal: {$errors} part bermasalah.\n");
    exit(1);
}

$size = filesize($outFile);

foreach ($names as $name) {
    echo "  - " . $name . "\n";
}

echo "\nOK\n";
echo "File   : {$outFile}\n";
echo "Slides : {$totalSlides}\n";
echo "Parts  : {$fileCount}\n";
echo "Size   : " . number_format($size / 1024, 1) . " KB\n";
echo "Semua part XML valid, terbaca, dan tercakup Content Types.\n";
