<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Security Monitor
    |--------------------------------------------------------------------------
    |
    | Master switch for the threat detection middleware. When disabled, no
    | request inspection is performed and nothing is written to the security
    | logs. IP blocking is controlled separately by "block_enforcement".
    |
    */

    'enabled' => (bool) env('SECURITY_MONITOR_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Block Enforcement
    |--------------------------------------------------------------------------
    |
    | When enabled, every request coming from an active blocked IP receives a
    | 403 response. When disabled, blocked IPs are still recorded so the admin
    | panel keeps working, but no request is rejected.
    |
    */

    'block_enforcement' => (bool) env('SECURITY_BLOCK_ENFORCEMENT', true),

    /*
    |--------------------------------------------------------------------------
    | Blocked Attempt Logging
    |--------------------------------------------------------------------------
    |
    | A blocked IP that keeps knocking will not flood the log table: one entry
    | is stored per IP for each "blocked_log_interval" seconds. The hit counter
    | on the blocked IP record is always updated.
    |
    */

    'blocked_log_interval' => (int) env('SECURITY_BLOCKED_LOG_INTERVAL', 10),

    /*
    |--------------------------------------------------------------------------
    | Automatic Blocking
    |--------------------------------------------------------------------------
    |
    | When an IP triggers at least "threshold" events of the configured levels
    | ("levels") inside the "window_minutes" window, it is automatically
    | blocked for "duration_hours" hours. Use 0 to block permanently.
    |
    */

    'auto_block' => [
        'enabled' => (bool) env('SECURITY_AUTO_BLOCK_ENABLED', true),
        'threshold' => (int) env('SECURITY_AUTO_BLOCK_THRESHOLD', 3),
        'window_minutes' => (int) env('SECURITY_AUTO_BLOCK_WINDOW', 10),
        'duration_hours' => (int) env('SECURITY_AUTO_BLOCK_DURATION', 24),
        'levels' => ['high', 'critical'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Instant Block (Zero Tolerance)
    |--------------------------------------------------------------------------
    |
    | Signatures below are attack patterns that never appear in normal
    | traffic (null byte uploads, double extensions, webshell names, path
    | traversal into the webroot, .htaccess/.env probes, SSTI canaries,
    | injected PHP code, vulnerability scanners). The FIRST match blocks the
    | source IP immediately, without waiting for the auto block threshold.
    |
    | "duration_hours" = 0 blocks permanently. "target" limits where a
    | signature is looked for: path, query, body, input (query + body),
    | user_agent or any.
    |
    */

    'instant_block' => [
        'enabled' => (bool) env('SECURITY_INSTANT_BLOCK_ENABLED', true),
        'duration_hours' => (int) env('SECURITY_INSTANT_BLOCK_DURATION', 720),
        'skip_whitelisted' => true,
        'signatures' => [
            [
                'id' => 'webshell_upload',
                'label' => 'Percobaan upload webshell (null byte / double extension)',
                'target' => 'any',
                'patterns' => [
                    // wne.php%00.jpg  →  null byte di tengah nama berkas
                    '/(%00|\x00|%2500)/i',
                    // wne.php.jpg  /  shell.phtml.png  /  wne.php;.jpg
                    // Kelas karakter tunggal (bukan "\s*[;.\s]*") agar tidak ada
                    // ambiguitas kuantifier yang bisa memperlambat regex.
                    '/\.(php|php[0-9]|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|htaccess)[\s;.]*\.(jpe?g|png|gif|bmp|svg|webp|ico|pdf|txt|zip|rar|docx?|xlsx?)\b/i',
                    // .php.jpg  /  .php.  /  .php::$DATA
                    '/\.(php|php[0-9]|phtml|pht|phar)\s*[;:.](\s|$|\?|%2e)/i',
                    '/(\$\_POST|\$\_GET|\$\_REQUEST|\$\_FILES|\$\_SERVER|\$GLOBALS)\s*\[/i',
                ],
            ],
            [
                'id' => 'unsafe_filename',
                'label' => 'Nama berkas unggahan mengandung ekstensi berbahaya',
                'target' => 'filename',
                'patterns' => [
                    '/\.(php|php[0-9]|phtml|pht|phar|phps|asp|aspx|ashx|asmx|jsp|jspx|cgi|pl|py|rb|sh|bash|exe|dll|bat|cmd|scr|js|html?|htaccess)\b/i',
                    '/(%00|\x00)/',
                    // ".." hanya berbahaya sebagai KOMPONEN path (../../x.jpg),
                    // bukan dua titik di tengah nama berkas (Laporan..2026.pdf).
                    '/(^|[\/\\])\.\.([\/\\]|$)|(\.\.)(%2f|%5c)/i',
                ],
            ],
            [
                'id' => 'webshell_path',
                'label' => 'Akses nama berkas webshell yang dikenal',
                'target' => 'path',
                'patterns' => [
                    '/(^|\/)(wne|wso|c99|r57|b374k|indoxploit|webshell|web-shell|shell|backdoor|defacer|hacked|alfa|kingsman|symlink|gags)\d*\.(php[0-9]?|phtml|phar|txt|jpg|png|gif|zip)\b/i',
                    '/(^|\/)(adminer|mysql-admin|sqlbuddy|phpspy|p0wny|weevely|antSword)\b/i',
                ],
            ],
            [
                'id' => 'path_traversal_public',
                'label' => 'Percobaan path traversal menuju folder publik',
                'target' => 'any',
                'patterns' => [
                    '/(\.\.\/){2,}/',
                    '/(\.\.\\\\){2,}/',
                    '/(%2e%2e(\/|%2f|\\\\|%5c)){2,}/i',
                    '/(\.\.\/)+(public|storage|vendor|config|resources|bootstrap|app)(\/|$)/i',
                    // Catatan: "var/www" sengaja TIDAK dipakai walau terlihat
                    // seperti path sistem, karena folder itulah document root
                    // aplikasi ini (/var/www/your-app/public/...)
                    // sehingga sering muncul di konten admin yang sah. Probe ke
                    // sana tetap tertangkap oleh pola traversal di atas.
                    '/\b(etc\/passwd|etc\/shadow|proc\/self|windows\/win\.ini|boot\.ini)\b/i',
                ],
            ],
            [
                'id' => 'config_probe',
                'label' => 'Percobaan akses berkas konfigurasi / rahasia',
                'target' => 'path',
                'patterns' => [
                    '/\.(env|env\.[a-z]+|htaccess|htpasswd|user\.ini|git|svn|hg|bzr|aws|ssh)\b/i',
                    '/(^|\/)(web\.config|php\.ini|composer\.(json|lock)|artisan|\.npmrc|\.dockerignore|Dockerfile|docker-compose\.ya?ml|id_rsa|id_dsa|\.my\.cnf|\.netrc)\b/i',
                    '/(^|\/)(backup|dump|database|db|data|www)\.(sql|sql\.gz|tar|tar\.gz|zip|bak|old|orig|save|swp)\b/i',
                ],
            ],
            [
                'id' => 'ssti',
                'label' => 'Percobaan Server-Side Template Injection (SSTI)',
                'target' => 'any',
                'patterns' => [
                    // {{7*7}} / {{7*'7'}} / {{ a+b }} / {{ a/b }}
                    // Tanda "-" DIBIARKAN di luar kelas operator karena terlalu
                    // umum di teks manusia ({{ nama - jabatan }}, {{ tanggal-laporan }}).
                    '/\{\{\s*[\d\'"a-z_]+(\s*[*+\/]\s*[\d\'"a-z_]+)+\s*\}\}/i',
                    // {{7-7}} / {{49-1}} — pengurangan hanya bila kedua sisi angka/kutip
                    '/\{\{\s*[\d\'"]+\s*-\s*[\d\'"]+\s*\}\}/i',
                    '/\{\{\s*(7\s*[*x]\s*7|49)\s*\}\}/i',
                    '/\$\{\s*[\d\'"a-z_]+(\s*[*+\/]\s*[\d\'"a-z_]+)+\s*\}/i',
                    '/\$\{\s*[\d\'"]+\s*-\s*[\d\'"]+\s*\}/i',
                    '/<%=\s*[\d\'"a-z_]+(\s*[*+.\-\/]\s*[\d\'"a-z_]+)+\s*%>/i',
                    '/\{\{\s*(self|config|app|_self|_context|request|globals)\b/i',
                    '/\b(ssti|twig|jinja2?|freemarker|velocity)\b[\s._-]*(id|env|key|uname|phpinfo|payload|inc)\b/i',
                    '/(\bphpinfo\s*\(|\buname\s+-\w+|;\s*(whoami|\bid)\b|\|\s*(whoami|\bid)\b)/i',
                ],
            ],
            [
                'id' => 'php_injection',
                'label' => 'Kode PHP disuntikkan melalui parameter / form',
                'target' => 'input',
                'patterns' => [
                    '/<\?(php|=|\s)/i',
                    '/<\?\s*\$|\?>.*<\?/',
                    '/(system|shell_exec|passthru|popen|proc_open|exec|eval|assert|create_function|base64_decode|gzinflate|str_rot13|preg_replace\s*\(\s*[\'"].*\/e)\s*\(\s*\$?/',
                    '/(include|require)(_once)?\s*\(?\s*[\'"][^\'"]*\.\.\//i',
                ],
            ],
            [
                'id' => 'scanner_ua',
                'label' => 'Perangkat pemindai kerentanan otomatis',
                'target' => 'user_agent',
                'patterns' => [
                    // "httpx" dan "photon" sengaja TIDAK ada di daftar ini:
                    // python-httpx adalah pustaka HTTP klien yang sah (integrasi
                    // OPD) sehingga blokir instan 30 hari akan salah sasaran.
                    // Keduanya tetap tertangkap secara perilaku (probe .env,
                    // wp-admin, dll) oleh signature lain.
                    '/\b(sqlmap|nikto|nmap|masscan|nessus|openvas|acunetix|netsparker|appscan|webinspect|burp|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|dirsearch|wpscan|joomscan|droopescan|nuclei|zgrab|hydra|medusa|metasploit|havij|arachni|skipfish|w3af|commix|jaeles|xray|zaproxy|zap|whatweb|wafw00f|subfinder|gospider|fimap|xsstrike|dalfox|tplmap|ysoserial)\b/i',
                ],
            ],
            [
                'id' => 'secret_exposure',
                'label' => 'Percobaan membaca kredensial / secret aplikasi',
                'target' => 'any',
                'patterns' => [
                    '/(APP_KEY|DB_PASSWORD|DB_USERNAME|MAIL_PASSWORD|AWS_SECRET|SECRET_KEY|PRIVATE_KEY)\s*=/i',
                    '/-----BEGIN\s+(RSA|OPENSSH|PGP|EC|DSA)?\s*PRIVATE KEY-----/i',
                    '/\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b/',
                ],
            ],
            [
                'id' => 'log4shell_jndi',
                'label' => 'Percobaan Log4Shell / JNDI injection',
                'target' => 'any',
                'patterns' => [
                    // ${jndi:ldap://...} / ${JNDI:ldaps://...} (case-insensitive,
                    // spasi antar token diizinkan untuk menembus normalisasi).
                    '/\$\{\s*j\s*n\s*d\s*i\s*:/i',
                    // Obfuscation klasik: ${${lower:j}ndi:...} / ${${upper:J}NDI:...}
                    '/\$\{\s*\$\{[^}]{0,80}\}\s*n\s*d\s*i\s*:/i',
                    // Obfuscation lain: ${j${lower:n}di:...} / ${j${::-n}di:...}
                    '/\$\{\s*j\s*\$\{[^}]{0,80}\}\s*d\s*i\s*:/i',
                    // Bentuk ter-URL-encode: %24%7Bjndi%3A / %24%7B%24%7Blower%3Aj%7Dndi%3A
                    '/%24%7b[a-z0-9%{}._:-]{0,140}ndi%3a/i',
                ],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Whitelist
    |--------------------------------------------------------------------------
    |
    | These addresses are never logged and never blocked. Accepts exact IPs
    | (127.0.0.1), wildcards (192.168.1.*) and CIDR ranges (10.0.0.0/8).
    | Always add the office / internal network and the reverse proxy here.
    |
    */

    'whitelist' => array_values(array_filter(array_map(
        'trim',
        explode(',', (string) env('SECURITY_IP_WHITELIST', '127.0.0.1,::1'))
    ))),

    /*
    |--------------------------------------------------------------------------
    | Detection Rules
    |--------------------------------------------------------------------------
    |
    | Every rule is matched against the request path, query string, body
    | (string inputs only) and user agent. Levels: low, medium, high, critical.
    |
    */

    'rules' => [
        [
            'id' => 'sql_injection',
            'label' => 'Indikasi SQL Injection',
            'level' => 'critical',
            'patterns' => [
                '/\b(union\b[^\n]{0,20}\bselect|select\b[^\n]{0,40}\bfrom|insert\b[^\n]{0,20}\binto|delete\b[^\n]{0,15}\bfrom|drop\b\s+(table|database)|alter\b\s+table)\b/i',
                '/\b(or|and)\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
                '/(\'\s*(or|and)\s*\'|"\s*(or|and)\s*")/i',
                '/(\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\bpg_sleep\s*\()/i',
                '/(\bxp_cmdshell\b|\binformation_schema\b|\bsysobjects\b|\bload_file\s*\(|\binto\s+outfile\b)/i',
                // Komentar SQL: kutip sebelum "--", "--" di akhir nilai, atau
                // "--" di awal nilai. Pola lebar "/--\s/" dibuang karena
                // teks Indonesia memakai "--" sebagai pemisah
                // ("Pekanbaru -- Pemerintah Kota", "Pasal 1 -- Ketentuan Umum").
                '/([\'"]\s*--|--\s*$|^\s*--|\/\*!\d|\bnull\s*,\s*null\s*,)/i',
            ],
        ],
        [
            'id' => 'xss',
            'label' => 'Indikasi Cross Site Scripting (XSS)',
            'level' => 'high',
            'patterns' => [
                '/<\s*script\b|<\s*\/\s*script\s*>/i',
                '/<\s*(iframe|object|embed|svg|img|body|link|meta)\b[^>]{0,80}(on\w+\s*=|javascript:|data:text\/html)/i',
                '/\bon(error|load|mouseover|focus|click|submit|animationstart)\s*=/i',
                '/javascript\s*:\s*[a-z(]/i',
                '/(document\.(cookie|domain|write)|window\.location\s*=|\balert\s*\(\s*\d*\s*\))/i',
                '/(%3cscript|&lt;script|\\u003cscript)/i',
            ],
        ],
        [
            'id' => 'path_traversal',
            'label' => 'Indikasi Path Traversal',
            'level' => 'critical',
            'patterns' => [
                '/(\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)/i',
                '/(\/etc\/(passwd|shadow|hosts)|\/proc\/self\/environ|\bboot\.ini\b|\bwin\.ini\b|\bsystem32\\\\)/i',
            ],
        ],
        [
            'id' => 'command_injection',
            'label' => 'Indikasi Command Injection',
            'level' => 'critical',
            'patterns' => [
                '/([;|`]\s*|\$\(\s*|\|\|\s*|&&\s*)(cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|cmd|powershell|chmod|chown|rm)\b/i',
                '/(\|\s*(cat|ls|whoami|id)\b|\$\(.*\)\s*;?)/i',
            ],
        ],
        [
            'id' => 'code_injection',
            'label' => 'Indikasi Code / File Inclusion',
            'level' => 'critical',
            'patterns' => [
                '/(php:\/\/|data:\/\/|expect:\/\/|zip:\/\/|phar:\/\/|glob:\/\/)/i',
                '/(\beval\s*\(|\bassert\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|\bexec\s*\(|\bpopen\s*\(|\bbase64_decode\s*\()/i',
            ],
        ],
        [
            'id' => 'template_injection',
            'label' => 'Indikasi Template / Expression Injection',
            'level' => 'high',
            'patterns' => [
                // Hanya "{{ ... }}" yang memuat operator/kurung (ciri ekspresi
                // template), bukan placeholder biasa seperti {{nama}}.
                '/\{\{[^}]{0,60}[(){}.|*+\/][^}]{0,60}\}\}/',
                '/<%=?\s*[a-z_]/i',
                '/(\bclass\.forname\b|\bruntime\.getruntime\b|\bprocessbuilder\b|\bjava\.lang\.)/i',
            ],
        ],
        [
            'id' => 'null_byte',
            'label' => 'Null Byte / Encoding Anomali',
            'level' => 'medium',
            'patterns' => [
                '/(%00|\x00|%2500)/i',
                '/(\.\.%00|\/\.\.%2f)/i',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Sensitive Path Probing
    |--------------------------------------------------------------------------
    |
    | Requests that are not part of the application (credentials, backups,
    | dashboards of other software, ...). Matched against every path segment
    | and the query string. Use "*" as wildcard.
    |
    */

    'sensitive_paths' => [
        'critical' => [
            '.env',
            '.env.*',
            '.git',
            '.git/*',
            '.ssh',
            '.ssh/*',
            'id_rsa',
            'id_dsa',
            '.htpasswd',
            '.htaccess',
            '.aws',
            '.aws/*',
            'credentials',
            'credentials.*',
            'config.php',
            'configuration.php',
            'database.yml',
            'docker-compose.yml',
            'docker-compose.yaml',
            'web.config',
            '*passwd',
            '*secret*',
            '*private*key*',
        ],
        'high' => [
            'wp-admin',
            'wp-admin/*',
            'wp-login.php',
            'wp-config.php',
            'wp-content/*',
            'wp-includes/*',
            'xmlrpc.php',
            'phpmyadmin',
            'pma',
            'myadmin',
            'mysql',
            'phpinfo.php',
            'info.php',
            'test.php',
            'shell.php',
            'c99.php',
            'r57.php',
            'cgi-bin/*',
            'cgi-bin',
            'telescope',
            'telescope/*',
            '_ignition',
            '_ignition/*',
            'horizon',
            'horizon/*',
            'actuator',
            'actuator/*',
            'server-status',
            'server-info',
            'install.php',
            'setup.php',
            'db.php',
            'backup.sql',
            'dump.sql',
            'database.sql',
            '*.sql',
            '*.bak',
            '*.old',
            '*.swp',
            '*.tar.gz',
            '*.zip',
            'composer.json',
            'composer.lock',
            'package.json',
            'yarn.lock',
            'artisan',
            'vendor/*',
            'storage/logs/*',
            'admin.php',
            'administrator',
            'solr',
            'elasticsearch',
            'kibana',
            '.svn',
            '.hg',
            '.bzr',
            '.idea',
            '.vscode',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Scanner User Agents
    |--------------------------------------------------------------------------
    */

    'scanner_agents' => [
        'sqlmap',
        'nikto',
        'nmap',
        'masscan',
        'nessus',
        'acunetix',
        'netsparker',
        'burpsuite',
        'burp-',
        'dirbuster',
        'gobuster',
        'feroxbuster',
        'ffuf',
        'wfuzz',
        'wpscan',
        'joomscan',
        'droopescan',
        'nuclei',
        'zgrab',
        'hydra',
        'metasploit',
        'havij',
        'arachni',
        'skipfish',
        'openvas',
        'w3af',
        'commix',
        'jaeles',
        'gospider',
        'httrack',
        'libwww-perl',
        'zmeu',
        'xray',
        'zap-',
        'fimap',
        'webinspect',
        'appscan',
        'dirsearch',
        'whatweb',
        'wafw00f',
        'subfinder',
    ],

    /*
    |--------------------------------------------------------------------------
    | Detection Tuning
    |--------------------------------------------------------------------------
    |
    | "max_inspect_length" caps the amount of request data scanned per request
    | so payloads cannot slow the application down. "exclude_paths" are routes
    | that are always ignored by the detector (IP blocking still applies).
    |
    */

    'max_inspect_length' => (int) env('SECURITY_MAX_INSPECT_LENGTH', 4000),

    /*
    |--------------------------------------------------------------------------
    | Reject Suspicious Requests
    |--------------------------------------------------------------------------
    |
    | When enabled, a request carrying a "critical" payload is rejected with a
    | 403 response instead of only being logged. Keep it disabled when the
    | application receives free text input that may look like an attack
    | (e.g. citizens pasting code or SQL snippets into a form).
    |
    */

    'block_suspicious_requests' => (bool) env('SECURITY_BLOCK_SUSPICIOUS', false),

    'exclude_paths' => [
        'up',
        'build/*',
        'favicon.ico',
    ],

    /*
    |--------------------------------------------------------------------------
    | Log Retention
    |--------------------------------------------------------------------------
    |
    | Logs older than this are removed by the scheduled "security:prune-logs"
    | command. Use 0 to keep everything forever.
    |
    */

    'retention_days' => (int) env('SECURITY_LOG_RETENTION_DAYS', 90),

    /*
    |--------------------------------------------------------------------------
    | Access Log Analysis
    |--------------------------------------------------------------------------
    |
    | Lokasi access log web server yang dianalisis oleh "security:scan-logs".
    | Request yang ditolak nginx/Apache sebelum sampai ke PHP (mis. berkas
    | .php yang di-return 403, probe .env, scanning massal) TIDAK pernah
    | tercatat aplikasi, sehingga satu-satunya jejaknya ada di berkas ini.
    |
    | "paths" menerima wildcard. "max_lines" membatasi jumlah baris yang dibaca
    | per berkas agar perintah tetap responsif pada log yang sangat besar
    | (gunakan --since atau rotasi log untuk analisis yang lebih lama).
    |
    */

    'access_log' => [
        'paths' => array_values(array_filter(array_map(
            'trim',
            explode(',', (string) env(
                'SECURITY_ACCESS_LOG_PATHS',
                '/var/log/nginx/access.log,/var/log/nginx/*access.log,/var/log/apache2/access.log'
            ))
        ))),
        'max_lines' => (int) env('SECURITY_ACCESS_LOG_MAX_LINES', 500000),

        /*
        | Tugas harian opsional: memindai access log dan menyimpan temuan ke
        | security_logs (tanpa memblokir otomatis) agar serangan yang tidak
        | terlihat aplikasi tetap muncul di panel. Blokir tetap manual melalui
        | "php artisan security:scan-logs --block" setelah hasilnya ditinjau,
        | supaya baris log lama tidak memblokir IP yang kini sudah bersih.
        */
        'auto_scan_enabled' => (bool) env('SECURITY_ACCESS_LOG_AUTO_SCAN', false),
        'auto_scan_since_hours' => (int) env('SECURITY_ACCESS_LOG_AUTO_SCAN_HOURS', 24),
    ],

    /*
    |--------------------------------------------------------------------------
    | Progressive Login Lockout
    |--------------------------------------------------------------------------
    |
    | Setelah "threshold" kali login gagal, akun + IP dikunci sementara selama
    | "base_minutes" menit. Setiap kelipatan kegagalan berikutnya menambah
    | durasi secara bertingkat:
    |
    |   3x gagal  -> kunci 1 menit
    |   6x gagal  -> kunci 2 menit
    |   9x gagal  -> kunci 3 menit
    |   ... dibatasi "max_minutes"
    |
    | "decay_minutes" mengatur berapa lama riwayat kegagalan dianggap relevan:
    | bila percobaan terakhir sudah lebih lama dari itu, level kunci direset
    | sehingga pengguna yang lupa sandi kemarin tidak langsung terkunci lama.
    |
    */

    'login_lockout' => [
        'enabled' => (bool) env('SECURITY_LOGIN_LOCKOUT_ENABLED', true),
        'threshold' => (int) env('SECURITY_LOGIN_LOCKOUT_THRESHOLD', 3),
        'base_minutes' => (int) env('SECURITY_LOGIN_LOCKOUT_BASE_MINUTES', 1),
        'max_minutes' => (int) env('SECURITY_LOGIN_LOCKOUT_MAX_MINUTES', 30),
        'decay_minutes' => (int) env('SECURITY_LOGIN_LOCKOUT_DECAY_MINUTES', 60),
    ],

    /*
    |--------------------------------------------------------------------------
    | Server Security Scan
    |--------------------------------------------------------------------------
    |
    | Pemeriksaan sisi server yang ditampilkan di /security/server.
    | "cache_minutes" menyimpan hasil scan agar halaman tidak selalu membaca
    | filesystem; admin dapat memaksa scan ulang dari halaman tersebut.
    |
    | "integrity_paths" adalah daftar berkas yang hash-nya dipantau untuk
    | mendeteksi perubahan tidak sah (backdoor). Baseline dibuat oleh admin
    | melalui halaman server security atau perintah "security:baseline".
    |
    */

    'server_scan' => [
        'cache_minutes' => (int) env('SECURITY_SERVER_SCAN_CACHE_MINUTES', 10),
        'max_files_scanned' => (int) env('SECURITY_SERVER_SCAN_MAX_FILES', 20000),
        'recent_changes_days' => (int) env('SECURITY_RECENT_CHANGES_DAYS', 7),
        'disk_warning_percent' => (int) env('SECURITY_DISK_WARNING_PERCENT', 20),
        'disk_critical_percent' => (int) env('SECURITY_DISK_CRITICAL_PERCENT', 10),
        'max_admin_accounts' => (int) env('SECURITY_MAX_ADMIN_ACCOUNTS', 5),
        'log_size_warning_mb' => (int) env('SECURITY_LOG_SIZE_WARNING_MB', 100),

        // Dibaca oleh audit aplikasi (ServerSecurityService::applicationChecks()).
        'public_api_key' => env('PUBLIC_API_KEY'),
        'trusted_proxies' => env('TRUSTED_PROXIES'),

        'integrity_paths' => [
            'public/index.php',
            'public/.htaccess',
            'artisan',
            'bootstrap/app.php',
            'bootstrap/providers.php',
            'routes/web.php',
            'routes/api.php',
            'routes/console.php',
            'config/security.php',
            'app/Http/Middleware/*.php',
            'app/Services/SecurityMonitorService.php',
            'app/Providers/AppServiceProvider.php',
            'app/Providers/FortifyServiceProvider.php',
        ],

        /*
        | Berkas yang dikecualikan dari pemindaian berkas mencurigakan agar tidak
        | terjadi false-positive pada berkas sistem yang memuat aturan keamanan.
        */
        'suspicious_files_exclude' => [
            'config/security.php',
            'app/Services/ServerSecurityService.php',
            'app/Services/SecurityMonitorService.php',
            'app/Http/Middleware/DetectSecurityThreats.php',
            'app/Console/Commands/SecurityBaselineCommand.php',
            'app/Console/Commands/PurgeInjectedData.php',
            'app/Console/Commands/SecurityScanAccessLogs.php',
            'routes/console.php',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | Model yang merepresentasikan entitas Pengguna/User di aplikasi host.
    |
    */
    'user_model' => env('SECURITY_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | Database Table Names
    |--------------------------------------------------------------------------
    |
    | Nama tabel database yang dipakai oleh paket ini.
    |
    */
    'table_names' => [
        'users' => env('SECURITY_USERS_TABLE', 'users'),
        'blocked_ips' => env('SECURITY_BLOCKED_IPS_TABLE', 'blocked_ips'),
        'security_logs' => env('SECURITY_LOGS_TABLE', 'security_logs'),
        'login_attempts' => env('SECURITY_LOGIN_ATTEMPTS_TABLE', 'login_attempts'),
        'ip_unblock_requests' => env('SECURITY_IP_UNBLOCK_REQUESTS_TABLE', 'ip_unblock_requests'),
        'user_logins' => env('SECURITY_USER_LOGINS_TABLE', 'user_logins'),
        'trusted_ips' => env('SECURITY_TRUSTED_IPS_TABLE', 'trusted_ips'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Headless REST API Routes Configuration
    |--------------------------------------------------------------------------
    |
    | Pengaturan routing API headless untuk panel keamanan.
    |
    */
    'routes' => [
        'enabled' => (bool) env('SECURITY_ROUTES_ENABLED', true),
        'prefix' => env('SECURITY_ROUTES_PREFIX', 'api/security'),
        'middleware' => ['api'],
        'auth_middleware' => ['auth'],
        'admin_middleware' => ['Internal\\SecurityMonitor\\Http\\Middleware\\EnsureSecurityAdmin'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Starter Kit Monitoring Dashboard
    |--------------------------------------------------------------------------
    |
    | Panel monitoring opsional yang dapat dipublikasikan ke dalam
    | aplikasi host melalui perintah:
    |
    |     # Livewire Starter Kit (Flux UI)
    |     php artisan vendor:publish --tag=starterkit-livewire
    |
    |     # React Starter Kit (Inertia + React)
    |     php artisan vendor:publish --tag=starterkit-react
    |
    | Publikasi tersebut menyalin berkas Blade (single-file Livewire component)
    | ke resources/views/pages/security beserta konfigurasi ini. Seluruh halaman
    | WAJIB melalui autentikasi (middleware "auth") dan secara default juga
    | dibatasi oleh Gate "manage-security-monitor" (middleware "security.admin").
    |
    | "driver" menentukan stack tampilan yang diaktifkan: "livewire" atau "react".
    |
    | Dashboard dinonaktifkan secara default agar paket tetap 100% headless
    | sampai pengguna secara sengaja mengaktifkannya.
    |
    */
    'dashboard' => [
        'enabled' => (bool) env('SECURITY_DASHBOARD_ENABLED', false),
        'driver' => env('SECURITY_DASHBOARD_DRIVER', 'livewire'),
        'prefix' => env('SECURITY_DASHBOARD_PREFIX', 'security'),
        'middleware' => ['web', 'auth'],
        'admin_middleware' => env('SECURITY_DASHBOARD_ADMIN_ONLY', false)
            ? ['Internal\\SecurityMonitor\\Http\\Middleware\\EnsureSecurityAdmin']
            : [],
        'admin_only' => (bool) env('SECURITY_DASHBOARD_ADMIN_ONLY', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Automatic Schedule Configuration
    |--------------------------------------------------------------------------
    |
    | Penjadwalan pembersihan log dan heartbeat.
    |
    */
    'schedule' => [
        'enabled' => (bool) env('SECURITY_SCHEDULE_ENABLED', true),
        'prune_at' => env('SECURITY_PRUNE_SCHEDULE', '02:30'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Support Email
    |--------------------------------------------------------------------------
    |
    | Alamat email bantuan untuk ditampilkan saat IP diblokir.
    |
    */
    'support_email' => env('SECURITY_SUPPORT_EMAIL', env('MAIL_FROM_ADDRESS', 'security@example.com')),

    /*
    |--------------------------------------------------------------------------
    | Middleware Registration
    |--------------------------------------------------------------------------
    |
    | Bila true, ServiceProvider akan secara otomatis menyisipkan middleware
    | BlockIpAddress dan DetectSecurityThreats ke HTTP Kernel global.
    |
    */
    'auto_register_middleware' => (bool) env('SECURITY_AUTO_REGISTER_MIDDLEWARE', false),
];
