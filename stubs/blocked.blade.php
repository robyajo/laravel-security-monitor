{{--
    Default 403 "blocked" page for robyajo/laravel-security-monitor.

    Dipublikasikan oleh:  php artisan vendor:publish --tag=security-views
    Tujuan default:       resources/views/errors/blocked.blade.php

    Halaman ini sengaja berdiri sendiri (inline CSS + JS kecil) supaya tetap
    tampil rapi tanpa perlu build step frontend apa pun — sejalan dengan prinsip
    "100% Pure PHP / Zero NPM" paket ini.

    Variabel yang tersedia dari middleware BlockIpAddress:
    $message, $reason, $ip, $deviceId, $localIp, $referenceId, $supportEmail,
    $block, $blockedAt, $expiresAt, $remaining
--}}
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>Akses Ditolak — 403</title>
    <style>
        :root { color-scheme: dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
            background: radial-gradient(1200px 600px at 50% -10%, #1e293b 0%, #0f172a 55%, #020617 100%);
            font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: #e2e8f0; padding: 24px;
        }
        .card {
            width: 100%; max-width: 560px; background: rgba(15, 23, 42, .82);
            border: 1px solid #1e293b; border-radius: 18px; padding: 32px;
            box-shadow: 0 30px 60px rgba(2, 6, 23, .55);
        }
        .badge {
            display: inline-block; font-weight: 700; letter-spacing: .08em; font-size: 13px;
            color: #06b6d4; border: 1px solid rgba(6, 182, 212, .4);
            background: rgba(6, 182, 212, .1); padding: 4px 10px; border-radius: 999px;
        }
        h1 { margin: 16px 0 8px; font-size: 26px; color: #f8fafc; }
        h2 { margin: 0 0 4px; font-size: 17px; color: #f8fafc; }
        .lead { margin: 0 0 20px; color: #94a3b8; line-height: 1.6; }
        .muted { color: #94a3b8; font-size: 13px; }
        .rows { display: grid; gap: 8px; margin: 0 0 20px; }
        .row {
            display: flex; justify-content: space-between; gap: 16px; font-size: 13px;
            background: #0b1220; border: 1px solid #1e293b; border-radius: 10px; padding: 10px 14px;
        }
        .row span { color: #94a3b8; }
        .row b { color: #e2e8f0; font-weight: 600; word-break: break-all; text-align: right; }
        hr { border: 0; border-top: 1px solid #1e293b; margin: 24px 0; }
        label { display: block; font-size: 12px; color: #94a3b8; margin: 12px 0 4px; }
        input, textarea {
            width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid #334155;
            background: #0b1220; color: #e2e8f0; font-size: 14px; font-family: inherit;
        }
        input:focus, textarea:focus { outline: none; border-color: #06b6d4; }
        button {
            margin-top: 16px; width: 100%; padding: 12px 16px; border: 0; border-radius: 10px;
            background: #06b6d4; color: #04212b; font-weight: 700; font-size: 14px; cursor: pointer;
        }
        button:disabled { opacity: .6; cursor: progress; }
        .result { margin-top: 14px; padding: 12px 14px; border-radius: 10px; font-size: 13px; }
        .result.ok { background: rgba(34, 197, 94, .12); border: 1px solid rgba(34, 197, 94, .4); color: #bbf7d0; }
        .result.err { background: rgba(239, 68, 68, .12); border: 1px solid rgba(239, 68, 68, .4); color: #fecaca; }
        a { color: #22d3ee; }
    </style>
</head>
<body>
<main class="card">
    <span class="badge">403 · AKSES DITOLAK</span>
    <h1>Permintaan Anda Diblokir</h1>
    <p class="lead">{{ $message ?? 'Alamat IP atau perangkat Anda diblokir karena terdeteksi aktivitas mencurigakan.' }}</p>

    <div class="rows">
        @if (! empty($reason))
            <div class="row"><span>Alasan</span><b>{{ $reason }}</b></div>
        @endif
        @if (! empty($ip))
            <div class="row"><span>Alamat IP</span><b>{{ $ip }}</b></div>
        @endif
        @if (! empty($deviceId))
            <div class="row"><span>ID Perangkat</span><b>{{ $deviceId }}</b></div>
        @endif
        @if (! empty($localIp))
            <div class="row"><span>IP Lokal</span><b>{{ $localIp }}</b></div>
        @endif
        @if (! empty($referenceId))
            <div class="row"><span>Kode Referensi</span><b>{{ $referenceId }}</b></div>
        @endif
    </div>

    <hr>

    <h2>Ajukan Pembukaan Blokir</h2>
    <p class="muted">Jika Anda merasa ini sebuah kesalahan, kirim permohonan berikut untuk ditinjau administrator.</p>

    <form id="security-appeal-form" novalidate>
        <input type="hidden" name="device_id" value="{{ $deviceId ?? '' }}">
        <input type="hidden" name="local_ip" value="{{ $localIp ?? '' }}">

        <label for="name">Nama</label>
        <input id="name" name="name" type="text" maxlength="100" required>

        <label for="email">Email</label>
        <input id="email" name="email" type="email" maxlength="150" required>

        <label for="phone">Telepon (opsional)</label>
        <input id="phone" name="phone" type="text" maxlength="30">

        <label for="reason">Alasan / Penjelasan</label>
        <textarea id="reason" name="reason" rows="4" maxlength="1000" required></textarea>

        <button type="submit">Kirim Permohonan</button>
    </form>

    <div id="security-appeal-result" class="result" hidden></div>

    @if (! empty($supportEmail))
        <p class="muted" style="margin-top:18px">Bantuan: <a href="mailto:{{ $supportEmail }}">{{ $supportEmail }}</a></p>
    @endif
</main>

<script>
    (function () {
        var form = document.getElementById('security-appeal-form');
        var result = document.getElementById('security-appeal-result');
        if (!form || !result) { return; }

        var endpoint = @json(url(config('security.routes.prefix', 'api/security') . '/unblock-tickets/submit'));
        var button = form.querySelector('button[type="submit"]');

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            button.disabled = true;
            result.hidden = false;
            result.className = 'result';
            result.textContent = 'Mengirim permohonan...';

            fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(Object.fromEntries(new FormData(form).entries()))
            }).then(function (response) {
                return response.json().then(function (body) {
                    return { ok: response.ok, body: body };
                });
            }).then(function (res) {
                if (res.ok && res.body && res.body.ticket_number) {
                    result.className = 'result ok';
                    result.textContent = 'Permohonan terkirim. Nomor tiket Anda: ' + res.body.ticket_number;
                    form.reset();
                } else {
                    result.className = 'result err';
                    result.textContent = (res.body && res.body.message)
                        ? res.body.message
                        : 'Gagal mengirim permohonan. Silakan coba lagi.';
                }
            }).catch(function () {
                result.className = 'result err';
                result.textContent = 'Terjadi kesalahan jaringan. Silakan coba lagi.';
            }).finally(function () {
                button.disabled = false;
            });
        });
    })();
</script>
</body>
</html>
