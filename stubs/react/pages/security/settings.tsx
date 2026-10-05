import { useState } from 'react';
import { Head, router } from '@inertiajs/react';
import '@/components/security/security.css';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input, Label } from '@/components/security/ui';

type SettingsProps = {
    settings: {
        auto_block_scope: 'device' | 'ip';
        instant_block_scope: 'device' | 'ip';
        auto_block_enabled: boolean;
        auto_block_threshold: number;
        auto_block_window: number;
        auto_block_duration: number;
        instant_block_enabled: boolean;
        instant_block_duration: number;
        block_enforcement: boolean;
    };
};

export default function SecuritySettings({ settings }: SettingsProps) {
    const [form, setForm] = useState(settings);
    const [saving, setSaving] = useState(false);
    const [saved, setSaved] = useState(false);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        setSaved(false);

        router.post('/security/settings', form, {
            preserveScroll: true,
            onSuccess: () => {
                setSaving(false);
                setSaved(true);
            },
            onError: () => {
                setSaving(false);
            },
        });
    };

    return (
        <div className="sec-root">
            <Head title="Security Settings" />

            <div className="sec-header">
                <h1 className="sec-title">Security Settings</h1>
                <p className="sec-subtitle">
                    Konfigurasi lingkup pemblokiran otomatis (Perangkat vs Alamat IP), ambang batas ancaman, dan kebijakan karantina
                </p>
            </div>

            <SecurityNav />

            {saved && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: 20 }}>
                    <span>✅ Pengaturan keamanan berhasil disimpan dan langsung diterapkan!</span>
                </div>
            )}

            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                {/* 1. Auto Block Scope */}
                <Card>
                    <CardHeader>
                        <CardTitle>🎯 Lingkup Pemblokiran Otomatis (Auto Block Scope)</CardTitle>
                        <p className="sec-card-desc">
                            Pilih apakah pemblokiran otomatis saat mencapai ambang batas hanya mengisolasi perangkat penyerang atau seluruh IP publik router.
                        </p>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
                            {/* Device Scope */}
                            <label
                                style={{
                                    cursor: 'pointer',
                                    border: `2px solid ${form.auto_block_scope === 'device' ? 'var(--sec-primary)' : 'var(--sec-border)'}`,
                                    borderRadius: 'var(--sec-radius)',
                                    padding: 18,
                                    background: form.auto_block_scope === 'device' ? 'rgba(59, 130, 246, 0.08)' : 'var(--sec-card)',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 10,
                                    transition: 'all 0.2s',
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <input
                                            type="radio"
                                            name="auto_block_scope"
                                            value="device"
                                            checked={form.auto_block_scope === 'device'}
                                            onChange={() => setForm({ ...form, auto_block_scope: 'device' })}
                                            style={{ accentColor: 'var(--sec-primary)', width: 18, height: 18 }}
                                        />
                                        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--sec-text)' }}>
                                            📱 Isolasi Perangkat Saja
                                        </span>
                                    </div>
                                    <Badge variant="success">Default / Rekomendasi</Badge>
                                </div>
                                <p style={{ fontSize: 13, color: 'var(--sec-text-muted)', lineHeight: 1.5, margin: 0 }}>
                                    Hanya memblokir perangkat spesifik penyerang berdasarkan Device ID / Fingerprint / LAN IP. Pengguna lain atau rekan kantor dalam satu jaringan WiFi / IP publik yang sama TETAP AMAN dan TIDAK IKUT TERBLOKIR.
                                </p>
                            </label>

                            {/* IP Scope */}
                            <label
                                style={{
                                    cursor: 'pointer',
                                    border: `2px solid ${form.auto_block_scope === 'ip' ? 'var(--sec-warning)' : 'var(--sec-border)'}`,
                                    borderRadius: 'var(--sec-radius)',
                                    padding: 18,
                                    background: form.auto_block_scope === 'ip' ? 'rgba(245, 158, 11, 0.08)' : 'var(--sec-card)',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 10,
                                    transition: 'all 0.2s',
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <input
                                            type="radio"
                                            name="auto_block_scope"
                                            value="ip"
                                            checked={form.auto_block_scope === 'ip'}
                                            onChange={() => setForm({ ...form, auto_block_scope: 'ip' })}
                                            style={{ accentColor: 'var(--sec-warning)', width: 18, height: 18 }}
                                        />
                                        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--sec-text)' }}>
                                            🌐 Seluruh IP Router Publik
                                        </span>
                                    </div>
                                    <Badge variant="warning">Hati-hati</Badge>
                                </div>
                                <p style={{ fontSize: 13, color: 'var(--sec-text-muted)', lineHeight: 1.5, margin: 0 }}>
                                    Memblokir seluruh alamat IP router publik. PERINGATAN: Semua pengguna lain, tamu, atau rekan kerja yang menggunakan koneksi WiFi/NAT router yang sama akan otomatis ikut terblokir jika satu perangkat terdeteksi.
                                </p>
                            </label>
                        </div>
                    </CardContent>
                </Card>

                {/* 2. Instant Block Scope */}
                <Card>
                    <CardHeader>
                        <CardTitle>⚡ Lingkup Pemblokiran Instan (Zero Tolerance Scope)</CardTitle>
                        <p className="sec-card-desc">
                            Lingkup isolasi untuk serangan berbahaya yang memicu blokir instan pada percobaan pertama (upload webshell, path traversal /etc/passwd, probe .env/.git).
                        </p>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
                            {/* Device Scope */}
                            <label
                                style={{
                                    cursor: 'pointer',
                                    border: `2px solid ${form.instant_block_scope === 'device' ? 'var(--sec-primary)' : 'var(--sec-border)'}`,
                                    borderRadius: 'var(--sec-radius)',
                                    padding: 18,
                                    background: form.instant_block_scope === 'device' ? 'rgba(59, 130, 246, 0.08)' : 'var(--sec-card)',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 10,
                                    transition: 'all 0.2s',
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <input
                                            type="radio"
                                            name="instant_block_scope"
                                            value="device"
                                            checked={form.instant_block_scope === 'device'}
                                            onChange={() => setForm({ ...form, instant_block_scope: 'device' })}
                                            style={{ accentColor: 'var(--sec-primary)', width: 18, height: 18 }}
                                        />
                                        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--sec-text)' }}>
                                            📱 Isolasi Perangkat Saja
                                        </span>
                                    </div>
                                    <Badge variant="success">Default / Rekomendasi</Badge>
                                </div>
                                <p style={{ fontSize: 13, color: 'var(--sec-text-muted)', lineHeight: 1.5, margin: 0 }}>
                                    Mengisolasi perangkat pelaku serangan fatal tanpa memutus koneksi pengguna umum lainnya di WiFi yang sama.
                                </p>
                            </label>

                            {/* IP Scope */}
                            <label
                                style={{
                                    cursor: 'pointer',
                                    border: `2px solid ${form.instant_block_scope === 'ip' ? 'var(--sec-warning)' : 'var(--sec-border)'}`,
                                    borderRadius: 'var(--sec-radius)',
                                    padding: 18,
                                    background: form.instant_block_scope === 'ip' ? 'rgba(245, 158, 11, 0.08)' : 'var(--sec-card)',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 10,
                                    transition: 'all 0.2s',
                                }}
                            >
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                        <input
                                            type="radio"
                                            name="instant_block_scope"
                                            value="ip"
                                            checked={form.instant_block_scope === 'ip'}
                                            onChange={() => setForm({ ...form, instant_block_scope: 'ip' })}
                                            style={{ accentColor: 'var(--sec-warning)', width: 18, height: 18 }}
                                        />
                                        <span style={{ fontWeight: 700, fontSize: 15, color: 'var(--sec-text)' }}>
                                            🌐 Seluruh IP Router Publik
                                        </span>
                                    </div>
                                    <Badge variant="warning">Ketat</Badge>
                                </div>
                                <p style={{ fontSize: 13, color: 'var(--sec-text-muted)', lineHeight: 1.5, margin: 0 }}>
                                    Blokir total seluruh IP publik. Cocok jika server berada di jaringan privat atau tidak melayani pengguna umum dari jaringan NAT/WiFi publik.
                                </p>
                            </label>
                        </div>
                    </CardContent>
                </Card>

                {/* 3. Auto Block Parameters */}
                <Card>
                    <CardHeader>
                        <CardTitle>⏱️ Parameter Ambang Batas Otomatis</CardTitle>
                        <p className="sec-card-desc">Aturan ambang batas jumlah pelanggaran sebelum tindakan karantina dijalankan.</p>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid var(--sec-border)' }}>
                                <div>
                                    <div style={{ fontWeight: 600, color: 'var(--sec-text)' }}>Aktifkan Pemblokiran Otomatis</div>
                                    <div style={{ fontSize: 13, color: 'var(--sec-text-muted)' }}>Secara otomatis memblokir pelanggar yang melewati ambang batas ancaman.</div>
                                </div>
                                <input
                                    type="checkbox"
                                    checked={form.auto_block_enabled}
                                    onChange={(e) => setForm({ ...form, auto_block_enabled: e.target.checked })}
                                    style={{ width: 20, height: 20, accentColor: 'var(--sec-primary)' }}
                                />
                            </div>

                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
                                <div>
                                    <Label>Ambang Batas Pelanggaran (Threshold)</Label>
                                    <Input
                                        type="number"
                                        min={1}
                                        max={100}
                                        value={form.auto_block_threshold}
                                        onChange={(e) => setForm({ ...form, auto_block_threshold: parseInt(e.target.value) || 1 })}
                                    />
                                    <span style={{ fontSize: 12, color: 'var(--sec-text-subtle)' }}>Default: 3 kali</span>
                                </div>

                                <div>
                                    <Label>Jendela Waktu Evaluasi (Menit)</Label>
                                    <Input
                                        type="number"
                                        min={1}
                                        max={1440}
                                        value={form.auto_block_window}
                                        onChange={(e) => setForm({ ...form, auto_block_window: parseInt(e.target.value) || 1 })}
                                    />
                                    <span style={{ fontSize: 12, color: 'var(--sec-text-subtle)' }}>Default: 10 menit</span>
                                </div>

                                <div>
                                    <Label>Durasi Masa Blokir (Jam)</Label>
                                    <Input
                                        type="number"
                                        min={0}
                                        max={8760}
                                        value={form.auto_block_duration}
                                        onChange={(e) => setForm({ ...form, auto_block_duration: parseInt(e.target.value) || 0 })}
                                    />
                                    <span style={{ fontSize: 12, color: 'var(--sec-text-subtle)' }}>Default: 24 jam (0 = permanen)</span>
                                </div>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* 4. Enforcement & Instant Block Duration */}
                <Card>
                    <CardHeader>
                        <CardTitle>🛡️ Penegakan Blokir & Durasi Instan</CardTitle>
                        <p className="sec-card-desc">Pengaturan penegakan HTTP 403 Forbidden dan masa karantina zero-tolerance.</p>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid var(--sec-border)' }}>
                                <div>
                                    <div style={{ fontWeight: 600, color: 'var(--sec-text)' }}>Penegakan Blokir (Block Enforcement)</div>
                                    <div style={{ fontSize: 13, color: 'var(--sec-text-muted)' }}>Tolak permintaan klien yang terblokir dengan HTTP 403 Forbidden.</div>
                                </div>
                                <input
                                    type="checkbox"
                                    checked={form.block_enforcement}
                                    onChange={(e) => setForm({ ...form, block_enforcement: e.target.checked })}
                                    style={{ width: 20, height: 20, accentColor: 'var(--sec-primary)' }}
                                />
                            </div>

                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid var(--sec-border)' }}>
                                <div>
                                    <div style={{ fontWeight: 600, color: 'var(--sec-text)' }}>Aktifkan Pemblokiran Instan (Zero Tolerance)</div>
                                    <div style={{ fontSize: 13, color: 'var(--sec-text-muted)' }}>Langsung blokir penyerang pada percobaan pertama serangan fatal.</div>
                                </div>
                                <input
                                    type="checkbox"
                                    checked={form.instant_block_enabled}
                                    onChange={(e) => setForm({ ...form, instant_block_enabled: e.target.checked })}
                                    style={{ width: 20, height: 20, accentColor: 'var(--sec-primary)' }}
                                />
                            </div>

                            <div style={{ maxWidth: 320 }}>
                                <Label>Durasi Masa Blokir Instan (Jam)</Label>
                                <Input
                                    type="number"
                                    min={0}
                                    max={8760}
                                    value={form.instant_block_duration}
                                    onChange={(e) => setForm({ ...form, instant_block_duration: parseInt(e.target.value) || 0 })}
                                />
                                <span style={{ fontSize: 12, color: 'var(--sec-text-subtle)' }}>Default: 720 jam (30 hari). 0 = permanen.</span>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                {/* Save Button */}
                <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 12, padding: '16px 0' }}>
                    <Button type="submit" variant="primary" disabled={saving}>
                        {saving ? '⏳ Menyimpan...' : '💾 Simpan Pengaturan'}
                    </Button>
                </div>
            </form>
        </div>
    );
}
