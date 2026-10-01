# 01. Integrasi Frontend React / Inertia

Karena **`robyajo/laravel-security-monitor`** dirancang secara **Headless (Pure REST API)**, Anda dapat membangun antarmuka dashboard keamanan, penanganan error pemblokiran, dan form CAPTCHA menggunakan React dan Inertia.js sesuai kebutuhan desain aplikasi Anda.

---

## 1. Menangani Respons HTTP 403 Terblokir (Axios Interceptor)

Ketika pengguna terblokir oleh WAF, setiap panggilan API atau request Inertia akan mengembalikan kode status **HTTP 403 Forbidden** dengan struktur JSON:

```json
{
    "success": false,
    "message": "Akses ditolak. Alamat IP atau perangkat Anda diblokir...",
    "reason": "Percobaan Server-Side Template Injection (SSTI)",
    "reference_id": "SEC-A1B2C3D4",
    "blocked": true
}
```

Anda dapat menangani respons ini secara global menggunakan Axios interceptor:

```javascript
// resources/js/lib/axios.js
import axios from 'axios';

const api = axios.create({
    baseURL: '/api',
});

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response && error.response.status === 403 && error.response.data?.blocked) {
            // Simpan detail blokir ke state manager / trigger modal permohonan banding
            window.dispatchEvent(new CustomEvent('security-blocked', {
                detail: error.response.data
            }));
        }
        return Promise.reject(error);
    }
);

export default api;
```

---

## 2. Komponen SVG CAPTCHA di React

Berikut adalah contoh komponen React siap pakai untuk menampilkan dan memvalidasi pure SVG CAPTCHA:

```tsx
// resources/js/Components/SecurityCaptcha.tsx
import React, { useState } from 'react';

interface CaptchaProps {
    value: string;
    onChange: (val: string) => void;
    error?: string;
}

export const SecurityCaptcha: React.FC<CaptchaProps> = ({ value, onChange, error }) => {
    const [timestamp, setTimestamp] = useState<number>(Date.now());

    const refreshCaptcha = () => {
        setTimestamp(Date.now());
        onChange(''); // Reset input
    };

    return (
        <div className="space-y-2">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                Kode Keamanan (CAPTCHA)
            </label>
            
            <div className="flex items-center space-x-3">
                <div className="border border-gray-300 dark:border-gray-700 rounded overflow-hidden bg-white p-1 shadow-sm">
                    <img
                        src={`/api/security/captcha?form=login&t=${timestamp}`}
                        alt="Security CAPTCHA"
                        className="h-10 w-36 object-contain"
                    />
                </div>
                
                <button
                    type="button"
                    onClick={refreshCaptcha}
                    className="p-2 text-sm bg-gray-100 hover:bg-gray-200 dark:bg-gray-800 dark:hover:bg-gray-700 rounded-md transition"
                    title="Muat ulang kode keamanan"
                >
                    🔄 Ganti
                </button>
            </div>

            <input
                type="text"
                value={value}
                onChange={(e) => onChange(e.target.value.toUpperCase())}
                placeholder="Ketik kode di atas"
                maxLength={6}
                className="w-full px-3 py-2 border rounded-md uppercase tracking-widest font-mono"
            />
            
            {error && (
                <p className="text-xs text-red-500 mt-1">{error}</p>
            )}
        </div>
    );
};
```

---

## 3. Komponen Modal Pengajuan Tiket Banding (Appeal Modal)

```tsx
// resources/js/Components/AppealTicketModal.tsx
import React, { useState } from 'react';
import axios from 'axios';

interface BlockedData {
    reference_id: string;
    reason: string;
    ip_address: string;
}

export const AppealTicketModal: React.FC<{ data: BlockedData; onClose: () => void }> = ({ data, onClose }) => {
    const [form, setForm] = useState({ name: '', email: '', phone: '', reason: '' });
    const [ticketNumber, setTicketNumber] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setErrorMsg(null);

        try {
            const res = await axios.post('/api/security/unblock-tickets/submit', {
                ...form,
                reason: `[Ref: ${data.reference_id}] ${form.reason}`,
            });
            setTicketNumber(res.data.ticket_number);
        } catch (err: any) {
            setErrorMsg(err.response?.data?.message || 'Gagal mengirimkan permohonan.');
        } finally {
            setLoading(false);
        }
    };

    if (ticketNumber) {
        return (
            <div className="p-6 bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-md mx-auto text-center">
                <h3 className="text-xl font-bold text-green-600 mb-2">Permohonan Berhasil Dikirim!</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                    Nomor tiket permohonan banding Anda adalah:
                </p>
                <div className="p-3 bg-gray-100 dark:bg-gray-800 rounded font-mono font-bold text-lg select-all">
                    {ticketNumber}
                </div>
                <p className="text-xs text-gray-500 mt-4">
                    Simpan nomor ini untuk memeriksa status pembukaan blokir secara berkala.
                </p>
                <button onClick={onClose} className="mt-4 px-4 py-2 bg-blue-600 text-white rounded">
                    Tutup
                </button>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit} className="p-6 bg-white dark:bg-gray-900 rounded-lg shadow-xl max-w-lg mx-auto space-y-4">
            <h2 className="text-lg font-bold text-red-600">Akses Dibatasi — Ajukan Permohonan Buka Blokir</h2>
            <p className="text-xs text-gray-500">ID Referensi: <strong>{data.reference_id}</strong> (IP: {data.ip_address})</p>

            {errorMsg && <div className="p-2 bg-red-100 text-red-700 text-xs rounded">{errorMsg}</div>}

            <div>
                <label className="block text-xs font-medium">Nama Lengkap</label>
                <input required type="text" className="w-full border p-2 rounded text-sm" value={form.name} onChange={e => setForm({...form, name: e.target.value})} />
            </div>
            <div>
                <label className="block text-xs font-medium">Email Dinas / Aktif</label>
                <input required type="email" className="w-full border p-2 rounded text-sm" value={form.email} onChange={e => setForm({...form, email: e.target.value})} />
            </div>
            <div>
                <label className="block text-xs font-medium">Alasan / Klarifikasi Aktivitas</label>
                <textarea required rows={3} className="w-full border p-2 rounded text-sm" value={form.reason} onChange={e => setForm({...form, reason: e.target.value})} placeholder="Jelaskan aktivitas apa yang sedang Anda lakukan..." />
            </div>
            <button type="submit" disabled={loading} className="w-full py-2 bg-blue-600 text-white rounded font-medium hover:bg-blue-700 transition">
                {loading ? 'Mengirim...' : 'Kirim Permohonan Banding'}
            </button>
        </form>
    );
};
```
