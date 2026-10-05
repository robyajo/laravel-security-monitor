import { Head, router, useForm } from '@inertiajs/react';
import { useState } from 'react';
import '@/components/security/security.css';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input, Label } from '@/components/security/ui';

type BlockedIp = {
    id: number;
    ip_address: string;
    device_id: string | null;
    reason: string | null;
    is_active: boolean;
    expires_at: string | null;
    hit_count: number;
};

type Paginator<T> = {
    data: T[];
    total: number;
    links: { url: string | null; label: string; active: boolean }[];
};

type BlockedIpsProps = {
    blocks: Paginator<BlockedIp>;
    stats: { total: number; active: number; permanent: number; hits: number };
    filters: { search: string; status: string };
    urls: {
        index: string;
        store: string;
        toggle: string;
        destroy: string;
    };
};

function statusOf(block: BlockedIp): string {
    if (!block.is_active) {
        return 'Disabled';
    }

    if (block.expires_at && new Date(block.expires_at) < new Date()) {
        return 'Expired';
    }

    return 'Active';
}

function statusBadgeVariant(status: string): 'critical' | 'high' | 'low' {
    if (status === 'Active') return 'critical';
    if (status === 'Expired') return 'high';
    return 'low';
}

export default function BlockedIps({
    blocks,
    stats,
    filters,
    urls,
}: BlockedIpsProps) {
    const [search, setSearch] = useState(filters.search);
    const [status, setStatus] = useState(filters.status);
    const [flashMsg, setFlashMsg] = useState<string | null>(null);

    const showNotification = (msg: string) => {
        setFlashMsg(msg);
        setTimeout(() => setFlashMsg(null), 4000);
    };

    const form = useForm({
        ip_address: '',
        reason: '',
        notes: '',
        duration_hours: 24,
        is_permanent: false,
    });

    const applyFilters = () => {
        router.get(
            urls.index,
            { search, status },
            { preserveState: true, preserveScroll: true, replace: true },
        );
    };

    const submitBlock = (event: React.FormEvent) => {
        event.preventDefault();

        form.post(urls.store, {
            preserveScroll: true,
            onSuccess: () => {
                form.reset();
                showNotification('IP blocked successfully.');
            },
        });
    };

    const toggle = (id: number) => {
        router.patch(
            urls.toggle.replace('__ID__', String(id)),
            {},
            {
                preserveScroll: true,
                onSuccess: () => showNotification('Block status updated.'),
            },
        );
    };

    const unblock = (id: number) => {
        if (!confirm('Remove this block entirely?')) {
            return;
        }

        router.delete(urls.destroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => showNotification('IP unblocked successfully.'),
        });
    };

    return (
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="Blocked IPs" />

            <SecurityNav />

            {flashMsg && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: '16px' }}>
                    <span>{flashMsg}</span>
                </div>
            )}

            <div className="sec-page-header">
                <h1 className="sec-page-title">Blocked IPs</h1>
                <p className="sec-page-subtitle">
                    Manage quarantined IP addresses and devices.
                </p>
            </div>

            <div className="sec-grid-4">
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Total blocks</div>
                    <div className="sec-stat-value">{stats.total}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Active</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-danger)' }}>{stats.active}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Permanent</div>
                    <div className="sec-stat-value">{stats.permanent}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Total hits</div>
                    <div className="sec-stat-value">{stats.hits}</div>
                </div>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Block an IP address</CardTitle>
                </CardHeader>
                <CardContent>
                    <form
                        onSubmit={submitBlock}
                        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px', alignItems: 'flex-end', paddingTop: '8px' }}
                    >
                        <div>
                            <Label htmlFor="ip_address">IP address *</Label>
                            <Input
                                id="ip_address"
                                value={form.data.ip_address}
                                onChange={(e) =>
                                    form.setData('ip_address', e.target.value)
                                }
                                placeholder="203.0.113.50"
                                required
                                style={{ width: '100%' }}
                            />
                            {form.errors.ip_address && (
                                <p style={{ color: 'var(--sec-danger)', fontSize: '11px', margin: '4px 0 0 0' }}>
                                    {form.errors.ip_address}
                                </p>
                            )}
                        </div>

                        <div>
                            <Label htmlFor="reason">Reason</Label>
                            <Input
                                id="reason"
                                value={form.data.reason}
                                onChange={(e) =>
                                    form.setData('reason', e.target.value)
                                }
                                placeholder="e.g. Repeated directory scanning"
                                style={{ width: '100%' }}
                            />
                        </div>

                        <div>
                            <Label htmlFor="duration_hours">
                                Duration (hours, 0 = permanent)
                            </Label>
                            <Input
                                id="duration_hours"
                                type="number"
                                min={0}
                                value={form.data.duration_hours}
                                onChange={(e) =>
                                    form.setData(
                                        'duration_hours',
                                        Number(e.target.value),
                                    )
                                }
                                style={{ width: '100%' }}
                            />
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '13px', cursor: 'pointer' }}>
                                <input
                                    type="checkbox"
                                    checked={form.data.is_permanent}
                                    onChange={(e) =>
                                        form.setData(
                                            'is_permanent',
                                            e.target.checked,
                                        )
                                    }
                                />
                                <span>Permanent block</span>
                            </label>

                            <Button
                                type="submit"
                                variant="danger"
                                disabled={form.processing}
                            >
                                Block IP
                            </Button>
                        </div>
                    </form>
                </CardContent>
            </Card>

            <div className="sec-toolbar">
                <div className="sec-toolbar-group">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search IP, device, reason…"
                        style={{ minWidth: '240px' }}
                    />

                    <select
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                        className="sec-select"
                    >
                        <option value="">All statuses</option>
                        <option value="active">Active</option>
                        <option value="expired">Expired</option>
                        <option value="permanent">Permanent</option>
                    </select>

                    <Button variant="secondary" onClick={applyFilters}>
                        Filter
                    </Button>
                </div>
            </div>

            <Card flush>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>IP address</th>
                                    <th>Reason</th>
                                    <th>Status</th>
                                    <th>Expires</th>
                                    <th style={{ textAlign: 'right' }}>Hits</th>
                                    <th style={{ textAlign: 'right' }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {blocks.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No blocked IPs match the current filters.
                                        </td>
                                    </tr>
                                )}
                                {blocks.data.map((block) => {
                                    const st = statusOf(block);

                                    return (
                                        <tr key={block.id}>
                                            <td>
                                                <div className="sec-font-mono" style={{ fontWeight: 600, fontSize: '13px' }}>
                                                    {block.ip_address}
                                                </div>
                                                {block.device_id && (
                                                    <div style={{ fontSize: '10px', color: 'var(--sec-text-muted)', fontFamily: 'var(--sec-font-mono)' }}>
                                                        {block.device_id}
                                                    </div>
                                                )}
                                            </td>
                                            <td style={{ maxWidth: '250px', fontSize: '12px' }}>
                                                {block.reason ?? '-'}
                                            </td>
                                            <td>
                                                <Badge variant={statusBadgeVariant(st)}>
                                                    {st}
                                                </Badge>
                                            </td>
                                            <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)', whiteSpace: 'nowrap' }}>
                                                {block.expires_at
                                                    ? new Date(block.expires_at).toLocaleString()
                                                    : 'Never'}
                                            </td>
                                            <td style={{ textAlign: 'right', fontSize: '12px' }} className="sec-font-mono">
                                                {block.hit_count}
                                            </td>
                                            <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() => toggle(block.id)}
                                                    style={{ marginRight: '6px' }}
                                                >
                                                    {block.is_active ? 'Disable' : 'Enable'}
                                                </Button>
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() => unblock(block.id)}
                                                >
                                                    Unblock
                                                </Button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>

            <div style={{ marginTop: '16px' }}>
                <Pagination links={blocks.links} total={blocks.total} />
            </div>
        </div>
    );
}
