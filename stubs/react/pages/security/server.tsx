import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import '@/components/security/security.css';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from '@/components/security/ui';

type Check = {
    id: string;
    label: string;
    status: string;
    value: string | null;
    detail: string | null;
    recommendation: string | null;
};

type Category = {
    id: string;
    label: string;
    checks: Check[];
};

type ServerProps = {
    report: {
        summary: {
            total: number;
            ok: number;
            info: number;
            warning: number;
            critical: number;
            score: number;
            status: string;
        };
        categories: Category[];
    };
    environment: Record<string, string>;
    baseline: {
        exists: boolean;
        created_at: string | null;
        files: number;
        watched: number;
    };
    integrity: {
        modified: string[];
        missing: string[];
        added: string[];
    };
    suspicious: Array<{
        id: string;
        path: string;
        threat_level: string;
        reason: string;
        size: string;
    }>;
    lockouts: Array<{
        id: number;
        email: string | null;
        ip_address: string | null;
        lockout_level: number;
        remaining: number;
    }>;
    urls: {
        index: string;
        refresh: string;
        baseline: string;
        baselineDestroy: string;
        suspiciousDestroy: string;
        lockoutDestroy: string;
    };
};

function statusBadgeVariant(status: string): 'critical' | 'high' | 'success' | 'low' {
    if (status === 'critical') return 'critical';
    if (status === 'warning') return 'high';
    if (status === 'ok') return 'success';
    return 'low';
}

export default function ServerAudit({
    report,
    environment,
    baseline,
    integrity,
    suspicious,
    lockouts,
    urls,
}: ServerProps) {
    const summary = report.summary;
    const [flashMsg, setFlashMsg] = useState<string | null>(null);

    const showNotification = (msg: string) => {
        setFlashMsg(msg);
        setTimeout(() => setFlashMsg(null), 4000);
    };

    const refresh = () => {
        router.get(urls.refresh, {}, {
            preserveScroll: true,
            onSuccess: () => showNotification('Server audit refreshed.'),
        });
    };

    const createBaseline = () => {
        if (!confirm('Create a new integrity baseline from the current files?')) {
            return;
        }

        router.post(urls.baseline, {}, {
            preserveScroll: true,
            onSuccess: () => showNotification('Integrity baseline created.'),
        });
    };

    const deleteBaseline = () => {
        if (!confirm('Delete the stored baseline?')) {
            return;
        }

        router.delete(urls.baselineDestroy, {
            preserveScroll: true,
            onSuccess: () => showNotification('Integrity baseline deleted.'),
        });
    };

    const deleteFile = (path: string) => {
        if (!confirm('Permanently delete this file?')) {
            return;
        }

        router.delete(urls.suspiciousDestroy, {
            data: { file_path: path },
            preserveScroll: true,
            onSuccess: () => showNotification('Suspicious file removed.'),
        });
    };

    const releaseLockout = (id: number) => {
        router.delete(urls.lockoutDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => showNotification('Lockout released.'),
        });
    };

    return (
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="Server Audit" />

            <SecurityNav />

            {flashMsg && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: '16px' }}>
                    <span>{flashMsg}</span>
                </div>
            )}

            <div className="sec-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                    <h1 className="sec-page-title">Server Audit</h1>
                    <p className="sec-page-subtitle">
                        Integrity, webshell scanner, and environment hygiene.
                    </p>
                </div>

                <Button variant="primary" onClick={refresh}>
                    Refresh
                </Button>
            </div>

            <div className="sec-grid-4">
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Health score</div>
                    <div className="sec-stat-value">
                        {summary.score}<span style={{ fontSize: '14px', color: 'var(--sec-text-subtle)' }}>/100</span>
                    </div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Critical</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-danger)' }}>{summary.critical}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Warnings</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-warning)' }}>{summary.warning}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Passed checks</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-success)' }}>{summary.ok}</div>
                </div>
            </div>

            <div className="sec-grid-2">
                <Card>
                    <CardHeader>
                        <div>
                            <CardTitle>Integrity baseline</CardTitle>
                            <p className="sec-card-subtitle">
                                {baseline.exists
                                    ? `${baseline.files} files tracked · created ${baseline.created_at ?? '-'}`
                                    : `No baseline created yet (${baseline.watched} files watched).`}
                            </p>
                        </div>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <Button size="sm" onClick={createBaseline}>
                                Create
                            </Button>
                            {baseline.exists && (
                                <Button
                                    size="sm"
                                    variant="danger"
                                    onClick={deleteBaseline}
                                >
                                    Delete
                                </Button>
                            )}
                        </div>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px', textAlign: 'center', paddingTop: '10px' }}>
                            <div style={{ padding: '10px', background: 'var(--sec-warning-bg)', border: '1px solid var(--sec-warning-border)', borderRadius: 'var(--sec-radius-sm)' }}>
                                <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--sec-warning)' }}>
                                    {integrity.modified.length}
                                </div>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--sec-text-muted)' }}>
                                    Modified
                                </div>
                            </div>
                            <div style={{ padding: '10px', background: 'var(--sec-danger-bg)', border: '1px solid var(--sec-danger-border)', borderRadius: 'var(--sec-radius-sm)' }}>
                                <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--sec-danger)' }}>
                                    {integrity.missing.length}
                                </div>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--sec-text-muted)' }}>
                                    Missing
                                </div>
                            </div>
                            <div style={{ padding: '10px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.3)', borderRadius: 'var(--sec-radius-sm)' }}>
                                <div style={{ fontSize: '20px', fontWeight: 700, color: '#0284c7' }}>
                                    {integrity.added.length}
                                </div>
                                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--sec-text-muted)' }}>
                                    New
                                </div>
                            </div>
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Environment</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div style={{ display: 'flex', flexDirection: 'column', paddingTop: '6px' }}>
                            {Object.entries(environment).map(([key, value]) => (
                                <div
                                    key={key}
                                    style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--sec-border-light)', fontSize: '13px' }}
                                >
                                    <span style={{ color: 'var(--sec-text-muted)', textTransform: 'capitalize' }}>
                                        {key.replace(/_/g, ' ')}
                                    </span>
                                    <span
                                        className="sec-font-mono"
                                        style={{ fontWeight: 600, maxWidth: '60%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                        title={value}
                                    >
                                        {value}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card flush>
                <CardHeader>
                    <CardTitle>Suspicious files &amp; webshells</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>File</th>
                                    <th>Threat</th>
                                    <th>Reason</th>
                                    <th style={{ textAlign: 'right' }}>Size</th>
                                    <th style={{ textAlign: 'right' }}>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {suspicious.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No suspicious files detected.
                                        </td>
                                    </tr>
                                )}
                                {suspicious.map((file) => (
                                    <tr key={file.id}>
                                        <td className="sec-font-mono" style={{ fontSize: '12px', fontWeight: 600 }}>
                                            {file.path}
                                        </td>
                                        <td>
                                            <Badge variant={statusBadgeVariant(file.threat_level)}>
                                                {file.threat_level}
                                            </Badge>
                                        </td>
                                        <td style={{ maxWidth: '280px', fontSize: '12px', color: 'var(--sec-text-muted)' }} title={file.reason}>
                                            {file.reason}
                                        </td>
                                        <td style={{ textAlign: 'right', fontSize: '12px' }} className="sec-font-mono">
                                            {file.size}
                                        </td>
                                        <td style={{ textAlign: 'right' }}>
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() => deleteFile(file.path)}
                                            >
                                                Delete
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>

            {lockouts.length > 0 && (
                <Card flush>
                    <CardHeader>
                        <CardTitle>Active login lockouts</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="sec-table-wrap">
                            <table className="sec-table">
                                <thead>
                                    <tr>
                                        <th>Email</th>
                                        <th>IP</th>
                                        <th>Level</th>
                                        <th>Remaining</th>
                                        <th style={{ textAlign: 'right' }}>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {lockouts.map((lockout) => (
                                        <tr key={lockout.id}>
                                            <td style={{ fontSize: '12px' }}>{lockout.email}</td>
                                            <td className="sec-font-mono" style={{ fontSize: '12px' }}>
                                                {lockout.ip_address}
                                            </td>
                                            <td>
                                                <Badge variant="high">{lockout.lockout_level}</Badge>
                                            </td>
                                            <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)' }}>
                                                {lockout.remaining}s
                                            </td>
                                            <td style={{ textAlign: 'right' }}>
                                                <Button
                                                    size="sm"
                                                    variant="secondary"
                                                    onClick={() => releaseLockout(lockout.id)}
                                                >
                                                    Release
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </CardContent>
                </Card>
            )}

            <Card>
                <CardHeader>
                    <CardTitle>Security checks</CardTitle>
                </CardHeader>
                <CardContent>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', paddingTop: '8px' }}>
                        {report.categories.map((category) => (
                            <div key={category.id}>
                                <h4 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--sec-text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', margin: '0 0 10px 0' }}>
                                    {category.label}
                                </h4>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    {category.checks.map((check) => (
                                        <div
                                            key={check.id}
                                            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '12px 14px', background: 'var(--sec-card-hover)', borderRadius: 'var(--sec-radius-sm)', gap: '12px' }}
                                        >
                                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                    <Badge variant={statusBadgeVariant(check.status)}>
                                                        {check.status}
                                                    </Badge>
                                                    <span style={{ fontSize: '14px', fontWeight: 600 }}>
                                                        {check.label}
                                                    </span>
                                                </div>
                                                {check.detail && (
                                                    <p style={{ fontSize: '12px', color: 'var(--sec-text-muted)', margin: 0 }}>
                                                        {check.detail}
                                                    </p>
                                                )}
                                                {check.recommendation && (
                                                    <p style={{ fontSize: '12px', color: 'var(--sec-warning)', margin: 0, fontWeight: 500 }}>
                                                        → {check.recommendation}
                                                    </p>
                                                )}
                                            </div>
                                            {check.value && (
                                                <span className="sec-badge sec-badge-low sec-font-mono" style={{ fontSize: '11px' }}>
                                                    {check.value}
                                                </span>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
