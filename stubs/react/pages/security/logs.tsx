import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import '@/components/security/security.css';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, Input } from '@/components/security/ui';

type LogEntry = {
    id: number;
    event_type: string;
    threat_level: string;
    rule_label: string | null;
    ip_address: string;
    method: string | null;
    path: string | null;
    created_at: string;
};

type Paginator<T> = {
    data: T[];
    current_page: number;
    last_page: number;
    total: number;
    links: { url: string | null; label: string; active: boolean }[];
};

type LogsProps = {
    logs: Paginator<LogEntry>;
    levels: string[];
    eventTypes: string[];
    filters: { search: string; level: string; event_type: string };
    urls: { index: string; clear: string; destroy: string };
};

const levelLabels: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
};

export default function SecurityLogs({
    logs,
    levels,
    eventTypes,
    filters,
    urls,
}: LogsProps) {
    const [search, setSearch] = useState(filters.search);
    const [level, setLevel] = useState(filters.level);
    const [eventType, setEventType] = useState(filters.event_type);
    const [flashMsg, setFlashMsg] = useState<string | null>(null);

    const showNotification = (msg: string) => {
        setFlashMsg(msg);
        setTimeout(() => setFlashMsg(null), 4000);
    };

    const applyFilters = () => {
        router.get(
            urls.index,
            { search, level, event_type: eventType },
            { preserveState: true, preserveScroll: true, replace: true },
        );
    };

    const destroy = (id: number) => {
        if (!confirm('Delete this log entry?')) {
            return;
        }

        router.delete(urls.destroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => showNotification('Log entry deleted.'),
        });
    };

    const clearAll = () => {
        if (!confirm('Clear ALL security logs? This cannot be undone.')) {
            return;
        }

        router.delete(urls.clear, {
            preserveScroll: true,
            onSuccess: () => showNotification('Security logs cleared.'),
        });
    };

    return (
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="Security Logs" />

            <SecurityNav />

            {flashMsg && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: '16px' }}>
                    <span>{flashMsg}</span>
                </div>
            )}

            <div className="sec-page-header">
                <h1 className="sec-page-title">Security Logs</h1>
                <p className="sec-page-subtitle">
                    Audit trail of detected threats and blocked requests.
                </p>
            </div>

            <div className="sec-toolbar">
                <div className="sec-toolbar-group">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) =>
                            e.key === 'Enter' && applyFilters()
                        }
                        placeholder="Search IP, path, evidence…"
                        style={{ minWidth: '240px' }}
                    />

                    <select
                        value={level}
                        onChange={(e) => setLevel(e.target.value)}
                        className="sec-select"
                    >
                        <option value="">All levels</option>
                        {levels.map((option) => (
                            <option key={option} value={option}>
                                {levelLabels[option] ?? option}
                            </option>
                        ))}
                    </select>

                    <select
                        value={eventType}
                        onChange={(e) => setEventType(e.target.value)}
                        className="sec-select"
                    >
                        <option value="">All events</option>
                        {eventTypes.map((option) => (
                            <option key={option} value={option}>
                                {option}
                            </option>
                        ))}
                    </select>

                    <Button variant="secondary" onClick={applyFilters}>
                        Filter
                    </Button>
                </div>

                <Button variant="danger" onClick={clearAll}>
                    Clear logs
                </Button>
            </div>

            <Card flush>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>Level</th>
                                    <th>Event</th>
                                    <th>IP</th>
                                    <th>Path</th>
                                    <th>When</th>
                                    <th style={{ textAlign: 'right' }}>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {logs.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No security logs match the current filters.
                                        </td>
                                    </tr>
                                )}
                                {logs.data.map((log) => (
                                    <tr key={log.id}>
                                        <td>
                                            <Badge variant={log.threat_level as any}>
                                                {levelLabels[log.threat_level] ?? log.threat_level}
                                            </Badge>
                                        </td>
                                        <td style={{ fontSize: '12px' }}>
                                            <div style={{ fontWeight: 600 }}>
                                                {log.event_type}
                                            </div>
                                            <div style={{ fontSize: '11px', color: 'var(--sec-text-muted)' }}>
                                                {log.rule_label}
                                            </div>
                                        </td>
                                        <td className="sec-font-mono" style={{ fontSize: '12px', fontWeight: 600 }}>
                                            {log.ip_address}
                                        </td>
                                        <td style={{ maxWidth: '280px', fontSize: '12px' }}>
                                            <span style={{ color: 'var(--sec-text-muted)', fontWeight: 600 }}>
                                                {log.method}
                                            </span>{' '}
                                            <span>{log.path}</span>
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)', whiteSpace: 'nowrap' }}>
                                            {new Date(log.created_at).toLocaleString()}
                                        </td>
                                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() => destroy(log.id)}
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

            <div style={{ marginTop: '16px' }}>
                <Pagination links={logs.links} total={logs.total} />
            </div>
        </div>
    );
}
