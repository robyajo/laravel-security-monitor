import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import '@/components/security/security.css';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, CardHeader, CardTitle, Input } from '@/components/security/ui';

type LoginRow = {
    id: number;
    session_id: string | null;
    ip_address: string;
    browser: string | null;
    operating_system: string | null;
    city: string | null;
    region: string | null;
    country: string | null;
    last_activity_at: string | null;
    logout_at: string | null;
    user: { name: string; email: string } | null;
};

type TrustedRow = {
    id: number;
    ip_address: string;
    device_name: string | null;
    verified_at: string | null;
    user: { name: string } | null;
};

type Paginator<T> = {
    data: T[];
    total: number;
    links: { url: string | null; label: string; active: boolean }[];
};

type SessionsProps = {
    logins: Paginator<LoginRow>;
    trustedIps: TrustedRow[];
    onlineCount: number;
    filters: { search: string };
    urls: {
        index: string;
        loginDestroy: string;
        sessionDestroy: string;
        trustedDestroy: string;
        storeMyIp: string;
    };
};

function isOnline(login: LoginRow): boolean {
    if (login.logout_at) {
        return false;
    }

    if (!login.last_activity_at) {
        return false;
    }

    return (
        new Date(login.last_activity_at).getTime() > Date.now() - 5 * 60 * 1000
    );
}

function location(login: LoginRow): string {
    const parts = [login.city, login.region, login.country].filter(Boolean);

    return parts.length > 0 ? parts.join(', ') : 'Unknown location';
}

export default function UserSessions({
    logins,
    trustedIps,
    onlineCount,
    filters,
    urls,
}: SessionsProps) {
    const [search, setSearch] = useState(filters.search);
    const [flashMsg, setFlashMsg] = useState<string | null>(null);

    const showNotification = (msg: string) => {
        setFlashMsg(msg);
        setTimeout(() => setFlashMsg(null), 4000);
    };

    const applyFilters = () => {
        router.get(
            urls.index,
            { search },
            { preserveState: true, preserveScroll: true, replace: true },
        );
    };

    const trustThisDevice = () => {
        router.post(
            urls.storeMyIp,
            {},
            {
                preserveScroll: true,
                onSuccess: () => showNotification('IP saved as trusted device.'),
            },
        );
    };

    const destroyLogin = (id: number) => {
        router.delete(urls.loginDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => showNotification('Login history entry deleted.'),
        });
    };

    const destroySession = (sessionId: string) => {
        if (!confirm('Force logout this session?')) {
            return;
        }

        router.delete(
            urls.sessionDestroy.replace(
                '__SESSION__',
                encodeURIComponent(sessionId),
            ),
            {
                preserveScroll: true,
                onSuccess: () => showNotification('Session terminated.'),
            },
        );
    };

    const destroyTrusted = (id: number) => {
        if (!confirm('Remove this trusted IP?')) {
            return;
        }

        router.delete(urls.trustedDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => showNotification('Trusted IP removed.'),
        });
    };

    return (
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="User Sessions" />

            <SecurityNav />

            {flashMsg && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: '16px' }}>
                    <span>{flashMsg}</span>
                </div>
            )}

            <div className="sec-toolbar">
                <div>
                    <h1 className="sec-page-title">User Sessions</h1>
                    <p className="sec-page-subtitle">
                        Active sessions, login history, and trusted devices.
                    </p>
                </div>

                <div className="sec-toolbar-group">
                    <div className="sec-stat-card" style={{ padding: '8px 14px' }}>
                        <div className="sec-stat-label" style={{ marginBottom: '2px' }}>Online now</div>
                        <div className="sec-stat-value" style={{ fontSize: '18px', color: 'var(--sec-success)', marginBottom: 0 }}>
                            {new Intl.NumberFormat().format(onlineCount)}
                        </div>
                    </div>

                    <Button variant="primary" onClick={trustThisDevice}>
                        🛡️ Trust this device
                    </Button>
                </div>
            </div>

            <div className="sec-toolbar">
                <div className="sec-toolbar-group">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search user, IP, browser…"
                        style={{ minWidth: '260px' }}
                    />
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
                                    <th>User</th>
                                    <th>IP</th>
                                    <th>Device</th>
                                    <th>Location</th>
                                    <th>Last activity</th>
                                    <th style={{ textAlign: 'right' }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {logins.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No login records found.
                                        </td>
                                    </tr>
                                )}
                                {logins.data.map((login) => (
                                    <tr key={login.id}>
                                        <td style={{ fontSize: '12px' }}>
                                            <div style={{ fontWeight: 600 }}>
                                                {login.user?.name ?? 'Deleted user'}
                                            </div>
                                            <div style={{ fontSize: '11px', color: 'var(--sec-text-muted)' }}>
                                                {login.user?.email}
                                            </div>
                                        </td>
                                        <td>
                                            <div className="sec-font-mono" style={{ fontSize: '12px', fontWeight: 600 }}>
                                                {login.ip_address}
                                            </div>
                                            {isOnline(login) && (
                                                <Badge variant="success" style={{ marginTop: '4px' }}>
                                                    Online
                                                </Badge>
                                            )}
                                        </td>
                                        <td style={{ fontSize: '12px' }}>
                                            <div>{login.browser ?? 'Unknown'}</div>
                                            <div style={{ fontSize: '11px', color: 'var(--sec-text-muted)' }}>
                                                {login.operating_system}
                                            </div>
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)' }}>
                                            {location(login)}
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)', whiteSpace: 'nowrap' }}>
                                            {login.last_activity_at
                                                ? new Date(login.last_activity_at).toLocaleString()
                                                : '-'}
                                        </td>
                                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                            {login.session_id && isOnline(login) && (
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() => destroySession(login.session_id!)}
                                                    style={{ marginRight: '6px' }}
                                                    title="Terminate session"
                                                >
                                                    🚪
                                                </Button>
                                            )}
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() => destroyLogin(login.id)}
                                                title="Delete record"
                                            >
                                                🗑️
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>

            <div style={{ margin: '16px 0 24px 0' }}>
                <Pagination links={logins.links} total={logins.total} />
            </div>

            <Card flush>
                <CardHeader>
                    <CardTitle>Trusted IPs</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>IP address</th>
                                    <th>User</th>
                                    <th>Device name</th>
                                    <th>Verified at</th>
                                    <th style={{ textAlign: 'right' }}>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {trustedIps.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '24px' }}
                                        >
                                            No trusted IPs yet.
                                        </td>
                                    </tr>
                                )}
                                {trustedIps.map((trusted) => (
                                    <tr key={trusted.id}>
                                        <td className="sec-font-mono" style={{ fontSize: '12px', fontWeight: 600 }}>
                                            {trusted.ip_address}
                                        </td>
                                        <td style={{ fontSize: '12px' }}>
                                            {trusted.user?.name ?? 'Deleted user'}
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)' }}>
                                            {trusted.device_name ?? '-'}
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)', whiteSpace: 'nowrap' }}>
                                            {trusted.verified_at
                                                ? new Date(trusted.verified_at).toLocaleString()
                                                : '-'}
                                        </td>
                                        <td style={{ textAlign: 'right' }}>
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() => destroyTrusted(trusted.id)}
                                            >
                                                🗑️
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
