import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

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
                onSuccess: () => toast.success('IP saved as trusted.'),
            },
        );
    };

    const destroyLogin = (id: number) => {
        router.delete(urls.loginDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => toast.success('Login history entry deleted.'),
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
                onSuccess: () => toast.success('Session terminated.'),
            },
        );
    };

    const destroyTrusted = (id: number) => {
        if (!confirm('Remove this trusted IP?')) {
            return;
        }

        router.delete(urls.trustedDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => toast.success('Trusted IP removed.'),
        });
    };

    return (
        <>
            <Head title="User Sessions" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div className="flex flex-wrap items-end justify-between gap-3">
                    <div>
                        <h1 className="text-xl font-semibold">User Sessions</h1>
                        <p className="text-sm text-muted-foreground">
                            Active sessions, login history, and trusted devices.
                        </p>
                    </div>

                    <div className="flex items-end gap-3">
                        <Card className="gap-0 py-3">
                            <CardHeader>
                                <p className="text-sm text-muted-foreground">
                                    Online now
                                </p>
                                <div className="text-xl font-semibold text-green-600 dark:text-green-400">
                                    {new Intl.NumberFormat().format(
                                        onlineCount,
                                    )}
                                </div>
                            </CardHeader>
                        </Card>

                        <Button onClick={trustThisDevice}>
                            Trust this device
                        </Button>
                    </div>
                </div>

                <div className="flex items-end gap-3">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search user, IP, browser…"
                        className="w-full sm:w-72"
                    />
                    <Button variant="secondary" onClick={applyFilters}>
                        Filter
                    </Button>
                </div>

                <Card className="py-0">
                    <CardContent className="overflow-x-auto px-0 py-0">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b text-left text-muted-foreground">
                                    <th className="px-4 py-3 font-medium">
                                        User
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        IP
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Device
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Location
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Last activity
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {logins.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No login records found.
                                        </td>
                                    </tr>
                                )}
                                {logins.data.map((login) => (
                                    <tr
                                        key={login.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3 text-xs">
                                            <div className="font-medium">
                                                {login.user?.name ??
                                                    'Deleted user'}
                                            </div>
                                            <div className="text-muted-foreground">
                                                {login.user?.email}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="font-mono text-xs">
                                                {login.ip_address}
                                            </div>
                                            {isOnline(login) && (
                                                <Badge variant="outline">
                                                    Online
                                                </Badge>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 text-xs">
                                            <div>
                                                {login.browser ?? 'Unknown'}
                                            </div>
                                            <div className="text-muted-foreground">
                                                {login.operating_system}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {location(login)}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {login.last_activity_at
                                                ? new Date(
                                                      login.last_activity_at,
                                                  ).toLocaleString()
                                                : '-'}
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center justify-end gap-1">
                                                {login.session_id &&
                                                    isOnline(login) && (
                                                        <Button
                                                            size="sm"
                                                            variant="ghost"
                                                            onClick={() =>
                                                                destroySession(
                                                                    login.session_id as string,
                                                                )
                                                            }
                                                        >
                                                            Terminate
                                                        </Button>
                                                    )}
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() =>
                                                        destroyLogin(login.id)
                                                    }
                                                >
                                                    Delete
                                                </Button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </CardContent>
                </Card>

                <Pagination links={logins.links} total={logins.total} />

                <Card>
                    <CardHeader>
                        <CardTitle>Trusted IPs</CardTitle>
                    </CardHeader>
                    <CardContent className="overflow-x-auto px-0">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b text-left text-muted-foreground">
                                    <th className="px-4 py-3 font-medium">
                                        IP
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        User
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Device
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Verified
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {trustedIps.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No trusted IPs yet.
                                        </td>
                                    </tr>
                                )}
                                {trustedIps.map((trusted) => (
                                    <tr
                                        key={trusted.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3 font-mono text-xs">
                                            {trusted.ip_address}
                                        </td>
                                        <td className="px-4 py-3 text-xs">
                                            {trusted.user?.name ??
                                                'Deleted user'}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {trusted.device_name}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {trusted.verified_at
                                                ? new Date(
                                                      trusted.verified_at,
                                                  ).toLocaleString()
                                                : '-'}
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() =>
                                                    destroyTrusted(trusted.id)
                                                }
                                            >
                                                Remove
                                            </Button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </CardContent>
                </Card>
            </div>
        </>
    );
}

UserSessions.layout = {
    breadcrumbs: [
        {
            title: 'User Sessions',
            href: '/security/sessions',
        },
    ],
};
