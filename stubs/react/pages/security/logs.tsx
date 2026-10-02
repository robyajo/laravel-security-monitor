import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

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

const levelVariants: Record<
    string,
    'default' | 'destructive' | 'secondary' | 'outline'
> = {
    critical: 'destructive',
    high: 'default',
    medium: 'secondary',
    low: 'outline',
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
            onSuccess: () => toast.success('Log entry deleted.'),
        });
    };

    const clearAll = () => {
        if (!confirm('Clear ALL security logs? This cannot be undone.')) {
            return;
        }

        router.delete(urls.clear, {
            preserveScroll: true,
            onSuccess: () => toast.success('Security logs cleared.'),
        });
    };

    return (
        <>
            <Head title="Security Logs" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div>
                    <h1 className="text-xl font-semibold">Security Logs</h1>
                    <p className="text-sm text-muted-foreground">
                        Audit trail of detected threats and blocked requests.
                    </p>
                </div>

                <div className="flex flex-wrap items-end justify-between gap-3">
                    <div className="flex flex-wrap items-end gap-3">
                        <Input
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            onKeyDown={(e) =>
                                e.key === 'Enter' && applyFilters()
                            }
                            placeholder="Search IP, path, evidence…"
                            className="w-full sm:w-72"
                        />

                        <select
                            value={level}
                            onChange={(e) => setLevel(e.target.value)}
                            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
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
                            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
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

                    <Button variant="destructive" onClick={clearAll}>
                        Clear logs
                    </Button>
                </div>

                <Card className="py-0">
                    <CardContent className="overflow-x-auto px-0 py-0">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b text-left text-muted-foreground">
                                    <th className="px-4 py-3 font-medium">
                                        Level
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Event
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        IP
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Path
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        When
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {logs.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No security logs match the current
                                            filters.
                                        </td>
                                    </tr>
                                )}
                                {logs.data.map((log) => (
                                    <tr
                                        key={log.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3">
                                            <Badge
                                                variant={
                                                    levelVariants[
                                                        log.threat_level
                                                    ] ?? 'outline'
                                                }
                                            >
                                                {levelLabels[
                                                    log.threat_level
                                                ] ?? log.threat_level}
                                            </Badge>
                                        </td>
                                        <td className="px-4 py-3 text-xs">
                                            <div className="font-medium">
                                                {log.event_type}
                                            </div>
                                            <div className="text-muted-foreground">
                                                {log.rule_label}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 font-mono text-xs">
                                            {log.ip_address}
                                        </td>
                                        <td className="max-w-xs truncate px-4 py-3 text-xs">
                                            <span className="text-muted-foreground">
                                                {log.method}
                                            </span>{' '}
                                            {log.path}
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {new Date(
                                                log.created_at,
                                            ).toLocaleString()}
                                        </td>
                                        <td className="px-4 py-3 text-right">
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
                    </CardContent>
                </Card>

                <Pagination links={logs.links} total={logs.total} />
            </div>
        </>
    );
}

SecurityLogs.layout = {
    breadcrumbs: [
        {
            title: 'Security Logs',
            href: '/security/logs',
        },
    ],
};
