import { Head, router, useForm } from '@inertiajs/react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

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

export default function BlockedIps({
    blocks,
    stats,
    filters,
    urls,
}: BlockedIpsProps) {
    const [search, setSearch] = useState(filters.search);
    const [status, setStatus] = useState(filters.status);

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
                toast.success('IP blocked.');
            },
        });
    };

    const toggle = (id: number) => {
        router.patch(
            urls.toggle.replace('__ID__', String(id)),
            {},
            {
                preserveScroll: true,
                onSuccess: () => toast.success('Block updated.'),
            },
        );
    };

    const unblock = (id: number) => {
        if (!confirm('Remove this block entirely?')) {
            return;
        }

        router.delete(urls.destroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => toast.success('IP unblocked.'),
        });
    };

    return (
        <>
            <Head title="Blocked IPs" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div>
                    <h1 className="text-xl font-semibold">Blocked IPs</h1>
                    <p className="text-sm text-muted-foreground">
                        Manage quarantined IP addresses and devices.
                    </p>
                </div>

                <div className="grid auto-rows-min gap-4 md:grid-cols-4">
                    <StatCard title="Total blocks" value={stats.total} />
                    <StatCard title="Active" value={stats.active} danger />
                    <StatCard title="Permanent" value={stats.permanent} />
                    <StatCard title="Total hits" value={stats.hits} />
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>Block an IP address</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <form
                            onSubmit={submitBlock}
                            className="grid gap-4 md:grid-cols-2"
                        >
                            <div className="grid gap-2">
                                <Label htmlFor="ip_address">IP address</Label>
                                <Input
                                    id="ip_address"
                                    value={form.data.ip_address}
                                    onChange={(e) =>
                                        form.setData(
                                            'ip_address',
                                            e.target.value,
                                        )
                                    }
                                    placeholder="203.0.113.50"
                                />
                                {form.errors.ip_address && (
                                    <p className="text-xs text-destructive">
                                        {form.errors.ip_address}
                                    </p>
                                )}
                            </div>

                            <div className="grid gap-2">
                                <Label htmlFor="reason">Reason</Label>
                                <Input
                                    id="reason"
                                    value={form.data.reason}
                                    onChange={(e) =>
                                        form.setData('reason', e.target.value)
                                    }
                                    placeholder="e.g. Repeated directory scanning"
                                />
                            </div>

                            <div className="grid gap-2">
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
                                />
                            </div>

                            <div className="flex items-end gap-2">
                                <label className="flex items-center gap-2 text-sm">
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
                                    Permanent block
                                </label>

                                <Button
                                    type="submit"
                                    variant="destructive"
                                    disabled={form.processing}
                                    className="ml-auto"
                                >
                                    Block IP
                                </Button>
                            </div>
                        </form>
                    </CardContent>
                </Card>

                <div className="flex flex-wrap items-end gap-3">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search IP, device, reason…"
                        className="w-full sm:w-72"
                    />

                    <select
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                        className="h-9 rounded-md border border-input bg-background px-3 text-sm"
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

                <Card className="py-0">
                    <CardContent className="overflow-x-auto px-0 py-0">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b text-left text-muted-foreground">
                                    <th className="px-4 py-3 font-medium">
                                        IP address
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Reason
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Status
                                    </th>
                                    <th className="px-4 py-3 text-right font-medium">
                                        Hits
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {blocks.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No blocked IPs match the current
                                            filters.
                                        </td>
                                    </tr>
                                )}
                                {blocks.data.map((block) => (
                                    <tr
                                        key={block.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3">
                                            <div className="font-mono text-xs">
                                                {block.ip_address}
                                            </div>
                                            {block.device_id && (
                                                <div className="text-[10px] text-muted-foreground">
                                                    {block.device_id}
                                                </div>
                                            )}
                                        </td>
                                        <td className="max-w-xs truncate px-4 py-3 text-xs text-muted-foreground">
                                            {block.reason}
                                        </td>
                                        <td className="px-4 py-3">
                                            <Badge
                                                variant={
                                                    statusOf(block) === 'Active'
                                                        ? 'destructive'
                                                        : 'outline'
                                                }
                                            >
                                                {statusOf(block)}
                                            </Badge>
                                        </td>
                                        <td className="px-4 py-3 text-right tabular-nums">
                                            {block.hit_count}
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center justify-end gap-1">
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() =>
                                                        toggle(block.id)
                                                    }
                                                >
                                                    {block.is_active
                                                        ? 'Disable'
                                                        : 'Enable'}
                                                </Button>
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() =>
                                                        unblock(block.id)
                                                    }
                                                >
                                                    Unblock
                                                </Button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </CardContent>
                </Card>

                <Pagination links={blocks.links} total={blocks.total} />
            </div>
        </>
    );
}

function StatCard({
    title,
    value,
    danger = false,
}: {
    title: string;
    value: number;
    danger?: boolean;
}) {
    return (
        <Card className="gap-1 py-5">
            <CardHeader>
                <p className="text-sm text-muted-foreground">{title}</p>
                <div
                    className={`text-2xl font-semibold ${danger ? 'text-red-600 dark:text-red-400' : ''}`}
                >
                    {new Intl.NumberFormat().format(value)}
                </div>
            </CardHeader>
        </Card>
    );
}

BlockedIps.layout = {
    breadcrumbs: [
        {
            title: 'Blocked IPs',
            href: '/security/blocked-ips',
        },
    ],
};
