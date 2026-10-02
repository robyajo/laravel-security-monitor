import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import { toast } from 'sonner';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

type Ticket = {
    id: number;
    ticket_number: string;
    ip_address: string;
    name: string;
    email: string;
    status: string;
    created_at: string;
};

type Paginator<T> = {
    data: T[];
    total: number;
    links: { url: string | null; label: string; active: boolean }[];
};

type TicketsProps = {
    tickets: Paginator<Ticket>;
    stats: { pending: number; approved: number; rejected: number };
    filters: { search: string; status: string };
    urls: { index: string; respond: string; destroy: string };
};

const statusVariant: Record<
    string,
    'default' | 'destructive' | 'secondary' | 'outline'
> = {
    pending: 'secondary',
    approved: 'default',
    rejected: 'destructive',
};

export default function UnblockAppeals({
    tickets,
    stats,
    filters,
    urls,
}: TicketsProps) {
    const [search, setSearch] = useState(filters.search);
    const [status, setStatus] = useState(filters.status);
    const [respondingId, setRespondingId] = useState<number | null>(null);
    const [action, setAction] = useState<'approve' | 'reject'>('approve');
    const [adminNotes, setAdminNotes] = useState('');

    const applyFilters = () => {
        router.get(
            urls.index,
            { search, status },
            { preserveState: true, preserveScroll: true, replace: true },
        );
    };

    const openRespond = (id: number, nextAction: 'approve' | 'reject') => {
        setRespondingId(id);
        setAction(nextAction);
        setAdminNotes('');
    };

    const submitRespond = (event: React.FormEvent) => {
        event.preventDefault();

        if (respondingId === null) {
            return;
        }

        router.post(
            urls.respond.replace('__ID__', String(respondingId)),
            { action, admin_notes: adminNotes },
            {
                preserveScroll: true,
                onSuccess: () => {
                    setRespondingId(null);
                    setAdminNotes('');
                    toast.success(
                        action === 'approve'
                            ? 'Ticket approved and IP unblocked.'
                            : 'Ticket rejected.',
                    );
                },
            },
        );
    };

    const destroy = (id: number) => {
        if (!confirm('Delete this ticket?')) {
            return;
        }

        router.delete(urls.destroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => toast.success('Ticket deleted.'),
        });
    };

    return (
        <>
            <Head title="Unblock Appeals" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div>
                    <h1 className="text-xl font-semibold">Unblock Appeals</h1>
                    <p className="text-sm text-muted-foreground">
                        Review self-service unblock requests from blocked users.
                    </p>
                </div>

                <div className="grid auto-rows-min gap-4 md:grid-cols-3">
                    <StatCard
                        title="Pending"
                        value={stats.pending}
                        className="text-amber-600 dark:text-amber-400"
                    />
                    <StatCard
                        title="Approved"
                        value={stats.approved}
                        className="text-green-600 dark:text-green-400"
                    />
                    <StatCard
                        title="Rejected"
                        value={stats.rejected}
                        className="text-red-600 dark:text-red-400"
                    />
                </div>

                <div className="flex flex-wrap items-end gap-3">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search ticket, IP, name, email…"
                        className="w-full sm:w-72"
                    />

                    <select
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                        className="h-9 rounded-md border border-input bg-background px-3 text-sm"
                    >
                        <option value="">All statuses</option>
                        <option value="pending">Pending</option>
                        <option value="approved">Approved</option>
                        <option value="rejected">Rejected</option>
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
                                        Ticket
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Applicant
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        IP
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Status
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Submitted
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {tickets.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No appeal tickets found.
                                        </td>
                                    </tr>
                                )}
                                {tickets.data.map((ticket) => (
                                    <tr
                                        key={ticket.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3 font-mono text-xs">
                                            {ticket.ticket_number}
                                        </td>
                                        <td className="px-4 py-3 text-xs">
                                            <div className="font-medium">
                                                {ticket.name}
                                            </div>
                                            <div className="text-muted-foreground">
                                                {ticket.email}
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 font-mono text-xs">
                                            {ticket.ip_address}
                                        </td>
                                        <td className="px-4 py-3">
                                            <Badge
                                                variant={
                                                    statusVariant[
                                                        ticket.status
                                                    ] ?? 'outline'
                                                }
                                            >
                                                {ticket.status}
                                            </Badge>
                                        </td>
                                        <td className="px-4 py-3 text-xs text-muted-foreground">
                                            {new Date(
                                                ticket.created_at,
                                            ).toLocaleString()}
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center justify-end gap-1">
                                                {ticket.status === 'pending' ? (
                                                    <>
                                                        <Button
                                                            size="sm"
                                                            onClick={() =>
                                                                openRespond(
                                                                    ticket.id,
                                                                    'approve',
                                                                )
                                                            }
                                                        >
                                                            Approve
                                                        </Button>
                                                        <Button
                                                            size="sm"
                                                            variant="outline"
                                                            onClick={() =>
                                                                openRespond(
                                                                    ticket.id,
                                                                    'reject',
                                                                )
                                                            }
                                                        >
                                                            Reject
                                                        </Button>
                                                    </>
                                                ) : (
                                                    <Button
                                                        size="sm"
                                                        variant="ghost"
                                                        onClick={() =>
                                                            destroy(ticket.id)
                                                        }
                                                    >
                                                        Delete
                                                    </Button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </CardContent>
                </Card>

                <Pagination links={tickets.links} total={tickets.total} />

                {respondingId !== null && (
                    <Card>
                        <CardHeader>
                            <CardTitle>
                                {action === 'approve'
                                    ? 'Approve appeal'
                                    : 'Reject appeal'}
                            </CardTitle>
                            <p className="text-sm text-muted-foreground">
                                {action === 'approve'
                                    ? 'The blocked IP/device will be unblocked automatically.'
                                    : 'The block will remain active.'}
                            </p>
                        </CardHeader>
                        <CardContent>
                            <form
                                onSubmit={submitRespond}
                                className="max-w-lg space-y-4"
                            >
                                <div className="grid gap-2">
                                    <Label htmlFor="admin_notes">
                                        Admin notes
                                    </Label>
                                    <textarea
                                        id="admin_notes"
                                        value={adminNotes}
                                        onChange={(e) =>
                                            setAdminNotes(e.target.value)
                                        }
                                        rows={3}
                                        className="min-h-20 rounded-md border border-input bg-background px-3 py-2 text-sm"
                                    />
                                </div>

                                <div className="flex justify-end gap-3">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        onClick={() => setRespondingId(null)}
                                    >
                                        Cancel
                                    </Button>
                                    <Button
                                        type="submit"
                                        variant={
                                            action === 'approve'
                                                ? 'default'
                                                : 'destructive'
                                        }
                                    >
                                        {action === 'approve'
                                            ? 'Approve & unblock'
                                            : 'Reject'}
                                    </Button>
                                </div>
                            </form>
                        </CardContent>
                    </Card>
                )}
            </div>
        </>
    );
}

function StatCard({
    title,
    value,
    className = '',
}: {
    title: string;
    value: number;
    className?: string;
}) {
    return (
        <Card className="gap-1 py-5">
            <CardHeader>
                <p className="text-sm text-muted-foreground">{title}</p>
                <div className={`text-2xl font-semibold ${className}`}>
                    {new Intl.NumberFormat().format(value)}
                </div>
            </CardHeader>
        </Card>
    );
}

UnblockAppeals.layout = {
    breadcrumbs: [
        {
            title: 'Unblock Appeals',
            href: '/security/tickets',
        },
    ],
};
