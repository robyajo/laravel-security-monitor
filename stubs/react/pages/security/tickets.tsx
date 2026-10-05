import { Head, router } from '@inertiajs/react';
import { useState } from 'react';
import '@/components/security/security.css';
import { Pagination } from '@/components/security/pagination';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, Input, Label } from '@/components/security/ui';

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

function statusBadgeVariant(status: string): 'critical' | 'high' | 'success' | 'low' {
    if (status === 'pending') return 'high';
    if (status === 'approved') return 'success';
    if (status === 'rejected') return 'critical';
    return 'low';
}

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
    const [flashMsg, setFlashMsg] = useState<string | null>(null);

    const showNotification = (msg: string) => {
        setFlashMsg(msg);
        setTimeout(() => setFlashMsg(null), 4000);
    };

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
                    showNotification(
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
            onSuccess: () => showNotification('Ticket deleted.'),
        });
    };

    return (
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="Unblock Appeals" />

            <SecurityNav />

            {flashMsg && (
                <div className="sec-alert sec-alert-success" style={{ marginBottom: '16px' }}>
                    <span>{flashMsg}</span>
                </div>
            )}

            <div className="sec-page-header">
                <h1 className="sec-page-title">Unblock Appeals</h1>
                <p className="sec-page-subtitle">
                    Review self-service unblock requests from blocked users.
                </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '20px' }}>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Pending</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-warning)' }}>{stats.pending}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Approved</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-success)' }}>{stats.approved}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Rejected</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-danger)' }}>{stats.rejected}</div>
                </div>
            </div>

            <div className="sec-toolbar">
                <div className="sec-toolbar-group">
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && applyFilters()}
                        placeholder="Search ticket, IP, name, email…"
                        style={{ minWidth: '260px' }}
                    />

                    <select
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                        className="sec-select"
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
            </div>

            <Card flush>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>Ticket</th>
                                    <th>Applicant</th>
                                    <th>IP</th>
                                    <th>Status</th>
                                    <th>Submitted</th>
                                    <th style={{ textAlign: 'right' }}>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {tickets.data.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={6}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No appeal tickets found.
                                        </td>
                                    </tr>
                                )}
                                {tickets.data.map((ticket) => (
                                    <tr key={ticket.id}>
                                        <td className="sec-font-mono" style={{ fontWeight: 600, fontSize: '12px' }}>
                                            {ticket.ticket_number}
                                        </td>
                                        <td>
                                            <div style={{ fontWeight: 600, fontSize: '13px' }}>
                                                {ticket.name}
                                            </div>
                                            <div style={{ fontSize: '11px', color: 'var(--sec-text-muted)' }}>
                                                {ticket.email}
                                            </div>
                                        </td>
                                        <td className="sec-font-mono" style={{ fontSize: '12px' }}>
                                            {ticket.ip_address}
                                        </td>
                                        <td>
                                            <Badge variant={statusBadgeVariant(ticket.status)}>
                                                {ticket.status}
                                            </Badge>
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)', whiteSpace: 'nowrap' }}>
                                            {new Date(ticket.created_at).toLocaleString()}
                                        </td>
                                        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                            {ticket.status === 'pending' ? (
                                                <div style={{ display: 'inline-flex', gap: '6px' }}>
                                                    <Button
                                                        size="sm"
                                                        variant="primary"
                                                        onClick={() => openRespond(ticket.id, 'approve')}
                                                    >
                                                        Approve
                                                    </Button>
                                                    <Button
                                                        size="sm"
                                                        variant="secondary"
                                                        onClick={() => openRespond(ticket.id, 'reject')}
                                                    >
                                                        Reject
                                                    </Button>
                                                </div>
                                            ) : (
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() => destroy(ticket.id)}
                                                >
                                                    🗑️
                                                </Button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </CardContent>
            </Card>

            <div style={{ marginTop: '16px' }}>
                <Pagination links={tickets.links} total={tickets.total} />
            </div>

            {/* Respond Modal */}
            {respondingId !== null && (
                <div className="sec-modal-backdrop" onClick={() => setRespondingId(null)}>
                    <div className="sec-modal-box" onClick={(e) => e.stopPropagation()}>
                        <div className="sec-modal-header">
                            <h3 className="sec-card-title">
                                {action === 'approve' ? 'Approve Appeal' : 'Reject Appeal'}
                            </h3>
                            <p className="sec-card-subtitle">
                                {action === 'approve'
                                    ? 'The blocked IP/device will be unblocked automatically.'
                                    : 'The block will remain active.'}
                            </p>
                        </div>
                        <form onSubmit={submitRespond}>
                            <div className="sec-modal-body">
                                <div>
                                    <Label htmlFor="admin_notes">Admin notes</Label>
                                    <textarea
                                        id="admin_notes"
                                        rows={3}
                                        value={adminNotes}
                                        onChange={(e) => setAdminNotes(e.target.value)}
                                        placeholder="Optional notes shown to the applicant…"
                                        className="sec-textarea"
                                    />
                                </div>
                            </div>
                            <div className="sec-modal-footer">
                                <Button variant="secondary" onClick={() => setRespondingId(null)}>
                                    Cancel
                                </Button>
                                <Button
                                    type="submit"
                                    variant={action === 'approve' ? 'primary' : 'danger'}
                                >
                                    {action === 'approve' ? 'Approve & unblock' : 'Reject'}
                                </Button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
