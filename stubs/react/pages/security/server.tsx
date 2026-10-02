import { Head, router } from '@inertiajs/react';
import { toast } from 'sonner';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

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

const statusVariant: Record<
    string,
    'default' | 'destructive' | 'secondary' | 'outline'
> = {
    critical: 'destructive',
    warning: 'secondary',
    ok: 'outline',
    info: 'outline',
};

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

    const refresh = () => {
        router.get(urls.refresh, {}, { preserveScroll: true });
    };

    const createBaseline = () => {
        if (
            !confirm('Create a new integrity baseline from the current files?')
        ) {
            return;
        }

        router.post(urls.baseline, {}, { preserveScroll: true });
    };

    const deleteBaseline = () => {
        if (!confirm('Delete the stored baseline?')) {
            return;
        }

        router.delete(urls.baselineDestroy, { preserveScroll: true });
    };

    const deleteFile = (path: string) => {
        if (!confirm('Permanently delete this file?')) {
            return;
        }

        router.delete(urls.suspiciousDestroy, {
            data: { file_path: path },
            preserveScroll: true,
        });
    };

    const releaseLockout = (id: number) => {
        router.delete(urls.lockoutDestroy.replace('__ID__', String(id)), {
            preserveScroll: true,
            onSuccess: () => toast.success('Lockout released.'),
        });
    };

    return (
        <>
            <Head title="Server Audit" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div className="flex items-center justify-between gap-4">
                    <div>
                        <h1 className="text-xl font-semibold">Server Audit</h1>
                        <p className="text-sm text-muted-foreground">
                            Integrity, webshell scanner, and environment
                            hygiene.
                        </p>
                    </div>

                    <Button onClick={refresh}>Refresh</Button>
                </div>

                <div className="grid auto-rows-min gap-4 md:grid-cols-4">
                    <MetricCard
                        title="Health score"
                        value={`${summary.score}/100`}
                    />
                    <MetricCard
                        title="Critical"
                        value={String(summary.critical)}
                        danger
                    />
                    <MetricCard
                        title="Warnings"
                        value={String(summary.warning)}
                    />
                    <MetricCard
                        title="Passed checks"
                        value={String(summary.ok)}
                    />
                </div>

                <div className="grid gap-4 lg:grid-cols-2">
                    <Card>
                        <CardHeader className="flex-row items-start justify-between">
                            <div>
                                <CardTitle>Integrity baseline</CardTitle>
                                <p className="text-sm text-muted-foreground">
                                    {baseline.exists
                                        ? `${baseline.files} files tracked · created ${baseline.created_at ?? '-'}`
                                        : `No baseline created yet (${baseline.watched} files watched).`}
                                </p>
                            </div>
                            <div className="flex gap-2">
                                <Button size="sm" onClick={createBaseline}>
                                    Create
                                </Button>
                                {baseline.exists && (
                                    <Button
                                        size="sm"
                                        variant="destructive"
                                        onClick={deleteBaseline}
                                    >
                                        Delete
                                    </Button>
                                )}
                            </div>
                        </CardHeader>
                        <CardContent className="grid grid-cols-3 gap-3 text-center">
                            <div>
                                <div className="text-lg font-semibold tabular-nums">
                                    {integrity.modified.length}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    Modified
                                </p>
                            </div>
                            <div>
                                <div className="text-lg font-semibold tabular-nums">
                                    {integrity.missing.length}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    Missing
                                </p>
                            </div>
                            <div>
                                <div className="text-lg font-semibold tabular-nums">
                                    {integrity.added.length}
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    New
                                </p>
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>Environment</CardTitle>
                        </CardHeader>
                        <CardContent className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-sm sm:grid-cols-2">
                            {Object.entries(environment).map(([key, value]) => (
                                <div
                                    key={key}
                                    className="flex items-center justify-between gap-2 border-b py-1 last:border-0"
                                >
                                    <span className="text-muted-foreground capitalize">
                                        {key.replace(/_/g, ' ')}
                                    </span>
                                    <span
                                        className="truncate font-medium"
                                        title={value}
                                    >
                                        {value}
                                    </span>
                                </div>
                            ))}
                        </CardContent>
                    </Card>
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>Suspicious files &amp; webshells</CardTitle>
                    </CardHeader>
                    <CardContent className="overflow-x-auto px-0">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b text-left text-muted-foreground">
                                    <th className="px-4 py-3 font-medium">
                                        File
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Threat
                                    </th>
                                    <th className="px-4 py-3 font-medium">
                                        Reason
                                    </th>
                                    <th className="px-4 py-3 text-right font-medium">
                                        Size
                                    </th>
                                    <th className="px-4 py-3" />
                                </tr>
                            </thead>
                            <tbody>
                                {suspicious.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={5}
                                            className="px-4 py-6 text-center text-muted-foreground"
                                        >
                                            No suspicious files detected.
                                        </td>
                                    </tr>
                                )}
                                {suspicious.map((file) => (
                                    <tr
                                        key={file.id}
                                        className="border-b last:border-0"
                                    >
                                        <td className="px-4 py-3 font-mono text-xs">
                                            {file.path}
                                        </td>
                                        <td className="px-4 py-3">
                                            <Badge
                                                variant={
                                                    statusVariant[
                                                        file.threat_level
                                                    ] ?? 'outline'
                                                }
                                            >
                                                {file.threat_level}
                                            </Badge>
                                        </td>
                                        <td
                                            className="max-w-sm truncate px-4 py-3 text-xs text-muted-foreground"
                                            title={file.reason}
                                        >
                                            {file.reason}
                                        </td>
                                        <td className="px-4 py-3 text-right text-xs">
                                            {file.size}
                                        </td>
                                        <td className="px-4 py-3 text-right">
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                onClick={() =>
                                                    deleteFile(file.path)
                                                }
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

                {lockouts.length > 0 && (
                    <Card>
                        <CardHeader>
                            <CardTitle>Active login lockouts</CardTitle>
                        </CardHeader>
                        <CardContent className="overflow-x-auto px-0">
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="border-b text-left text-muted-foreground">
                                        <th className="px-4 py-3 font-medium">
                                            Email
                                        </th>
                                        <th className="px-4 py-3 font-medium">
                                            IP
                                        </th>
                                        <th className="px-4 py-3 font-medium">
                                            Level
                                        </th>
                                        <th className="px-4 py-3 font-medium">
                                            Remaining
                                        </th>
                                        <th className="px-4 py-3" />
                                    </tr>
                                </thead>
                                <tbody>
                                    {lockouts.map((lockout) => (
                                        <tr
                                            key={lockout.id}
                                            className="border-b last:border-0"
                                        >
                                            <td className="px-4 py-3 text-xs">
                                                {lockout.email}
                                            </td>
                                            <td className="px-4 py-3 font-mono text-xs">
                                                {lockout.ip_address}
                                            </td>
                                            <td className="px-4 py-3">
                                                {lockout.lockout_level}
                                            </td>
                                            <td className="px-4 py-3 text-xs">
                                                {lockout.remaining}s
                                            </td>
                                            <td className="px-4 py-3 text-right">
                                                <Button
                                                    size="sm"
                                                    variant="ghost"
                                                    onClick={() =>
                                                        releaseLockout(
                                                            lockout.id,
                                                        )
                                                    }
                                                >
                                                    Release
                                                </Button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </CardContent>
                    </Card>
                )}

                <Card>
                    <CardHeader>
                        <CardTitle>Security checks</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-6">
                        {report.categories.map((category) => (
                            <div key={category.id} className="space-y-2">
                                <h3 className="text-sm font-medium text-muted-foreground">
                                    {category.label}
                                </h3>
                                <div className="space-y-2">
                                    {category.checks.map((check) => (
                                        <div
                                            key={check.id}
                                            className="flex items-start justify-between gap-3 rounded-lg border p-3"
                                        >
                                            <div className="space-y-0.5">
                                                <div className="flex items-center gap-2">
                                                    <Badge
                                                        variant={
                                                            statusVariant[
                                                                check.status
                                                            ] ?? 'outline'
                                                        }
                                                    >
                                                        {check.status}
                                                    </Badge>
                                                    <span className="text-sm font-medium">
                                                        {check.label}
                                                    </span>
                                                </div>
                                                {check.detail && (
                                                    <p className="text-xs text-muted-foreground">
                                                        {check.detail}
                                                    </p>
                                                )}
                                                {check.recommendation && (
                                                    <p className="text-xs text-amber-600 dark:text-amber-400">
                                                        → {check.recommendation}
                                                    </p>
                                                )}
                                            </div>
                                            {check.value && (
                                                <Badge variant="outline">
                                                    {check.value}
                                                </Badge>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </CardContent>
                </Card>
            </div>
        </>
    );
}

function MetricCard({
    title,
    value,
    danger = false,
}: {
    title: string;
    value: string;
    danger?: boolean;
}) {
    return (
        <Card className="gap-1 py-5">
            <CardHeader>
                <p className="text-sm text-muted-foreground">{title}</p>
                <div
                    className={`text-2xl font-semibold ${danger ? 'text-red-600 dark:text-red-400' : ''}`}
                >
                    {value}
                </div>
            </CardHeader>
        </Card>
    );
}

ServerAudit.layout = {
    breadcrumbs: [
        {
            title: 'Server Audit',
            href: '/security/server',
        },
    ],
};
