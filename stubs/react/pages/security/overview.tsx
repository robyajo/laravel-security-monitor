import { Head, router } from '@inertiajs/react';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

type TrendPoint = {
    key: string;
    label: string;
    tooltip: string;
    total: number;
    levels: Record<string, number>;
};

type Attacker = {
    ip_address: string;
    hits: number;
    level: string;
    last_seen: string;
};

type OverviewProps = {
    range: 'week' | 'month' | 'year';
    stats: Record<string, number>;
    levels: Record<string, number>;
    trend: {
        total: number;
        peak: { label: string; total: number };
        points: TrendPoint[];
    };
    attackers: Attacker[];
    urls: { self: string };
};

const levelLabels: Record<string, string> = {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
};

const levelClasses: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-neutral-400',
};

function formatNumber(value: number | undefined): string {
    return new Intl.NumberFormat().format(value ?? 0);
}

export default function SecurityOverview({
    range,
    stats,
    levels,
    trend,
    attackers,
    urls,
}: OverviewProps) {
    const maxTrend = Math.max(1, ...trend.points.map((p) => p.total));
    const levelTotal = Math.max(
        1,
        Object.values(levels).reduce((sum, value) => sum + value, 0),
    );

    const changeRange = (value: string) => {
        router.get(
            urls.self,
            { range: value },
            { preserveState: true, preserveScroll: true, replace: true },
        );
    };

    return (
        <>
            <Head title="Security Overview" />

            <div className="flex h-full flex-1 flex-col gap-6 p-4">
                <SecurityNav />

                <div className="flex items-center justify-between gap-4">
                    <div>
                        <h1 className="text-xl font-semibold">
                            Security Overview
                        </h1>
                        <p className="text-sm text-muted-foreground">
                            Threat summary, blocks, and recent security
                            activity.
                        </p>
                    </div>

                    <div className="flex items-center gap-2">
                        {(['week', 'month', 'year'] as const).map((option) => (
                            <Button
                                key={option}
                                size="sm"
                                variant={
                                    range === option ? 'default' : 'outline'
                                }
                                onClick={() => changeRange(option)}
                            >
                                {option === 'week'
                                    ? '7 days'
                                    : option === 'month'
                                      ? '30 days'
                                      : '12 months'}
                            </Button>
                        ))}
                    </div>
                </div>

                <div className="grid auto-rows-min gap-4 md:grid-cols-2 xl:grid-cols-4">
                    <StatCard
                        title="Logs today"
                        value={formatNumber(stats.logs_today)}
                        hint={`${formatNumber(stats.total_logs)} total recorded`}
                    />
                    <StatCard
                        title="Critical threats today"
                        value={formatNumber(stats.critical_today)}
                        hint="Requires immediate review"
                        danger
                    />
                    <StatCard
                        title="Active blocks"
                        value={formatNumber(stats.active_blocks)}
                        hint={`${formatNumber(stats.total_blocks)} total blocks`}
                    />
                    <StatCard
                        title="Unique IPs today"
                        value={formatNumber(stats.unique_ips_today)}
                        hint={`${formatNumber(stats.blocked_attempts_today)} blocked attempts`}
                    />
                </div>

                <div className="grid gap-4 lg:grid-cols-2">
                    <Card>
                        <CardHeader>
                            <CardTitle>Attack trend</CardTitle>
                            <p className="text-sm text-muted-foreground">
                                Total {formatNumber(trend.total)} &middot; Peak{' '}
                                {trend.peak.label} (
                                {formatNumber(trend.peak.total)})
                            </p>
                        </CardHeader>
                        <CardContent>
                            <div className="flex h-40 items-end gap-1.5">
                                {trend.points.map((point) => (
                                    <div
                                        key={point.key}
                                        className="group flex flex-1 flex-col items-center justify-end gap-1"
                                        title={`${point.tooltip} · ${point.total}`}
                                    >
                                        <div
                                            className="w-full rounded-t bg-red-500/70 transition group-hover:bg-red-500"
                                            style={{
                                                height: `${Math.max(2, Math.round((point.total / maxTrend) * 130))}px`,
                                            }}
                                        />
                                        <span className="text-[10px] text-muted-foreground">
                                            {point.label}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader>
                            <CardTitle>Threats by severity (24h)</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                            {(
                                ['critical', 'high', 'medium', 'low'] as const
                            ).map((level) => {
                                const count = levels[level] ?? 0;

                                return (
                                    <div key={level} className="space-y-1">
                                        <div className="flex items-center justify-between text-sm">
                                            <span className="font-medium">
                                                {levelLabels[level]}
                                            </span>
                                            <span className="tabular-nums">
                                                {formatNumber(count)}
                                            </span>
                                        </div>
                                        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                                            <div
                                                className={`h-full rounded-full ${levelClasses[level]}`}
                                                style={{
                                                    width: `${Math.round((count / levelTotal) * 100)}%`,
                                                }}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </CardContent>
                    </Card>
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>Top attackers (24h)</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                                <thead>
                                    <tr className="border-b text-left text-muted-foreground">
                                        <th className="py-2 pr-4 font-medium">
                                            IP address
                                        </th>
                                        <th className="py-2 pr-4 font-medium">
                                            Hits
                                        </th>
                                        <th className="py-2 pr-4 font-medium">
                                            Highest level
                                        </th>
                                        <th className="py-2 font-medium">
                                            Last seen
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {attackers.length === 0 && (
                                        <tr>
                                            <td
                                                colSpan={4}
                                                className="py-6 text-center text-muted-foreground"
                                            >
                                                No threats recorded in the last
                                                24 hours.
                                            </td>
                                        </tr>
                                    )}
                                    {attackers.map((attacker) => (
                                        <tr
                                            key={attacker.ip_address}
                                            className="border-b last:border-0"
                                        >
                                            <td className="py-2 pr-4 font-mono text-xs">
                                                {attacker.ip_address}
                                            </td>
                                            <td className="py-2 pr-4 tabular-nums">
                                                {formatNumber(attacker.hits)}
                                            </td>
                                            <td className="py-2 pr-4">
                                                <Badge variant="outline">
                                                    {levelLabels[
                                                        attacker.level
                                                    ] ?? attacker.level}
                                                </Badge>
                                            </td>
                                            <td className="py-2 text-xs text-muted-foreground">
                                                {new Date(
                                                    attacker.last_seen,
                                                ).toLocaleString()}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </>
    );
}

function StatCard({
    title,
    value,
    hint,
    danger = false,
}: {
    title: string;
    value: string;
    hint: string;
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
                <p className="text-xs text-muted-foreground">{hint}</p>
            </CardHeader>
        </Card>
    );
}

SecurityOverview.layout = {
    breadcrumbs: [
        {
            title: 'Security Overview',
            href: '/security',
        },
    ],
};
