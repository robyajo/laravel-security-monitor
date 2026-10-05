import { Head, router } from '@inertiajs/react';
import '@/components/security/security.css';
import { SecurityNav } from '@/components/security/security-nav';
import { Badge, Button, Card, CardContent, CardHeader, CardTitle } from '@/components/security/ui';

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
        <div className="sec-root" style={{ padding: '24px 20px', minHeight: '100vh', background: 'var(--sec-bg)' }}>
            <Head title="Security Overview" />

            <SecurityNav />

            <div className="sec-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                    <h1 className="sec-page-title">Security Overview</h1>
                    <p className="sec-page-subtitle">
                        Threat summary, blocks, and recent security activity.
                    </p>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {(['week', 'month', 'year'] as const).map((option) => (
                        <Button
                            key={option}
                            size="sm"
                            variant={range === option ? 'primary' : 'secondary'}
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

            <div className="sec-grid-4">
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Logs today</div>
                    <div className="sec-stat-value">{formatNumber(stats.logs_today)}</div>
                    <div className="sec-stat-desc">{`${formatNumber(stats.total_logs)} total recorded`}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Critical threats today</div>
                    <div className="sec-stat-value" style={{ color: 'var(--sec-danger)' }}>{formatNumber(stats.critical_today)}</div>
                    <div className="sec-stat-desc">Requires immediate review</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Active blocks</div>
                    <div className="sec-stat-value">{formatNumber(stats.active_blocks)}</div>
                    <div className="sec-stat-desc">{`${formatNumber(stats.total_blocks)} total blocks`}</div>
                </div>
                <div className="sec-stat-card">
                    <div className="sec-stat-label">Unique IPs today</div>
                    <div className="sec-stat-value">{formatNumber(stats.unique_ips_today)}</div>
                    <div className="sec-stat-desc">{`${formatNumber(stats.blocked_attempts_today)} blocked attempts`}</div>
                </div>
            </div>

            <div className="sec-grid-2">
                <Card>
                    <CardHeader>
                        <CardTitle>Attack trend</CardTitle>
                        <p className="sec-card-subtitle">
                            Total {formatNumber(trend.total)} &middot; Peak{' '}
                            {trend.peak.label} ({formatNumber(trend.peak.total)})
                        </p>
                    </CardHeader>
                    <CardContent>
                        <div className="sec-chart-box">
                            {trend.points.map((point) => (
                                <div
                                    key={point.key}
                                    className="sec-chart-col"
                                    title={`${point.tooltip} · ${point.total}`}
                                >
                                    <div
                                        className="sec-chart-bar"
                                        style={{
                                            height: `${Math.max(4, Math.round((point.total / maxTrend) * 120))}px`,
                                        }}
                                    />
                                    <span className="sec-chart-label">
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
                    <CardContent>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '8px' }}>
                            {(
                                ['critical', 'high', 'medium', 'low'] as const
                            ).map((level) => {
                                const count = levels[level] ?? 0;
                                const barColor = level === 'critical' ? 'var(--sec-danger)' : (level === 'high' ? 'var(--sec-warning)' : (level === 'medium' ? '#d97706' : 'var(--sec-text-subtle)'));

                                return (
                                    <div key={level}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                                            <Badge variant={level as any}>
                                                {levelLabels[level]}
                                            </Badge>
                                            <span className="sec-font-mono" style={{ fontSize: '13px', fontWeight: 600 }}>
                                                {formatNumber(count)}
                                            </span>
                                        </div>
                                        <div style={{ height: '6px', width: '100%', background: 'var(--sec-border-light)', borderRadius: '9999px', overflow: 'hidden' }}>
                                            <div
                                                style={{
                                                    height: '100%',
                                                    borderRadius: '9999px',
                                                    width: `${Math.round((count / levelTotal) * 100)}%`,
                                                    background: barColor,
                                                }}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </CardContent>
                </Card>
            </div>

            <Card flush>
                <CardHeader>
                    <CardTitle>Top attackers (24h)</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="sec-table-wrap">
                        <table className="sec-table">
                            <thead>
                                <tr>
                                    <th>IP address</th>
                                    <th>Hits</th>
                                    <th>Highest level</th>
                                    <th>Last seen</th>
                                </tr>
                            </thead>
                            <tbody>
                                {attackers.length === 0 && (
                                    <tr>
                                        <td
                                            colSpan={4}
                                            style={{ textAlign: 'center', color: 'var(--sec-text-muted)', padding: '36px' }}
                                        >
                                            No threats recorded in the last 24 hours.
                                        </td>
                                    </tr>
                                )}
                                {attackers.map((attacker) => (
                                    <tr key={attacker.ip_address}>
                                        <td className="sec-font-mono" style={{ fontWeight: 600, fontSize: '12px' }}>
                                            {attacker.ip_address}
                                        </td>
                                        <td className="sec-font-mono" style={{ fontSize: '12px' }}>
                                            {formatNumber(attacker.hits)}
                                        </td>
                                        <td>
                                            <Badge variant={(attacker.level as any) ?? 'low'}>
                                                {levelLabels[attacker.level] ?? attacker.level}
                                            </Badge>
                                        </td>
                                        <td style={{ fontSize: '12px', color: 'var(--sec-text-muted)' }}>
                                            {new Date(attacker.last_seen).toLocaleString()}
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
