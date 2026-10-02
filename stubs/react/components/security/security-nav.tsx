import { Link, usePage } from '@inertiajs/react';
import { cn } from '@/lib/utils';

const items = [
    { title: 'Overview', href: '/security' },
    { title: 'Security Logs', href: '/security/logs' },
    { title: 'Blocked IPs', href: '/security/blocked-ips' },
    { title: 'Server Audit', href: '/security/server' },
    { title: 'Sessions', href: '/security/sessions' },
    { title: 'Appeals', href: '/security/tickets' },
];

export function SecurityNav() {
    const { url } = usePage();
    const current = url.split('?')[0];

    return (
        <nav className="flex flex-wrap gap-1 border-b border-sidebar-border/70 pb-3 dark:border-sidebar-border">
            {items.map((item) => {
                const active = current === item.href;

                return (
                    <Link
                        key={item.href}
                        href={item.href}
                        prefetch
                        className={cn(
                            'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
                            active
                                ? 'bg-accent text-accent-foreground'
                                : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
                        )}
                    >
                        {item.title}
                    </Link>
                );
            })}
        </nav>
    );
}
