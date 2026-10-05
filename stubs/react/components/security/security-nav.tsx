import { Link, usePage } from '@inertiajs/react';

const items = [
    { title: 'Overview', href: '/security', icon: '📊' },
    { title: 'Security Logs', href: '/security/logs', icon: '📜' },
    { title: 'Blocked IPs', href: '/security/blocked-ips', icon: '🚫' },
    { title: 'Server Audit', href: '/security/server', icon: '🛡️' },
    { title: 'Sessions', href: '/security/sessions', icon: '👥' },
    { title: 'Appeals', href: '/security/tickets', icon: '📩' },
    { title: 'Settings', href: '/security/settings', icon: '⚙️' },
];

export function SecurityNav() {
    const { url } = usePage();
    const current = url.split('?')[0];

    return (
        <nav className="sec-nav-bar" aria-label="Security Navigation">
            {items.map((item) => {
                const active = current === item.href;

                return (
                    <Link
                        key={item.href}
                        href={item.href}
                        prefetch
                        className={`sec-nav-link ${active ? 'active' : ''}`}
                    >
                        <span>{item.icon}</span>
                        <span>{item.title}</span>
                    </Link>
                );
            })}
        </nav>
    );
}
