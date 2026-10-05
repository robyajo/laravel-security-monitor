import { router } from '@inertiajs/react';
import { Button } from './ui';

export type PageLink = {
    url: string | null;
    label: string;
    active: boolean;
};

export function Pagination({
    links,
    total,
}: {
    links: PageLink[];
    total: number;
}) {
    if (links.length <= 3) {
        return <p style={{ fontSize: '13px', color: 'var(--sec-text-muted)', margin: 0 }}>{total} entries</p>;
    }

    return (
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '4px' }}>
            {links.map((link, index) => (
                <Button
                    key={index}
                    size="sm"
                    variant={link.active ? 'primary' : 'secondary'}
                    disabled={!link.url}
                    onClick={() =>
                        link.url &&
                        router.get(link.url, {}, { preserveScroll: true })
                    }
                    dangerouslySetInnerHTML={{
                        __html: link.label,
                    }}
                />
            ))}
        </div>
    );
}
