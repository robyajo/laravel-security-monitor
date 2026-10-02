import { router } from '@inertiajs/react';
import { Button } from '@/components/ui/button';

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
        return <p className="text-sm text-muted-foreground">{total} entries</p>;
    }

    return (
        <div className="flex flex-wrap items-center gap-1">
            {links.map((link, index) => (
                <Button
                    key={index}
                    size="sm"
                    variant={link.active ? 'default' : 'outline'}
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
