<?php

/**
 * Portal Dokumentasi — Generator.
 *
 * Membaca seluruh bab markdown di documents/<section>/*.md (kecuali README.md)
 * lalu menulis satu berkas mandiri documents/index.html yang ditata dengan
 * Tailwind CSS Play CDN, serta marked.js dan Mermaid.js (keduanya dari CDN).
 *
 * Jalankan:
 *   php documents/generate.php
 */

$base = __DIR__;
$version = "1.1.0";

$docs = [];

$directories = glob($base . "/*", GLOB_ONLYDIR) ?: [];
sort($directories);

foreach ($directories as $directory) {
    $files = glob($directory . "/*.md") ?: [];
    sort($files);

    foreach ($files as $file) {
        $filename = basename($file);

        if ($filename === "README.md") {
            continue;
        }

        $content = (string) file_get_contents($file);
        $title = $filename;

        if (preg_match('/^#\s+(.+)$/m', $content, $matches) === 1) {
            $title = trim($matches[1]);
        }

        $docs[] = [
            "section" => basename($directory),
            "filename" => $filename,
            "title" => $title,
            "content" => $content,
        ];
    }
}

$payload = json_encode($docs, JSON_UNESCAPED_UNICODE);

$template = <<<'HTML'
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laravel Security Monitor (Bulwark) — Portal Dokumentasi Resmi</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.tailwindcss.com?plugins=typography"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'system-ui', 'sans-serif'],
                        mono: ['"Fira Code"', 'monospace'],
                    },
                },
            },
        };
    </script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
    <style>
        html { scroll-behavior: smooth; }
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 8px; }
        .mermaid svg { max-width: 100%; height: auto; }
    </style>
</head>
<body class="min-h-screen bg-slate-50 font-sans text-slate-900 antialiased dark:bg-slate-950 dark:text-slate-100">
    <header class="fixed inset-x-0 top-0 z-40 flex h-16 items-center justify-between gap-3 border-b border-slate-200 bg-white/85 px-4 backdrop-blur sm:px-6 dark:border-slate-800 dark:bg-slate-900/85">
        <div class="flex items-center gap-3 overflow-hidden">
            <button onclick="toggleSidebar()" class="rounded-lg border border-slate-200 px-3 py-2 text-lg leading-none md:hidden dark:border-slate-700" aria-label="Buka navigasi">☰</button>
            <a href="#" onclick="loadDoc(0); return false;" class="flex items-center gap-3">
                <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-sky-600 to-indigo-600 text-xl shadow-lg shadow-sky-600/30">🛡️</div>
                <div class="flex items-center gap-2">
                    <span class="hidden text-base font-extrabold sm:inline">Laravel Security Monitor</span>
                    <span class="rounded-full border border-sky-400/30 bg-sky-400/10 px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-sky-500 dark:text-sky-300">Bulwark v__VERSION__</span>
                </div>
            </a>
        </div>
        <div class="flex items-center gap-2">
            <button onclick="toggleTheme()" class="rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold transition hover:border-sky-400 dark:border-slate-700 dark:bg-slate-800">🌓 <span class="hidden sm:inline">Ganti Tema</span></button>
            <a href="https://github.com/robyajo/laravel-security-monitor" target="_blank" class="rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-sm font-semibold transition hover:border-sky-400 dark:border-slate-700 dark:bg-slate-800">GitHub</a>
        </div>
    </header>

    <div id="backdrop" onclick="toggleSidebar()" class="fixed inset-0 z-20 hidden bg-slate-950/50 md:hidden"></div>

    <aside id="sidebar" class="fixed bottom-0 left-0 top-16 z-30 w-80 -translate-x-full overflow-y-auto border-r border-slate-200 bg-white p-5 transition-transform duration-300 md:translate-x-0 dark:border-slate-800 dark:bg-slate-900">
        <div class="relative mb-4">
            <span class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">🔍</span>
            <input id="searchInput" type="text" oninput="handleSearch(this.value)" placeholder="Cari topik dokumentasi..." class="w-full rounded-lg border border-slate-200 bg-slate-50 py-2.5 pl-9 pr-3 text-sm outline-none transition focus:border-sky-400 focus:ring-2 focus:ring-sky-400/20 dark:border-slate-700 dark:bg-slate-950">
        </div>
        <nav id="navTree" class="space-y-1 pb-10"></nav>
    </aside>

    <main class="pt-16 md:pl-80">
        <div class="mx-auto max-w-4xl px-5 py-10 sm:px-6">
            <div class="mb-5 flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
                <span>Dokumentasi</span>
                <span>&rsaquo;</span>
                <span id="activeBreadcrumb" class="text-sky-500 dark:text-sky-300">Memulai</span>
            </div>
            <article id="articleContent" class="prose prose-slate max-w-none dark:prose-invert prose-headings:scroll-mt-20 prose-pre:rounded-xl prose-pre:border prose-pre:border-slate-800 prose-pre:bg-slate-900 prose-code:before:content-none prose-code:after:content-none prose-a:text-sky-600 dark:prose-a:text-sky-400"></article>
        </div>
    </main>

    <script>
        const docsData = __DOCS_DATA__;
        let currentIndex = 0;

        function sectionLabel(section) {
            return section.replace(/^\d+-/, '').replace(/-/g, ' ').toUpperCase();
        }

        function buildNav() {
            const nav = document.getElementById('navTree');
            nav.innerHTML = '';

            let currentSection = '';
            let list = null;

            docsData.forEach((doc, idx) => {
                if (doc.section !== currentSection) {
                    currentSection = doc.section;

                    const heading = document.createElement('div');
                    heading.className = 'mb-1 mt-4 px-2 text-[11px] font-extrabold uppercase tracking-wider text-slate-400';
                    heading.textContent = sectionLabel(currentSection);
                    nav.appendChild(heading);

                    list = document.createElement('ul');
                    list.className = 'space-y-0.5';
                    nav.appendChild(list);
                }

                const li = document.createElement('li');
                const a = document.createElement('a');
                a.className = 'nav-link block cursor-pointer truncate rounded-lg px-3 py-2 text-sm font-medium text-slate-500 transition hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-white';
                a.dataset.index = String(idx);
                a.textContent = doc.title;
                a.onclick = () => loadDoc(idx);
                li.appendChild(a);
                list.appendChild(li);
            });
        }

        function setActive(index) {
            document.querySelectorAll('.nav-link').forEach((el) => {
                const active = Number(el.dataset.index) === index;
                el.classList.toggle('bg-sky-400/10', active);
                el.classList.toggle('text-sky-600', active);
                el.classList.toggle('dark:text-sky-300', active);
                el.classList.toggle('font-bold', active);
            });
        }

        function renderMermaid(article) {
            article.querySelectorAll('pre > code.language-mermaid, pre > code.lang-mermaid').forEach((code) => {
                const div = document.createElement('div');
                div.className = 'mermaid not-prose my-6 flex justify-center';
                div.textContent = code.textContent;
                code.parentElement.replaceWith(div);
            });
        }

        function attachCopyButtons(article) {
            article.querySelectorAll('pre').forEach((pre) => {
                pre.classList.add('relative');

                const btn = document.createElement('button');
                btn.className = 'copy-btn absolute right-3 top-3 rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-semibold text-slate-300 transition hover:bg-sky-600 hover:text-white';
                btn.textContent = 'Salin';
                btn.onclick = () => {
                    const code = pre.querySelector('code') ? pre.querySelector('code').innerText : pre.innerText;
                    navigator.clipboard.writeText(code).then(() => {
                        btn.textContent = 'Tersalin! ✓';
                        setTimeout(() => { btn.textContent = 'Salin'; }, 1800);
                    });
                };

                pre.appendChild(btn);
            });
        }

        async function loadDoc(index) {
            const doc = docsData[index];
            if (!doc) { return; }

            currentIndex = index;
            setActive(index);
            document.getElementById('activeBreadcrumb').textContent = doc.title;

            const article = document.getElementById('articleContent');
            article.innerHTML = window.marked ? marked.parse(doc.content) : doc.content;

            renderMermaid(article);
            attachCopyButtons(article);

            if (window.mermaid) {
                try {
                    await mermaid.run({ nodes: article.querySelectorAll('.mermaid') });
                } catch (error) {
                    console.warn('Mermaid render skipped:', error);
                }
            }

            window.scrollTo({ top: 0, behavior: 'smooth' });
            closeSidebar();
        }

        function handleSearch(query) {
            const q = query.toLowerCase().trim();
            document.querySelectorAll('#navTree .nav-link').forEach((el) => {
                const match = el.textContent.toLowerCase().includes(q);
                el.parentElement.style.display = match ? '' : 'none';
            });
        }

        function toggleTheme() {
            const dark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('bulwark-theme', dark ? 'dark' : 'light');

            if (window.mermaid) {
                mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'default', securityLevel: 'loose' });
            }

            loadDoc(currentIndex);
        }

        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const backdrop = document.getElementById('backdrop');
            const hidden = sidebar.classList.toggle('-translate-x-full');
            backdrop.classList.toggle('hidden', hidden);
        }

        function closeSidebar() {
            if (window.innerWidth < 768) {
                document.getElementById('sidebar').classList.add('-translate-x-full');
                document.getElementById('backdrop').classList.add('hidden');
            }
        }

        (function initTheme() {
            const saved = localStorage.getItem('bulwark-theme');
            const dark = saved ? saved === 'dark' : true;
            document.documentElement.classList.toggle('dark', dark);
        })();

        if (window.mermaid) {
            mermaid.initialize({
                startOnLoad: false,
                securityLevel: 'loose',
                theme: document.documentElement.classList.contains('dark') ? 'dark' : 'default',
            });
        }

        buildNav();
        loadDoc(0);
    </script>
</body>
</html>
HTML;

$html = str_replace(
    ["__DOCS_DATA__", "__VERSION__"],
    [$payload, $version],
    $template,
);

file_put_contents($base . "/index.html", $html);

echo "Generated documents/index.html with " .
    count($docs) .
    " chapters." .
    PHP_EOL;
