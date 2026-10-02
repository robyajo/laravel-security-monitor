<?php

namespace Internal\SecurityMonitor\Http\Controllers\Dashboard;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Inertia;
use Inertia\Response;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

/**
 * Overview page for the Inertia + React monitoring dashboard.
 */
class OverviewController extends Controller
{
    public function __invoke(Request $request, SecurityMonitorService $security): Response
    {
        $range = (string) $request->query('range', 'week');

        if (! in_array($range, ['week', 'month', 'year'], true)) {
            $range = 'week';
        }

        return Inertia::render('security/overview', [
            'range' => $range,
            'stats' => $security->stats(),
            'levels' => $security->levelBreakdown(),
            'trend' => $security->attackTrend($range),
            'attackers' => $security->topAttackers(5)
                ->map(fn ($row): array => (array) $row)
                ->all(),
            'urls' => [
                'self' => route('security.dashboard.overview'),
            ],
        ]);
    }
}
