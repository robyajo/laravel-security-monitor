<?php

namespace Internal\SecurityMonitor\Http\Controllers\Dashboard;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Inertia;
use Inertia\Response;
use Internal\SecurityMonitor\Models\SecurityLog;

/**
 * Security log management page for the Inertia + React dashboard.
 */
class LogController extends Controller
{
    public function index(Request $request): Response
    {
        $query = SecurityLog::query()->latest('id');

        $search = (string) $request->query('search', '');
        $level = (string) $request->query('level', '');
        $eventType = (string) $request->query('event_type', '');

        if ($search !== '') {
            $query->where(function ($q) use ($search): void {
                $q->where('path', 'like', "%{$search}%")
                    ->orWhere('evidence', 'like', "%{$search}%")
                    ->orWhere('rule_label', 'like', "%{$search}%")
                    ->orWhere('user_agent', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%");
            });
        }

        if (in_array($level, SecurityLog::LEVELS, true)) {
            $query->where('threat_level', $level);
        }

        if ($eventType !== '') {
            $query->where('event_type', $eventType);
        }

        return Inertia::render('security/logs', [
            'logs' => $query->paginate(25)->withQueryString(),
            'levels' => SecurityLog::LEVELS,
            'eventTypes' => SecurityLog::query()
                ->select('event_type')
                ->distinct()
                ->orderBy('event_type')
                ->pluck('event_type')
                ->all(),
            'filters' => [
                'search' => $search,
                'level' => $level,
                'event_type' => $eventType,
            ],
            'urls' => [
                'index' => route('security.dashboard.logs'),
                'clear' => route('security.dashboard.logs.clear'),
                'destroy' => route('security.dashboard.logs.destroy', ['id' => '__ID__']),
            ],
        ]);
    }

    public function clear(): RedirectResponse
    {
        $count = SecurityLog::query()->count();
        SecurityLog::query()->truncate();

        return back()->with('toast', [
            'type' => 'success',
            'message' => __(':count log entries cleared.', ['count' => $count]),
        ]);
    }

    public function destroy(int $id): RedirectResponse
    {
        SecurityLog::query()->whereKey($id)->delete();

        return back()->with('toast', [
            'type' => 'success',
            'message' => __('Log entry deleted.'),
        ]);
    }
}
