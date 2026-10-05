<?php

namespace Internal\SecurityMonitor\Http\Controllers\Dashboard;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Inertia\Inertia;
use Inertia\Response;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

class SettingController extends Controller
{
    public function __construct(
        protected SecurityMonitorService $securityService,
    ) {}

    /**
     * Render the settings page on Inertia + React dashboard.
     */
    public function index(): Response
    {
        return Inertia::render('security/settings', [
            'settings' => $this->securityService->getSettings(),
        ]);
    }

    /**
     * Update settings from the dashboard form.
     */
    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'auto_block_scope' => ['nullable', 'string', 'in:device,ip'],
            'instant_block_scope' => ['nullable', 'string', 'in:device,ip'],
            'auto_block_enabled' => ['nullable', 'boolean'],
            'auto_block_threshold' => ['nullable', 'integer', 'min:1', 'max:100'],
            'auto_block_window' => ['nullable', 'integer', 'min:1', 'max:1440'],
            'auto_block_duration' => ['nullable', 'integer', 'min:0', 'max:8760'],
            'instant_block_enabled' => ['nullable', 'boolean'],
            'instant_block_duration' => ['nullable', 'integer', 'min:0', 'max:8760'],
            'block_enforcement' => ['nullable', 'boolean'],
        ]);

        $this->securityService->updateSettings($validated);

        return back()->with('security_message', 'Pengaturan keamanan berhasil diperbarui.');
    }
}
