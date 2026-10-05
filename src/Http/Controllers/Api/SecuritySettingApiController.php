<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Internal\SecurityMonitor\Services\SecurityMonitorService;

class SecuritySettingApiController extends Controller
{
    public function __construct(
        protected SecurityMonitorService $securityService,
    ) {}

    /**
     * Get current security monitor settings.
     */
    public function index(): JsonResponse
    {
        return response()->json([
            'success' => true,
            'settings' => $this->securityService->getSettings(),
        ]);
    }

    /**
     * Update security monitor settings.
     */
    public function update(Request $request): JsonResponse
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

        $updated = $this->securityService->updateSettings($validated);

        return response()->json([
            'success' => true,
            'message' => 'Pengaturan keamanan berhasil diperbarui.',
            'settings' => $updated,
        ]);
    }
}
