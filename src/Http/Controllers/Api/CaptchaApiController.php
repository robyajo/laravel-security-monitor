<?php

namespace Internal\SecurityMonitor\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Internal\SecurityMonitor\Services\CaptchaService;

class CaptchaApiController extends Controller
{
    public function __construct(protected CaptchaService $captcha) {}

    public function image(Request $request): Response
    {
        $svg = $this->captcha->generate();

        return response($svg, 200, [
            'Content-Type' => 'image/svg+xml; charset=utf-8',
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
            'Expires' => '0',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    public function verify(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'captcha' => ['required', 'string'],
            'form' => ['nullable', 'string'],
        ]);

        $valid = $this->captcha->verify($validated['captcha']);

        return response()->json([
            'success' => $valid,
            'valid' => $valid,
            'message' => $valid
                ? 'Captcha valid.'
                : 'Captcha tidak valid atau kedaluwarsa.',
        ]);
    }
}
