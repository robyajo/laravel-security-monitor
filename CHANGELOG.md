# Changelog

All notable changes to `robyajo/laravel-security-monitor` will be documented in this file.

## [1.0.12] - 2026-10-02

### Fixed

- **PHP 8.2 / 8.3 compatibility (critical)**: `UserLoginService` chained a
  method call directly off a `new` expression
  (`new $model()->newQuery()`). That syntax only parses from PHP 8.4, so on
  PHP 8.2/8.3 it raised a `ParseError` that failed every PHP 8.2/8.3 test-matrix
  job as well as the Pint job. It now uses `$model::query()`, which parses and
  formats identically on every supported PHP version.
- PHPStan: the `view()->exists('errors.blocked')` suppression now matches both
  the `true` and `false` evaluation, since the result depends on whether the
  host application has published the view.

## [1.0.11] - 2026-10-02

### Fixed

- CI: `laravel/pint` and `larastan/larastan` are no longer `require-dev`
  dependencies. Pint requires PHP 8.3 and Larastan 3 requires Laravel 11+, which
  broke the PHP 8.2 / Laravel 10 matrix jobs. Both tools are now installed only
  in their dedicated CI jobs; run `composer dev:tools` locally to use them.
- PHPStan: replaced the environment-dependent `view()->exists()` ignore with an
  identifier-scoped ignore for `src/Http/Middleware/BlockIpAddress.php`.

## [1.0.10] - 2026-10-02

### Changed

- The application audit now reads `PUBLIC_API_KEY` and `TRUSTED_PROXIES` via
  `config('security.server_scan.*')` instead of calling `env()`
  inside a service, and the weak-key placeholder list no longer references an
  app-specific value.

### Fixed

- PHPStan: added `tests/*`-scoped ignores for Pest's magic `$this` /
  `TestCall` so IDE analysis of the test suite stays quiet, plus
  `reportUnmatchedIgnoredErrors: false`.

## [1.0.9] - 2026-10-02

### Added

- Static analysis setup: Larastan + PHPStan (`phpstan.neon.dist`,
  `phpstan-baseline.neon`), a `composer analyse` script, and a dedicated
  "Static Analysis" CI job.
- Regression tests covering the CAPTCHA endpoint, login recording, session
  logout, trusted IP storage, admin auto-unblock, and server scan with admins.

### Fixed

- `pushMiddleware()` was called on the `Illuminate\Contracts\Http\Kernel`
  interface; middleware auto-registration now narrows to the concrete
  Foundation kernel before calling it.
- `CaptchaApiController` called the protected `CaptchaService::render()`; the
  public `/captcha` endpoint now uses `generate()` and verifies with the correct
  signature.
- Several listeners and services referenced a non-existent `User` class
  (`RecordUserLogin`, `ResetLoginAttempts`, `UserLoginService::trustIp()`,
  `UserLoginService::getRealtimeActiveUsers()`, and
  `ServerSecurityService::accountChecks()`), which silently disabled login
  recording, admin auto-unblock, and the 2FA server audit. All now resolve the
  configured user model dynamically.
- Added the missing `UserLoginService::logoutSession()` method used by the
  admin session endpoint.
- Corrected model relationship PHPDoc that referenced a non-existent
  `User` class, and used `getAuthIdentifier()` where the authenticated user
  contract is in play.

## [1.0.8] - 2026-10-02

### Added

- Publishable default 403 page `resources/views/errors/blocked.blade.php`
  (`vendor:publish --tag=security-views`), including a self-contained appeal
  form wired to the public unblock-ticket endpoint. Integrated into
  `security:install` with a new `--without-views` option.
- Laravel Pint configuration (`pint.json`), `composer format` / `composer lint`
  scripts, and a dedicated "Code Style" CI job.

### Changed

- Applied Laravel Pint code style across the source and test suites.

## [1.0.7] - 2026-10-02

### Added

- Presentation deck for the package under `paparan/`
  (`Laravel-Security-Monitor-Bulwark.pptx`, 20 slides) with a reproducible
  generator (`paparan/generate.php`). Excluded from the Composer distribution.

## [1.0.4] - 2026-10-02

### Changed

- Exclude development-only assets (`.agents/`, `AGENTS.md`, `DOCS/`, `.github/`,
  `push.sh`) from the Composer distribution archive via `.gitattributes`
  `export-ignore` rules and the `archive.exclude` Composer setting, so
  `composer require` installs only the runtime package.

## [1.0.0] - 2026-10-01

### Added

- **Self-Hosted WAF & Threat Engine**:
    - Zero-tolerance instant block signatures (null byte, double extensions, path traversal, webshell probes, SSTI canary, polyglot uploads).
    - Multi-tier progressive threat scoring and auto-blocking with sliding time windows.
    - ReDoS-hardened regex patterns tuned against real-world incidents.
    - Reverse proxy support (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).
- **Device-Level Quarantine & Scope**:
    - Granular blocking via `device_id` and `local_ip` (WebRTC / device fingerprint) to avoid punishing innocent users on shared NAT/router public IPs.
    - Block scopes: `ip` (entire router) vs `device` (specific client device).
- **Public Appeal & Ticket Submissions**:
    - Public headless REST API for unblock appeal ticket submission and verification.
    - Admin approval/rejection endpoints with automatic IP/device quarantine release.
- **Multi-Tier Stepped Login Protection**:
    - Stepped progressive lockouts (1m -> 5m -> 15m -> 1h -> 24h) preventing brute force and credential stuffing attacks.
    - Automatic failed login security event logging.
- **Zero-Dependency SVG CAPTCHA**:
    - Pure SVG vector-matrix challenge generator without GD or Imagick PHP extension requirements.
    - Cryptographically secure one-time stateless session tokens.
- **Server Integrity & Security Scanner**:
    - SHA-256 baseline creation and change verification.
    - Suspicious file & webshell scanner with safe admin deletion capabilities (traversal protected, vital files protected).
    - Server configuration audit (PHP version, debug mode, HTTPS cookies, Fortify 2FA).
- **Apache / Nginx Access Log Scanner**:
    - Streaming log parser to detect web attacks rejected before reaching Laravel.
    - Auto-import and zero-tolerance IP blocking from raw server logs.
- **Headless REST API Architecture**:
    - 100% decoupled from any specific frontend (React/Inertia/Blade/Livewire/Mobile).
    - Pure JSON endpoints for logs, blocked IPs, server scans, sessions, appeals, and captcha.
- **Enterprise Extensibility**:
    - Configurable user model (`config('security.user_model')`).
    - Configurable table names (`config('security.table_names.*')`).
    - `HasSecurityRelations` model trait for seamless user relationship bindings.
    - Laravel 10, 11, 12, and 13 compatibility.
