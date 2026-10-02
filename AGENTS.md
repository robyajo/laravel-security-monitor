# Agent Guidelines for `robyajo/laravel-security-monitor`

## 1. Project Overview & Foundational Context

This repository is **`robyajo/laravel-security-monitor`** (Bulwark), an enterprise-grade, standalone, headless self-hosted Web Application Firewall (WAF), threat detection engine, and security auditing library for the Laravel ecosystem.

- **Package Name**: `robyajo/laravel-security-monitor`
- **Root Namespace**: `Internal\SecurityMonitor\`
- **Target Environments**: PHP `^8.2 | ^8.3 | ^8.4`, Laravel `^10.0 | ^11.0 | ^12.0 | ^13.0`
- **Package Type**: `library` (Composer only)

### 1.1. Zero NPM / Pure PHP Principle (Spatie-Standard)

- **100% Pure PHP**: This package MUST NOT introduce any NPM, Node.js, or frontend build step dependency.
- **Spatie-Style Core Integration**: Like popular Spatie packages (`spatie/laravel-permission`, `spatie/laravel-activitylog`, `spatie/laravel-honeypot`), once installed via `composer require`, the package hooks directly and cleanly into Laravel Core:
    1. **Package Auto-Discovery**: `SecurityMonitorServiceProvider` & `SecurityMonitor` Facade.
    2. **Eloquent Model Trait**: `HasSecurityRelations` trait on the host `User` model (analogous to Spatie's `HasRoles`).
    3. **Core Auth Event Hooks**: Listens to native `\Illuminate\Auth\Events\Failed` and `Login` events automatically.
    4. **Core HTTP Kernel & Middleware**: Aliased as `'security.block'`, `'security.detect'`, `'security.admin'`, `'security.activity'`, with optional zero-touch auto-registration (`SECURITY_AUTO_REGISTER_MIDDLEWARE=true`).
    5. **Core Authorization Gate**: Registers `Gate::define('manage-security-monitor')`.
    6. **Core Artisan Commands**: 6 commands automatically available under `php artisan security:*`.
    7. **Core Task Scheduler**: Hooks daily log pruning and heartbeat directly into `Schedule`.
    8. **Core Validation Rules**: Implements `ValidationRule` (`SafeImageFile`, `SafeAssetPath`).
- **Universal Applicability**: Once installed, developers are free to apply it anywhere across their application: pure Blade views, headless APIs, Livewire, Filament/Nova admin panels, Inertia/React/Vue, or console microservices without restriction.

---

## 2. Comprehensive Documentation Suite (`documents/`)

The repository contains an authoritative, 24-chapter documentation suite located in `documents/`. Agents MUST consult these documents for architectural details, schema specs, API payload contracts, and integration recipes:

- **Master Table of Contents**: [`documents/README.md`](./documents/README.md)
- **Interactive Documentation Portal**: [`documents/index.html`](./documents/index.html) (Tailwind CSS Play CDN + marked.js + Mermaid.js single-page app with full-text search, dark/light theme, and copy-to-clipboard code snippets). Regenerate it from the markdown chapters after editing any `documents/**/*.md` file by running `php documents/generate.php`.
- **Modular Guides**:
    1. `documents/01-getting-started/`:
        - `01-introduction.md` — Philosophy, Spatie-standard core integration, headless architecture, ReDoS safety.
        - `02-installation.md` — Zero-NPM Composer setup, ServiceProvider registration, Artisan `security:install`, tag publishing, and migrations.
        - `03-configuration.md` — Complete breakdown of every key in `config/security.php` and 30+ `.env` variables.
    2. `documents/02-core-architecture/`:
        - `01-threat-detection-engine.md` — Inspection targets, instant vs auto-block, threat levels, ReDoS immunity rules.
        - `02-device-quarantine.md` — Shared IP/NAT mitigation, `X-Device-Id` and `X-Local-Ip` isolation, `block_scope`.
        - `03-reverse-proxy-resolution.md` — Real client IP resolution order (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`), spoof prevention.
        - `04-models-and-database.md` — Dynamic table names, `HasSecurityRelations` trait, full Eloquent models & scopes.
    3. `documents/03-security-modules/`:
        - `01-stepped-login-throttling.md` — Exponential penalty lockout tiers (1m to 24h), event listeners, manual unlock.
        - `03-server-security-and-webshells.md` — SHA-256 integrity baseline, webshell scanning, defensive deletion safeguards.
        - `04-access-log-streaming.md` — Generator-based streaming log parser (< 15MB RAM), CLI flags, daily cron.
        - `05-appeal-tickets-system.md` — Self-service unblock appeals, 30m cooldown rate-limit, admin approval automation.
        - `06-session-and-activity-tracking.md` — Active online users, throttled 45s activity heartbeat, session invalidation.
    4. `documents/04-rest-api-reference/`:
        - `01-api-overview.md` — JSON envelope format, HTTP status codes, Gate authorization hierarchy.
        - `02-public-endpoints.md` — Appeal submission/status endpoints.
        - `03-user-endpoints.md` — Trusted IP registration endpoint.
        - `04-admin-endpoints.md` — Full API contracts for logs, blocked IPs, server audit, user sessions, and tickets.
    5. `documents/05-cli-and-automation/`:
        - `01-artisan-commands.md` — Complete argument & option reference for all 6 CLI commands.
        - `02-scheduled-tasks.md` — Scheduled cron tasks (log pruning, heartbeat, daily access log scan).
    6. `documents/06-webserver-hardening/`:
        - `01-nginx-hardened-waf.md` — Dual rate-limit zones, Vite bypass, strict single-PHP execution, storage sandbox.
        - `02-apache-htaccess-hardening.md` — Apache & LiteSpeed hardening, webshell defense, double extension mitigation, dotfile & backup exposure lockdown.
        - `03-production-checklist.md` — Pre-flight checklist, permissions, emergency unblock runbook.
    7. `documents/07-integration-guides/`:
        - `01-frontend-react-inertia.md` — Axios interceptor for 403, Appeal modal.
        - `02-frontend-blade-livewire.md` — Customizing `errors/blocked.blade.php` and form protection.
        - `03-custom-rules-and-whitelist.md` — Custom regex signatures, CIDR subnets, URI exclusion paths.

---

## 3. Skills Activation

When working in this repository, you MUST activate the relevant skills located in `.agents/skills/`:

1. **`laravel-security-monitor`** (`.agents/skills/laravel-security-monitor/SKILL.md`):
    - **Activate whenever**: Writing, modifying, tuning, or testing WAF detection signatures, instant blocking rules, device-level quarantine, stepped login throttle, server security & webshell scanning, access log streaming, headless REST API controllers, Eloquent models, or Pest test cases.
2. **`pest-testing`** (`.agents/skills/pest-testing/SKILL.md`):
    - **Activate whenever**: Writing or running tests using Pest PHP and Orchestra Testbench.
3. **`laravel-best-practices`** (`.agents/skills/laravel-best-practices/SKILL.md`):
    - **Activate whenever**: Implementing general Laravel patterns, Eloquent relationships, validation rules, or Artisan commands.

---

## 4. Critical Architecture Rules & Constraints

### 4.1. Zero-Tolerance Threat Detection & ReDoS Safety

- **Zero-Tolerance Signatures**: Null-byte upload (`.php%00.jpg`), double extensions (`.php.jpg`), path traversal (`../../../public/`), sensitive probe (`.htaccess`, `.env`, `.git`), and SSTI canary (`{{7*7}}`) must trigger an instant block on the very first request without requiring repeated attempts.
- **Strict ReDoS Immunity**: Detection regular expressions must never contain unbounded nested quantifiers like `(a+)+` or `(.*[a-z])+`. Always ensure new regex patterns pass `Tests\Feature\DetectorTuningTest`.
- **False-Positive Prevention**: Detection patterns must not trigger on normal admin actions, valid filenames, standard search queries, or legitimate JSON payloads.

### 4.2. Decoupled Models and Database Tables

- **Never Hardcode User Model**: Always resolve the host application's user model dynamically:
    ```php
    $userModel = config('security.user_model', 'App\Models\User');
    ```
- **Dynamic Table Names**: Models must dynamically read table names from configuration:
    ```php
    public function getTable(): string
    {
        return config('security.table_names.blocked_ips', parent::getTable());
    }
    ```
- **Eloquent Host Integration**: Host apps integrate with the package using `Internal\SecurityMonitor\Concerns\HasSecurityRelations` on their `User` model.

### 4.3. Device-Level Quarantine & Reverse Proxy Support

- Support both `block_scope = 'ip'` (entire router/NAT) and `block_scope = 'device'` (specific `device_id` and `local_ip`).
- Client IP resolution must account for trusted reverse proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).

### 4.4. Server Security & Safe Sanitization

- `ServerSecurityService::deleteSuspiciousFile()` must strictly validate:
    1. No path traversal (`..` or null-bytes).
    2. The target file must reside strictly inside `base_path()`.
    3. Core vital system files (`public/index.php`, `.env`, `composer.json`, `bootstrap/app.php`) are strictly protected and can never be deleted through this feature.

---

## 5. Testing & Verification Standards

- **Test Suite**: Built using **Pest PHP** (`^2.0 | ^3.0 | ^4.0`) and **Orchestra Testbench** (`orchestra/testbench`).
- **Test Runner Command**:
    ```bash
    ./vendor/bin/pest
    ```
- **Running a Specific Test**:
    ```bash
    ./vendor/bin/pest --filter=InstantBlockTest
    ```
- **Test Harness**: All tests extend `Internal\SecurityMonitor\Tests\TestCase` which sets up an in-memory SQLite database (`:memory:`), auto-migrates package tables, and registers middleware.
- **Quality Invariant**: **All 64+ tests and 274+ assertions must pass with zero failures before any work is considered complete.**

---

## 6. Directory Structure & Conventions

```text
documents/                 # Authoritative 24-chapter documentation suite + index.html
src/
├── Concerns/              # Reusable Eloquent traits (HasSecurityRelations)
├── Console/Commands/      # Artisan commands (security:install, security:scan-logs, security:baseline, etc.)
├── Facades/               # Static facade accessors (SecurityMonitor)
├── Http/
│   ├── Controllers/Api/   # Headless JSON REST API controllers
│   ├── Controllers/Dashboard/ # Inertia + React dashboard controllers
│   └── Middleware/        # WAF & session tracking middleware
├── Listeners/             # Auth event listeners (LogFailedLoginAttempt, RecordUserLogin, ResetLoginAttempts)
├── Models/                # Eloquent models with dynamic table names
├── Rules/                 # Validation rules (SafeImageFile, SafeAssetPath)
├── Services/              # Core security engines & business logic
└── SecurityMonitorServiceProvider.php # Package bootstrapping & registration

config/
└── security.php           # Full signature definitions & default options

database/migrations/       # Consolidated package migrations

routes/
├── security.php           # Headless REST API routes
├── security-dashboard.php # Optional Livewire Starter Kit dashboard routes (auth + security.admin)
└── security-dashboard-react.php # Optional Inertia + React dashboard routes (auth + security.admin)

stubs/
├── nginx.conf.stub        # Hardened Nginx WAF configuration template
├── htaccess.stub          # Hardened Apache .htaccess template
├── blocked.blade.php      # Default 403 "blocked" page
├── env.stub               # Documented SECURITY_* environment block
├── livewire/pages/security/ # Livewire Starter Kit monitoring dashboard (tag: starterkit-livewire)
└── react/                 # React Starter Kit monitoring dashboard (tag: starterkit-react)
```

---

## 7. Coding Style

- Use explicit return type declarations and parameter type hints on all methods and functions.
- Use PHP 8 constructor property promotion:
    ```php
    public function __construct(
        protected SecurityMonitorService $security,
    ) {}
    ```
- Prefer PHPDoc blocks with array shape type definitions for complex array structures.
- Always use curly braces for all control structures.
