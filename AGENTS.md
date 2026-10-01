# Agent Guidelines for `robyajo/laravel-security-monitor`

## 1. Project Overview & Foundational Context

This repository is **`robyajo/laravel-security-monitor`** (Bulwark), a standalone, headless self-hosted Web Application Firewall (WAF), threat detection engine, and security auditing library for the Laravel ecosystem.

- **Package Name**: `robyajo/laravel-security-monitor`
- **Root Namespace**: `Internal\SecurityMonitor\`
- **Target Environments**: PHP `^8.2 | ^8.3 | ^8.4`, Laravel `^10.0 | ^11.0 | ^12.0 | ^13.0`
- **Core Architecture**: **Headless Only (Pure REST API)**. This package MUST NOT introduce frontend coupling (no Inertia, React, Vue, Blade views, or Tailwind dependencies). All functionality is exposed via JSON REST API endpoints under `/api/security/*` and Artisan CLI commands.

---

## 2. Skills Activation

When working in this repository, you MUST activate the relevant skills located in `.agents/skills/` (or `.agents/skill/`):

1. **`laravel-security-monitor`** (`.agents/skills/laravel-security-monitor/SKILL.md`):
   - **Activate whenever**: Writing, modifying, tuning, or testing WAF detection signatures, instant blocking rules, device-level quarantine, stepped login throttle, SVG captcha, server security & webshell scanning, access log streaming, headless REST API controllers, Eloquent models, or Pest test cases.
2. **`pest-testing`** (`.agents/skills/pest-testing/SKILL.md`):
   - **Activate whenever**: Writing or running tests using Pest PHP and Orchestra Testbench.
3. **`laravel-best-practices`** (`.agents/skills/laravel-best-practices/SKILL.md`):
   - **Activate whenever**: Implementing general Laravel patterns, Eloquent relationships, validation rules, or Artisan commands.

---

## 3. Critical Architecture Rules & Constraints

### 3.1. Zero-Tolerance Threat Detection & ReDoS Safety
- **Zero-Tolerance Signatures**: Null-byte upload (`.php%00.jpg`), double extensions (`.php.jpg`), path traversal (`../../../public/`), sensitive probe (`.htaccess`, `.env`, `.git`), and SSTI canary (`{{7*7}}`) must trigger an instant block on the very first request without requiring repeated attempts.
- **Strict ReDoS Immunity**: Detection regular expressions must never contain unbounded nested quantifiers like `(a+)+` or `(.*[a-z])+`. Always ensure new regex patterns pass `Tests\Feature\DetectorTuningTest`.
- **False-Positive Prevention**: Detection patterns must not trigger on normal admin actions, valid filenames, standard search queries, or legitimate JSON payloads.

### 3.2. Decoupled Models and Database Tables
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

### 3.3. Device-Level Quarantine & Reverse Proxy Support
- Support both `block_scope = 'ip'` (entire router/NAT) and `block_scope = 'device'` (specific `device_id` and `local_ip`).
- Client IP resolution must account for trusted reverse proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`).

### 3.4. Server Security & Safe Sanitization
- `ServerSecurityService::deleteSuspiciousFile()` must strictly validate:
  1. No path traversal (`..` or null-bytes).
  2. The target file must reside strictly inside `base_path()`.
  3. Core vital system files (`public/index.php`, `.env`, `composer.json`, `bootstrap/app.php`) are strictly protected and can never be deleted through this feature.

---

## 4. Testing & Verification Standards

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
- **Quality Invariant**: **All 62+ tests and 260+ assertions must pass with zero failures before any work is considered complete.**

---

## 5. Directory Structure & Conventions

```text
src/
├── Concerns/                # Reusable Eloquent traits (HasSecurityRelations)
├── Console/Commands/        # Artisan commands (security:install, security:scan-logs, security:baseline, etc.)
├── Facades/                 # Static facade accessors (SecurityMonitor)
├── Http/
│   ├── Controllers/Api/     # Headless JSON REST API controllers
│   └── Middleware/          # WAF & session tracking middleware
├── Listeners/               # Auth event listeners (LogFailedLoginAttempt, RecordUserLogin)
├── Models/                  # Eloquent models with dynamic table names
├── Rules/                   # Validation rules (SafeImageFile, SafeAssetPath, ValidCaptcha)
├── Services/                # Core security engines & business logic
└── SecurityMonitorServiceProvider.php # Package bootstrapping & registration

config/
└── security.php             # Full signature definitions & default options

database/migrations/         # Consolidated package migrations

routes/
└── security.php             # Headless REST API routes

stubs/
└── nginx.conf.stub          # Hardened Nginx WAF configuration template
```

---

## 6. Coding Style

- Use explicit return type declarations and parameter type hints on all methods and functions.
- Use PHP 8 constructor property promotion:
  ```php
  public function __construct(
      protected SecurityMonitorService $security,
  ) {}
  ```
- Prefer PHPDoc blocks with array shape type definitions for complex array structures.
- Always use curly braces for all control structures.
