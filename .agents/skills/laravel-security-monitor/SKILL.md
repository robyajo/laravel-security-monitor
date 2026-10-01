---
name: laravel-security-monitor
description: "Comprehensive development, maintenance, and integration guide for the robyajo/laravel-security-monitor package. Activate this skill whenever writing, modifying, or testing WAF detection signatures, instant blocking rules, device-level quarantine, stepped login throttle, zero-dependency SVG captcha, server security & webshell scanning, access log streaming, headless REST API controllers, Eloquent models, or Pest test cases. Covers package architecture, ReDoS prevention, Orchestra Testbench harnesses, and host app integration rules."
license: MIT
metadata:
  author: robyajo
---

# Laravel Security Monitor Development & Integration Guide

`robyajo/laravel-security-monitor` (Bulwark) is an enterprise-grade, headless self-hosted Web Application Firewall (WAF), threat detection engine, and security auditing toolkit for Laravel applications.

> **Authoritative Documentation**: Complete 24-chapter guides and an interactive offline portal are located in [`documents/`](../../documents/) and [`documents/index.html`](../../documents/index.html).

---

## 1. Core Architecture Principles

1. **Zero NPM / Standar Spatie (100% Pure PHP)**:
   - The package has **NO NPM, NO Node.js, and NO frontend build step dependencies**.
   - Like standard Spatie packages (`spatie/laravel-permission`), once installed via `composer require`, it hooks directly into Laravel Core and can be used anywhere across any frontend stack (Blade, Livewire, Filament, Inertia, or headless API).
   - Core hooks utilized:
     - **Package Auto-Discovery**: `SecurityMonitorServiceProvider` + `SecurityMonitor` Facade.
     - **Core Eloquent Model Trait**: `HasSecurityRelations` on host `User` model (similar to Spatie's `HasRoles`).
     - **Core Auth Events**: Automatically listens to `\Illuminate\Auth\Events\Failed` and `Login`.
     - **Core HTTP Middleware**: Aliased as `'security.block'`, `'security.detect'`, `'security.admin'`, `'security.activity'`.
     - **Core Gate**: `Gate::define('manage-security-monitor')`.
     - **Core Artisan Commands**: 6 commands under `php artisan security:*`.
     - **Core Scheduler**: Auto-registered prune & heartbeat tasks.
     - **Validation Rules**: `SafeImageFile`, `SafeAssetPath`, `ValidCaptcha`.
     - **Zero-Dep SVG Captcha**: Generated via pure PHP vector math (no GD, no Imagick, no client JS).

2. **Headless Only (Pure REST API)**:
   - The package never renders or assumes a frontend stack (no Inertia, React, Blade, or Livewire coupling).
   - All management features are exposed as structured JSON REST API endpoints under `/api/security/*`.
   - Host applications can build custom dashboards in Blade, React, Vue, Livewire, or mobile apps.

3. **Loose Coupling & Decoupled Models**:
   - Never hardcode `App\Models\User` or standard table names.
   - User model resolution is always retrieved via `config('security.user_model', 'App\Models\User')`.
   - All database tables are dynamically configured via `config('security.table_names.*')`.
   - The `HasSecurityRelations` trait (`Internal\SecurityMonitor\Concerns\HasSecurityRelations`) is added to the host application's User model to provide Eloquent relations (`logins()`, `trustedIps()`, `securityLogs()`, `blockedIps()`, `resolvedTickets()`).

4. **ReDoS Immunity**:
   - Detection signatures must never use unbounded nested quantifiers (e.g., `(a+)+` or `(.*[a-z])+`).
   - Every regex pattern must pass `DetectorTuningTest` and execute in sub-millisecond time even against adversarial 100KB+ payloads.

5. **Multi-Tenant / Shared Router Awareness**:
   - Public IPs often belong to corporate routers or shared Wi-Fi.
   - The quarantine engine supports `block_scope = 'device'` using client `device_id` (WebRTC fingerprint) and `local_ip` to isolate rogue devices without affecting innocent users on the same router.

---

## 2. Threat Detection & Zero-Tolerance Engine

### Instant Block vs. Progressive Threshold
- **Zero-Tolerance Signatures** (`config('security.instant_block.signatures')`):
  - Null-byte upload: `\.php%00\.jpg`, `\.php\0\.png`.
  - Double extensions: `\.php\.(?:jpe?g|png|gif|webp|svg)`.
  - Path traversal: `(?:\.\.[\/\\])+`, `\.\.%2f`, `\.\.%5c`.
  - Probes for sensitive files: `\.htaccess`, `\.env`, `\.git/config`.
  - SSTI canary probes: `\{\{7\*7\}\}`, `\$\{7\*7\}`.
  - *Action*: Triggered on the **very first attempt** without waiting for threshold, immediately writing to `blocked_ips` (default: 720 hours / 30 days) and returning HTTP 403.
- **Progressive Threat Threshold** (`config('security.auto_block.*')`):
  - Suspicious queries (SQLi patterns, XSS probes, scanner UAs) increment threat scores in a sliding window (default: 3 occurrences in 10 minutes).
  - Reaching threshold escalates to automatic quarantine with configurable duration (default: 24 hours).

### Validation Rules
- `SafeImageFile`:
  - Inspects file binary headers and contents.
  - Rejects polyglot JPEGs/PNGs containing embedded `<?php` or `<?=`.
  - Rejects SVG files containing `<script>`, `javascript:`, or event handlers (`onload`, `onerror`).
- `SafeAssetPath`:
  - Enforces safe asset and icon paths.
  - Rejects relative path traversals (`../../../`), backslashes (`..\..\`), and shell extensions.
- `ValidCaptcha`:
  - Validates zero-dependency SVG captcha token and challenge phrase.

---

## 3. Server Security & Integrity Scanner

### Integrity Baseline (`ServerSecurityService`)
- Monitored files (`config('security.server_scan.integrity_paths')`): `app/`, `config/`, `routes/`, `public/index.php`, `bootstrap/app.php`.
- SHA-256 hash map stored in `storage/app/security-baseline.json`.
- `integrityReport()` returns modified, missing, and newly added files.

### Suspicious File & Webshell Detection
- Scans `public/` and `storage/app/public/` for executable extensions (`.php`, `.phtml`, `.php5`, `.phar`).
- Matches known webshell signatures (e.g., `b374k`, `c99`, `r57`, `wso`, `eval(base64_decode(`).
- `deleteSuspiciousFile($relativePath, $userId)`:
  - Enforces path containment within `base_path()`.
  - Prohibits path traversal (`..`).
  - Protects vital system files (`public/index.php`, `.env`, `composer.json`, `bootstrap/app.php`).
  - Logs deletion audit records to `security_logs`.

---

## 4. Headless REST API Endpoints

All endpoints use prefix `/api/security` (configurable in `config/security.php`):

### Public
- `GET /api/security/captcha`: SVG captcha challenge.
- `POST /api/security/captcha/verify`: Stateless captcha verification.
- `POST /api/security/unblock-tickets/submit`: Appeal ticket submission (30m cooldown).
- `GET /api/security/unblock-tickets/check/{ticketNumber}`: Appeal status lookup.

### Authenticated User
- `POST /api/security/trusted-ips/save-my-ip`: Save current IP as trusted.

### Admin Protected (`auth` + `security.admin`)
- **Logs**: `GET /logs`, `DELETE /logs/clear`, `DELETE /logs/{id}`.
- **Blocked IPs**: `GET /blocked-ips`, `POST /blocked-ips`, `GET /blocked-ips/{id}`, `PATCH /blocked-ips/{id}/toggle`, `DELETE /blocked-ips/{id}`.
- **Server Audit**: `GET /server`, `POST /server/baseline`, `DELETE /server/baseline`, `DELETE /server/suspicious-files`, `DELETE /lockouts/{id}`.
- **Sessions**: `GET /user-sessions`, `GET /user-sessions/realtime`, `DELETE /user-sessions/session/{id}`, `DELETE /trusted-ips/{id}`.
- **Appeals**: `GET /unblock-tickets`, `POST /unblock-tickets/{id}/respond`, `DELETE /unblock-tickets/{id}`.

### Web Server Hardening & Publishing
- `php artisan vendor:publish --tag=security-nginx`: Publishes `nginx.conf` template with dual-zone rate limiting, strict single-PHP execution (`/index.php` only), storage sandboxing (nosniff + CSP sandbox), and double-extension blocking.
- `php artisan vendor:publish --tag=security-htaccess`: Publishes `public/.htaccess` template with Apache hardening (dotfile protection, double extension blocking, dump/log protection, directory indexing disabled).
- `php artisan vendor:publish --tag=security-all`: Publishes config, migrations, `nginx.conf`, and `public/.htaccess` in a single command.
- `php artisan security:install`: Interactive one-stop command that publishes assets and auto-appends hardening rules to `public/.htaccess` with automatic backup.

---

## 5. Artisan CLI Commands

| Command | Purpose |
| :--- | :--- |
| `security:install` | Publish all package assets: config, migrations, and hardened `nginx.conf` with interactive options. |
| `security:scan-logs` | Stream & parse Apache/Nginx access logs for zero-tolerance attacks; auto-block offending IPs. |
| `security:baseline` | Audit, create (`--create`), or destroy (`--prune`) SHA-256 integrity baseline. |
| `security:unblock-ip {ip}` | Lift block on IP or device immediately (emergency escape hatch). |
| `security:prune-logs {--days=}` | Remove logs older than retention period (default: 90 days). |
| `security:purge-injected-data {--force}` | Scan & clean residual pentest payloads from application database tables. |

---

## 6. Testing Conventions (Pest & Orchestra Testbench)

- **Test Runner**: `./vendor/bin/pest`
- **Harness**: `Internal\SecurityMonitor\Tests\TestCase` extends `Orchestra\Testbench\TestCase`.
- **In-Memory SQLite**: Runs migrations automatically in `:memory:` via `defineDatabaseMigrations()`.
- **Simulating Attackers**:
  ```php
  $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.77'])->get('/?q=%7B%7B7*7%7D%7D')->assertForbidden();
  ```
- **Simulating Devices**:
  ```php
  $this->withHeaders([
      'X-Device-Id' => 'dev-uuid-001',
      'X-Local-Ip' => '192.168.1.15',
  ])->get('/');
  ```
- **Assertions**:
  - Always use `assertSuccessful()`, `assertForbidden()`, `assertNotFound()`.
  - Verify database state using `expect(BlockedIp::query()->...)->not->toBeNull()`.
- **Target Invariant**: All 64+ tests and 274+ assertions must pass with zero failures.
