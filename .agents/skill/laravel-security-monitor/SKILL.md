---
name: laravel-security-monitor
description: "Comprehensive development, maintenance, and integration guide for the robyajo/laravel-security-monitor package. Activate this skill whenever writing, modifying, or testing WAF detection signatures, instant blocking rules, device-level quarantine, stepped login throttle, zero-dependency SVG captcha, server security & webshell scanning, access log streaming, headless REST API controllers, Eloquent models, or Pest test cases. Covers package architecture, ReDoS prevention, Orchestra Testbench harnesses, and host app integration rules."
license: MIT
metadata:
  author: robyajo
---

# Laravel Security Monitor Development & Integration Guide

`robyajo/laravel-security-monitor` (Bulwark) is an enterprise-grade, headless self-hosted Web Application Firewall (WAF), threat detection engine, and security auditing toolkit for Laravel applications.

---

## 1. Core Architecture Principles

1. **Headless Only (Pure REST API)**:
   - The package never renders or assumes a frontend stack (no Inertia, React, Blade, or Livewire coupling).
   - All management features are exposed as structured JSON REST API endpoints under `/api/security/*`.
   - Host applications can build custom dashboards in Blade, React, Vue, Livewire, or mobile apps.

2. **Loose Coupling & Decoupled Models**:
   - Never hardcode `App\Models\User` or standard table names.
   - User model resolution is always retrieved via `config('security.user_model', 'App\Models\User')`.
   - All database tables are dynamically configured via `config('security.table_names.*')`.
   - The `HasSecurityRelations` trait (`Internal\SecurityMonitor\Concerns\HasSecurityRelations`) is added to the host application's User model to provide Eloquent relations (`logins()`, `trustedIps()`, `securityLogs()`, `blockedIps()`, `resolvedTickets()`).

3. **ReDoS Immunity**:
   - Detection signatures must never use unbounded nested quantifiers (e.g., `(a+)+` or `(.*[a-z])+`).
   - Every regex pattern must pass `DetectorTuningTest` and execute in sub-millisecond time even against adversarial 100KB+ payloads.

4. **Multi-Tenant / Shared Router Awareness**:
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
  - *Action*: Triggered on the **very first attempt** without waiting for threshold, immediately writing to `blocked_ips` and returning HTTP 403.
- **Progressive Threat Threshold** (`config('security.auto_block.*')`):
  - Suspicious queries (SQLi patterns, XSS probes, scanner UAs) increment threat scores in a sliding window (default: 3 occurrences in 10 minutes).
  - Reaching threshold escalates to automatic quarantine with configurable duration (default: 720 hours / 30 days).

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
- `POST /api/security/unblock-tickets/submit`: Appeal ticket submission.
- `GET /api/security/unblock-tickets/check/{ticketNumber}`: Appeal status lookup.

### Authenticated User
- `POST /api/security/trusted-ips/save-my-ip`: Save current IP as trusted.

### Admin Protected (`auth` + `security.admin`)
- **Logs**: `GET /logs`, `DELETE /logs/clear`, `DELETE /logs/{id}`.
- **Blocked IPs**: `GET /blocked-ips`, `POST /blocked-ips`, `GET /blocked-ips/{id}`, `PATCH /blocked-ips/{id}/toggle`, `DELETE /blocked-ips/{id}`.
- **Server Audit**: `GET /server`, `POST /server/baseline`, `DELETE /server/baseline`, `DELETE /server/suspicious-files`, `DELETE /lockouts/{id}`.
- **Sessions**: `GET /user-sessions`, `GET /user-sessions/realtime`, `DELETE /user-sessions/session/{id}`, `DELETE /trusted-ips/{id}`.
- **Appeals**: `GET /unblock-tickets`, `POST /unblock-tickets/{id}/respond`, `DELETE /unblock-tickets/{id}`.

---

## 5. Artisan CLI Commands

| Command | Purpose |
| :--- | :--- |
| `security:scan-logs` | Stream & parse Apache/Nginx access logs for zero-tolerance attacks; auto-block offending IPs. |
| `security:baseline` | Audit, create (`--create`), or destroy (`--destroy`) SHA-256 integrity baseline. |
| `security:unblock-ip {ip}` | Lift block on IP or device immediately. |
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
