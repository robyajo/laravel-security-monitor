# Changelog

All notable changes to `robyajo/laravel-security-monitor` will be documented in this file.

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
