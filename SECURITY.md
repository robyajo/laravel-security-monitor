# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

`robyajo/laravel-security-monitor` (Bulwark) is a security tool, so every report
is taken seriously.

**Please do not open a public issue for security vulnerabilities.**

Report privately through one of these channels instead:

- **GitHub Private Vulnerability Reporting** — open the repository's
  **Security** tab and click **Report a vulnerability**.
- **Email** — `robyfull.dev@gmail.com`

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof of concept, payload, or raw request).
- The affected package version(s) and your PHP/Laravel versions.
- Any suggested remediation, if known.

## What to Expect

- **Acknowledgement** within 72 hours.
- **Assessment and severity triage** within 7 days.
- **Credit** in the release notes once a fix is published, unless you prefer to
  remain anonymous.

## Scope

In scope:

- Bypass of the WAF detection engine (false negatives on known attack vectors).
- ReDoS (catastrophic backtracking) in a detection signature.
- Authentication or authorization weaknesses in the REST API endpoints.
- Path traversal or arbitrary file deletion in the server security sanitizer.

Out of scope:

- Issues that require an already-compromised host or physical access.
- Missing hardening on the consumer application that the package does not control.
