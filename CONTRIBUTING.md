# Contributing

Thanks for considering a contribution to `robyajo/laravel-security-monitor`
(Bulwark). This guide explains how to set up the project and submit changes.

## Requirements

- PHP `^8.2`
- Composer 2
- No NPM, Node.js, or frontend build step is allowed. This package is **100%
  pure PHP** and follows the Spatie package conventions.

## Getting Started

```bash
git clone https://github.com/robyajo/laravel-security-monitor.git
cd laravel-security-monitor
composer install
```

## Running the Test Suite

```bash
./vendor/bin/pest
```

The suite runs on an in-memory SQLite database via Orchestra Testbench. All
tests and assertions must pass before a pull request is considered ready.

To run a single test file:

```bash
./vendor/bin/pest tests/Feature/DetectorTuningTest.php
```

## Coding Standards

- Follow PSR-12 and the existing code style in `src/`.
- Use explicit return types and parameter type hints on every method.
- Prefer PHP 8 constructor property promotion.
- Always use curly braces for control structures.
- Keep detection signatures free of nested quantifiers such as `(a+)+` or
  `(.*[a-z])+` — every new regex must pass `DetectorTuningTest`.

## Security-Sensitive Changes

Because this is a security package, please double-check that your change does
not introduce false positives for legitimate traffic, and does not weaken the
safeguards in `ServerSecurityService::deleteSuspiciousFile()`.

Never report a vulnerability through a public issue or pull request. See
[SECURITY.md](SECURITY.md) for the private disclosure process.

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Make your change, including tests and documentation updates.
3. Run `./vendor/bin/pest` and `composer validate --strict`.
4. Open a pull request and fill in the pull request template.

Please keep pull requests focused on a single concern; unrelated refactors make
review harder.
