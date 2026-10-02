# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Non-blocking asynchronous RPC caller (`_rpc_call_async`) offloading synchronous RPC pool calls to thread worker pool.
- Strict on-chain verification in `/api/rent/confirm` checking transaction `accountKeys` and authenticating `CloseAccount` instructions against owner wallet.
- `TRUST_PROXY_HEADERS` configuration guard for reverse proxy IP extraction to prevent spoofed `X-Forwarded-For` rate limit bypass.
- Constant-time secret comparison via `hmac.compare_digest` for `/api/stats` endpoint.
- HTML sanitization helper `escapeHtml` in client UI preventing XSS in dynamically rendered DOM attributes.
- GitHub Actions CI workflow testing on Python 3.12 and 3.13 with `pyflakes`, `pytest`, and `pip-audit`.
- Pinned dependency lockfile (`requirements.txt`) compiled from top-level `requirements.in`.
- Deterministic test harness with `tests/conftest.py` price cache reset and isolated mock pricing.
- Standardized open-source repository templates: Issue forms, PR template, Dependabot configuration, Contributing guidelines, and Security policy.

### Changed
- Refactored and deduplicated transaction compilation logic between synchronous and asynchronous wrappers into unified `_compile_tx_payload`.
- Stripped UTF-8 BOM from `.gitignore` and source files.
- Removed unused imports across entire project codebase.
