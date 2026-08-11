# Changelog

All notable changes to SecureVault are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Full open-source repository packaging: CI/CD, branding, documentation, and contribution tooling.

## [1.0.0] - 2026-08-01

### Added
- **Core cryptography**
  - AES-256-GCM (OS-backed) and XChaCha20-Poly1305 (libsodium) AEAD engines, selectable per vault.
  - Argon2id key derivation (RFC 9106) with configurable memory/time cost.
  - Envelope key hierarchy: random DEK wrapped by a password-derived master key.
  - Purpose-bound associated data to prevent key-reuse across item/domain contexts.
  - CSPRNG-based `CryptoRandom` and zeroizing `SecureBytes` buffers.
- **Hardware trust**
  - TPM-backed keys via CNG *Microsoft Platform Crypto Provider* with automatic DPAPI fallback.
  - FIDO2 / WebAuthn passkeys through Windows Hello (Microsoft Passport KSP).
  - Biometric / TPM one-tap unlock.
- **Storage & integrity**
  - SQLite vault containing only ciphertext, with per-row HMAC-SHA256 integrity.
  - Header integrity MAC and tamper detection (`TamperDetectedException`).
  - Hash-chained, append-only audit log with verification.
  - Automatic version history for items (50 snapshots) with rollback.
  - Soft delete / restore / purge.
- **Item types**
  - Logins (with OTP-secret support), secure notes, encrypted files, SSH keys, API tokens, passkeys.
  - Search, favorites, type filters, AI-suggested tags (local only).
- **Security & health**
  - HaveIBeenPwned k-anonymity breach checking (5-hex-char prefix only).
  - Heuristic phishing / brand-lookalike URL detection.
  - Local AI-assisted weak-password and password-composition analysis.
  - Password & Diceware passphrase generator with entropy estimates.
- **Backup & sync**
  - Passphrase-sealed, tamper-evident encrypted backups (`*.svault`).
  - End-to-end encrypted sync over folder or WebDAV providers; DEK never leaves the device.
- **Application**
  - Minimalist dark WPF UI with dashboard, item editor, generator, security panel, settings.
  - Auto-lock timer, clipboard guard (auto-clear), per-app data isolation.
  - ASLR/DEP/PerMonitorV2 DPI manifest hardening.

### Security
- Initial threat model and security policy; see `docs/security.md` and `SECURITY.md`.

## [0.1.0] - 2026-07-15

### Added
- Project scaffolding: solution layout, core library, WPF shell, xUnit test project.
- Initial AES-GCM engine and vault create/unlock flow (internal preview).

---

The format and parts of the wording are inspired by
[Keep a Changelog](https://keepachangelog.com/); versioning follows
[Semantic Versioning](https://semver.org/).
