# Roadmap

This is the living roadmap for SecureVault. Priorities shift with user feedback and
security research; milestone dates are indicative, not commitments.

Legend: `[ ]` planned · `[~]` in progress · `[x]` done

## v1.1 — Quality & platform hardening

- [ ] Import/export: CSV, `pass`, and Bitwarden vault import.
- [ ] Browser-style autofill prototype (Windows-only helper).
- [ ] Single-file publisher for MSI/Portable packaging.
- [ ] Localization foundation (resx) + first languages.
- [ ] Crash reporting with opt-in, privacy-preserving diagnostics.
- [ ] More integration tests + property-based tests for crypto round-trips.

## v1.2 — Sync & collaboration

- [~] Conflict-free multi-device sync refinements (per-item resolution).
- [ ] Shared read-only items via signed share tokens.
- [ ] Emergency-access / trusted-recovery workflows (Shamir share of a recovery key).
- [ ] Auto-sync scheduling and sync health dashboard.

## v1.3 — Modern auth & quantum-resistance

- [ ] Post-quantum KEM/key-encapsulation option (Kyber/ML-KEM) for the DEK envelope.
- [ ] Full WebAuthn relying-party integration for passwordless vault unlock.
- [ ] Hardware-backed passkeys for individual logins (store passkey metadata + prompts).
- [ ] TOTP authenticator with camera-less manual entry and QR export.

## v2.0 — Vision

- [ ] Official mobile companion (encrypted peer-to-peer sync or read-only mirror).
- [ ] Plugin/extension system for item kinds.
- [ ] Audit and compliance export (SIGMA-friendly JSON).
- [ ] Formal security review and third-party audit before a 2.0 announcement.

## Non-goals

- Cloud password storage in plaintext or with server-side decryption keys.
- Telemetry that can observe vault contents.
- Breaking the offline-first or zero-knowledge properties.

## How to influence the roadmap

Open a feature request or discussion. Items with strong community demand and clear
security value get prioritized.
