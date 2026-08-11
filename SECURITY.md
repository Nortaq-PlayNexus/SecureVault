# Security Policy

SecureVault is a security product. We take the security of our users and of this
project seriously.

## Supported versions

Only the latest release line receives security patches. Backports are made on a
case-by-case basis for severe, actively exploited vulnerabilities.

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report them privately via one of:

- **GitHub Security Advisories** (preferred):
  https://github.com/Nortaq-PlayNexus/SecureVault/security/advisories/new
- **Email**: `security@securevault.example` (PGP key available on request)

Please include:

1. The affected component and version.
2. A description of the vulnerability and its impact on confidentiality, integrity,
   or availability.
3. Steps to reproduce, including any proof of concept.
4. Your name/alias and how you'd like to be credited (or request anonymity).

### What happens next

1. We acknowledge your report within **72 hours**.
2. We triage and assess the severity, and keep you informed of progress.
3. We prepare a fix, and coordinate disclosure with you.
4. We credit you in the release notes (unless you prefer otherwise).

We follow **responsible disclosure**: reporters get at least 90 days before a
public announcement unless the issue is already being exploited or is trivially
discoverable.

## Scope

In scope:

- The `SecureVault.Core` cryptography, key handling, storage, and sync/backup formats.
- The `SecureVault.App` session, unlock, and clipboard handling.
- The CI/CD pipeline and release artifacts.

Out of scope (informational only):

- Local attacks requiring an already-compromised or physically-attacked machine
  while the vault is **unlocked** (in-memory secrets are expected).
- Social engineering of the user.
- Denial-of-service against third-party services (e.g., HIBP, WebDAV hosts).

## Security model

See [docs/security.md](docs/security.md) for the full threat model, key hierarchy,
and adversarial analysis. In short:

- The vault file contains **no plaintext**; all items are AEAD ciphertext bound to
  their item id via associated data.
- The data-encryption key (DEK) never leaves the device and is wrapped by the
  master key, which is derived on demand with Argon2id (never stored).
- Every row carries an HMAC-SHA256 integrity tag; the header is covered by its own
  MAC. Tampering is detected on unlock and surfaces as `TamperDetectedException`.
- The audit log is hash-chained and append-only, providing tamper-evidence.
- Sync and backups operate on already-encrypted containers; the remote host and
  backup media never see plaintext.

## Acknowledgements

We thank all security researchers who help keep SecureVault safe. Contributors are
listed in the release notes of the fixing release.
