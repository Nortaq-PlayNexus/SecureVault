# Deployment

This document covers releasing SecureVault to users and setting up production CI/CD.

## Release model

SecureVault releases are **tagged** from `main`. Semantic versioning is used; see
`CHANGELOG.md`. Releases produce:

- A **single-file, self-contained** `win-x64` executable (recommended for most users).
- The source archive (GitHub auto-creates).
- Attestations from CI (artifacts are built on a clean `windows-latest` runner).

## Local publish

```powershell
dotnet publish src\SecureVault.App -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o publish/win-x64
```

Output: `publish/win-x64/SecureVault.exe`.

> `IncludeNativeLibrariesForSelfExtract` bundles SQLite native libraries so the exe runs
> without extra files. The first launch self-extracts into a cache and is slightly slower.

## Signing

For public distribution, sign the executable:

```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 `
  publish\win-x64\SecureVault.exe
```

CI does **not** sign by default (no certificate in the repo). Wire signing secrets into the
`release.yml` workflow via GitHub Secrets (`CODE_SIGNING_CERT`, `CODE_SIGNING_PASSWORD`) and
set the workflow to call `signtool` when those are present.

## GitHub Actions workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `ci.yml` | push / PR | Build (Debug+Release), format check, tests, publish smoke |
| `codeql.yml` | push / PR / schedule | GitHub CodeQL static security analysis (C#) |
| `release.yml` | tag `v*` | Build release artifacts, attach to GitHub Release |

### Publishing a release

```powershell
git tag v1.0.0
git push origin v1.0.0
```

The `release.yml` workflow builds and uploads the single-file exe plus checksums to the
GitHub Release for that tag.

## Environment configuration

There is **no configuration file for secrets**. All user configuration lives inside the
encrypted vault (`VaultSettings`) or in `%LOCALAPPDATA%\SecureVault`:

| Item | Location |
| --- | --- |
| Vault database | `%LOCALAPPDATA%\SecureVault\vault.db` |
| Sync staging | `%LOCALAPPDATA%\SecureVault\sync` |
| Backups (user-chosen) | anywhere, `*.svault` |

## Docker

A `Dockerfile` is provided for **build verification and headless testing** in a Windows
container (WPF is a GUI framework, so the app itself cannot run usefully in a container; the
container verifies that the solution restores, builds, formats, and passes tests):

```powershell
docker build -t securevault:ci .
```

See `Dockerfile` and `docs/development.md`. CI runs on GitHub-hosted `windows-latest`
runners, which is the canonical build environment.

## Rollback & disaster recovery

- **Backups**: encrypted `*.svault` files. Restore from **Settings → Backup**.
- **Sync copies**: the remote `{vaultId:N}.svault` container is the encrypted database; a
  pull is conflict-safe and keeps a local timestamped copy.
- **Master password loss**: unrecoverable by design. Users should store the backup passphrase
  and master password in a safe place (or a hardware-backed vault) — never in plaintext.

## Monitoring & telemetry

SecureVault has **no telemetry** by design. Operational visibility is limited to:

- The in-app audit log (hash-chained), shown in **Security & health → Audit log**.
- Exit/error messages surfaced by the app.
- CI/CD logs on GitHub.

If you add diagnostics, they must never include secrets and must be opt-in.
