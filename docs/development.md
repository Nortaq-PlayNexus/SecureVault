# Development Guide

Everything you need to build, test, debug, and publish SecureVault.

## Prerequisites

- **Windows 10 1809+ / Windows 11** (the app and tests are Windows-only).
- **[.NET 6 SDK](https://dotnet.microsoft.com/download/dotnet/6.0)** (6.0.4xx recommended).
- Optional: [Visual Studio 2022](https://visualstudio.microsoft.com/) or VS Code + C# Dev Kit.
- Optional: a TPM 2.0 and Windows Hello to exercise hardware features.

Verify:

```powershell
dotnet --version
```

## Clone & restore

```powershell
git clone https://github.com/SecureVault/SecureVault.git
cd SecureVault
dotnet restore SecureVault.sln
```

## Build

```powershell
dotnet build SecureVault.sln -c Debug      # daily development
dotnet build SecureVault.sln -c Release    # CI-grade, warnings-as-errors
```

Both configurations must build with **0 warnings**. The solution uses
`Directory.Build.props` to enable the .NET analyzers (`AnalysisLevel=latest`,
`AnalysisMode=Recommended`, `EnforceCodeStyleInBuild`) and `TreatWarningsAsErrors` in Release.

## Run the app

```powershell
dotnet run --project src\SecureVault.App -c Debug
# or launch the built exe:
.\src\SecureVault.App\bin\Release\net6.0-windows10.0.19041.0\SecureVault.exe
```

Vault data is created in `%LOCALAPPDATA%\SecureVault\vault.db` on first run. To reset
everything, delete that folder (this is destructive — back up first).

## Test

```powershell
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Debug
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Release
```

- 46 tests cover crypto round-trips/tamper, KDF, envelopes, vault lifecycle, CRUD, versioning,
  delete/restore, password change, file items, settings, tamper detection, audit chain,
  backups, sync (folder provider), password generation, phishing, and AI analysis.
- Tests create real vaults in temp directories and clean up after themselves.
- Hardware (TPM/passkey) tests are skipped gracefully when no TPM is present.

### Coverage guidance

- Any change to AEAD, KDF, envelope, row MAC, or storage format **must** add failure-mode tests
  (wrong key, wrong AAD, tampered blob, truncated file).
- Sync/backup tests should cover round-trip and wrong-passphrase rejection.

## Code style

- `dotnet format` enforces the rules in `.editorconfig` (CRLF, UTF-8, 4-space indent, C# style).
- CI runs `dotnet format --verify-no-changes`.

```powershell
dotnet format SecureVault.sln          # apply
dotnet format SecureVault.sln --verify-no-changes   # check
```

- No `TODO`s, placeholders, or dead code in merged changes (see `CONTRIBUTING.md`).

## Project structure conventions

| Concern | Where |
| --- | --- |
| Crypto & storage | `src/SecureVault.Core` |
| Domain logic | `src/SecureVault.Core/Vault/VaultService.cs` |
| WPF UI | `src/SecureVault.App/Views`, `Services`, `Theme.xaml` |
| Tests | `tests/SecureVault.Tests` |

Never add UI types to Core and never reference WPF from Core. New secrets handling must use
`SecureBytes`/`CryptoRandom` and zeroize buffers.

## Debugging tips

- **Tamper detection**: `TamperDetectedException` fires on unlock if the header MAC or any
  row MAC fails. Test by flipping a byte in `vault.db`.
- **TPM issues**: check `tpm.msc`; if no TPM is present, `HardwareKeyProvider` falls back to
  DPAPI. The blob's first byte records which (`0x01` TPM, `0x00` DPAPI).
- **SQLite file locks**: keep one `VaultDatabase` per vault and call `FlushToDisk()` (WAL
  checkpoint) before copying/backing-up the file.
- **Analyzer noise**: keep fixes minimal and idiomatic; when a rule is intentionally not
  followed (e.g., SHA-1 in the HIBP checker), suppress narrowly with a justification comment.

## Rebuilding assets

```powershell
powershell -ExecutionPolicy Bypass -File eng\scripts\generate-icon.ps1
```

Regenerates `assets/icons/securevault.ico` from the brand mark.

## CI/CD

See `.github/workflows/ci.yml` for the canonical pipeline: build → format check → test → code
quality. Releases are cut from tags by `.github/workflows/release.yml`; see
`docs/deployment.md`.
