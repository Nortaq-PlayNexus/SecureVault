# Contributing to SecureVault

Thank you for your interest in contributing. SecureVault is a security-focused project, so
contributions are reviewed carefully — especially anything touching cryptography, storage, or
the threat model. This guide tells you how to help in the most effective way.

## Code of Conduct

All interactions in this project are governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to follow it.

## Ways to contribute

- **Report bugs** — open an issue with a clear reproduction.
- **Suggest features** — open a feature request; see [ROADMAP](ROADMAP.md) for direction.
- **Improve documentation** — typos, better guides, clearer diagrams.
- **Write tests** — the test suite lives in `tests/SecureVault.Tests`.
- **Fix issues / build features** — pick an issue labelled `good first issue`.

## Reporting bugs

Please use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml). A great report
includes:

1. SecureVault version and how it was installed (release vs. source build).
2. Windows version (run `winver`).
3. Whether a TPM / Windows Hello is present (`tpm.msc`, `winhello`).
4. Steps to reproduce, expected behaviour, and actual behaviour.
5. Logs or screenshots if they don't contain secrets.

> **Never** paste real vault data, master passwords, or passwords into an issue.

## Security vulnerabilities

Do **not** open a public issue for a security vulnerability. Report it privately via
[GitHub Security Advisories](https://github.com/SecureVault/SecureVault/security/advisories/new)
or `security@securevault.example`. See [SECURITY.md](SECURITY.md) for details.

## Development setup

```powershell
git clone https://github.com/SecureVault/SecureVault.git
cd SecureVault
dotnet restore
dotnet build SecureVault.sln -c Release
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj
```

Requirements: Windows 10/11, [.NET 6 SDK](https://dotnet.microsoft.com/download/dotnet/6.0).
The project targets `net6.0-windows10.0.19041.0` and is Windows-only by design.

See [docs/development.md](docs/development.md) for the full guide (tooling, conventions,
debugging, publishing).

## Code standards

- **No warnings allowed.** `Directory.Build.props` enables the .NET analyzers
  (`AnalysisLevel=latest`) and treats warnings as errors in Release.
- **Formatting.** Run `dotnet format` and ensure `dotnet format --verify-no-changes` passes:
  ```powershell
  dotnet format SecureVault.sln
  ```
- **Follow the [architecture](docs/architecture.md).** Keep cryptography in
  `SecureVault.Core`, UI in `SecureVault.App`, and never mix them.
- **Security-first.** New code that handles secrets must zeroize buffers, use constant-time
  comparisons where relevant, and document any cryptographic choices.
- **No dead code, no placeholders, no `TODO`s** in merged code.
- XML doc comments on all public APIs.

## Tests

The test suite is run by CI (`ci.yml`) and must pass in **both Debug and Release**:

```powershell
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Debug
dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Release
```

When you change a security-sensitive behavior (encryption, MACs, key derivation, storage
format), add tests that cover the new behavior and the failure modes.

## Pull request workflow

1. Create a branch from `main`: `git checkout -b fix/short-description`.
2. Make focused commits with clear messages (see below).
3. Add or update tests.
4. Run the full build + test suite locally.
5. Open a PR using the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
6. CI must pass; a maintainer will review. Keep changes reviewable — split large PRs.

### Commit messages

We use conventional, imperative-style messages:

```
feat: add WebDAV sync provider
fix: recompute header MAC when updating vault metadata
test: cover rollback from version history
docs: describe backup container format
```

## Review process

- Every PR is reviewed by at least one maintainer.
- Security-sensitive PRs (crypto, storage, auth) require a maintainer with crypto context.
- Changes that alter the on-disk format or backup/sync format must bump the format version
  and update `docs/database.md` / `docs/backup-sync.md`.

## Getting help

- Open a discussion or an issue for questions about contribution.
- Prefer small, well-scoped PRs — they get merged faster.
