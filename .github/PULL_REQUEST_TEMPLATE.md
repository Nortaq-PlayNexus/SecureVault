## Summary

<!-- One or two sentences describing the change and why. -->

Fixes #<!-- issue number --> (if applicable)

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / performance
- [ ] Documentation
- [ ] Dependency update
- [ ] Security-related change

## Security / privacy impact

<!--
Check all that apply and explain:

- Does this touch cryptography, key handling, or storage formats?
- Does it change the on-disk format or backup/sync format? (If so, the format version
  MUST be bumped and docs/database.md & docs/backup-sync.md updated.)
- Does it send data off the device? (Must not, unless explicitly user-opted-in and k-anonymous.)
-->
- [ ] No impact
- [ ] Explains impact (required if any box above is relevant)

## Tests

- [ ] Added/updated unit or integration tests
- [ ] Ran `dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Debug`
- [ ] Ran `dotnet test tests\SecureVault.Tests\SecureVault.Tests.csproj -c Release`
- [ ] `dotnet build SecureVault.sln -c Release` has 0 warnings
- [ ] `dotnet format SecureVault.sln --verify-no-changes` passes

## Checklist

- [ ] No TODOs, placeholders, or dead code
- [ ] XML docs added for new public APIs
- [ ] CHANGELOG.md updated (Unreleased section)
- [ ] README/docs updated where relevant
