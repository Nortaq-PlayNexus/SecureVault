# Implementation review

Review date: 10 November 2026. Scope: source inspection, not a penetration test or independent security certification. Windows/TPM behavior has not been executed in this review environment.

| Finding | Source | Follow-up |
| --- | --- | --- |
| TPM failure falls back to current-user DPAPI | Crypto/HardwareKeyProvider.cs: Protect | Expose the actual wrapping mode to users; do not infer it from provider construction. |
| Provider-name construction is used as an availability probe | Crypto/HardwareKeyProvider.cs: TpmAvailable; Crypto/PasskeyProvider.cs: IsAvailable | Test actual provider operations on Windows, including missing hardware and policy restrictions. |
| Decrypted data key is stored in a managed byte array while unlocked | Vault/VaultService.cs | Treat an unlocked compromised process as outside the protection boundary. |
| Version records are written with MACs but GetVersions does not verify them | Storage/VaultDatabase.cs | Add verification and tamper tests before claiming every read is authenticated. |
| Audit-chain suffix removal and database rollback lack external freshness anchors | Storage/VaultDatabase.cs: VerifyAuditChain | Design an explicit rollback threat model; a valid retained chain is not proof of completeness. |
| ChangeNote is UTF-8 encoded into change_note_enc, not encrypted | Storage/VaultDatabase.cs: InsertVersion | Do not put secrets in change notes; plan a versioned migration before changing the stored format. |
| .NET 6 is the configured target | Project files and CI | Plan and test a supported-framework migration separately from existing dependency PRs. |

Paths above are relative to src/SecureVault.Core unless otherwise stated. Documentation corrections preserve the vault format and existing records. Runtime fixes require regression tests for old vault compatibility, Windows provider behavior and failure handling.
