# Security Model & Threat Model

This document describes what SecureVault protects, who it defends against, and how the
cryptography is composed to provide those guarantees.

## Goals

1. **Confidentiality at rest.** A vault file without the master password reveals nothing.
2. **Integrity & tamper-evidence.** Any modification to the vault (file or rows) is detected
   before secrets are presented.
3. **Zero knowledge of the sync/backup host.** The DEK never leaves the device; remote
   storage sees only ciphertext.
4. **Harvest-now, decrypt-later resistance.** 256-bit keys + AEAD make wholesale post-quantum
   decryption of exported ciphertext infeasible.
5. **Local, private intelligence.** Breach checking, phishing analysis, and "AI" tagging
   never leak secrets or plaintext off the device.

## Assumptions / trust boundary

SecureVault protects data **at rest** and **in transit to the sync host**. It does **not**
protect against:

- A compromised OS or an attacker running code with the user's privileges while the vault is
  **unlocked** (in-memory secrets are exposed by definition).
- Physical seizure while the vault is unlocked or while the master password is on screen.
- Malicious hardware backdoors or a malicious BIOS/TPM firmware.

These assumptions are standard for client-side encryption products and are stated in
`SECURITY.md`.

## Threat model

| # | Threat actor | Capability | Mitigation |
| --- | --- | --- | --- |
| T1 | Casual/curious user or malware that copies files | Reads vault `.db`, backups, sync containers | Everything is AEAD ciphertext; no plaintext in any file |
| T2 | Attacker with a copy of the vault file offline | Brute force the master password | Argon2id (memory-hard), salt per vault, adjustable cost |
| T3 | Attacker modifies the vault file | Flip bits, reorder/duplicate rows, roll back | Per-row HMAC, header MAC, hash-chained audit log, version history |
| T4 | Sync/WebDAV/folder host | Reads the remote container, tampers with it | Container is the encrypted DB; provider cannot see plaintext |
| T5 | Adversary monitoring the network | Observes breach-check traffic | k-anonymity: only 5 hex chars of SHA-1 leave the device |
| T6 | Adversary with a stolen device | Recover TPM/DPAPI keys or the master password from the OS | TPM non-exportable keys; DPAPI current-user scope; vault never auto-stores the password |
| T7 | Future quantum adversary | Harvest ciphertext now, decrypt later | 256-bit keys + AEAD; roadmap adds ML-KEM for the DEK envelope |

## Key management

### Hierarchy

```
master key  = Argon2id(password, salt16, p=1, m=64MiB, t=3)     [derived per unlock]
DEK         = CSPRNG(32)                                        [generated once, wrapped only]
integrity   = HKDF(DEK, purpose="securevault/integrity")        [sub-key, domain separated]
```

- The **DEK** is wrapped with the master key via `KeyEnvelope` (AEAD with purpose AAD
  `securevault:key-envelope:v1\xFFdek:vault:{vaultId}`). Purpose binding means a wrapped DEK
  cannot be replayed under another context.
- The **integrity key** is a separate sub-key: encryption material and integrity material can
  never be swapped.
- `SecureBytes` and `CryptographicOperations.ZeroMemory` zeroize key buffers after use.

### Hardware keys

- **TPM** (`Microsoft Platform Crypto Provider`): RSA OAEP-SHA256, non-exportable. Used to wrap
  the DEK so it can only be unwrapped with the TPM present. Blob prefix byte `0x01`.
- **DPAPI** fallback: `ProtectedData.Protect(scope=CurrentUser)`. Blob prefix byte `0x00`.
- **Passkeys** (`Microsoft Passport KSP`): ECDSA P-256, non-exportable, gated by Windows Hello.

## Integrity design

Every integrity value is `HMAC-SHA256(key=integrityKey, ...)` computed in constant time
(`CryptographicOperations.FixedTimeEquals`) on comparison:

| Location | Inputs |
| --- | --- |
| Header MAC | Serialized header with `IntegrityMac=null`, stable field order |
| Item row | `id · type · deleted · favorite · payload_enc · content_enc · updated_at("O") · version` |
| Version row | `itemId · version · payload_enc · content_enc` |
| Setting row | `key · value` |
| Audit chain | `prev_hash · timestamp_enc · event_enc` |

### Hash-chained audit log

Each audit event's hash covers the previous event's hash. The verifier checks the retained chain for edits and broken links. Removing a valid suffix (including every row) is not detected without an independently trusted final hash and length.

### Rollback detection

Item writes include MACs, but GetVersions currently reads historical snapshots without verifying their stored MAC. A complete older row with its valid MAC, or an older database snapshot, cannot be distinguished from the latest state without an external trusted freshness reference. MACs alone do not prevent rollback.

## Privacy of networked features

### Breach checking (HIBP k-anonymity)

`CheckPasswordAsync` sends only `SHA-1(password)[0..5]` (5 hex chars) to
`https://api.pwnedpasswords.com/range/{prefix}` and compares the returned suffix list locally.
The full hash and the password never leave the device. SHA-1 is intentionally used here — the
HIBP protocol requires it, but the disclosed prefix and request metadata still reveal information to the service.

### Phishing detection

Entirely local heuristics on URLs/domains (HTTP, raw-IP hosts, brand lookalikes via
Damerau-Levenshtein, hyphenated impersonation, unusual TLDs). Nothing is transmitted.

### "AI" tagging / analysis

Deterministic, local keyword classification over in-memory plaintext. Nothing is persisted,
logged, or sent.

## Clipboard & session hygiene

- `ClipboardGuard` clears copied secrets after a configurable delay (default 30 s), only when
  the copied text still matches what we put there.
- `AutoLockService` locks the vault after inactivity (default 5 min), zeroing in-memory keys.
- Normal Lock zeroes the DEK and integrity-key arrays; the database is disposed by Dispose, not Lock. Managed copies and an already compromised process are outside this guarantee.

## Recommended deployment hygiene

- Use a strong, unique master password and enable the generator's Diceware option for
  human-memorable high-entropy passphrases.
- Enable **hardware unlock** (TPM) and Windows Hello when available.
- Enable **automatic encrypted backups**; store `.svault` files off-machine.
- Treat the master password as a root credential: never reuse it, never store it in a
  plaintext note, and prefer TPM/Hello unlock on shared machines.
