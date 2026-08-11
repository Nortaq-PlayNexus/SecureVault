# Backup & Sync Format

Both backup and sync are **zero-knowledge by construction**: they operate on the vault
database, which holds only ciphertext + MACs. No plaintext ever leaves the device, and the
data-encryption key never leaves the device.

## Backup container (`*.svault`)

A backup is the entire vault database sealed into a single portable container:

```
┌───────────────────────────────────────────────┐
│ Magic      uint32  0x5356424B  ("SVBK")       │
│ Version    byte    1                          │
│ Suite      byte    CipherSuite                │
│ SaltLen    int32   16                         │
│ Salt       byte[]  Argon2id salt              │
│ HeaderLen  int32                              │
│ Header     byte[]  static plaintext header    │
│ DbLen      int32                              │
│ Db         byte[]  AEAD(nonce‖ct‖tag) of db   │
└───────────────────────────────────────────────┘
```

- The passphrase derives a 32-byte key with Argon2id (default parameters) and a fresh salt.
- The database bytes are sealed with AES-256-GCM using the static header bytes as AAD, so the
  header cannot be swapped and the container is tamper-evident.
- `ValidateBackup` re-opens the container with the passphrase (constant-time failure).
- Before backing up, the WAL is checkpointed (`wal_checkpoint(FULL)`) so the main `.db`
  contains all committed data.

## Sync protocol

The sync remote stores a single file: `{vaultId:N}.svault` — but **without** a passphrase:
the file pushed is the vault database itself after a WAL checkpoint. It is already encrypted
with the vault DEK, so the remote host (folder or WebDAV) sees only ciphertext.

```mermaid
sequenceDiagram
    participant A as Device A (unlocked)
    participant S as SyncService
    participant R as Remote (folder/WebDAV)

    A->>S: Push(provider)
    S->>A: FlushToDisk() → WAL checkpoint
    S->>A: Encrypt/verify DB bytes
    S->>R: Upload vaultId.svault
    R-->>S: ok
    S->>A: Record last-sync state; append audit event
```

### Conflict safety

- **Pull** (`Pull`): if the remote file is newer and valid, it is copied to a staging path,
  integrity-verified, and swapped in; the previous local file is preserved as a timestamped
  backup next to it.
- **Push** (`Push`): writes the local database to the remote, keeping the local copy intact.
- **Two-way** (`Sync`): pushes, then pulls the freshest copy so both ends converge.

### Integrity on the wire

- Downloading a vault that fails header MAC or row MAC verification is rejected
  (`TamperDetectedException`) and the local vault is left untouched.
- Remote filenames are derived from the vault id, so two vaults can share one folder/WebDAV
  collection without collision.

## Providers

| Provider | Transport | Notes |
| --- | --- | --- |
| `FolderSyncProvider` | Local filesystem | Dropbox/OneDrive/NAS mounts |
| `WebDavSyncProvider` | HTTP(S) WebDAV (MKCOL/PUT/GET/DELETE) | Optional basic auth; self-signed certs supported only via explicit `ignoreSslErrors` opt-in |

## Security notes

- The remote never sees the DEK or plaintext — only the already-encrypted database file.
- Do not put secrets in `sync_state`; it is stored in plaintext by design (operational data only).
- Backups should be stored off-device and protected by a strong passphrase.
