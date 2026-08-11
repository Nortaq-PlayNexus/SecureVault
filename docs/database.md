# Database Schema & On-Disk Format

The vault is a single SQLite database (`vault.db`, WAL mode). It contains **no plaintext
secrets**: every secret-bearing column is an AEAD ciphertext blob, and every row carries an
HMAC keyed by the vault integrity key. The schema itself is structural only.

## Vault meta

```sql
CREATE TABLE vault_meta (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    cipher_suite   INTEGER NOT NULL,
    header_json    TEXT    NOT NULL
);
```

`header_json` holds the serialized `VaultHeader` (JSON): KDF name/salt/parameters, cipher
suite, the password-wrapped DEK, the optional hardware-wrapped DEK, and the header
integrity MAC. The header contains no plaintext secrets.

## Items

```sql
CREATE TABLE items (
    id          TEXT    PRIMARY KEY,
    type        INTEGER NOT NULL,
    payload_enc BLOB    NOT NULL,
    content_enc BLOB    NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    favorite    INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    mac         BLOB    NOT NULL
);
```

- `id` — item UUID in `"N"` (no-hyphen) form.
- `payload_enc` — AEAD `nonce || ct || tag` of the JSON payload, bound to
  AAD `securevault:item:{id}:payload`.
- `content_enc` — AEAD blob of raw file/SSH-key content, bound to AAD
  `securevault:item:{id}:content` (null for non-file items).
- `mac` — `HMAC-SHA256(integrityKey, id·type·deleted·favorite·payload_enc·content_enc·updated_at("O")·version)`.

## Version history

```sql
CREATE TABLE item_versions (
    item_id        TEXT NOT NULL,
    version        INTEGER NOT NULL,
    payload_enc    BLOB NOT NULL,
    content_enc    BLOB NULL,
    created_at     TEXT NOT NULL,
    change_note_enc BLOB NULL,
    mac            BLOB NOT NULL,
    PRIMARY KEY (item_id, version)
);
```

A snapshot is appended on every update; the newest 50 are retained. Each snapshot is MACed
independently, so it can be verified and rolled back.

## Audit log (hash chain)

```sql
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_enc    BLOB NOT NULL,
    event_enc BLOB NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
);
```

- `hash = HMAC-SHA256(integrityKey, prev_hash · ts_enc · event_enc)`.
- The first entry uses a zero prev_hash. `VerifyAuditChain` replays the chain and detects any
  truncation, reorder, or edit.

## Settings

```sql
CREATE TABLE settings (
    key      TEXT PRIMARY KEY,
    value_enc BLOB NOT NULL,
    mac      BLOB NOT NULL
);
```

## Sync state (unencrypted by design)

```sql
CREATE TABLE sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Stores **non-secret** operational values only (sync provider type, last-sync timestamp, remote
URL/folder path). Never store secrets here — use `settings` instead.

## AEAD wire format

Both cipher suites use the same envelope: **`nonce || ciphertext || tag`**.

| Suite | Nonce | Tag | Item payload overhead |
| --- | --- | --- | --- |
| `Aes256Gcm` | 12 B | 16 B | 28 B |
| `XChaCha20Poly1305` | 24 B | 16 B | 40 B |

## Encryption AAD (purpose binding)

| Object | AAD |
| --- | --- |
| Vault DEK envelope | `securevault:key-envelope:v1 \xFF dek:vault:{vaultId}` |
| Item payload | `securevault:item:{id}:payload` |
| Item content | `securevault:item:{id}:content` |
| Backup container | static header bytes (see `docs/backup-sync.md`) |

## Timestamps

Stored as `DateTimeOffset.ToString("O")` (ISO 8601 round-trip, UTC) and parsed with
`CultureInfo.InvariantCulture` + `DateTimeStyles.RoundtripKind`. String comparisons are never
used for timestamps.

## Migration policy

- `vault_meta.schema_version` gates format changes; the current value is `1`.
- Any change to the on-disk format **must** bump `VaultHeader.CurrentSchemaVersion`, add a
  migration step in `InitializeSchema`/`VaultService`, and update this document.
- Cryptographic parameter changes (KDF cost, cipher suite) are header fields, not schema
  changes, and are backward-compatible by construction.
