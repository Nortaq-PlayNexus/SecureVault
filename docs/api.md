# API Reference — `SecureVault.Core`

`SecureVault.Core` is the platform-independent (Windows-targeted) engine behind the app.
All public types are in `src/SecureVault.Core`. Everything here is thread-unsafe unless noted;
an unlocked `VaultService` is not thread-safe and should be used from a single logical flow.

## Namespace map

| Namespace | Contents |
| --- | --- |
| `SecureVault.Core.Vault` | `VaultService` — the domain facade |
| `SecureVault.Core.Crypto` | AEAD engines, `Argon2IdKdf`, `KeyEnvelope`, `KeyDerivation`, `CryptoRandom`, `SecureBytes`, `HardwareKeyProvider`, `PasskeyProvider`, `CipherSuite` |
| `SecureVault.Core.Storage` | `VaultDatabase`, `TamperDetectedException` |
| `SecureVault.Core.Model` | `VaultHeader`, `VaultItem`, payloads, `VaultSettings`, `AuditEvent`, `AuditAction` |
| `SecureVault.Core.Security` | `PasswordGenerator`, `BreachChecker`, `PhishingDetector` |
| `SecureVault.Core.Backup` | `BackupService` |
| `SecureVault.Core.Sync` | `SyncService`, `ISyncProvider`, `FolderSyncProvider`, `WebDavSyncProvider` |
| `SecureVault.Core.AI` | `AiOrganizer` |

## `VaultService`

```csharp
var vault = new VaultService(@"C:\vault.db");

// Create
vault.Create(masterPassword, suite: CipherSuite.Aes256Gcm, vaultName: "Personal",
             enableHardware: true);

// Unlock
bool ok = vault.Unlock(masterPassword);          // password
bool ok = vault.UnlockWithHardware();            // TPM / DPAPI (needs HardwareWrappedDek)

// Lock / dispose (zeroizes keys)
vault.Lock();

// Items
var item = vault.AddItem(VaultItemType.Login, new LoginPayload { ... }, content: null, tags: null);
vault.UpdateItem(id, newPayload, content, tags);
vault.DeleteItem(id);                 // soft delete → trash
vault.RestoreItem(id);
vault.PurgeItem(id);                  // permanent (removes versions too)
var items = vault.GetItems();         // excludes trashed
var trashed = vault.GetDeletedItems();
var versions = vault.GetVersions(id);
vault.RollbackItem(id, version);

// Payloads
var login = vault.DecryptPayload<LoginPayload>(item);

// Password / security
vault.ChangeMasterPassword(old, newP);
vault.EnableHardwareUnlock();
vault.DisableHardwareUnlock();

// Settings & audit
var settings = vault.GetSettings();
vault.SaveSettings(settings);
var events = vault.GetAuditEvents();

// Sync/backup support
vault.FlushToDisk();                  // WAL checkpoint
var header = VaultService.PeekHeader(path); // static: read header w/o opening

// Properties
bool IsUnlocked; VaultHeader? Header; string VaultPath;
```

### Exceptions

- `TamperDetectedException` — thrown when header MAC, row MAC, or the audit chain fails.
- `CryptographicException` — wrong password, unwrap failures, TPM failures.
- `InvalidOperationException` — vault not unlocked, item missing, etc.

## Crypto

```csharp
// Engines
IEncryptionEngine aes   = EncryptionEngine.Create(CipherSuite.Aes256Gcm);
IEncryptionEngine xch   = EncryptionEngine.Create(CipherSuite.XChaCha20Poly1305);
byte[] ct = aes.Encrypt(key, plaintext, aad);
byte[] pt = aes.Decrypt(key, ct, aad);          // throws CryptographicException on auth failure

// KDF
byte[] salt = Argon2IdKdf.GenerateSalt();                       // 16 B
byte[] key  = Argon2IdKdf.DeriveKey(password, salt, Argon2IdParameters.Default);

// Key envelope (wrap a DEK)
byte[] env = KeyEnvelope.Seal(masterKey, dek, suite, "dek:vault:{" + vaultId + "}");
byte[] dek = KeyEnvelope.Open(masterKey, env, suite, context);   // or TryOpen

// Sub-keys (domain separation)
byte[] integrity = KeyDerivation.DeriveIntegrityKey(dek);

// Random & buffers
byte[] rnd = CryptoRandom.GetBytes(32);
int n      = CryptoRandom.GetInt(max);
Guid g     = CryptoRandom.NewGuid();
using var sb = new SecureBytes(plaintext);      // zeroizes on dispose

// Hardware / passkeys
var hw = new HardwareKeyProvider(vaultId.ToString());
byte[] wrapped = hw.Protect(dek, "dek");
byte[] dek = hw.Unprotect(wrapped, "dek");

PasskeyProvider.CreatePasskey(rpId, userId, displayName, challenge);
PasskeyProvider.Sign(keyName, challenge);
PasskeyProvider.Verify(publicKeyBlob, challenge, signature);
```

## Security

```csharp
var pw = PasswordGenerator.Generate(new PasswordOptions { Length = 24 });
var phrase = PasswordGenerator.GeneratePassphrase(6, "-", includeDigit: true);
double bits = PasswordGenerator.EstimateEntropy(pw);

using var breach = new BreachChecker(networkEnabled: true);
var result = await breach.CheckPasswordAsync(pw);   // HIBP k-anonymity; password never leaves device

var phish = PhishingDetector.Analyze("https://paypa1.com/login");
```

## Backup & Sync

```csharp
await BackupService.CreateBackupAsync(vault, @"C:\backup.svault", "passphrase");
await BackupService.RestoreBackupAsync(@"C:\backup.svault", @"C:\restored.db", "passphrase");
bool valid = BackupService.ValidateBackup(@"C:\backup.svault", "passphrase");

ISyncProvider folder = new FolderSyncProvider(@"D:\SecureVaultSync");
ISyncProvider webdav = new WebDavSyncProvider("https://dav.example.com/vaults", "user", "pass");
var sync = new SyncService(folder, vault);
await sync.PushAsync();
await sync.PullAsync();
await sync.SyncAsync();              // two-way, conflict-safe
```

## AI

```csharp
var suggestion = AiOrganizer.SuggestTags(item, payload);       // tags or null
var findings = AiOrganizer.AnalyzeStrength(password, username, url); // advisory list
```

## Design notes

- **Static utility classes** (`PasswordGenerator`, `PhishingDetector`, `Argon2IdKdf`,
  `BackupService`, `PasskeyProvider`) are stateless by design; instance call sites in the app
  use them via their static members.
- Engines hold no key material; keys are passed per call as `ReadOnlySpan<byte>` and zeroized
  by callers.
- `VaultDatabase` uses SQLite in WAL mode; keep a single connection per vault instance and
  dispose before backing up/syncing the file.
