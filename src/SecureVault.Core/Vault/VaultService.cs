using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;
using SecureVault.Core.Storage;

namespace SecureVault.Core.Vault;

/// <summary>
/// Orchestrates vault lifecycle and all item operations. Holds the data
/// encryption key in memory only while unlocked and zeroizes on lock/dispose.
/// </summary>
public sealed class VaultService : IDisposable
    {
    private VaultDatabase? _db;
    private IEncryptionEngine? _engine;
    private byte[]? _dek;
    private byte[]? _integrityKey;
    private bool _disposed;

    public string VaultPath { get; }
    public VaultHeader? Header { get; private set; }
    public bool IsUnlocked => _dek is not null;

    public VaultService(string vaultPath)
        {
        VaultPath = vaultPath;
        }

    /// <summary>Read the vault header without unlocking (e.g. to detect hardware unlock availability).</summary>
    public static VaultHeader? PeekHeader(string vaultPath)
        {
        if (!File.Exists(vaultPath)) return null;
        using var db = new VaultDatabase(vaultPath);
        return db.LoadHeader();
        }

    // ---------- Creation ----------

    /// <summary>Create a new vault, deriving the master key from the password.</summary>
    public VaultHeader Create(
        string masterPassword,
        CipherSuite suite = CipherSuite.Aes256Gcm,
        Argon2IdParameters? kdf = null,
        string vaultName = "My Vault",
        bool enableHardware = false)
        {
        if (IsUnlocked) throw new InvalidOperationException("Vault is already unlocked.");
        if (string.IsNullOrEmpty(masterPassword)) throw new ArgumentException("A master password is required.", nameof(masterPassword));

        var header = new VaultHeader
            {
            VaultId = CryptoRandom.NewGuid(),
            CipherSuite = suite,
            KdfSalt = Argon2IdKdf.GenerateSalt(),
            KdfParameters = kdf ?? Argon2IdParameters.Default,
            VaultName = vaultName,
            };

        var masterKey = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(masterPassword), header.KdfSalt, header.KdfParameters);
        try
            {
            var dek = CryptoRandom.GetBytes(VaultHeader.KeySizeBytes);
            header.PasswordWrappedDek = KeyEnvelope.Seal(masterKey, dek, suite, $"dek:vault:{header.VaultId}");

            if (enableHardware && OperatingSystem.IsWindows())
                {
                var hardware = new HardwareKeyProvider(header.VaultId.ToString());
                header.HardwareWrappedDek = hardware.Protect(dek, "dek");
                }

            _db = new VaultDatabase(VaultPath);
            _db.SaveHeader(header);

            var integrity = KeyDerivation.DeriveIntegrityKey(dek);
            header.IntegrityMac = ComputeHeaderMac(header, integrity);
            _db.SaveHeader(header);

            _dek = dek;
            _integrityKey = integrity;
            _engine = EncryptionEngine.Create(suite);
            Header = header;

            AppendAudit(AuditAction.VaultCreated, "Vault created");
            return header;
            }
        finally
            {
            CryptographicOperations.ZeroMemory(masterKey);
            }
        }

    // ---------- Unlock ----------

    /// <summary>Unlock with the master password.</summary>
    public bool Unlock(string masterPassword)
        {
        if (IsUnlocked) return true;
        if (string.IsNullOrEmpty(masterPassword)) return false;

        _db ??= new VaultDatabase(VaultPath);
        Header = _db.LoadHeader() ?? throw new InvalidOperationException("No vault found at this path.");
        var header = Header;

        var masterKey = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(masterPassword), header.KdfSalt, header.KdfParameters);
        try
            {
            if (!KeyEnvelope.TryOpen(masterKey, header.PasswordWrappedDek, header.CipherSuite, $"dek:vault:{header.VaultId}", out var dek))
                {
                AppendAudit(AuditAction.FailedUnlock, "Incorrect master password");
                return false;
                }
            ActivateKeys(dek!, header);
            AppendAudit(AuditAction.VaultUnlocked, "Unlocked with master password");
            return true;
            }
        finally
            {
            CryptographicOperations.ZeroMemory(masterKey);
            }
        }

    /// <summary>Unlock using the hardware-protected DEK (TPM/DPAPI).</summary>
    public bool UnlockWithHardware()
        {
        if (IsUnlocked) return true;
        _db ??= new VaultDatabase(VaultPath);
        Header = _db.LoadHeader() ?? throw new InvalidOperationException("No vault found at this path.");
        var header = Header;

        if (header.HardwareWrappedDek is null) return false;
        if (!OperatingSystem.IsWindows()) return false;

        var hardware = new HardwareKeyProvider(header.VaultId.ToString());
        try
            {
            var dek = hardware.Unprotect(header.HardwareWrappedDek, "dek");
            ActivateKeys(dek, header);
            AppendAudit(AuditAction.VaultUnlocked, "Unlocked with hardware key");
            return true;
            }
        catch (CryptographicException)
            {
            AppendAudit(AuditAction.FailedUnlock, "Hardware unlock failed");
            return false;
            }
        }

    private void ActivateKeys(byte[] dek, VaultHeader header)
        {
        _dek = dek;
        _integrityKey = KeyDerivation.DeriveIntegrityKey(dek);
        _engine = EncryptionEngine.Create(header.CipherSuite);

        var expected = ComputeHeaderMac(header, _integrityKey);
        if (header.IntegrityMac is null || !CryptographicOperations.FixedTimeEquals(expected, header.IntegrityMac))
            {
            _dek = null;
            _integrityKey = null;
            _engine = null;
            throw new TamperDetectedException("Vault header integrity check failed. The vault may have been tampered with.");
            }
        }

    // ---------- Lock ----------

    public void Lock()
        {
        if (_dek is not null) AppendAudit(AuditAction.VaultLocked, "Vault locked");
        if (_dek is not null) CryptographicOperations.ZeroMemory(_dek);
        _dek = null;
        if (_integrityKey is not null) CryptographicOperations.ZeroMemory(_integrityKey);
        _integrityKey = null;
        Header = null;
        }

    // ---------- Password / hardware management ----------

    /// <summary>Verify a master password without changing unlock state.</summary>
    public bool VerifyPassword(string masterPassword)
        {
        if (string.IsNullOrEmpty(masterPassword)) return false;
        _db ??= new VaultDatabase(VaultPath);
        var header = _db.LoadHeader();
        if (header is null) return false;

        var masterKey = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(masterPassword), header.KdfSalt, header.KdfParameters);
        try
            {
            return KeyEnvelope.TryOpen(masterKey, header.PasswordWrappedDek, header.CipherSuite, $"dek:vault:{header.VaultId}", out _);
            }
        finally
            {
            CryptographicOperations.ZeroMemory(masterKey);
            }
        }

    public void ChangeMasterPassword(string oldPassword, string newPassword)
        {
        RequireUnlocked();
        if (!VerifyPassword(oldPassword)) throw new CryptographicException("Old master password is incorrect.");

        var header = Header!;
        header.KdfSalt = Argon2IdKdf.GenerateSalt();
        var newMaster = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(newPassword), header.KdfSalt, header.KdfParameters);
        try
            {
            header.PasswordWrappedDek = KeyEnvelope.Seal(newMaster, _dek!, header.CipherSuite, $"dek:vault:{header.VaultId}");
            }
        finally
            {
            CryptographicOperations.ZeroMemory(newMaster);
            }

        var integrity = _integrityKey!;
        header.IntegrityMac = ComputeHeaderMac(header, integrity);
        _db!.SaveHeader(header);
        Header = header;
        AppendAudit(AuditAction.VaultPasswordChanged, "Master password changed");
        }

    public void EnableHardwareUnlock()
        {
        RequireUnlocked();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Hardware unlock requires Windows.");
        var header = Header!;
        var hardware = new HardwareKeyProvider(header.VaultId.ToString());
        header.HardwareWrappedDek = hardware.Protect(_dek!, "dek");
        header.IntegrityMac = ComputeHeaderMac(header, _integrityKey!);
        _db!.SaveHeader(header);
        }

    public void DisableHardwareUnlock()
        {
        RequireUnlocked();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Hardware unlock requires Windows.");
        var header = Header!;
        new HardwareKeyProvider(header.VaultId.ToString()).Delete("dek");
        header.HardwareWrappedDek = null;
        header.IntegrityMac = ComputeHeaderMac(header, _integrityKey!);
        _db!.SaveHeader(header);
        }

    // ---------- Item CRUD ----------

    public VaultItem AddItem(VaultItemType type, object payload, byte[]? content = null, string[]? tags = null)
        {
        RequireUnlocked();
        var item = new VaultItem
            {
            Id = CryptoRandom.NewGuid(),
            Type = type,
            Tags = tags ?? Array.Empty<string>(),
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            };
        EncryptAndStoreItem(item, payload, content);
        AppendAudit(AuditAction.ItemAdded, $"{type} item added", item.Id.ToString());
        return item;
        }

    public void UpdateItem(Guid itemId, object payload, byte[]? content = null, string[]? tags = null)
        {
        RequireUnlocked();
        var existing = _db!.GetItem(itemId, _integrityKey!) ?? throw new KeyNotFoundException($"Item '{itemId}' not found.");

        // snapshot for version history
        var version = new ItemVersion
            {
            ItemId = itemId,
            Version = existing.Version,
            EncryptedPayload = existing.EncryptedPayload,
            EncryptedContent = existing.EncryptedContent,
            CreatedAt = DateTimeOffset.UtcNow,
            };
        _db.InsertVersion(version, _integrityKey!);

        existing.Version += 1;
        existing.UpdatedAt = DateTimeOffset.UtcNow;
        existing.Tags = tags ?? existing.Tags;
        EncryptItem(existing, payload, content);
        _db.UpdateItem(existing, _integrityKey!);
        AppendAudit(AuditAction.ItemUpdated, $"{existing.Type} item updated", itemId.ToString());
        }

    public void DeleteItem(Guid itemId)
        {
        RequireUnlocked();
        _db!.SoftDeleteItem(itemId, _integrityKey!);
        AppendAudit(AuditAction.ItemDeleted, "Item soft-deleted", itemId.ToString());
        }

    public void RestoreItem(Guid itemId)
        {
        RequireUnlocked();
        _db!.RestoreItem(itemId, _integrityKey!);
        AppendAudit(AuditAction.ItemRestored, "Item restored", itemId.ToString());
        }

    public void PurgeItem(Guid itemId)
        {
        RequireUnlocked();
        _db!.PurgeItem(itemId);
        }

    public IReadOnlyList<VaultItem> GetItems() => RequireUnlockedResult(_db!.GetItems(_integrityKey!));

    public IReadOnlyList<VaultItem> GetDeletedItems() => RequireUnlockedResult(_db!.GetDeletedItems(_integrityKey!));

    public VaultItem? GetItem(Guid itemId) => RequireUnlockedResult(_db!.GetItem(itemId, _integrityKey!));

    public IReadOnlyList<ItemVersion> GetVersions(Guid itemId) => RequireUnlockedResult(_db!.GetVersions(itemId));

    /// <summary>Decrypt an item's payload into a typed object.</summary>
    public T DecryptPayload<T>(VaultItem item) where T : class
        {
        RequireUnlocked();
        var json = _engine!.Decrypt(_dek!, item.EncryptedPayload, AadFor(item));
        return JsonSerializer.Deserialize<T>(json)
            ?? throw new InvalidOperationException("Failed to deserialize payload.");
        }

    /// <summary>Decrypt a file item's content.</summary>
    public byte[] DecryptContent(VaultItem item)
        {
        RequireUnlocked();
        if (item.EncryptedContent is null) throw new InvalidOperationException("Item has no content.");
        return _engine!.Decrypt(_dek!, item.EncryptedContent, AadFor(item, content: true));
        }

    // ---------- Settings ----------

    public VaultSettings GetSettings()
        {
        RequireUnlocked();
        var bytes = _db!.GetSetting("settings", _integrityKey!);
        if (bytes is null) return new VaultSettings();
        var json = _engine!.Decrypt(_dek!, bytes, AadFor("settings"));
        return JsonSerializer.Deserialize<VaultSettings>(json) ?? new VaultSettings();
        }

    public void SaveSettings(VaultSettings settings)
        {
        RequireUnlocked();
        var json = JsonSerializer.Serialize(settings);
        var bytes = _engine!.Encrypt(_dek!, Encoding.UTF8.GetBytes(json), AadFor("settings"));
        _db!.SetSetting("settings", bytes, _integrityKey!);
        AppendAudit(AuditAction.SettingsChanged, "Settings updated");
        }

    // ---------- Audit ----------

    public void AppendAudit(AuditAction action, string detail, string? targetId = null)
        {
        if (_db is null) return;
        var evt = new AuditEvent
            {
            Timestamp = DateTimeOffset.UtcNow,
            Action = action,
            Detail = detail,
            TargetId = targetId,
            };
        var json = JsonSerializer.SerializeToUtf8Bytes(evt);
        byte[] encrypted;
        if (_dek is not null && _engine is not null)
            {
            encrypted = _engine.Encrypt(_dek, json, AadFor("audit"));
            }
        else
            {
            // Pre-unlock events (failed unlock) are stored unencrypted but still chained.
            encrypted = json;
            }
        _db.AppendAudit(encrypted, BitConverter.GetBytes(evt.Timestamp.UtcTicks), _integrityKey ?? new byte[32]);
        }

    public IReadOnlyList<AuditEvent> GetAuditEvents()
        {
        RequireUnlocked();
        var result = new List<AuditEvent>();
        foreach (var enc in _db!.GetAuditEvents())
            {
            byte[] json;
            try
                {
                json = _engine!.Decrypt(_dek!, enc, AadFor("audit"));
                }
            catch (CryptographicException)
                {
                json = enc; // pre-unlock, unencrypted
                }
            try
                {
                result.Add(JsonSerializer.Deserialize<AuditEvent>(json)!);
                }
            catch
                {
                // ignore unparseable events
                }
            }
        return result;
        }

    public bool VerifyAuditChain() => RequireUnlockedResult(_db!.VerifyAuditChain(_integrityKey!));

    // ---------- Sync state ----------

    public string? GetSyncState(string key) => _db?.GetSyncState(key);
    public void SetSyncState(string key, string value) => _db?.SetSyncState(key, value);

    /// <summary>Checkpoint the WAL into the main DB file so backups/sync capture all data.</summary>
    public void FlushToDisk() => _db?.Checkpoint();

    // ---------- Encryption helpers ----------

    private void EncryptAndStoreItem(VaultItem item, object payload, byte[]? content)
        {
        EncryptItem(item, payload, content);
        _db!.InsertItem(item, _integrityKey!);
        }

    private void EncryptItem(VaultItem item, object payload, byte[]? content)
        {
        var json = JsonSerializer.SerializeToUtf8Bytes(payload);
        item.EncryptedPayload = _engine!.Encrypt(_dek!, json, AadFor(item));
        if (content is not null)
            {
            item.EncryptedContent = _engine.Encrypt(_dek!, content, AadFor(item, content: true));
            }
        }

    private static byte[] AadFor(VaultItem item, bool content = false) =>
        Encoding.UTF8.GetBytes($"securevault:item:{item.Id}:{(content ? "content" : "payload")}");

    private static byte[] AadFor(string domain) => Encoding.UTF8.GetBytes($"securevault:{domain}");

    private static byte[] ComputeHeaderMac(VaultHeader header, ReadOnlySpan<byte> integrityKey)
        {
        using var hmac = new HMACSHA256(integrityKey.ToArray());
        // Serialize with the MAC field nulled so the digest is stable.
        var copy = new VaultHeader
            {
            SchemaVersion = header.SchemaVersion,
            VaultId = header.VaultId,
            CipherSuite = header.CipherSuite,
            KdfName = header.KdfName,
            KdfSalt = header.KdfSalt,
            KdfParameters = header.KdfParameters,
            PasswordWrappedDek = header.PasswordWrappedDek,
            HardwareWrappedDek = header.HardwareWrappedDek,
            CreatedAt = header.CreatedAt,
            UpdatedAt = header.UpdatedAt,
            VaultName = header.VaultName,
            };
        return hmac.ComputeHash(JsonSerializer.SerializeToUtf8Bytes(copy));
        }

    private void RequireUnlocked()
        {
        if (!IsUnlocked) throw new InvalidOperationException("Vault is locked.");
        }

    private T RequireUnlockedResult<T>(T value)
        {
        RequireUnlocked();
        return value;
        }

    public void Dispose()
        {
        if (_disposed) return;
        Lock();
        _db?.Dispose();
        _db = null;
        _disposed = true;
        }
    }
