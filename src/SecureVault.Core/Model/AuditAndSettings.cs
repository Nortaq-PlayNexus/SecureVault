namespace SecureVault.Core.Model;

public enum AuditAction
    {
    VaultCreated = 1,
    VaultUnlocked = 2,
    VaultLocked = 3,
    VaultPasswordChanged = 4,
    VaultRecoveryUsed = 5,
    ItemAdded = 10,
    ItemUpdated = 11,
    ItemDeleted = 12,
    ItemRestored = 13,
    FileImported = 14,
    SyncStarted = 20,
    SyncCompleted = 21,
    SyncFailed = 22,
    BackupCreated = 30,
    BackupRestored = 31,
    SettingsChanged = 40,
    PasskeyCreated = 50,
    FailedUnlock = 90,
    TamperDetected = 99,
    }

public sealed class AuditEvent
    {
    public long Id { get; set; }
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public AuditAction Action { get; set; }
    public string Detail { get; set; } = string.Empty;
    public string? TargetId { get; set; }
    }

/// <summary>App settings. Sensitive values are stored encrypted.</summary>
public sealed class VaultSettings
    {
    public string VaultName { get; set; } = "My Vault";
    public string Theme { get; set; } = "Dark";
    public int AutoLockMinutes { get; set; } = 5;
    public bool ClipboardClearEnabled { get; set; } = true;
    public int ClipboardClearSeconds { get; set; } = 30;
    public bool HardwareUnlockEnabled { get; set; }
    public bool WindowsHelloEnabled { get; set; }
    public bool AutoBackupEnabled { get; set; }
    public int AutoBackupIntervalHours { get; set; } = 24;
    public string? AutoBackupDirectory { get; set; }
    public bool BackupRetentionEnabled { get; set; } = true;
    public int BackupRetentionCount { get; set; } = 10;
    public bool SyncEnabled { get; set; }
    public string? SyncProvider { get; set; }
    public bool BreachCheckEnabled { get; set; } = true;
    public bool PhishingCheckEnabled { get; set; } = true;
    public string? LastSyncAt { get; set; }
    }
