using SecureVault.Core.Model;
using SecureVault.Core.Vault;

namespace SecureVault.App.Services;

/// <summary>
/// Application-wide session state: holds the currently unlocked vault service
/// and cached settings. Callers access services through this singleton.
/// </summary>
public sealed class SessionManager
    {
    public static SessionManager Instance { get; } = new();

    public VaultService? Vault { get; private set; }
    public VaultSettings? Settings { get; private set; }
    public bool IsUnlocked => Vault?.IsUnlocked == true;
    public string? VaultPath { get; private set; }

    private SessionManager() { }

    public void SetVault(VaultService vault, string path, VaultSettings settings)
        {
        Vault = vault;
        VaultPath = path;
        Settings = settings;
        }

    public void SaveSettings()
        {
        if (Vault is null || Settings is null) return;
        Vault.SaveSettings(Settings);
        }

    public void Lock()
        {
        SaveSettings();
        Vault?.Dispose();
        Vault = null;
        Settings = null;
        VaultPath = null;
        }
    }
