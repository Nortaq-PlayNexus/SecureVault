using System.Text.Json.Serialization;

namespace SecureVault.Core.Model;

public enum VaultItemType
    {
    Login = 1,
    Note = 2,
    SshKey = 3,
    ApiToken = 4,
    File = 5,
    Passkey = 6,
    }

/// <summary>Encrypted payload types stored in the vault.</summary>
public static class VaultItemPayload
    {
    public const string KindKey = "kind";
    public const string KindLogin = "login";
    public const string KindNote = "note";
    public const string KindSshKey = "ssh";
    public const string KindApiToken = "api";
    public const string KindFile = "file";
    public const string KindPasskey = "passkey";
    }

/// <summary>A single encrypted entry in the vault.</summary>
public sealed class VaultItem
    {
    public Guid Id { get; set; } = Guid.NewGuid();
    public VaultItemType Type { get; set; }
    public string Title { get; set; } = string.Empty;
    public string[] Tags { get; set; } = Array.Empty<string>();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public int Version { get; set; } = 1;
    public bool Favorite { get; set; }
    public bool Deleted { get; set; }

    /// <summary>Encrypted JSON payload (metadata).</summary>
    public byte[] EncryptedPayload { get; set; } = Array.Empty<byte>();

    /// <summary>Encrypted raw content, used for file items.</summary>
    public byte[]? EncryptedContent { get; set; }
    }

public sealed class LoginPayload
    {
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? OtpSecret { get; set; }
    public string? Notes { get; set; }
    }

public sealed class NotePayload
    {
    public string Text { get; set; } = string.Empty;
    }

public sealed class SshKeyPayload
    {
    public string KeyType { get; set; } = "ed25519";
    public string PrivateKey { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string? Passphrase { get; set; }
    public string? Notes { get; set; }
    }

public sealed class ApiTokenPayload
    {
    public string Name { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string? Url { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public string? Notes { get; set; }
    }

public sealed class FilePayload
    {
    public string FileName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public long Size { get; set; }
    public string? Notes { get; set; }
    }

public sealed class PasskeyPayload
    {
    public string RpId { get; set; } = string.Empty;
    public string UserHandle { get; set; } = string.Empty;
    public string CredentialId { get; set; } = string.Empty;
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    public string? Notes { get; set; }
    }

/// <summary>An encrypted snapshot of an entry for version history.</summary>
public sealed class ItemVersion
    {
    public Guid ItemId { get; set; }
    public int Version { get; set; }
    public byte[] EncryptedPayload { get; set; } = Array.Empty<byte>();
    public byte[]? EncryptedContent { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string ChangeNote { get; set; } = string.Empty;
    }
