using SecureVault.Core.Crypto;

namespace SecureVault.Core.Model;

/// <summary>
/// The vault header: KDF parameters, cipher suite, the wrapped data-encryption
/// key envelopes (password and optional hardware/TPM), plus a tamper-evident
/// MAC. The header itself contains no plaintext secrets.
/// </summary>
public sealed class VaultHeader
    {
    public const int CurrentSchemaVersion = 1;
    public const int KeySizeBytes = 32;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;
    public Guid VaultId { get; set; } = Guid.NewGuid();
    public CipherSuite CipherSuite { get; set; } = CipherSuite.Aes256Gcm;

    public string KdfName { get; set; } = "argon2id";
    public byte[] KdfSalt { get; set; } = Array.Empty<byte>();
    public Argon2IdParameters KdfParameters { get; set; } = Argon2IdParameters.Default;

    /// <summary>DEK wrapped by the Argon2id-derived master key.</summary>
    public byte[] PasswordWrappedDek { get; set; } = Array.Empty<byte>();

    /// <summary>DEK wrapped by the hardware key (TPM/DPAPI), optional.</summary>
    public byte[]? HardwareWrappedDek { get; set; }

    /// <summary>HMAC-SHA256 over the serialized header, keyed with the integrity key.</summary>
    public byte[]? IntegrityMac { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    public string VaultName { get; set; } = "My Vault";
    }
