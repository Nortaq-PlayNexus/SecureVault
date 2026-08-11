namespace SecureVault.Core.Crypto;

public enum CipherSuite
    {
    Aes256Gcm = 1,
    XChaCha20Poly1305 = 2,
    }

/// <summary>
/// Symmetric encryption engine contract. All engines use AEAD with a 32-byte
/// key and support associated data binding (e.g. entry id / version).
/// </summary>
public interface IEncryptionEngine
    {
    CipherSuite Suite { get; }
    int KeySizeBytes { get; }
    int NonceSizeBytes { get; }
    int TagSizeBytes { get; }

    /// <summary>Encrypt plaintext. Returns nonce || ciphertext || tag.</summary>
    byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);

    /// <summary>Decrypt a buffer produced by <see cref="Encrypt"/>.</summary>
    byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData = default);

    /// <summary>Attempt to decrypt, returning false instead of throwing on auth failure.</summary>
    bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, out byte[]? plaintext, ReadOnlySpan<byte> associatedData = default);
    }

public static class EncryptionEngine
    {
    public static IEncryptionEngine Create(CipherSuite suite) => suite switch
        {
            CipherSuite.Aes256Gcm => new AesGcmEngine(),
            CipherSuite.XChaCha20Poly1305 => new XChaChaEngine(),
            _ => throw new NotSupportedException($"Cipher suite {suite} is not supported."),
            };
    }
