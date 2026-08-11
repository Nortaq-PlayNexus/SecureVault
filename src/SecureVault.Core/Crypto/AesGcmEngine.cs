using System.Security.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// AES-256-GCM using the OS-backed System.Security.Cryptography implementation.
/// Wire format: nonce(12) || ciphertext || tag(16).
/// </summary>
public sealed class AesGcmEngine : IEncryptionEngine
    {
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public CipherSuite Suite => CipherSuite.Aes256Gcm;
    public int KeySizeBytes => 32;
    public int NonceSizeBytes => NonceSize;
    public int TagSizeBytes => TagSize;

    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
        if (key.Length != KeySizeBytes) throw new ArgumentException("AES-256-GCM requires a 32-byte key.", nameof(key));

        var nonce = CryptoRandom.GetNonce(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(key);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var result = new byte[NonceSize + ciphertext.Length + TagSize];
        nonce.CopyTo(result, 0);
        ciphertext.CopyTo(result, NonceSize);
        tag.CopyTo(result, NonceSize + ciphertext.Length);
        return result;
        }

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData = default)
        {
        if (!TryDecrypt(key, sealedData, out var plaintext, associatedData))
            throw new CryptographicException("Authentication failed for AES-256-GCM sealed data.");
        return plaintext!;
        }

    public bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, out byte[]? plaintext, ReadOnlySpan<byte> associatedData = default)
        {
        plaintext = null;
        if (key.Length != KeySizeBytes) return false;
        if (sealedData.Length < NonceSize + TagSize) return false;

        var nonce = sealedData[..NonceSize];
        var tag = sealedData[^TagSize..];
        var ciphertext = sealedData[NonceSize..^TagSize];

        var result = new byte[ciphertext.Length];
        try
            {
            using var gcm = new AesGcm(key);
            gcm.Decrypt(nonce, ciphertext, tag, result, associatedData);
            }
        catch (CryptographicException)
            {
            CryptographicOperations.ZeroMemory(result);
            return false;
            }

        plaintext = result;
        return true;
        }
    }
