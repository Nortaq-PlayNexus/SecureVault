using System.Security.Cryptography;
using NSec.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// XChaCha20-Poly1305 using the libsodium-backed NSec implementation.
/// Wire format: nonce(24) || ciphertext || tag(16).
/// </summary>
public sealed class XChaChaEngine : IEncryptionEngine
    {
    private const int NonceSize = 24;
    private const int TagSize = 16;

    public CipherSuite Suite => CipherSuite.XChaCha20Poly1305;
    public int KeySizeBytes => 32;
    public int NonceSizeBytes => NonceSize;
    public int TagSizeBytes => TagSize;

    private static readonly AeadAlgorithm Algorithm = AeadAlgorithm.XChaCha20Poly1305;

    public byte[] Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
        if (key.Length != KeySizeBytes) throw new ArgumentException("XChaCha20-Poly1305 requires a 32-byte key.", nameof(key));

        var nonce = CryptoRandom.GetNonce(NonceSize);
        var keyBlob = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
        try
            {
            var ciphertext = Algorithm.Encrypt(keyBlob, nonce, associatedData, plaintext);
            var result = new byte[NonceSize + ciphertext.Length];
            nonce.CopyTo(result, 0);
            ciphertext.CopyTo(result, NonceSize);
            return result;
            }
        finally
            {
            keyBlob.Dispose();
            }
        }

    public byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData = default)
        {
        if (!TryDecrypt(key, sealedData, out var plaintext, associatedData))
            throw new CryptographicException("Authentication failed for XChaCha20-Poly1305 sealed data.");
        return plaintext!;
        }

    public bool TryDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, out byte[]? plaintext, ReadOnlySpan<byte> associatedData = default)
        {
        plaintext = null;
        if (key.Length != KeySizeBytes) return false;
        if (sealedData.Length < NonceSize + TagSize) return false;

        var nonce = sealedData[..NonceSize];
        var ciphertext = sealedData[NonceSize..];

        var keyBlob = Key.Import(Algorithm, key, KeyBlobFormat.RawSymmetricKey);
        try
            {
            plaintext = Algorithm.Decrypt(keyBlob, nonce, associatedData, ciphertext);
            return plaintext is not null;
            }
        catch
            {
            return false;
            }
        finally
            {
            keyBlob.Dispose();
            }
        }
    }
