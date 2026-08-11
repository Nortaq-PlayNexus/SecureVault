using System.Security.Cryptography;
using System.Text;

namespace SecureVault.Core.Crypto;

/// <summary>
/// Binary envelope wrapping a data-encryption key under a wrapping key. Format:
///   [cipherSuite:1][nonce:n][ciphertext][tag:16]
/// bound to a purpose AAD so key material can never be replayed across uses.
/// </summary>
public static class KeyEnvelope
    {
    private static readonly byte[] PurposeTag = Encoding.UTF8.GetBytes("securevault:key-envelope:v1");

    public static byte[] Seal(ReadOnlySpan<byte> wrappingKey, ReadOnlySpan<byte> keyMaterial, CipherSuite suite, string context)
        {
        var engine = EncryptionEngine.Create(suite);
        var aad = BuildAad(context);
        return engine.Encrypt(wrappingKey, keyMaterial, aad);
        }

    public static byte[] Open(ReadOnlySpan<byte> wrappingKey, byte[] envelope, CipherSuite suite, string context)
        {
        var engine = EncryptionEngine.Create(suite);
        var aad = BuildAad(context);
        return engine.Decrypt(wrappingKey, envelope, aad);
        }

    public static bool TryOpen(ReadOnlySpan<byte> wrappingKey, byte[] envelope, CipherSuite suite, string context, out byte[]? keyMaterial)
        {
        var engine = EncryptionEngine.Create(suite);
        var aad = BuildAad(context);
        return engine.TryDecrypt(wrappingKey, envelope, out keyMaterial, aad);
        }

    private static byte[] BuildAad(string context)
        {
        var contextBytes = Encoding.UTF8.GetBytes(context);
        var aad = new byte[PurposeTag.Length + 1 + contextBytes.Length];
        PurposeTag.CopyTo(aad, 0);
        aad[PurposeTag.Length] = 0xFF;
        contextBytes.CopyTo(aad, PurposeTag.Length + 1);
        return aad;
        }

    public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        CryptographicOperations.FixedTimeEquals(a, b);
    }
