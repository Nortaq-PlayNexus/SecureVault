using System.Security.Cryptography;
using System.Text;

namespace SecureVault.Core.Crypto;

/// <summary>
/// Domain-separated key derivation: derives distinct sub-keys from a master
/// secret using HMAC-SHA256 with a purpose label, so keys can never be reused
/// across domains.
/// </summary>
public static class KeyDerivation
    {
    public const int KeySize = 32;

    public static byte[] DeriveSubKey(ReadOnlySpan<byte> master, string purpose, int size = KeySize)
        {
        using var hmac = new HMACSHA256(master.ToArray());
        var info = Encoding.UTF8.GetBytes("securevault/" + purpose);
        return hmac.ComputeHash(info)[..size];
        }

    /// <summary>Derive the vault integrity key from the data-encryption key.</summary>
    public static byte[] DeriveIntegrityKey(ReadOnlySpan<byte> dek) => DeriveSubKey(dek, "integrity");
    }
