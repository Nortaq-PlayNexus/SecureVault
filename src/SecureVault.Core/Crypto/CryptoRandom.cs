using System.Security.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// CSPRNG-backed helpers for random byte and nonce generation.
/// All random material in the vault must flow through this type.
/// </summary>
public static class CryptoRandom
    {
    public static byte[] GetBytes(int count)
        {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        var buffer = new byte[count];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
        }

    public static void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    public static byte[] GetNonce(int size) => GetBytes(size);

    public static int GetInt(int maxExclusive)
        {
        if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));
        using var rng = RandomNumberGenerator.Create();
        var buffer = new byte[4];
        rng.GetBytes(buffer);
        uint value = BitConverter.ToUInt32(buffer, 0) & 0x7FFFFFFF;
        return (int)(value % (uint)maxExclusive);
        }

    public static Guid NewGuid()
        {
        var bytes = GetBytes(16);
        return new Guid(bytes);
        }
    }
