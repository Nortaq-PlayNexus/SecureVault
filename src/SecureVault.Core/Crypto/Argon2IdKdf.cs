using NSec.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>Argon2id parameters (RFC 9106).</summary>
public readonly record struct Argon2IdParameters(int DegreeOfParallelism, long MemorySizeKib, long NumberOfPasses)
    {
    public static readonly Argon2IdParameters Default = new(1, 64 * 1024, 3);        // 64 MiB, 3 passes
    public static readonly Argon2IdParameters Moderate = new(1, 256 * 1024, 3);      // 256 MiB, 3 passes
    public static readonly Argon2IdParameters Strong = new(1, 1024 * 1024, 4);       // 1 GiB, 4 passes

    public Argon2Parameters ToNSec() => new()
        {
        DegreeOfParallelism = DegreeOfParallelism,
        MemorySize = MemorySizeKib,
        NumberOfPasses = NumberOfPasses,
        };
    }

/// <summary>
/// Argon2id key derivation wrapping the libsodium-backed NSec implementation.
/// </summary>
public sealed class Argon2IdKdf
    {
    public const int SaltSizeBytes = 16;

    public static byte[] GenerateSalt() => CryptoRandom.GetBytes(SaltSizeBytes);

    /// <summary>Derive a key from a password using Argon2id.</summary>
    public static byte[] DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Argon2IdParameters parameters, int keySizeBytes = 32)
        {
        if (salt.Length != SaltSizeBytes)
            throw new ArgumentException($"Argon2id requires a {SaltSizeBytes}-byte salt.", nameof(salt));

        var nsParams = parameters.ToNSec();
        var algorithm = new Argon2id(in nsParams);
        return algorithm.DeriveBytes(password, salt, keySizeBytes);
        }
    }
