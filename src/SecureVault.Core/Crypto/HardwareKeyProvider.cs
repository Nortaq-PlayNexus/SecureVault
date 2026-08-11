using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// Hardware-backed key protection. Uses the TPM via the CNG "Microsoft Platform
/// Crypto Provider" KSP when available, falling back to DPAPI (current-user
/// protected data) otherwise. Never exports private key material.
/// </summary>
[SupportedOSPlatform("windows")]
public interface IHardwareKeyProvider
    {
    string Name { get; }
    bool IsHardwareBacked { get; }
    bool IsAvailable { get; }
    byte[] Protect(byte[] plaintext, string context);
    byte[] Unprotect(byte[] protectedData, string context);
    void Delete(string context);
    }

[SupportedOSPlatform("windows")]
public sealed class HardwareKeyProvider : IHardwareKeyProvider
    {
    private const string TpmProvider = "Microsoft Platform Crypto Provider";

    private readonly string _keyPrefix;

    public HardwareKeyProvider(string vaultId)
        {
        _keyPrefix = $"SecureVault/{vaultId}/";
        }

    public string Name => "TPM+DPAPI";
    public bool IsHardwareBacked => TpmAvailable();

    public bool IsAvailable => true; // DPAPI always available; TPM preferred

    public byte[] Protect(byte[] plaintext, string context)
        {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

        var keyName = _keyPrefix + context;

        if (TpmAvailable())
            {
            try
                {
                using var key = GetOrCreateTpmKey(keyName);
                using var rsa = new RSACng(key);
                return new byte[] { 1 }.Concat(rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256)).ToArray();
                }
            catch (CryptographicException)
                {
                // TPM operation failed (e.g. key eviction policy) — fall back to DPAPI.
                }
            }

        var entropy = GetContextEntropy(context);
        var protectedBytes = ProtectedData.Protect(plaintext, entropy, DataProtectionScope.CurrentUser);
        return new byte[] { 0 }.Concat(protectedBytes).ToArray();
        }

    public byte[] Unprotect(byte[] protectedData, string context)
        {
        if (protectedData is null || protectedData.Length == 0)
            throw new ArgumentException("Invalid protected data.", nameof(protectedData));

        var mode = protectedData[0];
        var payload = protectedData[1..];

        if (mode == 1)
            {
            var keyName = _keyPrefix + context;
            try
                {
                using var key = CngKey.Open(keyName, new CngProvider(TpmProvider), CngKeyOpenOptions.None);
                using var rsa = new RSACng(key);
                return rsa.Decrypt(payload, RSAEncryptionPadding.OaepSHA256);
                }
            catch (CryptographicException)
                {
                throw new CryptographicException("Unable to decrypt with the TPM key. The key may have been evicted or the TPM state changed.");
                }
            }

        var entropy = GetContextEntropy(context);
        return ProtectedData.Unprotect(payload, entropy, DataProtectionScope.CurrentUser);
        }

    public void Delete(string context)
        {
        var keyName = _keyPrefix + context;
        try
            {
            using var key = CngKey.Open(keyName, new CngProvider(TpmProvider), CngKeyOpenOptions.None);
            key.Delete();
            }
        catch (CryptographicException)
            {
            // key already absent
            }
        }

    private static CngKey GetOrCreateTpmKey(string name)
        {
        try
            {
            return CngKey.Open(name, new CngProvider(TpmProvider), CngKeyOpenOptions.None);
            }
        catch (CryptographicException)
            {
            var creation = new CngKeyCreationParameters
                {
                Provider = new CngProvider(TpmProvider),
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Decryption,
                };
            var key = CngKey.Create(CngAlgorithm.Rsa, name, creation);
            return key;
            }
        }

    private static bool TpmAvailable()
        {
        try
            {
            _ = new CngProvider(TpmProvider);
            return true;
            }
        catch
            {
            return false;
            }
        }

    private static byte[] GetContextEntropy(string context)
        {
        if (string.IsNullOrEmpty(context)) return Array.Empty<byte>();
        using var sha = SHA256.Create();
        return sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes("securevault:" + context));
        }
    }

