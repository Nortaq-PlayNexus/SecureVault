using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// FIDO2/WebAuthn-style passkeys backed by Windows Hello (Microsoft Passport
/// Key Storage Provider). Private keys are non-exportable and protected by the
/// TPM and biometrics / PIN. This implements the credential side of the
/// WebAuthn ceremony (creating &amp; using resident keys).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PasskeyProvider
    {
    private const string PassportProvider = "Microsoft Passport Key Storage Provider";

    public static bool IsAvailable
        {
        get
            {
            try
                {
                var _ = new CngProvider(PassportProvider);
                return true;
                }
            catch
                {
                return false;
                }
            }
        }

    /// <summary>
    /// Create a passkey credential bound to Windows Hello. The key is created in
    /// the Passport KSP (hardware-protected) and is non-exportable.
    /// </summary>
    public static PasskeyCredential CreatePasskey(string rpId, string userId, string displayName, byte[] challenge)
        {
        if (!IsAvailable) throw new PlatformNotSupportedException("Windows Hello is not available on this device.");

        var keyName = $"SecureVault/passkey/{rpId}/{Sanitize(userId)}/{CryptoRandom.NewGuid():N}";
        var creation = new CngKeyCreationParameters
            {
            Provider = new CngProvider(PassportProvider),
            KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ProtectKey,
                friendlyName: "SecureVault passkey sign-in",
                description: "Windows will prompt you to confirm this secure sign-in.",
                useContext: "SecureVault"),
            };

        using var key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creation);
        var publicKey = key.Export(CngKeyBlobFormat.EccPublicBlob);

        // Sign the challenge with the passkey key to complete the credential.
        using var signer = new ECDsaCng(key)
            {
            HashAlgorithm = CngAlgorithm.Sha256,
            };
        var signature = signer.SignData(challenge, HashAlgorithmName.SHA256);

        return new PasskeyCredential(
            Id: CryptoRandom.GetBytes(32),
            RpId: rpId,
            UserId: userId,
            DisplayName: displayName,
            KeyName: keyName,
            PublicKey: publicKey,
            Signature: signature,
            CreatedAt: DateTimeOffset.UtcNow);
        }

    /// <summary>
    /// Authenticate: sign a challenge with an existing passkey key, proving
    /// possession of the hardware-resident private key. Invokes the Windows
    /// Hello confirmation prompt.
    /// </summary>
    public static byte[] Sign(string keyName, byte[] challenge)
        {
        using var key = CngKey.Open(keyName, new CngProvider(PassportProvider), CngKeyOpenOptions.None);
        using var signer = new ECDsaCng(key)
            {
            HashAlgorithm = CngAlgorithm.Sha256,
            };
        return signer.SignData(challenge, HashAlgorithmName.SHA256);
        }

    public static bool Verify(byte[] publicKeyBlob, byte[] challenge, byte[] signature)
        {
        try
            {
            using var key = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
            using var verifier = new ECDsaCng(key);
            return verifier.VerifyData(challenge, signature, HashAlgorithmName.SHA256);
            }
        catch
            {
            return false;
            }
        }

    public static void Delete(string keyName)
        {
        try
            {
            using var key = CngKey.Open(keyName, new CngProvider(PassportProvider), CngKeyOpenOptions.None);
            key.Delete();
            }
        catch (CryptographicException)
            {
            // already gone
            }
        }

    private static string Sanitize(string value)
        {
        var chars = value.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray();
        return new string(chars);
        }
    }

public readonly record struct PasskeyCredential(
    byte[] Id,
    string RpId,
    string UserId,
    string DisplayName,
    string KeyName,
    byte[] PublicKey,
    byte[] Signature,
    DateTimeOffset CreatedAt);

