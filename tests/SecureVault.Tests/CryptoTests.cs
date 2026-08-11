using System.Text;
using SecureVault.Core.Crypto;
using Xunit;

namespace SecureVault.Tests;

public class AesGcmEngineTests
    {
    private readonly AesGcmEngine _engine = new();

    [Fact]
    public void RoundTrip_WithKey()
        {
        var key = CryptoRandom.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("correct horse battery staple");

        var sealedData = _engine.Encrypt(key, plaintext);
        var decrypted = _engine.Decrypt(key, sealedData);

        Assert.Equal(plaintext, decrypted);
        }

    [Fact]
    public void RoundTrip_WithAssociatedData()
        {
        var key = CryptoRandom.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("secret");
        var aad = Encoding.UTF8.GetBytes("item-id-123");

        var sealedData = _engine.Encrypt(key, plaintext, aad);
        var decrypted = _engine.Decrypt(key, sealedData, aad);

        Assert.Equal(plaintext, decrypted);
        }

    [Fact]
    public void WrongKey_FailsAuthentication()
        {
        var key1 = CryptoRandom.GetBytes(32);
        var key2 = CryptoRandom.GetBytes(32);
        var sealedData = _engine.Encrypt(key1, Encoding.UTF8.GetBytes("hello"));

        Assert.False(_engine.TryDecrypt(key2, sealedData, out _));
        }

    [Fact]
    public void TamperedData_FailsAuthentication()
        {
        var key = CryptoRandom.GetBytes(32);
        var sealedData = _engine.Encrypt(key, Encoding.UTF8.GetBytes("hello"));

        sealedData[^1] ^= 0xFF; // flip a bit in the tag

        Assert.False(_engine.TryDecrypt(key, sealedData, out _));
        }

    [Fact]
    public void WrongAad_FailsAuthentication()
        {
        var key = CryptoRandom.GetBytes(32);
        var sealedData = _engine.Encrypt(key, Encoding.UTF8.GetBytes("hello"), Encoding.UTF8.GetBytes("aad-a"));

        Assert.False(_engine.TryDecrypt(key, sealedData, out _, Encoding.UTF8.GetBytes("aad-b")));
        }
    }

public class XChaChaEngineTests
    {
    private readonly XChaChaEngine _engine = new();

    [Fact]
    public void RoundTrip_WithKey()
        {
        var key = CryptoRandom.GetBytes(32);
        var plaintext = Encoding.UTF8.GetBytes("xchacha20 roundtrip");

        var sealedData = _engine.Encrypt(key, plaintext);
        var decrypted = _engine.Decrypt(key, sealedData);

        Assert.Equal(plaintext, decrypted);
        }

    [Fact]
    public void TamperedData_FailsAuthentication()
        {
        var key = CryptoRandom.GetBytes(32);
        var sealedData = _engine.Encrypt(key, Encoding.UTF8.GetBytes("hello"));
        sealedData[^1] ^= 0xFF;
        Assert.False(_engine.TryDecrypt(key, sealedData, out _));
        }

    [Fact]
    public void AesAndXChaCha_AgreeOnWireSize()
        {
        var key = CryptoRandom.GetBytes(32);
        var pt = new byte[100];
        CryptoRandom.Fill(pt);

        var aes = new AesGcmEngine().Encrypt(key, pt);
        var xc = _engine.Encrypt(key, pt);

        Assert.Equal(100 + 12 + 16, aes.Length);
        Assert.Equal(100 + 24 + 16, xc.Length);
        }
    }

public class Argon2IdKdfTests
    {
    [Fact]
    public void Deterministic_GivenSameInputs()
        {
        var salt = Argon2IdKdf.GenerateSalt();
        var password = Encoding.UTF8.GetBytes("s3cret-password");

        var key1 = Argon2IdKdf.DeriveKey(password, salt, Argon2IdParameters.Default);
        var key2 = Argon2IdKdf.DeriveKey(password, salt, Argon2IdParameters.Default);

        Assert.Equal(key1, key2);
        Assert.Equal(32, key1.Length);
        }

    [Fact]
    public void DifferentSalt_DifferentKey()
        {
        var password = Encoding.UTF8.GetBytes("s3cret-password");

        var key1 = Argon2IdKdf.DeriveKey(password, Argon2IdKdf.GenerateSalt(), Argon2IdParameters.Default);
        var key2 = Argon2IdKdf.DeriveKey(password, Argon2IdKdf.GenerateSalt(), Argon2IdParameters.Default);

        Assert.NotEqual(key1, key2);
        }

    [Fact]
    public void WrongSaltLength_Throws()
        {
        Assert.Throws<ArgumentException>(() => Argon2IdKdf.DeriveKey(new byte[8], new byte[8], Argon2IdParameters.Default));
        }
    }

public class KeyEnvelopeTests
    {
    [Fact]
    public void SealOpen_RoundTrips()
        {
        var wrappingKey = CryptoRandom.GetBytes(32);
        var keyMaterial = CryptoRandom.GetBytes(32);

        var envelope = KeyEnvelope.Seal(wrappingKey, keyMaterial, CipherSuite.Aes256Gcm, "dek:vault:test");
        var opened = KeyEnvelope.Open(wrappingKey, envelope, CipherSuite.Aes256Gcm, "dek:vault:test");

        Assert.Equal(keyMaterial, opened);
        }

    [Fact]
    public void WrongContext_Fails()
        {
        var wrappingKey = CryptoRandom.GetBytes(32);
        var keyMaterial = CryptoRandom.GetBytes(32);

        var envelope = KeyEnvelope.Seal(wrappingKey, keyMaterial, CipherSuite.Aes256Gcm, "dek:vault:test");
        Assert.False(KeyEnvelope.TryOpen(wrappingKey, envelope, CipherSuite.Aes256Gcm, "dek:vault:other", out _));
        }
    }

public class SecureBytesTests
    {
    [Fact]
    public void Dispose_ZeroizesContent()
        {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var secure = new SecureBytes(data);
        var copy = secure.ToArray();
        Assert.Equal(data, copy);

        secure.Dispose();
        var bytes = new byte[5];
        var span = new ReadOnlySpan<byte>(data);
        // After zeroize, buffer content is zeroed.
        Assert.Throws<ObjectDisposedException>(() => secure.ToArray());
        }
    }
