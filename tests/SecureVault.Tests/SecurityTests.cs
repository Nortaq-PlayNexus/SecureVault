using System.Linq;
using SecureVault.Core.AI;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;
using SecureVault.Core.Security;
using Xunit;

namespace SecureVault.Tests;

public class PasswordGeneratorTests
    {
    [Fact]
    public void GeneratesRequestedLength()
        {
        var password = PasswordGenerator.Generate(new PasswordOptions { Length = 24 });
        Assert.Equal(24, password.Length);
        }

    [Fact]
    public void IncludesAllEnabledClasses()
        {
        var password = PasswordGenerator.Generate(new PasswordOptions { Length = 64 });
        Assert.Contains(password, char.IsLower);
        Assert.Contains(password, char.IsUpper);
        Assert.Contains(password, char.IsDigit);
        Assert.Contains(password, c => !char.IsLetterOrDigit(c));
        }

    [Fact]
    public void UniqueOutputs_AreDistinct()
        {
        var set = Enumerable.Range(0, 20).Select(_ => PasswordGenerator.Generate()).ToHashSet();
        Assert.Equal(20, set.Count);
        }

    [Fact]
    public void Passphrase_HasExpectedWordCount()
        {
        var phrase = PasswordGenerator.GeneratePassphrase(6, "-", includeDigit: false);
        Assert.Equal(6, phrase.Split('-').Length);
        Assert.DoesNotContain(phrase, char.IsUpper);
        }

    [Fact]
    public void EmptyOptions_Throws()
        {
        Assert.Throws<InvalidOperationException>(() => PasswordGenerator.Generate(new PasswordOptions
            {
            IncludeLowercase = false,
            IncludeUppercase = false,
            IncludeDigits = false,
            IncludeSymbols = false,
            }));
        }

    [Fact]
    public void EntropyIsReasonable()
        {
        var password = PasswordGenerator.Generate(new PasswordOptions { Length = 20 });
        Assert.True(PasswordGenerator.EstimateEntropy(password) > 100);
        }
    }

public class PhishingDetectorTests
    {
    [Theory]
    [InlineData("https://paypal-secure-login.com/verify")]
    [InlineData("http://amazon.com")]                       // HTTP (unencrypted)
    [InlineData("https://secure-bankofamerica.xyz/login")]
    [InlineData("https://microsoft-account-verify.net")]
    public void DetectsSuspiciousUrls(string url)
        {
        var result = PhishingDetector.Analyze(url);
        Assert.True(result.Suspicious, $"Expected {url} to be flagged.");
        }

    [Theory]
    [InlineData("https://www.paypal.com/signin")]
    [InlineData("https://github.com/login")]
    [InlineData("https://mail.google.com")]
    [InlineData("")]
    public void AllowsLegitimateUrls(string url)
        {
        var result = PhishingDetector.Analyze(url);
        Assert.False(result.Suspicious, $"Expected {url} to be allowed.");
        }
    }

public class AiOrganizerTests
    {
    [Fact]
    public void SuggestsTagsForBankingSite()
        {
        var item = new VaultItem { Id = CryptoRandom.NewGuid(), Title = "Chase Bank", Type = VaultItemType.Login };
        var payload = new LoginPayload { Url = "https://chase.com/bank" };

        var suggestion = AiOrganizer.SuggestTags(item, payload);
        Assert.NotNull(suggestion);
        Assert.Contains("finance", suggestion!.SuggestedTags);
        }

    [Fact]
    public void NoTags_ForUnknownContent()
        {
        var item = new VaultItem { Id = CryptoRandom.NewGuid(), Title = "Qwerty Placeholder", Type = VaultItemType.Note };
        var suggestion = AiOrganizer.SuggestTags(item, new NotePayload { Text = "random text qwerty" });
        Assert.Null(suggestion);
        }

    [Fact]
    public void FlagsWeakPassword()
        {
        var findings = AiOrganizer.AnalyzeStrength("password", "bob", "https://example.com");
        Assert.NotEmpty(findings);
        }
    }
