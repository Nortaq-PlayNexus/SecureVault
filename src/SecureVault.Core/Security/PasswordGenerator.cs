using System.Text;
using SecureVault.Core.Crypto;

namespace SecureVault.Core.Security;

public sealed record PasswordOptions
    {
    public int Length { get; init; } = 20;
    public bool IncludeLowercase { get; init; } = true;
    public bool IncludeUppercase { get; init; } = true;
    public bool IncludeDigits { get; init; } = true;
    public bool IncludeSymbols { get; init; } = true;
    public bool ExcludeAmbiguous { get; init; } = true;
    public string CustomCharset { get; init; } = string.Empty;
    }

/// <summary>
/// Cryptographically secure random password and passphrase generation.
/// </summary>
public sealed class PasswordGenerator
    {
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{};:,.<>?";
    private const string Ambiguous = "Il1O0|`'\"";

    private static readonly string[] Diceware =
    {
        "abacus","ability","absent","academy","access","accident","account","accuse","achieve","acid",
        "acoustic","acquire","across","action","active","actor","actually","adapt","address","admire",
        "adult","advance","adventure","advice","afford","afraid","africa","after","again","against",
        "agency","airport","alarm","alcohol","almost","alley","alone","alpha","already","alright",
        "altitude","amber","ambition","amount","ancient","angle","animal","answer","anthem","anyone",
        "apart","apology","appear","apple","approach","april","apron","arcade","arch","area","arena",
        "argue","arise","armchair","armed","around","arrange","arrow","artist","asleep","aspect",
        "assault","assist","assume","asthma","athlete","atom","attic","attitude","attract","auction",
        "audience","aunt","author","autumn","avenue","average","avoid","award","aware","away",
        "awesome","axis","baby","backdrop","backup","bacon","badge","bagpipe","balance","balloon",
        "bamboo","banana","band","bandwidth","banner","banquet","bargain","barrel","basement","basic",
        "basket","bass","battle","bayonet","beach","beacon","bead","beak","beam","bean",
        "bear","beard","beast","beauty","become","bedroom","beef","before","begin","behave",
        "behind","belief","belong","below","bench","benefit","berry","beside","better","beyond",
        "bicycle","bifocal","bike","billing","binary","binding","biology","bird","birth","biscuit",
        "bishop","bitcoin","blackout","blade","blanket","blaze","blessing","blindfold","blink","blizzard",
        "block","blood","bloom","blossom","blueprint","blunder","board","bobcat","body","bogus",
    };

    public static string Generate(PasswordOptions? options = null)
        {
        options ??= new PasswordOptions();

        var charset = BuildCharset(options);
        if (charset.Length == 0)
            throw new InvalidOperationException("At least one character class must be enabled.");

        var sb = new StringBuilder(options.Length);
        for (int i = 0; i < options.Length; i++)
            sb.Append(charset[CryptoRandom.GetInt(charset.Length)]);
        return sb.ToString();
        }

    /// <summary>Generate a strong random passphrase from the Diceware word list.</summary>
    public static string GeneratePassphrase(int wordCount = 6, string separator = "-", bool includeDigit = true)
        {
        var words = new string[wordCount];
        for (int i = 0; i < wordCount; i++)
            words[i] = Diceware[CryptoRandom.GetInt(Diceware.Length)];
        var phrase = string.Join(separator, words);
        if (includeDigit)
            {
            var digit = CryptoRandom.GetInt(10).ToString(System.Globalization.CultureInfo.InvariantCulture);
            var pos = CryptoRandom.GetInt(wordCount + 1);
            var parts = new List<string>(words) { digit };
            parts.Insert(pos, digit);
            return string.Join(separator, parts);
            }
        return phrase;
        }

    /// <summary>Rough entropy estimate of a password in bits.</summary>
    public static double EstimateEntropy(string password)
        {
        if (string.IsNullOrEmpty(password)) return 0;
        var pool = 0;
        if (password.Any(char.IsLower)) pool += 26;
        if (password.Any(char.IsUpper)) pool += 26;
        if (password.Any(char.IsDigit)) pool += 10;
        if (password.Any(c => !char.IsLetterOrDigit(c))) pool += 33;
        return password.Length * Math.Log2(pool);
        }

    private static string BuildCharset(PasswordOptions options)
        {
        var sb = new StringBuilder();
        if (options.CustomCharset.Length > 0) return options.CustomCharset;
        if (options.IncludeLowercase) sb.Append(Lower);
        if (options.IncludeUppercase) sb.Append(Upper);
        if (options.IncludeDigits) sb.Append(Digits);
        if (options.IncludeSymbols) sb.Append(Symbols);

        if (options.ExcludeAmbiguous)
            {
            foreach (var c in Ambiguous)
                sb.Replace(c.ToString(), string.Empty);
            }
        return sb.ToString();
        }
    }
