namespace SecureVault.Core.Security;

public sealed record PhishingAnalysisResult
    {
    public bool Suspicious { get; init; }
    public string[] Reasons { get; init; } = Array.Empty<string>();
    public double RiskScore { get; init; }
    }

/// <summary>
/// Heuristic phishing/domain-lookalike detection. Operates entirely on
/// non-secret data (URLs / domains) and never transmits anything.
/// </summary>
public sealed class PhishingDetector
    {
    private static readonly string[] CommonTlds =
        { "com", "net", "org", "io", "co", "dev", "app", "info", "biz", "xyz", "online", "site", "shop", "store", "me" };

    private static readonly string[] Brands =
        { "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp",
          "chase", "wellsfargo", "bankofamerica", "gmail", "yahoo", "outlook", "twitter", "github", "dropbox", "linkedin" };

    public static PhishingAnalysisResult Analyze(string? url)
        {
        if (string.IsNullOrWhiteSpace(url)) return new PhishingAnalysisResult();
        var reasons = new List<string>();

        if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            reasons.Add("Uses unencrypted HTTP");

        var host = ExtractHost(url);
        if (string.IsNullOrEmpty(host))
            {
            reasons.Add("Could not parse domain");
            return new PhishingAnalysisResult { Suspicious = true, Reasons = reasons.ToArray(), RiskScore = 0.3 };
            }

        if (System.Net.IPAddress.TryParse(host.Split(':')[0], out _))
            reasons.Add("Domain is a raw IP address");

        var labels = host.Split('.');
        var registered = GetRegistrableName(labels);

        // Exact brand registered name with an unusual TLD (e.g. paypal.xyz)
        if (labels.Length >= 2)
            {
            var baseName = labels[^2];
            var tld = labels[^1];
            if (Brands.Contains(baseName.ToLowerInvariant()) && !CommonTlds.Contains(tld.ToLowerInvariant()))
                reasons.Add($"Brand '{baseName}' paired with uncommon TLD '.{tld}'");
            }

        // Brand hidden in a subdomain (e.g. login.paypal.verify.com)
        if (labels.Length >= 3)
            {
            var subName = labels[^3];
            if (Brands.Contains(subName.ToLowerInvariant()))
                reasons.Add($"Brand '{subName}' used as a subdomain");
            }

        // Hyphenated brand impersonation (e.g. paypal-secure.com, microsoft-account.net)
        if (registered is not null && HasHyphenatedBrand(registered))
            reasons.Add("Domain contains a hyphenated brand impersonation");

        // Homoglyph / substitution lookalikes of a brand (e.g. paypa1.com, rnicrosoft.com)
        if (registered is not null && IsLookalike(registered, out var target))
            reasons.Add($"Domain resembles '{target}' (lookalike)");

        if (labels.Length > 5) reasons.Add("Unusually long domain");

        return new PhishingAnalysisResult
            {
            Suspicious = reasons.Count > 0,
            Reasons = reasons.ToArray(),
            RiskScore = Math.Min(reasons.Count * 0.25, 1.0),
            };
        }

    private static string? ExtractHost(string url)
        {
        var cleaned = url.Trim();
        var proto = cleaned.IndexOf("://", StringComparison.Ordinal);
        if (proto >= 0) cleaned = cleaned[(proto + 3)..];
        var end = cleaned.IndexOfAny(new[] { '/', '?', '#', ':' });
        if (end >= 0) cleaned = cleaned[..end];
        if (string.IsNullOrEmpty(cleaned)) return null;
        return cleaned;
        }

    /// <summary>eTLD+1 heuristic using a small common-TLD list; returns null for unknown TLDs.</summary>
    private static string? GetRegistrableName(string[] labels)
        {
        if (labels.Length < 2) return labels.Length == 1 ? labels[0] : null;
        var tld = labels[^1].ToLowerInvariant();
        if (CommonTlds.Contains(tld))
            {
            var name = labels[^2].ToLowerInvariant();
            return name + "." + tld;
            }
        return labels.Length == 2 ? labels[^2].ToLowerInvariant() + "." + tld : null;
        }

    private static bool HasHyphenatedBrand(string registrable)
        {
        var baseName = registrable.Split('.')[0];
        return Brands.Any(b => baseName.Contains(b + "-") || baseName.Contains("-" + b));
        }

    private static bool IsLookalike(string registrable, out string target)
        {
        target = string.Empty;
        var baseName = registrable.Split('.')[0];
        if (string.IsNullOrEmpty(baseName)) return false;

        foreach (var brand in Brands)
            {
            if (baseName == brand) continue; // exact brand is fine
            if (baseName.Contains(brand)) { target = brand; return true; }
            if (baseName.Length == brand.Length && DamerauLevenshtein(baseName, brand) <= 1)
                {
                target = brand;
                return true;
                }
            }
        return false;
        }

    private static int DamerauLevenshtein(string a, string b)
        {
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;

        for (int i = 1; i <= a.Length; i++)
            {
            for (int j = 1; j <= b.Length; j++)
                {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    {
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
                    }
                }
            }
        return d[a.Length, b.Length];
        }
    }
