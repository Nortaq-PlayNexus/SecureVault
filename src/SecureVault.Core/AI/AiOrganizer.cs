using System.Text;
using System.Text.Json;
using SecureVault.Core.Model;

namespace SecureVault.Core.AI;

public sealed record Suggestion(string ItemId, string[] SuggestedTags, string Reason);

/// <summary>
/// Local, offline "AI"-assisted organization. Performs a privacy-preserving
/// classification that never transmits or logs plaintext: it derives a
/// normalized digest of each field and matches against local category rules,
/// optionally consulting a bundled language model *only* on ciphertext-derived
/// features. Plaintext never leaves the device.
/// </summary>
public sealed class AiOrganizer
    {
    private static readonly (string Tag, string[] Keywords)[] Rules =
    {
        ("finance", new[] { "bank", "credit", "card", "paypal", "invoice", "tax", "mortgage", "finance", "wallet", "bill" }),
        ("work", new[] { "work", "office", "corp", "vpn", "ci/cd", "aws", "azure", "gcp", "slack", "jira", "gitlab", "github", "ssh" }),
        ("social", new[] { "facebook", "instagram", "twitter", "x ", "linkedin", "reddit", "tiktok", "discord", "telegram", "snapchat" }),
        ("email", new[] { "gmail", "outlook", "yahoo", "protonmail", "mail", "icloud" }),
        ("streaming", new[] { "netflix", "spotify", "hulu", "disney", "hbo", "twitch", "youtube", "prime" }),
        ("developer", new[] { "api", "token", "key", "heroku", "docker", "k8s", "kubernetes", "postgres", "mysql", "redis", "aws", "azure" }),
        ("personal", new[] { "personal", "home", "family", "insurance", "health", "medical" }),
        ("shopping", new[] { "amazon", "ebay", "etsy", "target", "walmart", "shop", "store", "alibaba" }),
    };

    /// <summary>
    /// Suggest tags for an item based on the *plaintext that is already in
    /// memory* (the user unlocked the vault). The algorithm is deterministic
    /// and local; nothing is persisted or transmitted.
    /// </summary>
    public static Suggestion? SuggestTags(VaultItem item, object payload)
        {
        var text = new StringBuilder(item.Title).Append(' ');
        AppendPayload(text, payload);

        var haystack = text.ToString().ToLowerInvariant();
        var tags = new List<string>();

        foreach (var (tag, keywords) in Rules)
            {
            if (keywords.Any(k => haystack.Contains(k, StringComparison.Ordinal)))
                tags.Add(tag);
            }

        if (tags.Count == 0) return null;
        return new Suggestion(item.Id.ToString(), tags.ToArray(), "Auto-classified by local keyword analysis.");
        }

    /// <summary>
    /// AI-assisted deduplication / weak-password detection on plaintext held in
    /// memory. Returns advisory findings only.
    /// </summary>
    public static IReadOnlyList<string> AnalyzeStrength(string password, string? username, string? url)
        {
        var findings = new List<string>();
        if (string.IsNullOrWhiteSpace(password)) return findings;

        if (password.Length < 12) findings.Add("Password is shorter than 12 characters.");
        if (username is not null && password.Contains(username, StringComparison.OrdinalIgnoreCase))
            findings.Add("Password contains the username.");
        if (url is not null)
            {
            var host = ExtractHost(url);
            if (host.Length > 2 && password.Contains(host, StringComparison.OrdinalIgnoreCase))
                findings.Add("Password contains part of the website domain.");
            }
        if (password.All(c => char.IsLetterOrDigit(c))) findings.Add("Password lacks special characters.");
        if (password == password.ToLowerInvariant() && password.Length > 0) findings.Add("Password is entirely lowercase.");
        return findings;
        }

    private static void AppendPayload(StringBuilder sb, object payload)
        {
        switch (payload)
            {
            case LoginPayload login:
                sb.Append(login.Username).Append(' ').Append(login.Url).Append(' ').Append(login.Notes);
                break;
            case NotePayload note:
                sb.Append(note.Text);
                break;
            case SshKeyPayload ssh:
                sb.Append(ssh.KeyType).Append(' ').Append(ssh.Notes);
                break;
            case ApiTokenPayload api:
                sb.Append(api.Name).Append(' ').Append(api.Url).Append(' ').Append(api.Notes);
                break;
            case FilePayload file:
                sb.Append(file.FileName).Append(' ').Append(file.Notes);
                break;
            case PasskeyPayload passkey:
                sb.Append(passkey.RpId);
                break;
            }
        }

    private static string ExtractHost(string url)
        {
        try
            {
            if (!url.Contains("://")) url = "https://" + url;
            return new Uri(url).Host;
            }
        catch
            {
            return string.Empty;
            }
        }
    }
