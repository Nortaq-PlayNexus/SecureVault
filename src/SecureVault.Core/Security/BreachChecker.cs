using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace SecureVault.Core.Security;

public sealed record BreachCheckResult
    {
    public bool Exposed { get; init; }
    public string Suffix { get; init; } = string.Empty;
    public int Count { get; init; }
    public string? Sha1Prefix { get; init; }
    public bool IsPwnedPassword { get; init; }
    }

/// <summary>
/// Breach intelligence using the HaveIBeenPwned k-anonymity API. Only the first
/// 5 hex chars of the SHA-1 password hash are ever sent; the full password and
/// full hash never leave the device.
/// </summary>
public sealed class BreachChecker : IDisposable
    {
    private readonly HttpClient _http;
    private readonly bool _networkEnabled;

    public BreachChecker(bool networkEnabled = true)
        {
        _networkEnabled = networkEnabled;
        _http = new HttpClient();
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("SecureVault/1.0 (breach-checker)");
        _http.Timeout = TimeSpan.FromSeconds(15);
        }

    // SHA-1 is REQUIRED by the HaveIBeenPwned k-anonymity protocol. Only the
    // first 5 hex chars of the hash are ever transmitted; the full hash and the
    // password never leave the device, so the weakness of SHA-1 preimages is
    // not exploitable in this design.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "HIBP k-anonymity API requires SHA-1 prefixes; full hashes never leave the device.")]
    public async Task<BreachCheckResult> CheckPasswordAsync(string password, CancellationToken ct = default)
        {
        if (!_networkEnabled || string.IsNullOrEmpty(password))
            return new BreachCheckResult();

        using var sha1 = SHA1.Create();
        var hash = Convert.ToHexString(sha1.ComputeHash(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..5];
        var suffix = hash[5..];

        var url = $"https://api.pwnedpasswords.com/range/{prefix}";
        try
            {
            var response = await _http.GetAsync(url, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            foreach (var line in body.Split('\n'))
                {
                var parts = line.Trim().Split(':');
                if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                    return new BreachCheckResult
                        {
                        Exposed = true,
                        Suffix = suffix,
                        Count = int.TryParse(parts[1], out var n) ? n : 0,
                        Sha1Prefix = prefix,
                        IsPwnedPassword = true,
                        };
                    }
                }
            return new BreachCheckResult { Exposed = false, Suffix = suffix, Sha1Prefix = prefix };
            }
        catch (HttpRequestException)
            {
            return new BreachCheckResult { Exposed = false, Sha1Prefix = prefix };
            }
        catch (TaskCanceledException)
            {
            return new BreachCheckResult { Exposed = false, Sha1Prefix = prefix };
            }
        }

    public void Dispose() => _http.Dispose();
    }
