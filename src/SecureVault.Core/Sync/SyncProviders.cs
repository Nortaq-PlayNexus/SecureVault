using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace SecureVault.Core.Sync;

/// <summary>
/// A sync backend that stores the (already fully encrypted) vault container.
/// Because the vault database contains only ciphertext and the data-encryption
/// key never leaves the device, sync is end-to-end encrypted by construction.
/// </summary>
public interface ISyncProvider
    {
    string Name { get; }
    Task<bool> ExistsAsync(string remotePath, CancellationToken ct = default);
    Task UploadAsync(string remotePath, byte[] content, CancellationToken ct = default);
    Task<byte[]?> DownloadAsync(string remotePath, CancellationToken ct = default);
    Task DeleteAsync(string remotePath, CancellationToken ct = default);
    }

/// <summary>Local-folder sync backend (e.g. Dropbox/OneDrive/NAS mount).</summary>
public sealed class FolderSyncProvider : ISyncProvider
    {
    private readonly string _root;
    public string Name => "Folder";
    public FolderSyncProvider(string root) => _root = root;

    private string Resolve(string remotePath) => Path.Combine(_root, remotePath);

    public Task<bool> ExistsAsync(string remotePath, CancellationToken ct = default) =>
        Task.FromResult(File.Exists(Resolve(remotePath)));

    public async Task UploadAsync(string remotePath, byte[] content, CancellationToken ct = default)
        {
        var path = Resolve(remotePath);
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(path, content, ct).ConfigureAwait(false);
        }

    public async Task<byte[]?> DownloadAsync(string remotePath, CancellationToken ct = default)
        {
        var path = Resolve(remotePath);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false) : null;
        }

    public Task DeleteAsync(string remotePath, CancellationToken ct = default)
        {
        var path = Resolve(remotePath);
        if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
        }
    }

/// <summary>WebDAV sync backend.</summary>
public sealed class WebDavSyncProvider : ISyncProvider, IDisposable
    {
    private readonly HttpClient _http;
    public string Name => "WebDAV";

    public WebDavSyncProvider(string baseUrl, string? username = null, string? password = null, bool ignoreSslErrors = false)
        {
        // Certificate validation bypass is STRICTLY opt-in (ignoreSslErrors) for
        // self-signed WebDAV/NAS servers, never the default. The encrypted
        // container provides confidentiality and integrity independent of TLS.
#pragma warning disable CA5359
        _http = new HttpClient(new SocketsHttpHandler
            {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                {
                RemoteCertificateValidationCallback = ignoreSslErrors ? (_, _, _, _) => true : null!,
                },
            });
#pragma warning restore CA5359
        _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _http.Timeout = TimeSpan.FromSeconds(60);
        if (!string.IsNullOrEmpty(username))
            {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);
            }
        }

    public async Task<bool> ExistsAsync(string remotePath, CancellationToken ct = default)
        {
        var request = new HttpRequestMessage(HttpMethod.Head, remotePath);
        var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        return response.IsSuccessStatusCode;
        }

    public async Task UploadAsync(string remotePath, byte[] content, CancellationToken ct = default)
        {
        // Ensure parent collection exists (best effort).
        var parent = remotePath.Contains('/') ? remotePath[..remotePath.LastIndexOf('/')] : string.Empty;
        if (!string.IsNullOrEmpty(parent)) await EnsureCollectionAsync(parent, ct).ConfigureAwait(false);

        var contentStream = new ByteArrayContent(content);
        var response = await _http.PutAsync(remotePath, contentStream, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        }

    public async Task<byte[]?> DownloadAsync(string remotePath, CancellationToken ct = default)
        {
        var response = await _http.GetAsync(remotePath, ct).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        }

    public async Task DeleteAsync(string remotePath, CancellationToken ct = default)
        {
        var response = await _http.DeleteAsync(remotePath, ct).ConfigureAwait(false);
        if (response.StatusCode != System.Net.HttpStatusCode.NotFound) response.EnsureSuccessStatusCode();
        }

    private async Task EnsureCollectionAsync(string collectionPath, CancellationToken ct)
        {
        var request = new HttpRequestMessage(new HttpMethod("MKCOL"), collectionPath);
        var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        // 201 created, 405 already exists, 301/302 redirect ok
        if (response.StatusCode is System.Net.HttpStatusCode.Created
            or System.Net.HttpStatusCode.Conflict
            or System.Net.HttpStatusCode.MethodNotAllowed) return;
        response.EnsureSuccessStatusCode();
        }

    public void Dispose() => _http.Dispose();
    }
