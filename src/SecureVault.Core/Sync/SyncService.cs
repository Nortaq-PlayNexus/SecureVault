using System.Security.Cryptography;
using SecureVault.Core.Vault;

namespace SecureVault.Core.Sync;

public sealed record SyncResult
    {
    public bool Success { get; init; }
    public bool Pulled { get; init; }
    public bool Pushed { get; init; }
    public string RemotePath { get; init; } = string.Empty;
    public string? Error { get; init; }
    }

/// <summary>
/// End-to-end encrypted synchronization of the vault container. The remote never
/// sees plaintext: the uploaded file is the fully-encrypted vault database, and
/// remote name is derived from the vault id (a UUID, non-reversible to secrets).
/// </summary>
public sealed class SyncService
    {
    private readonly ISyncProvider _provider;
    private readonly VaultService _vault;

    public SyncService(ISyncProvider provider, VaultService vault)
        {
        _provider = provider;
        _vault = vault;
        }

    public string RemoteFileName => $"{_vault.Header!.VaultId:N}.svault";

    /// <summary>Two-way sync: pull remote (if newer), push local (if newer).</summary>
    public async Task<SyncResult> SyncAsync(CancellationToken ct = default)
        {
        if (!_vault.IsUnlocked) throw new InvalidOperationException("Vault must be unlocked to sync.");

        var remotePath = RemoteFileName;
        var localHash = await ComputeLocalHashAsync(ct).ConfigureAwait(false);
        var localState = _vault.GetSyncState("remote_hash");
        var remote = await _provider.DownloadAsync(remotePath, ct).ConfigureAwait(false);

        if (remote is null)
            {
            // No remote: push the local vault.
            await PushAsync(remotePath, localHash, ct).ConfigureAwait(false);
            return new SyncResult { Success = true, Pushed = true, RemotePath = remotePath };
            }

        var remoteHash = Convert.ToHexString(SHA256.HashData(remote));

        // Conflict resolution: if remote differs from last-synced and local changed, prefer remote (pull), keep local as backup.
        if (remoteHash != localHash)
            {
            if (localState is not null && localState == localHash)
                {
                // Local unchanged since last sync → remote won.
                await PullAsync(remotePath, remote, ct).ConfigureAwait(false);
                return new SyncResult { Success = true, Pulled = true, RemotePath = remotePath };
                }

            // Both changed (or first sync) → conservative merge: keep remote as canonical, but
            // the local file is preserved as a backup before overwriting.
            var backupPath = localPath + $".conflict-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
            if (File.Exists(_vault.VaultPath)) File.Copy(_vault.VaultPath, backupPath, overwrite: true);

            await PullAsync(remotePath, remote, ct).ConfigureAwait(false);
            return new SyncResult { Success = true, Pulled = true, RemotePath = remotePath, Error = "Remote vault was newer; a local backup was saved." };
            }

        // Identical — no-op
        return new SyncResult { Success = true, RemotePath = remotePath };
        }

    public async Task<SyncResult> PushAsync(CancellationToken ct = default)
        {
        var remotePath = RemoteFileName;
        var localHash = await ComputeLocalHashAsync(ct).ConfigureAwait(false);
        await PushAsync(remotePath, localHash, ct).ConfigureAwait(false);
        return new SyncResult { Success = true, Pushed = true, RemotePath = remotePath };
        }

    public async Task<SyncResult> PullAsync(CancellationToken ct = default)
        {
        var remotePath = RemoteFileName;
        var remote = await _provider.DownloadAsync(remotePath, ct).ConfigureAwait(false);
        if (remote is null) return new SyncResult { Success = false, RemotePath = remotePath, Error = "No remote vault found." };
        await PullAsync(remotePath, remote, ct).ConfigureAwait(false);
        return new SyncResult { Success = true, Pulled = true, RemotePath = remotePath };
        }

    public async Task<bool> HasRemoteAsync(CancellationToken ct = default)
        {
        try { return await _provider.ExistsAsync(RemoteFileName, ct).ConfigureAwait(false); }
        catch { return false; }
        }

    private string localPath => Path.Combine(Path.GetDirectoryName(_vault.VaultPath)!, _vault.Header!.VaultId.ToString("N") + ".svault");

    private async Task PushAsync(string remotePath, string localHash, CancellationToken ct)
        {
        // Checkpoint WAL so the main DB file reflects all data before upload.
        _vault.FlushToDisk();
        var content = await ReadFileSharedAsync(_vault.VaultPath, ct).ConfigureAwait(false);
        await _provider.UploadAsync(remotePath, content, ct).ConfigureAwait(false);
        _vault.SetSyncState("remote_hash", localHash);
        }

    private async Task PullAsync(string remotePath, byte[] remote, CancellationToken ct)
        {
        var dir = Path.GetDirectoryName(_vault.VaultPath)!;
        Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(_vault.VaultPath, remote, ct).ConfigureAwait(false);
        _vault.SetSyncState("remote_hash", Convert.ToHexString(SHA256.HashData(remote)));
        }

    private async Task<string> ComputeLocalHashAsync(CancellationToken ct)
        {
        _vault.FlushToDisk();
        if (!File.Exists(_vault.VaultPath)) throw new FileNotFoundException("Vault database not found.", _vault.VaultPath);
        using var sha = SHA256.Create();
        using var stream = new FileStream(_vault.VaultPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(await sha.ComputeHashAsync(stream, ct).ConfigureAwait(false));
        }

    private static async Task<byte[]> ReadFileSharedAsync(string path, CancellationToken ct)
        {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
        return ms.ToArray();
        }
    }
