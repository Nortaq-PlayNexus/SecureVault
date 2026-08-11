using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SecureVault.Core.Model;
using SecureVault.Core.Sync;
using SecureVault.Core.Vault;
using Xunit;

namespace SecureVault.Tests;

public class SyncServiceTests : IDisposable
    {
    private readonly string _tempDir;
    public SyncServiceTests()
        {
        _tempDir = Path.Combine(Path.GetTempPath(), "sv-sync-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        }

    public void Dispose()
        {
        GC.SuppressFinalize(this);
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

    [Fact]
    public async Task PushThenPull_OnSecondDevice_RoundTrips()
        {
        var remoteRoot = Path.Combine(_tempDir, "remote");
        var vaultA = Path.Combine(_tempDir, "deviceA.db");
        var vaultB = Path.Combine(_tempDir, "deviceB.db");

        // Device A: create vault, push.
        string remotePath;
        using (var vault = new VaultService(vaultA))
            {
            vault.Create("master-pass");
            vault.AddItem(VaultItemType.Note, new NotePayload { Text = "synced note" });

            var sync = new SyncService(new FolderSyncProvider(remoteRoot), vault);
            var result = await sync.PushAsync();
            Assert.True(result.Success);
            remotePath = sync.RemoteFileName;
            }

        Assert.True(File.Exists(Path.Combine(remoteRoot, remotePath)));

        // Device B: copy remote into its own DB path, then unlock.
        File.Copy(Path.Combine(remoteRoot, remotePath), vaultB);

        using (var vault = new VaultService(vaultB))
            {
            Assert.True(vault.Unlock("master-pass"));
            var items = vault.GetItems();
            Assert.Single(items);
            Assert.Equal("synced note", vault.DecryptPayload<NotePayload>(items[0]).Text);
            }
        }

    [Fact]
    public async Task TwoWaySync_WithNoRemote_Pushes()
        {
        var remoteRoot = Path.Combine(_tempDir, "remote-empty");
        var vaultPath = Path.Combine(_tempDir, "vault.db");

        using (var vault = new VaultService(vaultPath))
            {
            vault.Create("master-pass");
            var sync = new SyncService(new FolderSyncProvider(remoteRoot), vault);
            var result = await sync.SyncAsync();
            Assert.True(result.Success);
            Assert.True(result.Pushed);
            Assert.True(await sync.HasRemoteAsync());
            }
        }
    }
