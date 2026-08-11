using System;
using System.IO;
using SecureVault.Core.Backup;
using SecureVault.Core.Model;
using SecureVault.Core.Vault;
using Xunit;

namespace SecureVault.Tests;

public class VaultServiceTests : IDisposable
    {
    private readonly string _tempDir;
    public VaultServiceTests()
        {
        _tempDir = Path.Combine(Path.GetTempPath(), "sv-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        }

    private string NewVaultPath() => Path.Combine(_tempDir, Guid.NewGuid().ToString("N") + ".db");

    public void Dispose()
        {
        GC.SuppressFinalize(this);
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

    [Fact]
    public void CreateAndUnlock_RoundTrips()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("correct-horse-battery-staple");
            Assert.True(vault.IsUnlocked);
            }

        using (var vault = new VaultService(path))
            {
            Assert.True(vault.Unlock("correct-horse-battery-staple"));
            Assert.True(vault.IsUnlocked);
            }
        }

    [Fact]
    public void WrongPassword_FailsUnlock()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("right-password");
            }
        using (var vault = new VaultService(path))
            {
            Assert.False(vault.Unlock("wrong-password"));
            Assert.False(vault.IsUnlocked);
            }
        }

    [Fact]
    public void AddAndRetrieveLogin_EncryptedAtRest()
        {
        var path = NewVaultPath();
        VaultItem? item;
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            item = vault.AddItem(VaultItemType.Login, new LoginPayload
                {
                Username = "alice",
                Password = "hunter2",
                Url = "https://example.com",
                });

            var loaded = vault.GetItem(item.Id)!;
            var payload = vault.DecryptPayload<LoginPayload>(loaded);
            Assert.Equal("alice", payload.Username);
            Assert.Equal("hunter2", payload.Password);
            Assert.Equal("https://example.com", payload.Url);
            }

        // At rest, the file must not contain the plaintext.
        var bytes = File.ReadAllBytes(path);
        var text = System.Text.Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain("hunter2", text);
        Assert.DoesNotContain("alice", text);
        }

    [Fact]
    public void UpdateItem_CreatesVersionHistory()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            var item = vault.AddItem(VaultItemType.Note, new NotePayload { Text = "v1" });

            vault.UpdateItem(item.Id, new NotePayload { Text = "v2" });
            vault.UpdateItem(item.Id, new NotePayload { Text = "v3" });

            var versions = vault.GetVersions(item.Id);
            Assert.Equal(2, versions.Count); // snapshots of v1 and v2

            var current = vault.DecryptPayload<NotePayload>(vault.GetItem(item.Id)!);
            Assert.Equal("v3", current.Text);
            Assert.Equal(3, vault.GetItem(item.Id)!.Version);
            }
        }

    [Fact]
    public void DeleteAndRestore()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            var item = vault.AddItem(VaultItemType.Note, new NotePayload { Text = "x" });

            vault.DeleteItem(item.Id);
            Assert.Empty(vault.GetItems());
            Assert.Single(vault.GetDeletedItems());

            vault.RestoreItem(item.Id);
            Assert.Single(vault.GetItems());
            }
        }

    [Fact]
    public void ChangePassword_ThenOldPasswordFails_NewSucceeds()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("old-password");
            var item = vault.AddItem(VaultItemType.Note, new NotePayload { Text = "keep" });

            vault.ChangeMasterPassword("old-password", "new-password");
            Assert.True(vault.VerifyPassword("new-password"));
            Assert.False(vault.VerifyPassword("old-password"));

            var note = vault.DecryptPayload<NotePayload>(vault.GetItem(item.Id)!);
            Assert.Equal("keep", note.Text);
            }
        }

    [Fact]
    public void FileItem_RoundTripsContent()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            var content = new byte[1024 * 8];
            new Random(42).NextBytes(content);

            var item = vault.AddItem(VaultItemType.File, new FilePayload
                {
                FileName = "backup.zip",
                Size = content.Length,
                }, content);

            var restored = vault.DecryptContent(vault.GetItem(item.Id)!);
            Assert.Equal(content, restored);
            }
        }

    [Fact]
    public void SshKeyAndApiToken_RoundTrip()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");

            var ssh = vault.AddItem(VaultItemType.SshKey, new SshKeyPayload
                {
                KeyType = "ed25519",
                PrivateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI x@y",
                });
            var sshBack = vault.DecryptPayload<SshKeyPayload>(vault.GetItem(ssh.Id)!);
            Assert.Contains("OPENSSH PRIVATE KEY", sshBack.PrivateKey);

            var api = vault.AddItem(VaultItemType.ApiToken, new ApiTokenPayload
                {
                Name = "GitHub",
                Token = "ghp_abc123",
                });
            var apiBack = vault.DecryptPayload<ApiTokenPayload>(vault.GetItem(api.Id)!);
            Assert.Equal("ghp_abc123", apiBack.Token);
            }
        }

    [Fact]
    public void XChaChaSuite_RoundTrips()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123", Core.Crypto.CipherSuite.XChaCha20Poly1305);
            var item = vault.AddItem(VaultItemType.Login, new LoginPayload { Username = "u", Password = "p" });
            var back = vault.DecryptPayload<LoginPayload>(vault.GetItem(item.Id)!);
            Assert.Equal("p", back.Password);
            }
        }

    [Fact]
    public void Settings_RoundTrip()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            var settings = new VaultSettings { AutoLockMinutes = 15, ClipboardClearSeconds = 45 };
            vault.SaveSettings(settings);

            var back = vault.GetSettings();
            Assert.Equal(15, back.AutoLockMinutes);
            Assert.Equal(45, back.ClipboardClearSeconds);
            }
        }

    [Fact]
    public void TamperedHeader_DetectedOnUnlock()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            }

        // Tamper with the header JSON stored in the DB (e.g. change the vault name).
        using (var db = new Core.Storage.VaultDatabase(path))
            {
            var header = db.LoadHeader()!;
            header.VaultName = "EVIL-MODIFIED";
            db.SaveHeader(header);
            }

        using var tamperedVault = new VaultService(path);
        Assert.Throws<Core.Storage.TamperDetectedException>(() => tamperedVault.Unlock("password123"));
        }

    [Fact]
    public void AuditLog_WritesAndVerifies()
        {
        var path = NewVaultPath();
        using (var vault = new VaultService(path))
            {
            vault.Create("password123");
            var item = vault.AddItem(VaultItemType.Note, new NotePayload { Text = "n" });
            vault.UpdateItem(item.Id, new NotePayload { Text = "n2" });

            Assert.True(vault.VerifyAuditChain());
            var events = vault.GetAuditEvents();
            Assert.Contains(events, e => e.Action == AuditAction.ItemAdded);
            }
        }
    }

public class BackupServiceTests : IDisposable
    {
    private readonly string _tempDir;
    public BackupServiceTests()
        {
        _tempDir = Path.Combine(Path.GetTempPath(), "sv-bak-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        }
    public void Dispose()
        {
        GC.SuppressFinalize(this);
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
        }

    [Fact]
    public async Task BackupRestore_RoundTrips()
        {
        var vaultPath = Path.Combine(_tempDir, "vault.db");
        var backupPath = Path.Combine(_tempDir, "backup.svault");
        var restorePath = Path.Combine(_tempDir, "restored.db");

        using (var vault = new VaultService(vaultPath))
            {
            vault.Create("master-pass");
            vault.AddItem(VaultItemType.Note, new NotePayload { Text = "precious data" });
            }

        using (var vault = new VaultService(vaultPath))
            {
            vault.Unlock("master-pass");
            await BackupService.CreateBackupAsync(vault, backupPath, "backup-pass");
            }

        Assert.True(File.Exists(backupPath));
        Assert.True(BackupService.ValidateBackup(backupPath, "backup-pass"));
        Assert.False(BackupService.ValidateBackup(backupPath, "wrong-pass"));

        await BackupService.RestoreBackupAsync(backupPath, restorePath, "backup-pass");

        using (var restored = new VaultService(restorePath))
            {
            Assert.True(restored.Unlock("master-pass"));
            var items = restored.GetItems();
            Assert.Single(items);
            Assert.Equal("precious data", restored.DecryptPayload<NotePayload>(items[0]).Text);
            }
        }
    }
