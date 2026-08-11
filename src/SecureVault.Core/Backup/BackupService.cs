using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Crypto;
using SecureVault.Core.Vault;

namespace SecureVault.Core.Backup;

/// <summary>
/// Encrypted vault backup &amp; restore. The whole vault database (which already
/// holds only ciphertext) is sealed into a single portable container keyed by a
/// passphrase, with tamper-evident AEAD and an integrity-checked envelope.
/// </summary>
public sealed class BackupService
    {
    private const uint Magic = 0x5356424B; // "SVBK"
    private const byte FormatVersion = 1;

    public static async Task CreateBackupAsync(
        VaultService vault,
        string outputPath,
        string? passphrase = null,
        CancellationToken ct = default)
        {
        if (!vault.IsUnlocked) throw new InvalidOperationException("Vault must be unlocked to back it up.");
        if (string.IsNullOrEmpty(passphrase)) throw new InvalidOperationException("A backup passphrase is required.");

        var dbPath = vault.VaultPath;
        if (!File.Exists(dbPath)) throw new FileNotFoundException("Vault database not found.", dbPath);

        // Flush WAL into the main db file before backing up.
        vault.FlushToDisk();

        var dbBytes = await ReadFileSharedAsync(dbPath, ct).ConfigureAwait(false);
        var wals = Directory.GetFiles(Path.GetDirectoryName(dbPath)!, Path.GetFileName(dbPath) + "-wal");
        var shms = Directory.GetFiles(Path.GetDirectoryName(dbPath)!, Path.GetFileName(dbPath) + "-shm");

        var header = BuildContainerHeader(vault);
        var container = SealContainer(header, passphrase, dbBytes);

        await File.WriteAllBytesAsync(outputPath, container, ct).ConfigureAwait(false);
        }

    /// <summary>Restore a backup into the given database path (must not exist).</summary>
    public static async Task RestoreBackupAsync(
        string backupPath,
        string outputDbPath,
        string passphrase,
        CancellationToken ct = default)
        {
        var container = await File.ReadAllBytesAsync(backupPath, ct).ConfigureAwait(false);
        var dbBytes = OpenContainer(container, passphrase);
        var dir = Path.GetDirectoryName(Path.GetFullPath(outputDbPath))!;
        Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(outputDbPath, dbBytes, ct).ConfigureAwait(false);
        }

    /// <summary>Returns true if the container opens with the given passphrase.</summary>
    public static bool ValidateBackup(string backupPath, string passphrase)
        {
        try
            {
            var container = File.ReadAllBytes(backupPath);
            _ = OpenContainer(container, passphrase);
            return true;
            }
        catch (CryptographicException)
            {
            return false;
            }
        catch (Exception)
            {
            return false;
            }
        }

    private static async Task<byte[]> ReadFileSharedAsync(string path, CancellationToken ct)
        {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct).ConfigureAwait(false);
        return ms.ToArray();
        }

    private static byte[] BuildContainerHeader(VaultService vault)
        {
        var sb = new StringBuilder();
        sb.Append("securevault-backup-v1|").Append(vault.Header!.VaultId).Append('|').Append(vault.Header.CipherSuite);
        sb.Append('|').Append(vault.Header.KdfParameters.MemorySizeKib)
          .Append('|').Append(vault.Header.KdfParameters.NumberOfPasses)
          .Append('|').Append(vault.Header.KdfParameters.DegreeOfParallelism);
        return Encoding.UTF8.GetBytes(sb.ToString());
        }

    private static byte[] SealContainer(byte[] header, string passphrase, byte[] dbBytes)
        {
        var salt = Argon2IdKdf.GenerateSalt();
        var key = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(passphrase), salt, Argon2IdParameters.Default);

        var suite = CipherSuite.Aes256Gcm;
        var engine = EncryptionEngine.Create(suite);
        var sealedDb = engine.Encrypt(key, dbBytes, header);

        using var ms = new MemoryStream();
        using (var w = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
            {
            w.Write(Magic);
            w.Write(FormatVersion);
            w.Write((byte)suite);
            w.Write(salt.Length);
            w.Write(salt);
            w.Write(header.Length);
            w.Write(header);
            w.Write(sealedDb.Length);
            w.Write(sealedDb);
            }
        return ms.ToArray();
        }

    private static byte[] OpenContainer(byte[] container, string passphrase)
        {
        try
            {
            using var ms = new MemoryStream(container);
            using var r = new BinaryReader(ms, Encoding.UTF8);
            if (r.ReadUInt32() != Magic) throw new CryptographicException("Not a SecureVault backup.");
            var version = r.ReadByte();
            if (version != FormatVersion) throw new CryptographicException($"Unsupported backup format version {version}.");
            var suite = (CipherSuite)r.ReadByte();
            var saltLen = r.ReadInt32();
            var salt = r.ReadBytes(saltLen);
            var headerLen = r.ReadInt32();
            var header = r.ReadBytes(headerLen);
            var dbLen = r.ReadInt32();
            var sealedDb = r.ReadBytes(dbLen);

            var kdf = new Argon2IdKdf();
            var key = Argon2IdKdf.DeriveKey(Encoding.UTF8.GetBytes(passphrase), salt, Argon2IdParameters.Default);
            var engine = EncryptionEngine.Create(suite);
            return engine.Decrypt(key, sealedDb, header);
            }
        catch (EndOfStreamException e)
            {
            throw new CryptographicException("Corrupt or truncated backup file.", e);
            }
        }
    }
