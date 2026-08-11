using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;

namespace SecureVault.Core.Storage;

/// <summary>
/// SQLite-backed vault storage. All secret-bearing values are stored as opaque
/// encrypted blobs; every row carries an HMAC (keyed by the vault integrity
/// key) so tampering is detected on read. Schema carries only structure, never
/// plaintext secrets.
/// </summary>
public sealed class VaultDatabase : IDisposable
    {
    private readonly SqliteConnection _connection;
    private bool _disposed;

    public string Path { get; }

    public VaultDatabase(string path)
        {
        Path = path;
        var connectionString = new SqliteConnectionStringBuilder
            {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            }.ToString();
        _connection = new SqliteConnection(connectionString);
        _connection.Open();
        InitializeSchema();
        }

    private void InitializeSchema()
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS vault_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                cipher_suite INTEGER NOT NULL,
                header_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS items (
                id TEXT PRIMARY KEY,
                type INTEGER NOT NULL,
                payload_enc BLOB NOT NULL,
                content_enc BLOB NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                favorite INTEGER NOT NULL DEFAULT 0,
                deleted INTEGER NOT NULL DEFAULT 0,
                mac BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS item_versions (
                item_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                payload_enc BLOB NOT NULL,
                content_enc BLOB NULL,
                created_at TEXT NOT NULL,
                change_note_enc BLOB NULL,
                mac BLOB NOT NULL,
                PRIMARY KEY (item_id, version)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_enc BLOB NOT NULL,
                event_enc BLOB NOT NULL,
                prev_hash BLOB NOT NULL,
                hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_enc BLOB NOT NULL,
                mac BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_items_deleted ON items (deleted);
            CREATE INDEX IF NOT EXISTS idx_versions_item ON item_versions (item_id, version DESC);
            ";
        cmd.ExecuteNonQuery();
        }

    public VaultHeader? LoadHeader()
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT header_json FROM vault_meta WHERE id = 1";
        var value = cmd.ExecuteScalar() as string;
        return value is null ? null : System.Text.Json.JsonSerializer.Deserialize<VaultHeader>(value);
        }

    public void SaveHeader(VaultHeader header)
        {
        var json = System.Text.Json.JsonSerializer.Serialize(header);
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO vault_meta (id, schema_version, cipher_suite, header_json)
            VALUES (1, $sv, $cs, $hj)
            ON CONFLICT(id) DO UPDATE SET
                schema_version = $sv, cipher_suite = $cs, header_json = $hj
            ";
        cmd.Parameters.AddWithValue("$sv", header.SchemaVersion);
        cmd.Parameters.AddWithValue("$cs", (int)header.CipherSuite);
        cmd.Parameters.AddWithValue("$hj", json);
        cmd.ExecuteNonQuery();
        }

    public void InsertItem(VaultItem item, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO items (id, type, payload_enc, content_enc, created_at, updated_at, version, favorite, deleted, mac)
            VALUES ($id, $type, $payload, $content, $created, $updated, $version, $fav, 0, $mac)
            ";
        BindItem(cmd, item, integrityKey);
        cmd.ExecuteNonQuery();
        }

    public void UpdateItem(VaultItem item, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            UPDATE items
            SET payload_enc = $payload, content_enc = $content,
                updated_at = $updated, version = $version, favorite = $fav, mac = $mac
            WHERE id = $id AND deleted = 0
            ";
        BindItem(cmd, item, integrityKey);
        cmd.ExecuteNonQuery();
        }

    private static void BindItem(SqliteCommand cmd, VaultItem item, ReadOnlySpan<byte> integrityKey)
        {
        cmd.Parameters.AddWithValue("$id", item.Id.ToString("N"));
        cmd.Parameters.AddWithValue("$type", (int)item.Type);
        cmd.Parameters.AddWithValue("$payload", item.EncryptedPayload);
        cmd.Parameters.AddWithValue("$content", (object?)item.EncryptedContent ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", item.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$updated", item.UpdatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$version", item.Version);
        cmd.Parameters.AddWithValue("$fav", item.Favorite ? 1 : 0);
        cmd.Parameters.AddWithValue("$mac", ComputeItemMac(item, integrityKey));
        }

    public VaultItem? GetItem(Guid id, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM items WHERE id = $id AND deleted = 0";
        cmd.Parameters.AddWithValue("$id", id.ToString("N"));
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return ReadItem(reader, integrityKey, out _);
        }

    public IReadOnlyList<VaultItem> GetItems(ReadOnlySpan<byte> integrityKey)
        {
        var results = new List<VaultItem>();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM items WHERE deleted = 0 ORDER BY updated_at DESC";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            {
            if (ReadItem(reader, integrityKey, out _) is { } item) results.Add(item);
            }
        return results;
        }

    public IReadOnlyList<VaultItem> GetDeletedItems(ReadOnlySpan<byte> integrityKey)
        {
        var results = new List<VaultItem>();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM items WHERE deleted = 1 ORDER BY updated_at DESC";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            {
            if (ReadItem(reader, integrityKey, out _) is { } item) results.Add(item);
            }
        return results;
        }

    public void SoftDeleteItem(Guid id, ReadOnlySpan<byte> integrityKey)
        {
        var item = GetItem(id, integrityKey);
        if (item is null) return;
        item.Deleted = true;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "UPDATE items SET deleted = 1, updated_at = $u, mac = $mac WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString("N"));
        cmd.Parameters.AddWithValue("$u", item.UpdatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$mac", ComputeItemMac(item, integrityKey));
        cmd.ExecuteNonQuery();
        }

    public void RestoreItem(Guid id, ReadOnlySpan<byte> integrityKey)
        {
        var item = GetDeletedItem(id, integrityKey);
        if (item is null) return;
        item.Deleted = false;
        item.UpdatedAt = DateTimeOffset.UtcNow;
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "UPDATE items SET deleted = 0, updated_at = $u, mac = $mac WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString("N"));
        cmd.Parameters.AddWithValue("$u", item.UpdatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$mac", ComputeItemMac(item, integrityKey));
        cmd.ExecuteNonQuery();
        }

    public void PurgeItem(Guid id)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "DELETE FROM items WHERE id = $id; DELETE FROM item_versions WHERE item_id = $id";
        cmd.Parameters.AddWithValue("$id", id.ToString("N"));
        cmd.ExecuteNonQuery();
        }

    private VaultItem? GetDeletedItem(Guid id, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM items WHERE id = $id AND deleted = 1";
        cmd.Parameters.AddWithValue("$id", id.ToString("N"));
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return ReadItem(reader, integrityKey, out _);
        }

    public void InsertVersion(ItemVersion version, ReadOnlySpan<byte> integrityKey)
        {
        var payload = version.EncryptedPayload;
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO item_versions (item_id, version, payload_enc, content_enc, created_at, change_note_enc, mac)
            VALUES ($item, $ver, $payload, $content, $created, $note, $mac)
            ";
        cmd.Parameters.AddWithValue("$item", version.ItemId.ToString("N"));
        cmd.Parameters.AddWithValue("$ver", version.Version);
        cmd.Parameters.AddWithValue("$payload", payload);
        cmd.Parameters.AddWithValue("$content", (object?)version.EncryptedContent ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", version.CreatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$note", (object?)System.Text.Encoding.UTF8.GetBytes(version.ChangeNote ?? "") ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$mac", ComputeVersionMac(version, integrityKey));
        cmd.ExecuteNonQuery();
        TrimVersions(version.ItemId);
        }

    private void TrimVersions(Guid itemId, int keep = 50)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            DELETE FROM item_versions WHERE item_id = $id AND version NOT IN (
                SELECT version FROM item_versions WHERE item_id = $id ORDER BY version DESC LIMIT $keep
            )
            ";
        cmd.Parameters.AddWithValue("$id", itemId.ToString("N"));
        cmd.Parameters.AddWithValue("$keep", keep);
        cmd.ExecuteNonQuery();
        }

    public IReadOnlyList<ItemVersion> GetVersions(Guid itemId)
        {
        var results = new List<ItemVersion>();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM item_versions WHERE item_id = $id ORDER BY version DESC";
        cmd.Parameters.AddWithValue("$id", itemId.ToString("N"));
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
            {
            results.Add(new ItemVersion
                {
                ItemId = itemId,
                Version = reader.GetInt32(reader.GetOrdinal("version")),
                EncryptedPayload = ReadBytes(reader, "payload_enc"),
                EncryptedContent = ReadNullableBytes(reader, "content_enc"),
                CreatedAt = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("created_at")),
                    System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind),
                ChangeNote = ReadNullableBytes(reader, "change_note_enc") is { } n ? System.Text.Encoding.UTF8.GetString(n) : string.Empty,
                });
            }
        return results;
        }

    public void AppendAudit(byte[] encryptedEvent, byte[] timestampBytes, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1";
        var prev = cmd.ExecuteScalar() as byte[] ?? new byte[32];

        var hash = ComputeChainHash(prev, timestampBytes, encryptedEvent, integrityKey);

        cmd.CommandText = @"
            INSERT INTO audit_log (ts_enc, event_enc, prev_hash, hash) VALUES ($ts, $ev, $prev, $hash)
            ";
        cmd.Parameters.AddWithValue("$ts", timestampBytes);
        cmd.Parameters.AddWithValue("$ev", encryptedEvent);
        cmd.Parameters.AddWithValue("$prev", prev);
        cmd.Parameters.AddWithValue("$hash", hash);
        cmd.ExecuteNonQuery();
        }

    public bool VerifyAuditChain(ReadOnlySpan<byte> integrityKey)
        {
        var rows = new List<(byte[] prev, byte[] ts, byte[] ev, byte[] hash)>();
        using (var cmd = _connection.CreateCommand())
            {
            cmd.CommandText = "SELECT prev_hash, ts_enc, event_enc, hash FROM audit_log ORDER BY id ASC";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                {
                rows.Add((
                    (byte[])reader["prev_hash"],
                    (byte[])reader["ts_enc"],
                    (byte[])reader["event_enc"],
                    (byte[])reader["hash"]));
                }
            }

        var expectedPrev = new byte[32];
        foreach (var row in rows)
            {
            var expectedHash = ComputeChainHash(expectedPrev, row.ts, row.ev, integrityKey);
            if (!CryptographicOperations.FixedTimeEquals(expectedHash, row.hash)) return false;
            if (!CryptographicOperations.FixedTimeEquals(expectedPrev, row.prev)) return false;
            expectedPrev = row.hash;
            }
        return true;
        }

    public IReadOnlyList<byte[]> GetAuditEvents()
        {
        var results = new List<byte[]>();
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT event_enc FROM audit_log ORDER BY id DESC";
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) results.Add((byte[])reader["event_enc"]);
        return results;
        }

    public void SetSetting(string key, byte[] valueEnc, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO settings (key, value_enc, mac) VALUES ($k, $v, $m)
            ON CONFLICT(key) DO UPDATE SET value_enc = $v, mac = $m
            ";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", valueEnc);
        cmd.Parameters.AddWithValue("$m", ComputeSettingMac(key, valueEnc, integrityKey));
        cmd.ExecuteNonQuery();
        }

    public byte[]? GetSetting(string key, ReadOnlySpan<byte> integrityKey)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT value_enc, mac FROM settings WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        var value = (byte[])reader["value_enc"];
        var mac = (byte[])reader["mac"];
        if (!VerifySettingMac(key, value, mac, integrityKey)) throw new TamperDetectedException($"Settings value '{key}' failed integrity check.");
        return value;
        }

    public string? GetSyncState(string key)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT value FROM sync_state WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
        }

    public void SetSyncState(string key, string value)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO sync_state (key, value) VALUES ($k, $v)
            ON CONFLICT(key) DO UPDATE SET value = $v
            ";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
        }

    public int CountItems() => ExecuteScalarInt("SELECT COUNT(*) FROM items WHERE deleted = 0");
    public long CountAuditEvents() => ExecuteScalarLong("SELECT COUNT(*) FROM audit_log");

    /// <summary>Force WAL content into the main database file (for backups/sync).</summary>
    public void Checkpoint()
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(FULL);";
        cmd.ExecuteNonQuery();
        }

    private static VaultItem? ReadItem(SqliteDataReader reader, ReadOnlySpan<byte> integrityKey, out bool macValid)
        {
        macValid = false;
        var item = new VaultItem
            {
            Id = Guid.Parse(reader.GetString(reader.GetOrdinal("id"))),
            Type = (VaultItemType)reader.GetInt32(reader.GetOrdinal("type")),
            EncryptedPayload = ReadBytes(reader, "payload_enc"),
            EncryptedContent = ReadNullableBytes(reader, "content_enc"),
            CreatedAt = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("created_at")),
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind),
            UpdatedAt = DateTimeOffset.Parse(reader.GetString(reader.GetOrdinal("updated_at")),
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind),
            Version = reader.GetInt32(reader.GetOrdinal("version")),
            Favorite = reader.GetInt32(reader.GetOrdinal("favorite")) == 1,
            Deleted = reader.GetInt32(reader.GetOrdinal("deleted")) == 1,
            };
        var storedMac = (byte[])reader["mac"];
        var expected = ComputeItemMac(item, integrityKey);
        if (!CryptographicOperations.FixedTimeEquals(storedMac, expected))
            {
            throw new TamperDetectedException($"Item '{item.Id}' failed integrity check.");
            }
        macValid = true;
        return item;
        }

    private static byte[] ReadBytes(SqliteDataReader reader, string column) => (byte[])reader[column];
    private static byte[]? ReadNullableBytes(SqliteDataReader reader, string column) =>
        reader.IsDBNull(reader.GetOrdinal(column)) ? null : (byte[])reader[column];

    private static byte[] ComputeItemMac(VaultItem item, ReadOnlySpan<byte> integrityKey)
        {
        return ComputeMac(integrityKey,
            Encoding.UTF8.GetBytes(item.Id.ToString("N")),
            new byte[] { (byte)item.Type, (byte)(item.Deleted ? 1 : 0), (byte)(item.Favorite ? 1 : 0) },
            item.EncryptedPayload,
            item.EncryptedContent,
            Encoding.UTF8.GetBytes(item.UpdatedAt.ToString("O")),
            BitConverter.GetBytes(item.Version));
        }

    private static byte[] ComputeVersionMac(ItemVersion version, ReadOnlySpan<byte> integrityKey)
        {
        return ComputeMac(integrityKey,
            Encoding.UTF8.GetBytes(version.ItemId.ToString("N")),
            BitConverter.GetBytes(version.Version),
            version.EncryptedPayload,
            version.EncryptedContent);
        }

    private static byte[] ComputeSettingMac(string key, byte[] value, ReadOnlySpan<byte> integrityKey)
        {
        return ComputeMac(integrityKey, Encoding.UTF8.GetBytes(key), value);
        }

    private static bool VerifySettingMac(string key, byte[] value, byte[] stored, ReadOnlySpan<byte> integrityKey)
        {
        var expected = ComputeSettingMac(key, value, integrityKey);
        return CryptographicOperations.FixedTimeEquals(expected, stored);
        }

    private static byte[] ComputeChainHash(byte[] prev, byte[] ts, byte[] ev, ReadOnlySpan<byte> integrityKey)
        {
        return ComputeMac(integrityKey, prev, ts, ev);
        }

    private static byte[] ComputeMac(ReadOnlySpan<byte> key, params byte[]?[] segments)
        {
        using var mac = new HMACSHA256(key.ToArray());
        using var buffer = new System.IO.MemoryStream();
        foreach (var segment in segments)
            {
            if (segment is null) continue;
            buffer.Write(segment, 0, segment.Length);
            }
        buffer.Position = 0;
        return mac.ComputeHash(buffer);
        }

    private int ExecuteScalarInt(string sql)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt32(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        }

    private long ExecuteScalarLong(string sql)
        {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt64(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        }

    public void Dispose()
        {
        if (_disposed) return;
        _connection.Dispose();
        _disposed = true;
        }
    }

public sealed class TamperDetectedException : Exception
    {
    public TamperDetectedException(string message) : base(message) { }
    }


