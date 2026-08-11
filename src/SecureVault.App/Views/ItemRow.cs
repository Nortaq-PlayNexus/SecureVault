using SecureVault.Core.Model;

namespace SecureVault.App.Views;

/// <summary>Display model for a vault item in the list.</summary>
public sealed class ItemRow
    {
    public VaultItem Item { get; init; } = new();
    public string TypeLabel { get; init; } = string.Empty;
    public string TypeGlyph { get; init; } = string.Empty;
    public string Subtitle { get; init; } = string.Empty;
    public string UpdatedLabel { get; init; } = string.Empty;
    public bool IsFavorite { get; init; }

    public static ItemRow From(VaultItem item, string subtitle, string updated)
        {
        var (label, glyph) = item.Type switch
            {
                VaultItemType.Login => ("Password", "\uD83D\uDD10"),
                VaultItemType.Note => ("Note", "\uD83D\uDCDD"),
                VaultItemType.SshKey => ("SSH key", "\uD83D\uDD17"),
                VaultItemType.ApiToken => ("API token", "\uD83D\uDD11"),
                VaultItemType.File => ("File", "\uD83D\uDCC1"),
                VaultItemType.Passkey => ("Passkey", "\uD83D\uDD12"),
                _ => ("Item", "\u26AA"),
                };
        return new ItemRow
            {
            Item = item,
            TypeLabel = label,
            TypeGlyph = glyph,
            Subtitle = subtitle,
            UpdatedLabel = updated,
            IsFavorite = item.Favorite,
            };
        }
    }
