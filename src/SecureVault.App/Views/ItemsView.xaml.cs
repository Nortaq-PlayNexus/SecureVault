using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using SecureVault.App.Services;
using SecureVault.Core.Model;
using SecureVault.Core.Security;

namespace SecureVault.App.Views
    {
    public partial class ItemsView : UserControl
        {
        private IReadOnlyList<ItemRow> _allRows = Array.Empty<ItemRow>();
        private bool _showDeleted;

        public ItemsView()
            {
            InitializeComponent();
            }

        public void Refresh()
            {
            var session = SessionManager.Instance;
            var vault = session.Vault;
            if (vault is null) return;

            var rows = new List<ItemRow>();
            var items = _showDeleted ? vault.GetDeletedItems() : vault.GetItems();
            foreach (var item in items)
                {
                rows.Add(ItemRow.From(item, BuildSubtitle(vault, item), item.UpdatedAt.ToLocalTime().ToString("MMM d, yyyy", System.Globalization.CultureInfo.InvariantCulture)));
                }
            _allRows = rows;
            CountText.Text = $"{rows.Count} item{(rows.Count == 1 ? "" : "s")}";
            ApplyFilter();
            }

        private static string BuildSubtitle(SecureVault.Core.Vault.VaultService vault, VaultItem item)
            {
            try
                {
                switch (item.Type)
                    {
                    case VaultItemType.Login:
                        var login = vault.DecryptPayload<LoginPayload>(item);
                        return string.IsNullOrEmpty(login.Username) ? login.Url : $"{login.Username} · {login.Url}";
                    case VaultItemType.Note:
                        var note = vault.DecryptPayload<NotePayload>(item);
                        return note.Text.Length > 60 ? note.Text[..60] + "…" : note.Text;
                    case VaultItemType.SshKey:
                        var ssh = vault.DecryptPayload<SshKeyPayload>(item);
                        return $"{ssh.KeyType} key";
                    case VaultItemType.ApiToken:
                        var api = vault.DecryptPayload<ApiTokenPayload>(item);
                        return api.Url ?? api.Name;
                    case VaultItemType.File:
                        var file = vault.DecryptPayload<FilePayload>(item);
                        return file.FileName;
                    case VaultItemType.Passkey:
                        var pass = vault.DecryptPayload<PasskeyPayload>(item);
                        return pass.RpId;
                    default:
                        return string.Empty;
                    }
                }
            catch
                {
                return string.Empty;
                }
            }

        private void ApplyFilter()
            {
            var q = SearchBox.Text?.Trim().ToLowerInvariant() ?? string.Empty;
            var filter = (TypeFilter.SelectedItem as ComboBoxItem)?.Content as string ?? "All types";
            var vault = SessionManager.Instance.Vault;

            IEnumerable<ItemRow> rows = _allRows;
            if (!string.IsNullOrEmpty(q))
                {
                rows = rows.Where(r =>
                    r.Item.Title.ToLowerInvariant().Contains(q) ||
                    r.Subtitle.ToLowerInvariant().Contains(q));
                }
            rows = rows.Where(r => MatchesFilter(r.Item.Type, filter));

            ItemList.ItemsSource = rows.ToList();
            }

        private static bool MatchesFilter(VaultItemType type, string filter) => filter switch
            {
                "Passwords" => type == VaultItemType.Login,
                "Notes" => type == VaultItemType.Note,
                "SSH keys" => type == VaultItemType.SshKey,
                "API tokens" => type == VaultItemType.ApiToken,
                "Files" => type == VaultItemType.File,
                "Passkeys" => type == VaultItemType.Passkey,
                _ => true,
                };

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();
        private void TypeFilter_SelectionChanged(object sender, SelectionChangedEventArgs e) => ApplyFilter();

        private void AddItemButton_Click(object sender, RoutedEventArgs e)
            {
            var dialog = new ItemEditorDialog(null);
            if (dialog.ShowDialog() == true) Refresh();
            }

        private void ItemList_SelectionChanged(object sender, SelectionChangedEventArgs e)
            {
            var row = ItemList.SelectedItem as ItemRow;
            if (row is null)
                {
                DetailTitle.Text = "Select an item";
                DetailSubtitle.Text = "Details appear here.";
                EditButton.IsEnabled = DeleteButton.IsEnabled = false;
                RestoreButton.Visibility = Visibility.Collapsed;
                return;
                }

            var vault = SessionManager.Instance.Vault!;
            DetailTitle.Text = row.Item.Title;
            DetailSubtitle.Text = BuildDetail(vault, row.Item);
            EditButton.IsEnabled = !_showDeleted;
            DeleteButton.IsEnabled = !_showDeleted;
            DeleteButton.Content = _showDeleted ? "Purge" : "Delete";
            RestoreButton.Visibility = _showDeleted ? Visibility.Visible : Visibility.Collapsed;
            }

        private static string BuildDetail(SecureVault.Core.Vault.VaultService vault, VaultItem item)
            {
            try
                {
                switch (item.Type)
                    {
                    case VaultItemType.Login:
                        var login = vault.DecryptPayload<LoginPayload>(item);
                        var lines = new List<string> { $"Username: {login.Username}", $"URL: {login.Url}" };
                        if (!string.IsNullOrEmpty(login.OtpSecret)) lines.Add("2FA: configured");
                        if (!string.IsNullOrEmpty(login.Notes)) lines.Add(login.Notes);
                        var phish = PhishingDetector.Analyze(login.Url);
                        if (phish.Suspicious) lines.Add($"⚠ Phishing warning: {string.Join("; ", phish.Reasons)}");
                        return string.Join("\n", lines);
                    case VaultItemType.Note:
                        return vault.DecryptPayload<NotePayload>(item).Text;
                    case VaultItemType.SshKey:
                        var ssh = vault.DecryptPayload<SshKeyPayload>(item);
                        return $"Type: {ssh.KeyType}\nPublic key:\n{ssh.PublicKey}";
                    case VaultItemType.ApiToken:
                        var api = vault.DecryptPayload<ApiTokenPayload>(item);
                        return $"Token: {api.Token}\nURL: {api.Url}\nExpires: {api.ExpiresAt?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "never"}";
                    case VaultItemType.File:
                        var file = vault.DecryptPayload<FilePayload>(item);
                        return $"{file.FileName} ({file.Size:N0} bytes) · {file.MimeType}";
                    case VaultItemType.Passkey:
                        var pass = vault.DecryptPayload<PasskeyPayload>(item);
                        return $"Relying party: {pass.RpId}";
                    default:
                        return string.Empty;
                    }
                }
            catch
                {
                return "Unable to decrypt item.";
                }
            }

        private void EditItemButton_Click(object sender, RoutedEventArgs e)
            {
            if (ItemList.SelectedItem is not ItemRow row) return;
            var dialog = new ItemEditorDialog(row.Item);
            if (dialog.ShowDialog() == true) Refresh();
            }

        private void DeleteItemButton_Click(object sender, RoutedEventArgs e)
            {
            if (ItemList.SelectedItem is not ItemRow row) return;
            var vault = SessionManager.Instance.Vault!;
            if (_showDeleted)
                {
                if (MessageBox.Show("Permanently purge this item? This cannot be undone.", "SecureVault",
                        MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
                vault.PurgeItem(row.Item.Id);
                }
            else
                {
                if (MessageBox.Show($"Move '{row.Item.Title}' to the trash?", "SecureVault",
                        MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                vault.DeleteItem(row.Item.Id);
                }
            Refresh();
            }

        private void RestoreItemButton_Click(object sender, RoutedEventArgs e)
            {
            if (ItemList.SelectedItem is not ItemRow row) return;
            SessionManager.Instance.Vault!.RestoreItem(row.Item.Id);
            Refresh();
            }

        private void ToggleDeleted_Click(object sender, RoutedEventArgs e)
            {
            _showDeleted = !_showDeleted;
            ShowDeletedButton.Content = _showDeleted ? "Back to items" : "Trash";
            Refresh();
            }
        }
    }
