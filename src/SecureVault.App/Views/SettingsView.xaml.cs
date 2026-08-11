using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SecureVault.App.Services;
using SecureVault.Core.Backup;
using SecureVault.Core.Sync;

namespace SecureVault.App.Views
    {
    public partial class SettingsView : UserControl
        {
        public SettingsView()
            {
            InitializeComponent();
            }

        public void Refresh()
            {
            var s = SessionManager.Instance.Settings;
            if (s is null) return;

            VaultNameBox.Text = s.VaultName;
            AutoLockEnabledBox.IsChecked = s.AutoLockMinutes > 0;
            AutoLockBox.Text = (s.AutoLockMinutes > 0 ? s.AutoLockMinutes : 5).ToString(System.Globalization.CultureInfo.InvariantCulture);
            ClipboardEnabledBox.IsChecked = s.ClipboardClearEnabled;
            ClipboardSecondsBox.Text = s.ClipboardClearSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            HardwareUnlockBox.IsChecked = s.HardwareUnlockEnabled;
            HelloUnlockBox.IsChecked = s.WindowsHelloEnabled;
            BreachCheckBox.IsChecked = s.BreachCheckEnabled;

            SyncProviderBox.SelectedIndex = s.SyncProvider switch
                {
                    "folder" => 1,
                    "webdav" => 2,
                    _ => 0,
                    };
            SyncFolderBox.Text = s.SyncProvider is not null ? ReadLocalSyncPath() : string.Empty;
            StatusText.Text = string.Empty;
            }

        private static string ReadLocalSyncPath()
            {
            var s = SessionManager.Instance.Settings;
            var stored = s?.SyncProvider;
            return stored switch
                {
                    "folder" => LoadSyncConfig("folder_path") ?? string.Empty,
                    "webdav" => LoadSyncConfig("webdav_url") ?? string.Empty,
                    _ => string.Empty,
                    };
            }

        private static string? LoadSyncConfig(string key)
            {
            var vault = SessionManager.Instance.Vault;
            return vault?.GetSyncState("sync:" + key);
            }

        private static void SaveSyncConfig(string key, string value)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;
            vault.SetSyncState("sync:" + key, value);
            }

        private void SaveButtonState()
            {
            var s = SessionManager.Instance.Settings;
            if (s is null) return;
            s.VaultName = VaultNameBox.Text.Trim();
            s.AutoLockMinutes = AutoLockEnabledBox.IsChecked == true ? int.TryParse(AutoLockBox.Text, out var m) ? m : 5 : 0;
            s.ClipboardClearEnabled = ClipboardEnabledBox.IsChecked == true;
            s.ClipboardClearSeconds = int.TryParse(ClipboardSecondsBox.Text, out var c) ? c : 30;
            s.BreachCheckEnabled = BreachCheckBox.IsChecked == true;
            SessionManager.Instance.SaveSettings();
            }

        private void HardwareUnlockBox_Changed(object sender, RoutedEventArgs e)
            {
            var s = SessionManager.Instance.Settings;
            var vault = SessionManager.Instance.Vault;
            if (s is null || vault is null) return;
            try
                {
                if (HardwareUnlockBox.IsChecked == true) vault.EnableHardwareUnlock();
                else vault.DisableHardwareUnlock();
                s.HardwareUnlockEnabled = HardwareUnlockBox.IsChecked == true;
                if (HardwareUnlockBox.IsChecked == false) HelloUnlockBox.IsChecked = false;
                SessionManager.Instance.SaveSettings();
                StatusText.Text = HardwareUnlockBox.IsChecked == true
                    ? "Hardware unlock enabled. Your unlock key is now protected by the TPM."
                    : "Hardware unlock disabled.";
                }
            catch (Exception ex)
                {
                StatusText.Text = "Error: " + ex.Message;
                }
            }

        private void HelloUnlockBox_Changed(object sender, RoutedEventArgs e)
            {
            var s = SessionManager.Instance.Settings;
            var vault = SessionManager.Instance.Vault;
            if (s is null || vault is null) return;
            try
                {
                if (HelloUnlockBox.IsChecked == true)
                    {
                    // Windows Hello relies on the hardware-protected key.
                    if (!s.HardwareUnlockEnabled)
                        {
                        vault.EnableHardwareUnlock();
                        s.HardwareUnlockEnabled = true;
                        HardwareUnlockBox.IsChecked = true;
                        }
                    }
                s.WindowsHelloEnabled = HelloUnlockBox.IsChecked == true;
                SessionManager.Instance.SaveSettings();
                StatusText.Text = s.WindowsHelloEnabled
                    ? "Windows Hello unlock enabled. The vault will prompt for biometrics on unlock."
                    : "Windows Hello unlock disabled.";
                }
            catch (Exception ex)
                {
                StatusText.Text = "Error: " + ex.Message;
                }
            }

        private void ChangePassword_Click(object sender, RoutedEventArgs e)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;
            var oldPw = CurrentPasswordBox.Password;
            var newPw = NewPasswordBox.Password;
            if (string.IsNullOrEmpty(oldPw) || string.IsNullOrEmpty(newPw))
                {
                StatusText.Text = "Enter both current and new passwords.";
                return;
                }
            try
                {
                vault.ChangeMasterPassword(oldPw, newPw);
                CurrentPasswordBox.Password = string.Empty;
                NewPasswordBox.Password = string.Empty;
                StatusText.Text = "Master password changed successfully.";
                }
            catch (Exception ex)
                {
                StatusText.Text = "Error: " + ex.Message;
                }
            }

        private async void BackupNow_Click(object sender, RoutedEventArgs e)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;

            var dialog = new SaveFileDialog { FileName = $"SecureVault-backup-{DateTime.Now:yyyyMMdd}.svault", Filter = "SecureVault backup (*.svault)|*.svault" };
            if (dialog.ShowDialog() != true) return;

            var pass = PromptForPassword("Set a backup passphrase", "Enter a passphrase to protect this backup (recommended: your master password).");
            if (pass is null) return;

            try
                {
                BackupStatusText.Text = "Encrypting backup…";
                await BackupService.CreateBackupAsync(vault, dialog.FileName, pass);
                BackupStatusText.Text = "Backup created successfully.";
                }
            catch (Exception ex)
                {
                BackupStatusText.Text = "Backup failed: " + ex.Message;
                }
            }

        private async void RestoreBackup_Click(object sender, RoutedEventArgs e)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;

            var open = new OpenFileDialog { Filter = "SecureVault backup (*.svault)|*.svault" };
            if (open.ShowDialog() != true) return;

            var pass = PromptForPassword("Enter backup passphrase", "Enter the passphrase that protects this backup.");
            if (pass is null) return;

            try
                {
                var target = App.DefaultVaultPath + ".restore.tmp";
                await BackupService.RestoreBackupAsync(open.FileName, target, pass);
                BackupStatusText.Text = "Backup verified and decrypted successfully. Restart the app to load it.";
                }
            catch (Exception ex)
                {
                BackupStatusText.Text = "Restore failed: " + ex.Message;
                }
            }

        private static string? PromptForPassword(string title, string message)
            {
            var prompt = new PasswordPromptWindow(title, message);
            return prompt.ShowDialog() == true ? prompt.Password : null;
            }

        private void SyncProviderBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
            {
            WebDavPanel.Visibility = SyncProviderBox.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
            SyncFolderLabel.Text = SyncProviderBox.SelectedIndex switch
                {
                    1 => "Folder path",
                    2 => "WebDAV URL",
                    _ => "Folder path",
                    };
            }

        private async void SyncNow_Click(object sender, RoutedEventArgs e) => await RunSyncAsync(SyncMode.TwoWay);
        private async void SyncPush_Click(object sender, RoutedEventArgs e) => await RunSyncAsync(SyncMode.Push);
        private async void SyncPull_Click(object sender, RoutedEventArgs e) => await RunSyncAsync(SyncMode.Pull);

        private async Task RunSyncAsync(SyncMode mode)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;

            var provider = BuildProvider();
            if (provider is null)
                {
                SyncStatusText.Text = "Choose a sync provider first.";
                return;
                }

            var settings = SessionManager.Instance.Settings!;
            settings.SyncEnabled = SyncProviderBox.SelectedIndex > 0;
            settings.SyncProvider = SyncProviderBox.SelectedIndex switch { 1 => "folder", 2 => "webdav", _ => null };
            SaveSyncSettings();
            SessionManager.Instance.SaveSettings();

            try
                {
                SyncStatusText.Text = "Syncing…";
                var sync = new SyncService(provider, vault);
                var result = mode switch
                    {
                        SyncMode.Push => await sync.PushAsync(),
                        SyncMode.Pull => await sync.PullAsync(),
                        _ => await sync.SyncAsync(),
                        };

                SyncStatusText.Text = result.Success
                    ? $"Sync complete (pushed: {result.Pushed}, pulled: {result.Pulled})" + (result.Error is not null ? " — " + result.Error : "")
                    : $"Sync failed: {result.Error}";
                }
            catch (Exception ex)
                {
                SyncStatusText.Text = "Sync failed: " + ex.Message;
                }
            }

        private void SaveSyncSettings()
            {
            if (SyncProviderBox.SelectedIndex == 1) SaveSyncConfig("folder_path", SyncFolderBox.Text.Trim());
            if (SyncProviderBox.SelectedIndex == 2)
                {
                SaveSyncConfig("webdav_url", WebDavUrlBox.Text.Trim());
                SaveSyncConfig("webdav_user", WebDavUserBox.Text.Trim());
                }
            }

        private ISyncProvider? BuildProvider()
            {
            return SyncProviderBox.SelectedIndex switch
                {
                    1 => new FolderSyncProvider(SyncFolderBox.Text.Trim()),
                    2 => new WebDavSyncProvider(WebDavUrlBox.Text.Trim(), WebDavUserBox.Text.Trim(), WebDavPassBox.Password),
                    _ => null,
                    };
            }

        private enum SyncMode { TwoWay, Push, Pull }
        }
    }
