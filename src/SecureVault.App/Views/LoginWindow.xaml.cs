using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using SecureVault.App.Services;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;
using SecureVault.Core.Vault;

namespace SecureVault.App.Views
    {
    public partial class LoginWindow : Window
        {
        private readonly string _vaultPath;
        private bool _isNewVault;
        public bool Unlocked { get; private set; }
        public VaultService? Vault { get; private set; }

        public LoginWindow(string? vaultPath = null)
            {
            InitializeComponent();
            _vaultPath = vaultPath ?? App.DefaultVaultPath;
            _isNewVault = !File.Exists(_vaultPath);
            ConfigureForMode();
            Loaded += async (_, _) => await CheckHelloAsync();
            }

        private void ConfigureForMode()
            {
            NewVaultPanel.Visibility = _isNewVault ? Visibility.Visible : Visibility.Collapsed;
            ExistingVaultPanel.Visibility = _isNewVault ? Visibility.Collapsed : Visibility.Visible;
            CreateButton.Visibility = _isNewVault ? Visibility.Visible : Visibility.Collapsed;
            HeaderText.Text = _isNewVault ? "Create your vault" : "Unlock your vault";
            ToggleText.Text = _isNewVault ? "I already have a vault on this device" : "I need to create a new vault";
            }

        private async Task CheckHelloAsync()
            {
            if (_isNewVault) return;
            var header = VaultService.PeekHeader(_vaultPath);
            HardwareUnlockButton.Visibility = header?.HardwareWrappedDek is not null ? Visibility.Visible : Visibility.Collapsed;
            await Task.CompletedTask;
            }

        private void ToggleText_MouseDown(object sender, MouseButtonEventArgs e)
            {
            _isNewVault = !_isNewVault;
            ConfigureForMode();
            }

        private void CreateButton_Click(object sender, RoutedEventArgs e)
            {
            var name = VaultNameBox.Text.Trim();
            var password = NewPasswordBox.Password;
            var confirm = ConfirmPasswordBox.Password;

            if (string.IsNullOrEmpty(name)) { ShowError("Please enter a vault name."); return; }
            if (password.Length < 8) { ShowError("Master password must be at least 8 characters."); return; }
            if (password != confirm) { ShowError("Passwords do not match."); return; }

            try
                {
                var service = new VaultService(_vaultPath);
                service.Create(password,
                    suite: CipherSuite.Aes256Gcm,
                    vaultName: name,
                    enableHardware: HardwareBox.IsChecked == true);

                var settings = service.GetSettings();
                settings.VaultName = name;
                if (HardwareBox.IsChecked == true)
                    {
                    settings.HardwareUnlockEnabled = true;
                    settings.WindowsHelloEnabled = true;
                    }
                service.SaveSettings(settings);

                SessionManager.Instance.SetVault(service, _vaultPath, settings);
                Vault = service;
                Unlocked = true;
                DialogResult = true;
                Close();
                }
            catch (Exception ex)
                {
                ShowError(ex.Message);
                }
            }

        private void UnlockButton_Click(object sender, RoutedEventArgs e) => UnlockWithPassword();

        private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
            {
            if (e.Key == Key.Enter) UnlockWithPassword();
            }

        private void UnlockWithPassword()
            {
            var password = PasswordBox.Password;
            if (string.IsNullOrEmpty(password)) { ShowError("Enter your master password."); return; }

            try
                {
                var service = new VaultService(_vaultPath);
                if (!service.Unlock(password))
                    {
                    ShowError("Incorrect master password.");
                    return;
                    }

                var settings = service.GetSettings();
                SessionManager.Instance.SetVault(service, _vaultPath, settings);
                Vault = service;
                Unlocked = true;
                DialogResult = true;
                Close();
                }
            catch (Core.Storage.TamperDetectedException ex)
                {
                ShowError("Security alert: " + ex.Message);
                }
            catch (Exception ex)
                {
                ShowError(ex.Message);
                }
            }

        private async void HardwareUnlockButton_Click(object sender, RoutedEventArgs e)
            {
            try
                {
                var service = new VaultService(_vaultPath);
                if (!service.UnlockWithHardware())
                    {
                    ShowError("Hardware unlock failed. The TPM key may be unavailable.");
                    return;
                    }
                var settings = service.GetSettings();
                SessionManager.Instance.SetVault(service, _vaultPath, settings);
                Vault = service;
                Unlocked = true;
                DialogResult = true;
                Close();
                }
            catch (Exception ex)
                {
                ShowError(ex.Message);
                }
            await Task.CompletedTask;
            }

        private void ShowError(string message)
            {
            ErrorText.Text = message;
            ErrorText.Visibility = Visibility.Visible;
            }
        }
    }
