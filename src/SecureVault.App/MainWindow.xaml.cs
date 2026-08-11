using System;
using System.Windows;
using System.Windows.Controls;
using SecureVault.App.Services;
using SecureVault.App.Views;

namespace SecureVault.App
    {
    public partial class MainWindow : Window, IDisposable
        {
        private readonly ItemsView _items = new();
        private readonly GeneratorView _generator = new();
        private readonly SecurityView _security = new();
        private readonly SettingsView _settings = new();
        private bool _disposed;

        public MainWindow()
            {
            InitializeComponent();
            Closed += (_, _) => Dispose();
            Loaded += (_, _) => RefreshAll();
            ShowView(_items);
            }

        public void Dispose()
            {
            if (_disposed) return;
            _disposed = true;
            _generator.Dispose();
            _security.Dispose();
            GC.SuppressFinalize(this);
            }

        private void RefreshAll()
            {
            VaultNameText.Text = SessionManager.Instance.Settings?.VaultName ?? "Vault";
            _items.Refresh();
            _generator.Refresh();
            _security.Refresh();
            _settings.Refresh();
            }

        private void Nav_Checked(object sender, RoutedEventArgs e)
            {
            if (!IsLoaded) return;

            if (sender == NavItems) ShowView(_items);
            else if (sender == NavGenerator) ShowView(_generator);
            else if (sender == NavSecurity) ShowView(_security);
            else if (sender == NavSettings) ShowView(_settings);
            }

        private void ShowView(UserControl view)
            {
            ContentHost.Content = view;
            }

        private void Lock_Click(object sender, RoutedEventArgs e)
            {
            SessionManager.Instance.Lock();

            var login = new LoginWindow();
            if (login.ShowDialog() == true && login.Unlocked)
                {
                NavItems.IsChecked = true;
                ShowView(_items);
                RefreshAll();
                }
            else
                {
                Application.Current.Shutdown();
                }
            }
        }
    }
