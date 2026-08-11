using System;
using System.IO;
using System.Windows;
using SecureVault.App.Views;

namespace SecureVault.App
    {
    public partial class App : Application
        {
        /// <summary>
        /// Default location of the vault database on this device. The vault is a
        /// single self-contained file (SQLite + encrypted payloads) so it can be
        /// backed up by simply copying it to another machine.
        /// </summary>
        public static string DefaultVaultPath { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SecureVault",
            "vault.svault");

        protected override void OnStartup(StartupEventArgs e)
            {
            base.OnStartup(e);

            var login = new LoginWindow();
            if (login.ShowDialog() == true && login.Unlocked)
                {
                var main = new MainWindow();
                MainWindow = main;
                main.Show();
                }
            else
                {
                Shutdown();
                }
            }
        }
    }
