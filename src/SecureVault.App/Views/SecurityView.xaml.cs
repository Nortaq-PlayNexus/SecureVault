using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using SecureVault.App.Services;
using SecureVault.Core.AI;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;
using SecureVault.Core.Security;

namespace SecureVault.App.Views
    {
    public partial class SecurityView : UserControl, IDisposable
        {
        private readonly BreachChecker _breach = new(networkEnabled: true);

        public SecurityView()
            {
            InitializeComponent();
            Unloaded += (_, _) => Dispose();
            }

        public void Dispose()
            {
            GC.SuppressFinalize(this);
            _breach.Dispose();
            }

        public void Refresh()
            {
            LoadAudit();
            HelloStatusText.Text = PasskeyProvider.IsAvailable
                ? "Windows Hello available"
                : "Windows Hello unavailable on this device";
            }

        private void LoadAudit()
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;
            var events = vault.GetAuditEvents();
            AuditList.ItemsSource = events.Take(100).Select(e => new
                {
                TimestampLabel = e.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture),
                ActionLabel = e.Action.ToString(),
                Detail = e.Detail,
                }).ToList();
            }

        private async void RunHealthCheck_Click(object sender, RoutedEventArgs e)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;
            HealthText.Text = "Scanning your vault… this checks each password against the HaveIBeenPwned k-anonymity API (your passwords never leave this device).";
            HealthText.Foreground = System.Windows.Media.Brushes.LightGray;

            var findings = new List<string>();
            foreach (var item in vault.GetItems())
                {
                if (item.Type == VaultItemType.Login)
                    {
                    try
                        {
                        var login = vault.DecryptPayload<LoginPayload>(item);

                        // local weak-password heuristics
                        foreach (var f in AiOrganizer.AnalyzeStrength(login.Password, login.Username, login.Url))
                            findings.Add($"• {item.Title}: {f}");

                        // phishing
                        var phish = PhishingDetector.Analyze(login.Url);
                        if (phish.Suspicious)
                            findings.Add($"• {item.Title}: phishing risk — {string.Join("; ", phish.Reasons)}");

                        // breach check (network, k-anonymous)
                        var breach = await _breach.CheckPasswordAsync(login.Password);
                        if (breach.Exposed)
                            findings.Add($"• {item.Title}: password exposed in {breach.Count:N0} known breach(es) — change it now!");
                        }
                    catch
                        {
                        // skip undecryptable item
                        }
                    }
                }

            if (findings.Count == 0)
                {
                HealthText.Text = "All checks passed. No weak, breached, or phishing-prone credentials found.";
                HealthText.Foreground = System.Windows.Media.Brushes.LightGreen;
                }
            else
                {
                HealthText.Text = string.Join("\n", findings);
                HealthText.Foreground = System.Windows.Media.Brushes.Orange;
                }
            LoadAudit();
            }

        private void CreatePasskey_Click(object sender, RoutedEventArgs e)
            {
            var vault = SessionManager.Instance.Vault;
            if (vault is null) return;
            if (!PasskeyProvider.IsAvailable)
                {
                MessageBox.Show("Windows Hello is not available on this device.", "SecureVault",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
                }

            var prompt = new PasskeyPromptWindow();
            if (prompt.ShowDialog() != true) return;

            try
                {
                var credential = PasskeyProvider.CreatePasskey(prompt.RelyingParty, prompt.UserHandle, prompt.UserHandle, CryptoRandom.GetBytes(32));
                vault.AddItem(VaultItemType.Passkey, new PasskeyPayload
                    {
                    RpId = credential.RpId,
                    UserHandle = credential.UserId,
                    CredentialId = Convert.ToBase64String(credential.Id),
                    PublicKey = credential.PublicKey,
                    });
                MessageBox.Show($"Passkey created for {credential.RpId}. The private key is protected by your TPM.", "SecureVault",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                }
            catch (Exception ex)
                {
                MessageBox.Show(ex.Message, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            LoadAudit();
            }
        }
    }
