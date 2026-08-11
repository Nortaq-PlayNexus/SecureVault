using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using SecureVault.App.Services;
using SecureVault.Core.Security;

namespace SecureVault.App.Views
    {
    public partial class GeneratorView : UserControl, IDisposable
        {
        private readonly ClipboardGuard _clipboard = new();
        private readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(150) };

        public GeneratorView()
            {
            InitializeComponent();
            Unloaded += (_, _) => Dispose();
            LengthSlider.ValueChanged += (_, _) => { LengthLabel.Text = ((int)LengthSlider.Value).ToString(System.Globalization.CultureInfo.InvariantCulture); _debounce.Stop(); _debounce.Start(); };
            foreach (var cb in new[] { LowercaseBox, UppercaseBox, DigitsBox, SymbolsBox, NoAmbiguousBox })
                cb.Checked += (_, _) => { _debounce.Stop(); _debounce.Start(); };
            foreach (var cb in new[] { LowercaseBox, UppercaseBox, DigitsBox, SymbolsBox, NoAmbiguousBox })
                cb.Unchecked += (_, _) => { _debounce.Stop(); _debounce.Start(); };
            _debounce.Tick += (_, _) => { _debounce.Stop(); Generate(); };
            }

        public void Refresh()
            {
            _clipboard.Configure(SessionManager.Instance.Settings?.ClipboardClearEnabled ?? true,
                SessionManager.Instance.Settings?.ClipboardClearSeconds ?? 30);
            Generate();
            }

        private void Generate_Click(object sender, RoutedEventArgs e) => Generate();
        private void GeneratePhrase_Click(object sender, RoutedEventArgs e) => GeneratePassphrase();

        private void Generate()
            {
            var options = new PasswordOptions
                {
                Length = (int)LengthSlider.Value,
                IncludeLowercase = LowercaseBox.IsChecked == true,
                IncludeUppercase = UppercaseBox.IsChecked == true,
                IncludeDigits = DigitsBox.IsChecked == true,
                IncludeSymbols = SymbolsBox.IsChecked == true,
                ExcludeAmbiguous = NoAmbiguousBox.IsChecked == true,
                };
            OutputBox.Text = PasswordGenerator.Generate(options);
            EntropyText.Text = $"Estimated entropy: {PasswordGenerator.EstimateEntropy(OutputBox.Text):N0} bits. " +
                               $"A 20-char password with all classes ≈ 100+ bits is considered strong.";
            }

        private void GeneratePassphrase()
            {
            var item = WordCountBox.SelectedItem as ComboBoxItem;
            var count = int.Parse(item?.Content?.ToString() ?? "6", System.Globalization.CultureInfo.InvariantCulture);
            var phrase = PasswordGenerator.GeneratePassphrase(count, "-", includeDigit: true);
            PassphraseOutputBox.Text = phrase;
            EntropyText.Text = $"Diceware passphrase: {count} words from a 4096-word list ≈ {count * 12:N0}+ bits of entropy.";
            }

        private void Copy_Click(object sender, RoutedEventArgs e) => _clipboard.CopyProtected(OutputBox.Text);
        private void CopyPhrase_Click(object sender, RoutedEventArgs e) => _clipboard.CopyProtected(PassphraseOutputBox.Text);

        public void Dispose()
            {
            GC.SuppressFinalize(this);
            _clipboard.Dispose();
            }
        }
    }
