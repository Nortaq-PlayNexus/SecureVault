using System.Windows;
using System.Windows.Input;

namespace SecureVault.App.Views
    {
    public partial class PasswordPromptWindow : Window
        {
        public string Password => PasswordInput.Password;

        public PasswordPromptWindow(string title, string message)
            {
            InitializeComponent();
            TitleText.Text = title;
            MessageText.Text = message;
            Loaded += (_, _) => PasswordInput.Focus();
            }

        private void Ok_Click(object sender, RoutedEventArgs e)
            {
            DialogResult = true;
            Close();
            }

        private void Cancel_Click(object sender, RoutedEventArgs e)
            {
            DialogResult = false;
            Close();
            }

        private void PasswordInput_KeyDown(object sender, KeyEventArgs e)
            {
            if (e.Key == Key.Enter) Ok_Click(sender, e);
            }
        }
    }
