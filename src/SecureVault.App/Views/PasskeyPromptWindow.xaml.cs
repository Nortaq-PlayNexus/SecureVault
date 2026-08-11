using System.Windows;

namespace SecureVault.App.Views
    {
    public partial class PasskeyPromptWindow : Window
        {
        public string RelyingParty => RpBox.Text.Trim();
        public string UserHandle => UserBox.Text.Trim();

        public PasskeyPromptWindow()
            {
            InitializeComponent();
            }

        private void Create_Click(object sender, RoutedEventArgs e)
            {
            if (string.IsNullOrWhiteSpace(RpBox.Text) || string.IsNullOrWhiteSpace(UserBox.Text))
                {
                MessageBox.Show("Relying party ID and user handle are required.", "SecureVault",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
                }
            DialogResult = true;
            Close();
            }

        private void Cancel_Click(object sender, RoutedEventArgs e)
            {
            DialogResult = false;
            Close();
            }
        }
    }
