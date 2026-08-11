using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SecureVault.App.Services;
using SecureVault.Core.AI;
using SecureVault.Core.Crypto;
using SecureVault.Core.Model;
using SecureVault.Core.Security;
using SecureVault.Core.Vault;

namespace SecureVault.App.Views
    {
    public partial class ItemEditorDialog : Window, IDisposable
        {
        private readonly VaultItem? _existing;
        private VaultItemType _selectedType = VaultItemType.Login;
        private byte[]? _fileContent;
        private string _filePath = string.Empty;
        private readonly ClipboardGuard _clipboard = new();

        public ItemEditorDialog(VaultItem? existing)
            {
            InitializeComponent();
            Closed += (_, _) => Dispose();
            _existing = existing;
            if (existing is not null)
                {
                Title = "Edit item";
                HeaderText.Text = "Edit item";
                LoadExisting(existing);
                }
            SelectPanel();
            TypeCombo.SelectedIndex = _selectedType switch
                {
                    VaultItemType.Login => 0,
                    VaultItemType.Note => 1,
                    VaultItemType.SshKey => 2,
                    VaultItemType.ApiToken => 3,
                    VaultItemType.File => 4,
                    VaultItemType.Passkey => 5,
                    _ => 0,
                    };
            }

        private void LoadExisting(VaultItem item)
            {
            var vault = SessionManager.Instance.Vault!;
            TitleBox.Text = item.Title;
            _selectedType = item.Type;

            switch (item.Type)
                {
                case VaultItemType.Login:
                    var login = vault.DecryptPayload<LoginPayload>(item);
                    UsernameBox.Text = login.Username;
                    PasswordBox.Password = login.Password;
                    UrlBox.Text = login.Url;
                    OtpBox.Text = login.OtpSecret;
                    LoginNotesBox.Text = login.Notes;
                    break;
                case VaultItemType.Note:
                    NoteBox.Text = vault.DecryptPayload<NotePayload>(item).Text;
                    break;
                case VaultItemType.SshKey:
                    var ssh = vault.DecryptPayload<SshKeyPayload>(item);
                    SshTypeBox.Text = ssh.KeyType;
                    SshPrivateBox.Text = ssh.PrivateKey;
                    SshPublicBox.Text = ssh.PublicKey;
                    SshPassphraseBox.Text = ssh.Passphrase;
                    break;
                case VaultItemType.ApiToken:
                    var api = vault.DecryptPayload<ApiTokenPayload>(item);
                    ApiNameBox.Text = api.Name;
                    ApiTokenBox.Text = api.Token;
                    ApiUrlBox.Text = api.Url;
                    break;
                case VaultItemType.File:
                    var file = vault.DecryptPayload<FilePayload>(item);
                    TitleBox.Text = file.FileName;
                    FilePathBox.Text = file.FileName;
                    _fileContent = vault.DecryptContent(item);
                    break;
                case VaultItemType.Passkey:
                    var pass = vault.DecryptPayload<PasskeyPayload>(item);
                    PasskeyRpBox.Text = pass.RpId;
                    PasskeyUserBox.Text = pass.UserHandle;
                    break;
                }
            }

        private void TypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
            {
            if (TypeCombo.SelectedIndex < 0) return;
            _selectedType = TypeCombo.SelectedIndex switch
                {
                    0 => VaultItemType.Login,
                    1 => VaultItemType.Note,
                    2 => VaultItemType.SshKey,
                    3 => VaultItemType.ApiToken,
                    4 => VaultItemType.File,
                    5 => VaultItemType.Passkey,
                    _ => VaultItemType.Login,
                    };
            SelectPanel();
            }

        private void SelectPanel()
            {
            LoginPanel.Visibility = _selectedType == VaultItemType.Login ? Visibility.Visible : Visibility.Collapsed;
            NotePanel.Visibility = _selectedType == VaultItemType.Note ? Visibility.Visible : Visibility.Collapsed;
            SshPanel.Visibility = _selectedType == VaultItemType.SshKey ? Visibility.Visible : Visibility.Collapsed;
            ApiPanel.Visibility = _selectedType == VaultItemType.ApiToken ? Visibility.Visible : Visibility.Collapsed;
            FilePanel.Visibility = _selectedType == VaultItemType.File ? Visibility.Visible : Visibility.Collapsed;
            PasskeyPanel.Visibility = _selectedType == VaultItemType.Passkey ? Visibility.Visible : Visibility.Collapsed;
            }

        private void GeneratePassword_Click(object sender, RoutedEventArgs e)
            {
            PasswordBox.Password = PasswordGenerator.Generate();
            _clipboard.CopyProtected(PasswordBox.Password);
            }

        private void ChooseFile_Click(object sender, RoutedEventArgs e)
            {
            var dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
                {
                _filePath = dialog.FileName;
                FilePathBox.Text = Path.GetFileName(_filePath);
                TitleBox.Text = Path.GetFileName(_filePath);
                }
            }

        private void Save_Click(object sender, RoutedEventArgs e)
            {
            var title = TitleBox.Text.Trim();
            if (string.IsNullOrEmpty(title))
                {
                ErrorText.Text = "Please enter a title.";
                return;
                }

            var vault = SessionManager.Instance.Vault!;
            object? payload = null;
            byte[]? content = null;

            try
                {
                switch (_selectedType)
                    {
                    case VaultItemType.Login:
                        payload = new LoginPayload
                            {
                            Username = UsernameBox.Text.Trim(),
                            Password = PasswordBox.Password,
                            Url = UrlBox.Text.Trim(),
                            OtpSecret = string.IsNullOrEmpty(OtpBox.Text) ? null : OtpBox.Text.Trim(),
                            Notes = LoginNotesBox.Text,
                            };
                        break;
                    case VaultItemType.Note:
                        payload = new NotePayload { Text = NoteBox.Text };
                        break;
                    case VaultItemType.SshKey:
                        payload = new SshKeyPayload
                            {
                            KeyType = SshTypeBox.Text.Trim(),
                            PrivateKey = SshPrivateBox.Text,
                            PublicKey = SshPublicBox.Text,
                            Passphrase = SshPassphraseBox.Text,
                            };
                        break;
                    case VaultItemType.ApiToken:
                        payload = new ApiTokenPayload
                            {
                            Name = ApiNameBox.Text.Trim(),
                            Token = ApiTokenBox.Text.Trim(),
                            Url = ApiUrlBox.Text.Trim(),
                            };
                        break;
                    case VaultItemType.File:
                        if (_fileContent is null)
                            {
                            ErrorText.Text = "Choose a file to encrypt.";
                            return;
                            }
                        payload = new FilePayload
                            {
                            FileName = Path.GetFileName(_filePath),
                            MimeType = GetMimeType(_filePath),
                            Size = _fileContent.LongLength,
                            };
                        content = _fileContent;
                        break;
                    case VaultItemType.Passkey:
                        payload = new PasskeyPayload
                            {
                            RpId = PasskeyRpBox.Text.Trim(),
                            UserHandle = PasskeyUserBox.Text.Trim(),
                            };
                        break;
                    }

                if (payload is null)
                    {
                    ErrorText.Text = "Incomplete item.";
                    return;
                    }

                // AI-assisted tagging suggestion (local only).
                var itemForTag = new VaultItem { Id = CryptoRandom.NewGuid(), Title = title, Type = _selectedType };
                var suggestion = AiOrganizer.SuggestTags(itemForTag, payload);

                if (_existing is null)
                    {
                    var created = vault.AddItem(_selectedType, payload, content, suggestion?.SuggestedTags);
                    if (string.IsNullOrEmpty(TitleBox.Text) && created.Type == VaultItemType.File)
                        TitleBox.Text = created.Title;
                    }
                else
                    {
                    vault.UpdateItem(_existing.Id, payload, content, suggestion?.SuggestedTags);
                    }

                DialogResult = true;
                Close();
                }
            catch (Exception ex)
                {
                ErrorText.Text = ex.Message;
                }
            }

        private void Cancel_Click(object sender, RoutedEventArgs e)
            {
            DialogResult = false;
            Close();
            }

        private static string GetMimeType(string path) => Path.GetExtension(path).ToLowerInvariant() switch
            {
                ".pdf" => "application/pdf",
                ".png" => "image/png",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".txt" => "text/plain",
                ".zip" => "application/zip",
                ".pem" or ".key" => "application/x-pem-file",
                ".json" => "application/json",
                _ => "application/octet-stream",
                };

        public void Dispose()
            {
            GC.SuppressFinalize(this);
            _clipboard.Dispose();
            }
        }
    }
