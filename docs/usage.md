# Usage Guide

A tour of SecureVault for end users.

## Getting started

1. Launch **SecureVault**. On first run you'll see **Create your vault**.
2. Pick a **vault name** and set a **master password** (≥ 8 chars; use the generator for a
   strong one — it's offered on the same screen's sibling panel).
3. Optionally tick **Enable hardware unlock** (TPM) so you can unlock with Windows Hello.
4. Click **Create vault**.

The vault file is created at `%LOCALAPPDATA%\SecureVault\vault.db`.

> Your master password is **never stored** and cannot be recovered. If you forget it, the
> only recovery is a backup (`.svault`) you made earlier.

## Unlocking

- **Password**: type your master password.
- **Windows Hello / TPM**: if enabled, click the hardware unlock button; Windows will prompt
  for biometrics or PIN.
- On a fresh device, choose **I need to create a new vault** to start over, or unlock and use
  **Sync** / **Backup restore** to bring your data in.

## The dashboard (Items)

The left sidebar lists: **Items**, **Password generator**, **Security & health**, **Settings**.

- **Search box** filters by title/username/url.
- **Filter** dropdowns for item type and favorites.
- **New item** button opens the item editor.
- Select an item to see a detail panel; **Edit**, **Copy username/password**, **Delete**
  (moves to trash), and for trashed items **Restore** or **Purge**.
- **Versions**: editing an item saves a snapshot; open the item and use **History** to review
  or roll back (last 50 versions).

### Item types

| Type | What it stores |
| --- | --- |
| Login | Username, password, URL, optional OTP secret, notes |
| Secure note | Free-form encrypted text |
| File | An encrypted file attachment |
| SSH key | Private/public key, optional passphrase |
| API token | Token, URL, expiry |
| Passkey | Windows Hello passkey credential metadata |

## Password generator

- Configure length, character classes, and whether to exclude ambiguous characters
  (`Il1O0|…`).
- Generate a **random password** or a **Diceware passphrase** (6+ memorable words from a
  4096-word list ≈ 72+ bits).
- **Copy** copies to the clipboard and (if enabled) auto-clears after 30 s.
- The entropy estimate updates live.

## Security & health

- **Run health check**:
  - Local analysis flags short, low-complexity, or personally-identifiable passwords.
  - **Phishing detection** flags suspicious URLs (HTTP, raw IPs, brand lookalikes,
    hyphenated impersonation).
  - **Breach check** queries HaveIBeenPwned using k-anonymity — only 5 hex chars of a SHA-1
    hash ever leave your device, and only if you enabled the network check.
- **Passkeys**: create a Windows Hello passkey bound to a relying party.
- **Audit log**: tamper-evident history of vault actions (unlocks, changes, syncs, backups).

## Settings

- **General**: vault name, auto-lock timer (default 5 min).
- **Clipboard**: auto-clear copied secrets (default on, 30 s).
- **Hardware**: enable/disable TPM hardware unlock and Windows Hello.
- **Breach checking**: toggle the network breach lookup.
- **Backup**: create an encrypted `*.svault` backup (passphrase required), restore from one.
- **Sync**: choose **Folder** (Dropbox/OneDrive/NAS) or **WebDAV**, enter the destination,
  then **Sync now**. Push/pull/two-way is conflict-safe and end-to-end encrypted.

## Privacy checklist

- [ ] Enabled hardware unlock (TPM) + Windows Hello
- [ ] Enabled auto-lock (5 min or less)
- [ ] Enabled clipboard auto-clear
- [ ] Created a backup and stored it off-device
- [ ] Set up sync to a folder/WebDAV you control
- [ ] Run **Security & health** at least monthly
