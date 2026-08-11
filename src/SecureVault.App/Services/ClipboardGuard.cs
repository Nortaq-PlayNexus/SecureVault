using System;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace SecureVault.App.Services;

/// <summary>
/// Clears sensitive data from the clipboard after a configurable delay. Only
/// text copied while the vault is unlocked is cleared, so the user's other
/// clipboard history is preserved.
/// </summary>
public sealed class ClipboardGuard : IDisposable
    {
    private readonly DispatcherTimer _timer;
    private string? _protectedText;
    private CancellationTokenSource? _cts;

    public ClipboardGuard()
        {
        _timer = new DispatcherTimer();
        _timer.Tick += (_, _) => ClearProtected();
        }

    public bool Enabled { get; private set; }
    public TimeSpan Delay { get; private set; } = TimeSpan.FromSeconds(30);

    public void Configure(bool enabled, int seconds)
        {
        Enabled = enabled;
        Delay = TimeSpan.FromSeconds(Math.Max(1, seconds));
        if (!enabled) ClearProtected();
        }

    /// <summary>Copy sensitive text and schedule its automatic clearing.</summary>
    public void CopyProtected(string text)
        {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        _protectedText = text;

        try
            {
            Clipboard.SetText(text);
            }
        catch
            {
            return;
            }

        if (!Enabled) return;
        _timer.Stop();
        _timer.Interval = Delay;
        _timer.Start();
        }

    /// <summary>Clear the protected clipboard contents if unchanged since copy.</summary>
    public void ClearProtected()
        {
        _timer.Stop();
        if (_protectedText is null) return;

        try
            {
            if (Clipboard.ContainsText())
                {
                var current = Clipboard.GetText();
                if (current == _protectedText) Clipboard.Clear();
                }
            }
        catch
            {
            // Clipboard is locked by another process; ignore.
            }
        finally
            {
            _protectedText = null;
            }
        }

    public void Dispose()
        {
        _cts?.Cancel();
        ClearProtected();
        }
    }
