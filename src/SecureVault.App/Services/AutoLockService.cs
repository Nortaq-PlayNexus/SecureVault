using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace SecureVault.App.Services;

/// <summary>
/// Automatically locks the vault after a period of inactivity. The timer resets
/// on any user input.
/// </summary>
public sealed class AutoLockService
    {
    private readonly DispatcherTimer _timer;
    private readonly Func<Task> _onLock;

    public AutoLockService(Func<Task> onLock)
        {
        _onLock = onLock;
        _timer = new DispatcherTimer();
        _timer.Tick += async (_, _) => { Stop(); await _onLock(); };
        }

    public TimeSpan Timeout { get; private set; } = TimeSpan.FromMinutes(5);
    public bool Enabled { get; private set; }

    public void Configure(bool enabled, int minutes)
        {
        Enabled = enabled;
        Timeout = TimeSpan.FromMinutes(Math.Max(1, minutes));
        if (enabled) Reset(); else Stop();
        }

    public void Reset()
        {
        if (!Enabled) return;
        _timer.Stop();
        _timer.Interval = Timeout;
        _timer.Start();
        }

    public void Stop() => _timer.Stop();
    }
