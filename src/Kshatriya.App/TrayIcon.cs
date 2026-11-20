using System.Runtime.InteropServices;
using Kshatriya.Presentation;
using Forms = System.Windows.Forms;

namespace Kshatriya.App;

/// <summary>
/// The notification-area icon: shows the protection level (ADR 0021), opens the app, starts a quick scan,
/// toggles informational notifications, exits. Its balloon tips are shown by Windows 10 and 11 as ordinary
/// toast notifications attributed to the app.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _notifications;
    private readonly Forms.ToolStripMenuItem _scanDrives;
    private readonly Forms.ToolStripMenuItem _statusItem;
    private readonly System.Drawing.Icon _baseIcon;
    private readonly Dictionary<ProtectionLevel, System.Drawing.Icon> _icons = [];
    private ProtectionLevel _level = ProtectionLevel.Checking;

    public TrayIcon(bool notificationsEnabled, bool scanDrivesEnabled, Action open, Action quickScan, Action<bool> setNotifications, Action<bool> setScanDrives, Action exit, Action openBrowserExtension)
    {
        _baseIcon = LoadIcon();
        _notifications = new Forms.ToolStripMenuItem("Show informational notifications")
        {
            CheckOnClick = true,
            Checked = notificationsEnabled,
            ToolTipText = "Scan results and external drives. Threats found in the background are always shown.",
        };
        _notifications.CheckedChanged += (_, _) => setNotifications(_notifications.Checked);
        _scanDrives = new Forms.ToolStripMenuItem("Scan USB drives when connected") { CheckOnClick = true, Checked = scanDrivesEnabled };
        _scanDrives.CheckedChanged += (_, _) => setScanDrives(_scanDrives.Checked);
        _statusItem = new Forms.ToolStripMenuItem("Checking protection…") { Enabled = false };
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Open Kshatriya Antivirus", null, (_, _) => open());
        menu.Items.Add("Quick scan", null, (_, _) => quickScan());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add(_notifications);
        menu.Items.Add(_scanDrives);
        menu.Items.Add("Set up the browser extension…", null, (_, _) => openBrowserExtension());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit (protection keeps running in the service)", null, (_, _) => exit());

        _icon = new Forms.NotifyIcon
        {
            Icon = _baseIcon,
            Text = "Kshatriya Antivirus",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => open();
        _icon.BalloonTipClicked += (_, _) => NotificationClicked?.Invoke();
    }

    /// <summary>The app icon at the notification-area size, or the system shield if the resource is unavailable.</summary>
    internal static System.Drawing.Icon LoadIcon()
    {
        try
        {
            var resource = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Kshatriya.App;component/Assets/kshatriya.ico"));
            if (resource is not null)
            {
                using var stream = resource.Stream;
                return new System.Drawing.Icon(stream, Forms.SystemInformation.SmallIconSize);
            }
        }
        catch (IOException)
        {
        }

        return (System.Drawing.Icon)System.Drawing.SystemIcons.Shield.Clone();
    }

    /// <summary>Raised when the user clicks the latest notification.</summary>
    public event Action? NotificationClicked;

    /// <summary>Updates the menu's check marks after the same preference changed on the Settings page.</summary>
    public void SetChecked(bool? notifications, bool? scanDrives)
    {
        if (notifications is { } n && _notifications.Checked != n)
        {
            _notifications.Checked = n;
        }

        if (scanDrives is { } d && _scanDrives.Checked != d)
        {
            _scanDrives.Checked = d;
        }
    }

    /// <summary>Tooltip text; Windows limits it to 127 characters.</summary>
    public void SetStatus(string text) => _icon.Text = text.Length <= 127 ? text : text[..127];

    /// <summary>
    /// Shows the protection level: a small amber dot when something is worth attention, a red one when action is
    /// needed or Kshatriya is not running. The tooltip and the menu's first line say it in words, so the dot never
    /// carries meaning alone.
    /// </summary>
    public void SetLevel(ProtectionLevel level, string text)
    {
        SetStatus(text);
        _statusItem.Text = text.Length <= 120 ? text : text[..120] + "…";
        if (level != _level)
        {
            _level = level;
            _icon.Icon = IconFor(level);
        }
    }

    public void Notify(string title, string message, bool warning) =>
        _icon.ShowBalloonTip(10_000, title, message, warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();
        foreach (System.Drawing.Icon icon in _icons.Values)
        {
            icon.Dispose();
        }

        _baseIcon.Dispose();
    }

    private System.Drawing.Icon IconFor(ProtectionLevel level)
    {
        System.Drawing.Color? dot = level switch
        {
            ProtectionLevel.AttentionRecommended => System.Drawing.Color.FromArgb(0xF2, 0xA9, 0x00),
            ProtectionLevel.ActionNeeded or ProtectionLevel.NotRunning => System.Drawing.Color.FromArgb(0xC4, 0x2B, 0x1C),
            _ => null,
        };
        if (dot is not { } colour)
        {
            return _baseIcon;
        }

        if (!_icons.TryGetValue(level, out System.Drawing.Icon? icon))
        {
            icon = WithDot(_baseIcon, colour);
            _icons[level] = icon;
        }

        return icon;
    }

    /// <summary>The icon with a dot in its lower-right corner, ringed in white so it reads on any taskbar.</summary>
    internal static System.Drawing.Icon WithDot(System.Drawing.Icon source, System.Drawing.Color colour)
    {
        using System.Drawing.Bitmap bitmap = source.ToBitmap();
        using (var g = System.Drawing.Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            int size = Math.Max(6, bitmap.Width / 2);
            var rect = new System.Drawing.Rectangle(bitmap.Width - size, bitmap.Height - size, size - 1, size - 1);
            using var fill = new System.Drawing.SolidBrush(colour);
            using var ring = new System.Drawing.Pen(System.Drawing.Color.White, Math.Max(1, size / 6));
            g.FillEllipse(fill, rect);
            g.DrawEllipse(ring, rect);
        }

        nint handle = bitmap.GetHicon();
        try
        {
            using var owned = System.Drawing.Icon.FromHandle(handle);
            return (System.Drawing.Icon)owned.Clone();
        }
        finally
        {
            NativeMethods.DestroyIcon(handle);
        }
    }
}

internal static partial class NativeMethods
{
    /// <summary>Frees the icon handle that <c>Bitmap.GetHicon</c> created (the cloned icon keeps its own copy).</summary>
    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DestroyIcon(nint icon);
}
