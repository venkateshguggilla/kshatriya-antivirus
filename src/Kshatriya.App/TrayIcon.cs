using Forms = System.Windows.Forms;

namespace Kshatriya.App;

/// <summary>
/// The notification-area icon: opens the app, toggles notifications, exits. Its balloon tips are shown by
/// Windows 10 and 11 as ordinary toast notifications attributed to the app.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Forms.ToolStripMenuItem _notifications;
    private readonly Forms.ToolStripMenuItem _scanDrives;

    public TrayIcon(bool notificationsEnabled, bool scanDrivesEnabled, Action open, Action<bool> setNotifications, Action<bool> setScanDrives, Action exit, Action openBrowserExtension)
    {
        _notifications = new Forms.ToolStripMenuItem("Show notifications") { CheckOnClick = true, Checked = notificationsEnabled };
        _notifications.CheckedChanged += (_, _) => setNotifications(_notifications.Checked);
        _scanDrives = new Forms.ToolStripMenuItem("Scan USB drives when connected") { CheckOnClick = true, Checked = scanDrivesEnabled };
        _scanDrives.CheckedChanged += (_, _) => setScanDrives(_scanDrives.Checked);
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open Kshatriya Antivirus", null, (_, _) => open());
        menu.Items.Add(_notifications);
        menu.Items.Add(_scanDrives);
        menu.Items.Add("Set up the browser extension…", null, (_, _) => openBrowserExtension());
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit (protection keeps running in the service)", null, (_, _) => exit());

        _icon = new Forms.NotifyIcon
        {
            Icon = LoadIcon(),
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

        return System.Drawing.SystemIcons.Shield;
    }

    /// <summary>Raised when the user clicks the latest notification.</summary>
    public event Action? NotificationClicked;

    /// <summary>Tooltip text; Windows limits it to 127 characters.</summary>
    public void SetStatus(string text) => _icon.Text = text.Length <= 127 ? text : text[..127];

    public void Notify(string title, string message, bool warning) =>
        _icon.ShowBalloonTip(10_000, title, message, warning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();
    }
}
