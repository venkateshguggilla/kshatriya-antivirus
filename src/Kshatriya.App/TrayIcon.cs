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

    public TrayIcon(bool notificationsEnabled, Action open, Action<bool> setNotifications, Action exit)
    {
        _notifications = new Forms.ToolStripMenuItem("Show notifications") { CheckOnClick = true, Checked = notificationsEnabled };
        _notifications.CheckedChanged += (_, _) => setNotifications(_notifications.Checked);
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open Kshatriya Antivirus", null, (_, _) => open());
        menu.Items.Add(_notifications);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit (protection keeps running in the service)", null, (_, _) => exit());

        _icon = new Forms.NotifyIcon
        {
            Icon = System.Drawing.SystemIcons.Shield,
            Text = "Kshatriya Antivirus",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => open();
        _icon.BalloonTipClicked += (_, _) => NotificationClicked?.Invoke();
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
