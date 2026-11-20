using Kshatriya.App.Infrastructure;

namespace Kshatriya.App.ViewModels;

/// <summary>
/// The user's own preferences (the same ones as in the notification-area menu), the browser extension and,
/// for administrators, exclusions.
/// </summary>
public sealed class SettingsViewModel(IAppSettings settings, IAppHost host, ExclusionsViewModel exclusions)
    : PageViewModel("Settings", "Your preferences for this app, and exclusions", Glyphs.Settings)
{
    /// <summary>Show informational notifications (scan results, external drives); critical ones are always shown (default on).</summary>
    public bool Notifications
    {
        get => settings.Notifications;
        set
        {
            if (value != settings.Notifications)
            {
                settings.SetNotifications(value);
                OnPropertyChanged();
            }
        }
    }

    /// <summary>Scan USB drives, external disks and memory cards when connected (default on).</summary>
    public bool ScanExternalDrives
    {
        get => settings.ScanExternalDrives;
        set
        {
            if (value != settings.ScanExternalDrives)
            {
                settings.SetScanExternalDrives(value);
                OnPropertyChanged();
            }
        }
    }

    public string StartupNote { get; } =
        "Kshatriya starts in the notification area when you sign in. You can turn that off in Task Manager > Startup apps; protection keeps running in the service either way.";

    public RelayCommand SetUpBrowserExtensionCommand => new(_ => host.OpenBrowserExtension());

    public ExclusionsViewModel Exclusions { get; } = exclusions;

    /// <summary>Called when the same preference was changed elsewhere (the notification-area menu).</summary>
    public void PreferencesChanged()
    {
        OnPropertyChanged(nameof(Notifications));
        OnPropertyChanged(nameof(ScanExternalDrives));
    }

    protected override Task RefreshCoreAsync() => Exclusions.RefreshCommand.ExecuteAsync(null);
}
