namespace Kshatriya.Presentation;

/// <summary>The kinds of notification Kshatriya may show (ADR 0021, section 3). There is deliberately no "all clear" kind.</summary>
public enum NotificationCategory
{
    /// <summary>Real-time monitoring, a schedule or behaviour detection found something.</summary>
    BackgroundFinding,

    /// <summary>The service stopped while the app was connected.</summary>
    ServiceStopped,

    /// <summary>The audit log failed its integrity check.</summary>
    AuditFailure,

    /// <summary>A scan the user started has finished.</summary>
    ScanFinished,

    /// <summary>A signed content update was installed.</summary>
    UpdateInstalled,

    /// <summary>An external drive was connected or scanned.</summary>
    ExternalDrive,
}

/// <summary>Critical notifications are always shown; informational ones can be turned off by category.</summary>
public enum NotificationImportance
{
    Critical,
    Informational,
}

/// <summary>The user's choices for informational notifications.</summary>
public sealed record NotificationPreferences
{
    public bool ScanResults { get; init; } = true;

    public bool Updates { get; init; } = true;

    public bool ExternalDrives { get; init; } = true;
}

/// <summary>Decides whether a notification is shown. Pure, so both apps and the tests agree on it.</summary>
public static class NotificationPolicy
{
    public static NotificationImportance ImportanceOf(NotificationCategory category) => category switch
    {
        NotificationCategory.BackgroundFinding or NotificationCategory.ServiceStopped or NotificationCategory.AuditFailure => NotificationImportance.Critical,
        _ => NotificationImportance.Informational,
    };

    /// <param name="category">What happened.</param>
    /// <param name="preferences">The user's choices for informational notifications.</param>
    /// <param name="appInForeground">Whether the app's window is visible; results the user is looking at need no notification.</param>
    public static bool ShouldNotify(NotificationCategory category, NotificationPreferences preferences, bool appInForeground)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        return category switch
        {
            NotificationCategory.BackgroundFinding or NotificationCategory.ServiceStopped or NotificationCategory.AuditFailure => true,
            NotificationCategory.ScanFinished => preferences.ScanResults && !appInForeground,
            NotificationCategory.UpdateInstalled => preferences.Updates && !appInForeground,
            NotificationCategory.ExternalDrive => preferences.ExternalDrives,
            _ => false,
        };
    }
}
