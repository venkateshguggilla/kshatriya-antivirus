using Android.App;
using Android.Content;

namespace Kshatriya.AndroidApp;

/// <summary>
/// Notifications (ADR 0021): one channel per kind, so people can silence the informational one in Android
/// settings and keep threat notifications. There are no "all clear" notifications. Tapping one opens Kshatriya.
/// </summary>
internal static class Notifier
{
    /// <summary>Threats and things to review: high importance.</summary>
    public const string FindingsChannel = "findings";

    /// <summary>Signature updates installed in the background: low importance, can be turned off.</summary>
    public const string UpdatesChannel = "updates";

    public static void EnsureChannel(Context context)
    {
        var manager = (NotificationManager)context.GetSystemService(Context.NotificationService)!;
        manager.CreateNotificationChannel(new NotificationChannel(FindingsChannel, "Threats found", NotificationImportance.High)
        {
            Description = "When Kshatriya finds a threat, or something to review, in an app or file.",
        });
        manager.CreateNotificationChannel(new NotificationChannel(UpdatesChannel, "Signature updates", NotificationImportance.Low)
        {
            Description = "When a signed signature update was installed automatically.",
        });
    }

    /// <summary>
    /// Notifies about findings not reported before: one notification for one finding, one summary for several.
    /// Nothing is shown for none.
    /// </summary>
    public static void ShowFindings(Context context, IReadOnlyList<Kshatriya.Mobile.MobileFinding> fresh, string where)
    {
        if (fresh.Count == 0)
        {
            return;
        }

        if (fresh.Count == 1)
        {
            Kshatriya.Mobile.MobileFinding f = fresh[0];
            string title = f.Confirmed ? $"Threat found {where}" : $"Something to review {where}";
            string text = f.Confirmed
                ? $"{f.DisplayName}: {f.DetectionName}. Open Kshatriya to review it."
                : $"{f.DisplayName} may be monitoring software. Fine if you installed it on purpose; open Kshatriya to review it.";
            Show(context, FindingsChannel, 1000 + Math.Abs(f.Key.GetHashCode(StringComparison.Ordinal) % 100_000), title, text);
            return;
        }

        int threats = fresh.Count(f => f.Confirmed);
        Show(context, FindingsChannel, 999, $"{fresh.Count} findings {where}",
            (threats > 0 ? $"{threats} threat(s), " : string.Empty) + $"latest: {fresh[^1].DisplayName}. Open Kshatriya to review them.");
    }

    /// <summary>An automatic update was installed (informational, low importance).</summary>
    public static void ShowUpdateInstalled(Context context, string message) =>
        Show(context, UpdatesChannel, 3000, "Signatures updated", message);

    public static void Show(Context context, string channel, int id, string title, string text)
    {
        EnsureChannel(context);
        var open = new Intent(context, typeof(MainActivity));
        open.SetFlags(ActivityFlags.NewTask | ActivityFlags.ClearTop);
        PendingIntent? tap = PendingIntent.GetActivity(context, 0, open, PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);
        Notification notification = new Notification.Builder(context, channel)
            .SetSmallIcon(Resource.Mipmap.appicon) // the Kshatriya logo, as before the redesign
            .SetContentTitle(title)
            .SetContentText(text)
            .SetStyle(new Notification.BigTextStyle().BigText(text))
            .SetContentIntent(tap)
            .SetAutoCancel(true)
            .Build();
        ((NotificationManager)context.GetSystemService(Context.NotificationService)!).Notify(id, notification);
    }
}
