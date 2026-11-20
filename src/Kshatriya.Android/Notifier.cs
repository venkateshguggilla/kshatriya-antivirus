using Android.App;
using Android.Content;

namespace Kshatriya.AndroidApp;

/// <summary>Notifications about findings. Tapping one opens Kshatriya.</summary>
internal static class Notifier
{
    private const string ChannelId = "findings";

    public static void EnsureChannel(Context context)
    {
        var manager = (NotificationManager)context.GetSystemService(Context.NotificationService)!;
        manager.CreateNotificationChannel(new NotificationChannel(ChannelId, "Threats found", NotificationImportance.High)
        {
            Description = "When Kshatriya finds a threat in an app or file.",
        });
    }

    /// <summary>
    /// Notifies about findings not reported before: one notification for one finding, one summary for several.
    /// Nothing is shown for none: there are no "all clear" notifications (ADR 0021).
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
            Show(context, 1000 + Math.Abs(f.Key.GetHashCode(StringComparison.Ordinal) % 100_000), title, text);
            return;
        }

        int threats = fresh.Count(f => f.Confirmed);
        Show(context, 999, $"{fresh.Count} findings {where}",
            (threats > 0 ? $"{threats} threat(s), " : string.Empty) + $"latest: {fresh[^1].DisplayName}. Open Kshatriya to review them.");
    }

    public static void Show(Context context, int id, string title, string text)
    {
        EnsureChannel(context);
        var open = new Intent(context, typeof(MainActivity));
        open.SetFlags(ActivityFlags.NewTask | ActivityFlags.ClearTop);
        PendingIntent? tap = PendingIntent.GetActivity(context, 0, open, PendingIntentFlags.Immutable | PendingIntentFlags.UpdateCurrent);
        Notification notification = new Notification.Builder(context, ChannelId)
            .SetSmallIcon(Resource.Mipmap.appicon)
            .SetContentTitle(title)
            .SetContentText(text)
            .SetStyle(new Notification.BigTextStyle().BigText(text))
            .SetContentIntent(tap)
            .SetAutoCancel(true)
            .Build();
        ((NotificationManager)context.GetSystemService(Context.NotificationService)!).Notify(id, notification);
    }
}
