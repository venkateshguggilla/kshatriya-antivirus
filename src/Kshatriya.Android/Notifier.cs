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
