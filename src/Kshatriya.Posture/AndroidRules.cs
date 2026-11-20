namespace Kshatriya.Posture;

/// <summary>Android settings an ordinary app can read (ADR 0022). Null values could not be read.</summary>
public sealed record AndroidSnapshot(
    bool? UsbDebugging,
    bool? DeveloperOptions,
    bool? ScreenLock,
    IReadOnlyList<string> AppsThatCanInstall,
    bool? AdvancedProtection);

/// <summary>Turns Android settings into checks. Each result says where to change it in Android's Settings.</summary>
public static class AndroidRules
{
    public static IEnumerable<PostureCheck> Evaluate(AndroidSnapshot snapshot)
    {
        const PostureArea area = PostureArea.Device;

        yield return snapshot.ScreenLock switch
        {
            true => new("android.screenLock", area, PostureState.Ok, "Screen lock is set", "Someone who picks up your phone cannot open it."),
            false => new("android.screenLock", area, PostureState.Risk, "No screen lock",
                "Anyone holding the phone can open it, install apps and read your data. Set a PIN, pattern or password in Settings > Security."),
            null => new("android.screenLock", area, PostureState.Unknown, "Screen lock", "Could not be read."),
        };

        yield return snapshot.UsbDebugging switch
        {
            true => new("android.usbDebugging", area, PostureState.Risk, "USB debugging is on",
                "A computer it is plugged into can install apps and read data. Turn it off in Settings > System > Developer options."),
            false => new("android.usbDebugging", area, PostureState.Ok, "USB debugging is off", "A computer cannot install apps over USB."),
            null => new("android.usbDebugging", area, PostureState.Unknown, "USB debugging", "Could not be read."),
        };

        if (snapshot.DeveloperOptions == true && snapshot.UsbDebugging != true)
        {
            yield return new("android.developerOptions", area, PostureState.Info, "Developer options are on",
                "Not a risk by itself. Turn them off in Settings > System > Developer options if you do not use them.");
        }

        int installers = snapshot.AppsThatCanInstall.Count;
        yield return installers == 0
            ? new("android.installers", area, PostureState.Ok, "Only app stores install apps", "No other app is allowed to install apps.")
            : new("android.installers", area, PostureState.Attention, $"{installers} app(s) can install other apps",
                string.Join(", ", snapshot.AppsThatCanInstall.Take(5)) + (installers > 5 ? ", ..." : string.Empty) +
                ". Allow this only for apps you trust: Settings > Apps > Special app access > Install unknown apps.");

        yield return snapshot.AdvancedProtection switch
        {
            true => new("android.advancedProtection", area, PostureState.Ok, "Advanced Protection is on",
                "Android blocks app installs from outside the Play Store and other risky features."),
            false => new("android.advancedProtection", area, PostureState.Info, "Advanced Protection is off",
                "Android 16 can block installs from outside the Play Store and other risky features: Settings > Security & privacy > Advanced Protection."),
            null => new("android.playProtect", area, PostureState.Info, "Keep Google Play Protect on",
                "Kshatriya cannot block app installs; Play Protect checks apps when they are installed. Check it in the Play Store > Play Protect."),
        };
    }
}
