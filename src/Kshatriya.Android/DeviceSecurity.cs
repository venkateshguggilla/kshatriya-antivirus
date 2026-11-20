using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Provider;
using Kshatriya.Posture;

namespace Kshatriya.AndroidApp;

/// <summary>
/// Reads the phone settings for the security check (ADR 0022). An ordinary app can only read these and
/// point the user to Android's own Settings; it cannot change them or block installs.
/// </summary>
internal static class DeviceSecurity
{
    private const string RequestInstallPackages = "android.permission.REQUEST_INSTALL_PACKAGES";
    private const string InstallOp = "android:request_install_packages";

    public static AndroidSnapshot Read(Context context)
    {
        ContentResolver resolver = context.ContentResolver!;
        bool? adb = ReadGlobal(resolver, Settings.Global.AdbEnabled);
        bool? developer = ReadGlobal(resolver, Settings.Global.DevelopmentSettingsEnabled);
        var keyguard = context.GetSystemService(Context.KeyguardService) as KeyguardManager;

        // Advanced Protection Mode (Android 16) needs a permission outside the fixed list in ADR 0020, so it is
        // not read; the rule then reminds the user to keep Play Protect on instead.
        return new AndroidSnapshot(adb, developer, keyguard?.IsDeviceSecure, AppsThatCanInstall(context), AdvancedProtection: null);
    }

    private static bool? ReadGlobal(ContentResolver resolver, string? name)
    {
        try
        {
            return name is null ? null : Settings.Global.GetInt(resolver, name, 0) == 1;
        }
        catch (Java.Lang.SecurityException)
        {
            return null;
        }
    }

    /// <summary>Apps (not part of Android) that ask to install other apps and were allowed to.</summary>
    private static List<string> AppsThatCanInstall(Context context)
    {
        PackageManager packages = context.PackageManager!;
        var appOps = context.GetSystemService(Context.AppOpsService) as AppOpsManager;
        var names = new List<string>();
        foreach (PackageInfo info in InstalledWithPermissions(packages))
        {
            ApplicationInfo? app = info.ApplicationInfo;
            if (app is null || info.PackageName is not { } name || name == context.PackageName
                || (app.Flags & (ApplicationInfoFlags.System | ApplicationInfoFlags.UpdatedSystemApp)) != 0
                || info.RequestedPermissions?.Contains(RequestInstallPackages) != true)
            {
                continue;
            }

            if (Allowed(appOps, app.Uid, name))
            {
                names.Add(packages.GetApplicationLabel(app) ?? name);
            }
        }

        return [.. names.Order(StringComparer.CurrentCultureIgnoreCase)];
    }

    private static bool Allowed(AppOpsManager? appOps, int uid, string package)
    {
        if (appOps is null)
        {
            return true; // cannot tell: the app at least asks for it
        }

        try
        {
            AppOpsManagerMode mode = OperatingSystem.IsAndroidVersionAtLeast(36)
                ? appOps.CheckOpNoThrow(InstallOp, uid, package)
                : OperatingSystem.IsAndroidVersionAtLeast(29)
                    ? CheckUnsafe(appOps, uid, package)
                    : CheckLegacy(appOps, uid, package);
            return mode == AppOpsManagerMode.Allowed;
        }
        catch (Java.Lang.SecurityException)
        {
            return true;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("android29.0")]
    [System.Runtime.Versioning.ObsoletedOSPlatform("android36.0")]
    private static AppOpsManagerMode CheckUnsafe(AppOpsManager appOps, int uid, string package) =>
        appOps.UnsafeCheckOpNoThrow(InstallOp, uid, package);

    [System.Runtime.Versioning.ObsoletedOSPlatform("android29.0")]
    private static AppOpsManagerMode CheckLegacy(AppOpsManager appOps, int uid, string package) =>
        appOps.CheckOpNoThrow(InstallOp, uid, package);

    private static IList<PackageInfo> InstalledWithPermissions(PackageManager packages) =>
        OperatingSystem.IsAndroidVersionAtLeast(33)
            ? packages.GetInstalledPackages(PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.Permissions))
            : InstalledLegacy(packages);

    [System.Runtime.Versioning.ObsoletedOSPlatform("android33.0")]
    private static IList<PackageInfo> InstalledLegacy(PackageManager packages) =>
        packages.GetInstalledPackages(PackageInfoFlags.Permissions);

    /// <summary>The Android Settings screen where a check's setting is changed.</summary>
    public static Intent? SettingsFor(string checkId) => checkId switch
    {
        "android.screenLock" => new Intent(Settings.ActionSecuritySettings),
        "android.usbDebugging" or "android.developerOptions" => new Intent(Settings.ActionApplicationDevelopmentSettings),
        "android.installers" => new Intent(Settings.ActionManageUnknownAppSources),
        "android.advancedProtection" => new Intent(Settings.ActionSecuritySettings),
        _ => null,
    };
}
