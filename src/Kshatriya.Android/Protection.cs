using Android.Content;
using Android.Content.PM;
using Kshatriya.Engines;
using Kshatriya.Engines.Hash;
using Kshatriya.Mobile;
using Kshatriya.Updates;

namespace Kshatriya.AndroidApp;

/// <summary>The scanner, the signed content and the installed-app targets, shared by the screen and the job.</summary>
internal sealed class Protection
{
    private Protection(MobileContentStore store, MobileScanner scanner, string contentStatus)
    {
        Store = store;
        Scanner = scanner;
        ContentStatus = contentStatus;
    }

    public MobileContentStore Store { get; }

    public MobileScanner Scanner { get; }

    /// <summary>One line about the signatures in use, for the screen.</summary>
    public string ContentStatus { get; }

    /// <summary>Builds the scanner from the built-in signatures plus the installed signed update, if any.</summary>
    public static Protection Load(Context context)
    {
        var store = new MobileContentStore(System.IO.Path.Combine(context.FilesDir!.AbsolutePath, "content"));
        HashSignatureDatabase signatures = HashSignatureDatabase.Empty;
        string status;
        try
        {
            VerifiedContent? content = store.LoadActive(DateTimeOffset.UtcNow);
            if (content is null)
            {
                status = "Signatures: built-in only (no signed update installed).";
            }
            else
            {
                signatures = MobileContentStore.SignaturesOf(content);
                status = $"Signatures: update {content.Manifest.Sequence}" + (content.Expired
                    ? $", EXPIRED on {content.Manifest.ExpiresUtc:yyyy-MM-dd}; import a newer update."
                    : $", valid until {content.Manifest.ExpiresUtc:yyyy-MM-dd}.");
            }
        }
        catch (Exception ex) when (ex is ContentVerificationException or IOException or FormatException)
        {
            status = $"Signatures: built-in only. The installed update was not loaded: {ex.Message}";
        }

        HashEngine engine = HashEngine.CreateDefault(signatures);
        return new Protection(store, new MobileScanner([engine]), $"{status} {engine.SignatureCount} signature(s) in use.");
    }

    /// <summary>The APK files of one installed app (base and splits).</summary>
    public static IEnumerable<MobileScanTarget> AppTargets(PackageManager packages, ApplicationInfo app)
    {
        string label = packages.GetApplicationLabel(app) ?? app.PackageName ?? "app";
        if (app.SourceDir is { } baseApk)
        {
            yield return FileTarget(label, baseApk, app.PackageName);
        }

        foreach (string split in app.SplitSourceDirs ?? [])
        {
            yield return FileTarget($"{label} ({System.IO.Path.GetFileName(split)})", split, app.PackageName);
        }
    }

    /// <summary>Every installed app's APK files.</summary>
    public static IEnumerable<MobileScanTarget> InstalledAppTargets(PackageManager packages) =>
        InstalledApps(packages)
            .OrderBy(a => packages.GetApplicationLabel(a), StringComparer.CurrentCultureIgnoreCase)
            .SelectMany(a => AppTargets(packages, a));

    public static ApplicationInfo? FindApp(PackageManager packages, string packageName)
    {
        try
        {
            return OperatingSystem.IsAndroidVersionAtLeast(33)
                ? packages.GetApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.Of(0))
                : GetApplicationInfoLegacy(packages, packageName);
        }
        catch (PackageManager.NameNotFoundException)
        {
            return null; // removed again before the scan
        }
    }

    private static IList<ApplicationInfo> InstalledApps(PackageManager packages) =>
        OperatingSystem.IsAndroidVersionAtLeast(33)
            ? packages.GetInstalledApplications(PackageManager.ApplicationInfoFlags.Of(0))
            : GetInstalledApplicationsLegacy(packages);

    [System.Runtime.Versioning.ObsoletedOSPlatform("android33.0")]
    private static IList<ApplicationInfo> GetInstalledApplicationsLegacy(PackageManager packages) =>
        packages.GetInstalledApplications(0);

    [System.Runtime.Versioning.ObsoletedOSPlatform("android33.0")]
    private static ApplicationInfo GetApplicationInfoLegacy(PackageManager packages, string packageName) =>
        packages.GetApplicationInfo(packageName, 0);

    private static MobileScanTarget FileTarget(string name, string path, string? packageName)
    {
        long? size = File.Exists(path) ? new FileInfo(path).Length : null;
        return new MobileScanTarget(name, path, size, () => File.OpenRead(path), packageName);
    }
}
