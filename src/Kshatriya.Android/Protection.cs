using System.Security.Cryptography;
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
    private Protection(MobileContentStore store, MobileScanner scanner, string contentStatus, VerifiedContent? content)
    {
        Store = store;
        Scanner = scanner;
        ContentStatus = contentStatus;
        ContentSequence = content?.Manifest.Sequence ?? 0;
        ContentExpiresUtc = content?.Manifest.ExpiresUtc;
        ContentExpired = content?.Expired ?? false;
    }

    /// <summary>The installed signed update (0: built-in signatures only), its expiry and whether it has expired.</summary>
    public long ContentSequence { get; }

    public DateTimeOffset? ContentExpiresUtc { get; }

    public bool ContentExpired { get; }

    private static readonly object s_findingsGate = new();
    private static FindingsStore? s_findings;

    /// <summary>The process-wide findings and scan history in app-private storage (ADR 0021, slice 6).</summary>
    public static FindingsStore Findings(Context context)
    {
        lock (s_findingsGate)
        {
            return s_findings ??= new FindingsStore(System.IO.Path.Combine(context.FilesDir!.AbsolutePath, "findings.json"));
        }
    }

    public MobileContentStore Store { get; }

    public MobileScanner Scanner { get; }

    /// <summary>One line about the signatures in use, for the screen.</summary>
    public string ContentStatus { get; }

    private static readonly object s_cacheGate = new();
    private static FileHashCache? s_cache;

    /// <summary>The process-wide hash cache in app-private storage (ADR 0020, point 11).</summary>
    public static FileHashCache Cache(Context context)
    {
        lock (s_cacheGate)
        {
            return s_cache ??= new FileHashCache(System.IO.Path.Combine(context.FilesDir!.AbsolutePath, "hash-cache.json"));
        }
    }

    /// <summary>Writes the hash cache; a failure only costs time on the next scan.</summary>
    public static void SaveCache(Context context)
    {
        try
        {
            Cache(context).Save();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Android.Util.Log.Warn("Kshatriya", $"The hash cache was not saved: {ex.Message}");
        }
    }

    /// <summary>Builds the scanner from the built-in signatures plus the installed signed update, if any.</summary>
    public static Protection Load(Context context)
    {
        var store = new MobileContentStore(System.IO.Path.Combine(context.FilesDir!.AbsolutePath, "content"));
        HashSignatureDatabase signatures = HashSignatureDatabase.Empty;
        AppIndicatorSet indicators = AppIndicatorSet.Empty;
        string status;
        VerifiedContent? content = null;
        try
        {
            content = store.LoadActive(DateTimeOffset.UtcNow);
            if (content is null)
            {
                status = "Signatures: built-in only (no signed update installed).";
            }
            else
            {
                signatures = MobileContentStore.SignaturesOf(content);
                indicators = MobileContentStore.AppIndicatorsOf(content);
                status = $"Signatures: update {content.Manifest.Sequence}" + (content.Expired
                    ? $", EXPIRED on {content.Manifest.ExpiresUtc:yyyy-MM-dd}; import a newer update."
                    : $", valid until {content.Manifest.ExpiresUtc:yyyy-MM-dd}.");
            }
        }
        catch (Exception ex) when (ex is ContentVerificationException or IOException or FormatException)
        {
            content = null;
            status = $"Signatures: built-in only. The installed update was not loaded: {ex.Message}";
        }

        HashEngine engine = HashEngine.CreateDefault(signatures);
        var scanner = new MobileScanner([engine], indicators: indicators, cache: Cache(context));
        string counts = $"{engine.SignatureCount} file signature(s)" + (indicators.Count > 0 ? $" and {indicators.Count} app indicator(s)" : string.Empty);
        return new Protection(store, scanner, $"{status} {counts} in use.", content);
    }

    /// <summary>The APK files of one installed app (base and splits).</summary>
    public static IEnumerable<MobileScanTarget> AppTargets(PackageManager packages, ApplicationInfo app)
    {
        string label = packages.GetApplicationLabel(app) ?? app.PackageName ?? "app";
        if (app.SourceDir is { } baseApk)
        {
            // The app's identity goes with its base APK, so an indicator match is reported once per app.
            AppIdentity? identity = app.PackageName is { } name ? Identity(packages, name) : null;
            yield return FileTarget(label, baseApk, app.PackageName, identity);
        }

        foreach (string split in app.SplitSourceDirs ?? [])
        {
            yield return FileTarget($"{label} ({System.IO.Path.GetFileName(split)})", split, app.PackageName, null);
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

    /// <summary>
    /// The app's package name and the SHA-1 and SHA-256 of its signing certificates (current signers and,
    /// where Android keeps it, the rotation history). Null if the app is gone.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms",
        Justification = "SHA-1 only looks up published certificate fingerprints (Echap lists SHA-1). A collision could only make an app match a list, which helps no attacker; SHA-256 is computed too.")]
    public static AppIdentity? Identity(PackageManager packages, string packageName)
    {
        IEnumerable<Android.Content.PM.Signature> signatures;
        try
        {
            signatures = SigningCertificates(packages, packageName);
        }
        catch (PackageManager.NameNotFoundException)
        {
            return null;
        }

        var sha1 = new List<string>();
        var sha256 = new List<string>();
        foreach (Android.Content.PM.Signature signature in signatures)
        {
            byte[]? der = signature.ToByteArray();
            if (der is { Length: > 0 })
            {
                sha1.Add(Convert.ToHexStringLower(SHA1.HashData(der)));
                sha256.Add(Convert.ToHexStringLower(SHA256.HashData(der)));
            }
        }

        return new AppIdentity(packageName, [.. sha1.Distinct()], [.. sha256.Distinct()]);
    }

    private static IEnumerable<Android.Content.PM.Signature> SigningCertificates(PackageManager packages, string packageName)
    {
        if (OperatingSystem.IsAndroidVersionAtLeast(28))
        {
            PackageInfo info = OperatingSystem.IsAndroidVersionAtLeast(33)
                ? packages.GetPackageInfo(packageName, PackageManager.PackageInfoFlags.Of((long)PackageInfoFlags.SigningCertificates))
                : GetPackageInfoLegacy(packages, packageName, PackageInfoFlags.SigningCertificates);
            SigningInfo? signing = info.SigningInfo;
            if (signing is null)
            {
                return [];
            }

            return signing.HasMultipleSigners
                ? signing.GetApkContentsSigners() ?? []
                : signing.GetSigningCertificateHistory() ?? [];
        }

        return GetPackageInfoLegacy(packages, packageName, PackageInfoFlags.Signatures).Signatures ?? [];
    }

    [System.Runtime.Versioning.ObsoletedOSPlatform("android33.0")]
    private static PackageInfo GetPackageInfoLegacy(PackageManager packages, string packageName, PackageInfoFlags flags) =>
        packages.GetPackageInfo(packageName, flags)!;

    /// <summary>The package names of every installed app (to resolve findings of removed apps).</summary>
    public static IReadOnlySet<string> InstalledPackageNames(PackageManager packages) =>
        new HashSet<string>(InstalledApps(packages).Select(a => a.PackageName).OfType<string>(), StringComparer.Ordinal);

    /// <summary>Installed apps for the Apps page: label, whether it is a system app, and when it was last updated.</summary>
    public static IReadOnlyList<InstalledApp> InstalledAppList(Context context)
    {
        PackageManager packages = context.PackageManager!;
        var apps = new List<InstalledApp>();
        foreach (ApplicationInfo app in InstalledApps(packages))
        {
            if (app.PackageName is not { } name || name == context.PackageName)
            {
                continue;
            }

            DateTimeOffset? updated = null;
            try
            {
                PackageInfo info = OperatingSystem.IsAndroidVersionAtLeast(33)
                    ? packages.GetPackageInfo(name, PackageManager.PackageInfoFlags.Of(0L))
                    : GetPackageInfoLegacy(packages, name, 0);
                updated = DateTimeOffset.FromUnixTimeMilliseconds(info.LastUpdateTime);
            }
            catch (PackageManager.NameNotFoundException)
            {
                continue; // removed meanwhile
            }

            bool system = (app.Flags & (ApplicationInfoFlags.System | ApplicationInfoFlags.UpdatedSystemApp)) != 0;
            apps.Add(new InstalledApp(name, packages.GetApplicationLabel(app) ?? name, system, updated));
        }

        return apps;
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

    private static MobileScanTarget FileTarget(string name, string path, string? packageName, AppIdentity? identity)
    {
        var file = new FileInfo(path);
        long? size = file.Exists ? file.Length : null;
        // Installed APKs are not changed in place (an update gets a new path), so path, size and time identify
        // the content for the hash cache.
        string? cacheKey = file.Exists ? FileHashCache.KeyFor(path, file.Length, file.LastWriteTimeUtc) : null;
        return new MobileScanTarget(name, path, size, () => File.OpenRead(path), packageName, identity, cacheKey);
    }
}
