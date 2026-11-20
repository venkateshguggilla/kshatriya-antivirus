using System.Globalization;
using Kshatriya.Presentation;

namespace Kshatriya.Mobile;

/// <summary>An installed app as the Apps page needs it (read from PackageManager by the Android app).</summary>
public sealed record InstalledApp(string PackageName, string Label, bool IsSystem, DateTimeOffset? LastUpdatedUtc = null);

/// <summary>The Apps page filters.</summary>
public enum AppsFilter
{
    NeedsReview,
    All,
    NotChecked,
    Recent,
}

/// <summary>One row on the Apps page.</summary>
public sealed record AppRow(string PackageName, string Label, string Detail, ResultTone Tone, string? FindingKey);

/// <summary>The Apps page (ADR 0021): search, filter chips with counts, one row per app.</summary>
public sealed record AppsState(AppsFilter Filter, string Query, IReadOnlyList<AppRow> Rows, int Total, int NeedsReview, int NotChecked, int Recent);

/// <summary>One row on the History page.</summary>
public sealed record HistoryRow(string Title, string Detail, string When, ResultTone Tone, string? FindingKey);

/// <summary>The Home page: the evaluated status and the lines under it.</summary>
public sealed record HomeState(StatusSnapshot Status, string LastChecked, string Signatures, string Updates);

/// <summary>A finding's bottom sheet: what matched, how strong the evidence is, and the safety note when relevant.</summary>
public sealed record FindingSheet(string Title, string Verdict, string Explanation, string? SafetyNote, IReadOnlyList<(string Label, string Value)> Details, bool CanReviewApp, bool Kept);

/// <summary>
/// Builds the Android screens' state from the stores (unidirectional data flow, ADR 0021 section 5). Pure
/// functions: the activity only renders what they return, and they are tested on every CI run without a device.
/// </summary>
public static class MobileScreens
{
    /// <summary>Apps updated within this time count as "Recent".</summary>
    public static readonly TimeSpan RecentWindow = TimeSpan.FromDays(7);

    public static HomeState Home(MobileStatusInputs inputs, FindingsStore findings, string signatures, string updates)
    {
        ArgumentNullException.ThrowIfNull(findings);
        StatusSnapshot status = MobileStatusEvaluator.Evaluate(inputs);
        ScanRecord? lastApps = findings.Scans.LastOrDefault(s => s.Kind == "apps");
        string last = findings.LastAppScanUtc is { } at
            ? $"{lastApps?.Checked ?? 0} apps checked {Ago(at, inputs.Now)}"
            : "Apps have not been checked yet";
        return new HomeState(status, last, signatures, updates);
    }

    public static AppsState Apps(IReadOnlyList<InstalledApp> apps, FindingsStore findings, AppsFilter filter, string query, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(apps);
        ArgumentNullException.ThrowIfNull(findings);
        var byPackage = findings.Findings.Where(f => f.IsApp && f.PackageName is not null && f.ResolvedReason is null)
            .GroupBy(f => f.PackageName!, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        IReadOnlySet<string> notChecked = findings.NotScannedApps;
        bool checkedOnce = findings.LastAppScanUtc is not null;

        AppRow Row(InstalledApp app)
        {
            if (byPackage.TryGetValue(app.PackageName, out MobileFinding? f))
            {
                string what = f.Confirmed ? Describe(f) : "Possible monitoring app · suspicious";
                return f.Kept
                    ? new AppRow(app.PackageName, app.Label, $"{what} · kept by you", ResultTone.Info, f.Key)
                    : new AppRow(app.PackageName, app.Label, what, f.Confirmed ? ResultTone.Danger : ResultTone.Warn, f.Key);
            }

            if (notChecked.Contains(app.PackageName))
            {
                return new AppRow(app.PackageName, app.Label, "Not checked", ResultTone.Info, null);
            }

            string origin = app.IsSystem ? " · system app" : string.Empty;
            return new AppRow(app.PackageName, app.Label, (checkedOnce ? "No match" : "Not checked yet") + origin, checkedOnce ? ResultTone.Ok : ResultTone.Info, null);
        }

        List<AppRow> rows = [.. apps.Select(Row)];
        bool IsRecent(InstalledApp a) => a.LastUpdatedUtc is { } u && now - u <= RecentWindow;
        HashSet<string> recent = [.. apps.Where(IsRecent).Select(a => a.PackageName)];
        int needsReview = rows.Count(r => r.Tone is ResultTone.Danger or ResultTone.Warn);
        IEnumerable<AppRow> shown = filter switch
        {
            AppsFilter.NeedsReview => rows.Where(r => r.Tone is ResultTone.Danger or ResultTone.Warn),
            AppsFilter.NotChecked => rows.Where(r => notChecked.Contains(r.PackageName)),
            AppsFilter.Recent => rows.Where(r => recent.Contains(r.PackageName)),
            _ => rows,
        };
        if (!string.IsNullOrWhiteSpace(query))
        {
            string q = query.Trim();
            shown = shown.Where(r => r.Label.Contains(q, StringComparison.OrdinalIgnoreCase) || r.PackageName.Contains(q, StringComparison.OrdinalIgnoreCase));
        }

        // Findings first, then by name.
        List<AppRow> ordered = [.. shown.OrderBy(r => r.Tone switch { ResultTone.Danger => 0, ResultTone.Warn => 1, _ => 2 }).ThenBy(r => r.Label, StringComparer.CurrentCultureIgnoreCase)];
        return new AppsState(filter, query ?? string.Empty, ordered, rows.Count, needsReview, rows.Count(r => notChecked.Contains(r.PackageName)), recent.Count);
    }

    public static IReadOnlyList<HistoryRow> History(FindingsStore findings, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var rows = new List<(DateTimeOffset At, HistoryRow Row)>();
        foreach (MobileFinding f in findings.Findings)
        {
            string state = f.ResolvedReason ?? (f.Kept ? "kept by you" : "needs review");
            ResultTone tone = !f.NeedsReview ? ResultTone.Info : f.Confirmed ? ResultTone.Danger : ResultTone.Warn;
            rows.Add((f.LastSeenUtc, new HistoryRow(f.DisplayName, $"{(f.Confirmed ? Describe(f) : "Suspicious")} · {f.Source} · {state}", Ago(f.LastSeenUtc, now), tone, f.Key)));
        }

        foreach (ScanRecord s in findings.Scans)
        {
            string result = s.Threats + s.Suspicious == 0 ? "no threats found"
                : string.Join(", ", new[] { s.Threats > 0 ? $"{s.Threats} threat(s)" : null, s.Suspicious > 0 ? $"{s.Suspicious} to review" : null }.Where(x => x is not null));
            string title = s.Kind switch
            {
                "apps" => "Apps checked",
                "new apps" => "New and updated apps checked",
                "update" => "Apps checked after an update",
                "folder" => "Folder scanned",
                _ => "Files scanned",
            };
            rows.Add((s.FinishedUtc, new HistoryRow(title, $"{s.Checked:N0} checked · {result}" + (s.NotScanned > 0 ? $" · {s.NotScanned} not checked" : string.Empty), Ago(s.FinishedUtc, now), s.Threats > 0 ? ResultTone.Danger : s.Suspicious > 0 ? ResultTone.Warn : ResultTone.Ok, null)));
        }

        return [.. rows.OrderByDescending(r => r.At).Select(r => r.Row)];
    }

    /// <summary>
    /// The bottom sheet for a finding. Monitoring-app findings carry a safety note: removing such an app can
    /// alert whoever installed it, so the user is pointed to advice before the removal step.
    /// </summary>
    public static FindingSheet Sheet(MobileFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        bool monitoring = finding.DetectionName.Contains("Stalkerware", StringComparison.OrdinalIgnoreCase)
            || finding.DetectionName.Contains("Watchware", StringComparison.OrdinalIgnoreCase)
            || (finding.IsApp && !finding.Confirmed);
        string verdict = finding.Confirmed ? Describe(finding) : monitoring ? "Possible monitoring app · suspicious" : "Suspicious";
        string explanation = finding.Confirmed
            ? finding.IsApp
                ? "This app matches a known entry exactly (its file fingerprint or the certificate it is signed with). Review it in Android settings and uninstall it if you did not install it on purpose."
                : "This file matches a known threat exactly by its fingerprint. Delete it with your file manager if you do not need it."
            : "Its package name is on a list of monitoring apps. A name alone is weak evidence: another app can use the same name. If you installed it yourself on purpose, you can keep it.";
        string? safety = monitoring
            ? "If someone else may have installed this, removing it can alert them. If you feel unsafe, get advice before you act."
            : null;
        var details = new List<(string, string)>
        {
            (finding.IsApp ? "Package" : "File", finding.IsApp ? finding.PackageName ?? finding.Location : finding.Location),
            ("What matched", $"{finding.DetectionName} ({finding.Category}, {finding.Confidence} confidence)"),
            ("Found by", finding.Source),
            ("First seen", finding.FirstSeenUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)),
        };
        return new FindingSheet(finding.DisplayName, verdict, explanation, safety, details, finding.IsApp && finding.ResolvedReason is null, finding.Kept);
    }

    private static string Describe(MobileFinding f) => f.Category switch
    {
        "malware" => "Malware",
        "pua" => "Potentially unwanted app",
        "test" => "Test file",
        _ => "Threat",
    };

    /// <summary>"just now", "5 min ago", "today 09:30", "yesterday", or a date.</summary>
    public static string Ago(DateTimeOffset at, DateTimeOffset now)
    {
        TimeSpan age = now - at;
        DateTimeOffset local = at.ToLocalTime();
        return age < TimeSpan.FromMinutes(1) ? "just now"
            : age < TimeSpan.FromHours(1) ? $"{(int)age.TotalMinutes} min ago"
            : local.Date == now.ToLocalTime().Date ? $"today {local:HH:mm}"
            : local.Date == now.ToLocalTime().Date.AddDays(-1) ? "yesterday"
            : local.ToString("d MMM", CultureInfo.CurrentCulture);
    }
}
