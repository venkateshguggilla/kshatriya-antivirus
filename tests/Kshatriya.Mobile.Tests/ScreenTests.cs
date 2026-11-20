using Kshatriya.Core;
using Kshatriya.Mobile;
using Kshatriya.Presentation;

namespace Kshatriya.Mobile.Tests;

/// <summary>Persisted findings and the Android screens' state (ADR 0021, slice 6).</summary>
public sealed class ScreenTests
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static MobileScanResult App(string package, ScanStatus status, string name = "Android.Stalkerware.Example", DetectionCategory category = DetectionCategory.PotentiallyUnwanted) => new(
        new MobileScanTarget(package, $"/data/app/{package}/base.apk", 10, () => Stream.Null, PackageName: package),
        new ScanItemResult
        {
            Path = $"/data/app/{package}/base.apk",
            Kind = ScanItemKind.File,
            Status = status,
            Detections = status is ScanStatus.Detected or ScanStatus.Suspicious
                ? [new Detection("app-indicators", name, status == ScanStatus.Detected ? category : DetectionCategory.Suspicious, status == ScanStatus.Detected ? DetectionConfidence.High : DetectionConfidence.Medium)]
                : [],
            Reason = status == ScanStatus.NotScanned ? ScanReason.TooLarge : ScanReason.None,
        });

    private static MobileStatusInputs Inputs(FindingsStore store, bool notifications = true)
    {
        (int confirmed, int suspicious) = store.CountUnresolved();
        return new MobileStatusInputs
        {
            UnresolvedConfirmedFindings = confirmed,
            UnresolvedSuspiciousFindings = suspicious,
            LastAppScanUtc = store.LastAppScanUtc,
            ContentSequence = 7,
            ContentExpiresUtc = s_now.AddDays(30),
            NotificationsAllowed = notifications,
            Now = s_now,
        };
    }

    [Fact]
    public void Recording_a_scan_keeps_new_findings_and_reports_them_once()
    {
        var store = new FindingsStore();

        IReadOnlyList<MobileFinding> first = store.Record([App("com.spy", ScanStatus.Detected), App("com.maps", ScanStatus.Clean)], "apps", "scan", s_now, allApps: true);
        IReadOnlyList<MobileFinding> again = store.Record([App("com.spy", ScanStatus.Detected)], "new apps", "new app", s_now.AddMinutes(15));

        Assert.Equal("app:com.spy", Assert.Single(first).Key);
        Assert.Empty(again);
        Assert.Equal((1, 0), store.CountUnresolved());
        Assert.Equal(s_now, store.LastAppScanUtc);
        Assert.Equal(2, store.Scans.Count);
    }

    [Fact]
    public void A_flagged_app_that_is_clean_now_or_removed_is_resolved()
    {
        var store = new FindingsStore();
        store.Record([App("com.a", ScanStatus.Suspicious), App("com.b", ScanStatus.Detected)], "apps", "scan", s_now, allApps: true);

        store.Record([App("com.a", ScanStatus.Clean)], "update", "update", s_now.AddDays(1));
        store.AppsRemoved(new HashSet<string> { "com.a" });

        Assert.Equal("no longer matches", store.Find("app:com.a")!.ResolvedReason);
        Assert.Equal("app removed", store.Find("app:com.b")!.ResolvedReason);
        Assert.Equal((0, 0), store.CountUnresolved());
    }

    [Fact]
    public void Keeping_a_finding_stops_it_counting()
    {
        var store = new FindingsStore();
        store.Record([App("com.family", ScanStatus.Suspicious, "Android.Watchware.Family")], "apps", "scan", s_now, allApps: true);

        Assert.True(store.SetKept("app:com.family", kept: true));

        Assert.Equal((0, 0), store.CountUnresolved());
        Assert.False(store.SetKept("app:none", kept: true));
    }

    [Fact]
    public void Findings_survive_a_restart_and_a_damaged_file_is_discarded()
    {
        string file = Path.Combine(Path.GetTempPath(), $"kshatriya-findings-{Guid.NewGuid():N}.json");
        try
        {
            var store = new FindingsStore(file);
            store.Record([App("com.spy", ScanStatus.Detected)], "apps", "scan", s_now, allApps: true);
            store.SetKept("app:com.spy", true);

            var reloaded = new FindingsStore(file);
            Assert.True(reloaded.Find("app:com.spy")!.Kept);
            Assert.Equal(s_now, reloaded.LastAppScanUtc);

            File.WriteAllText(file, "[ not json");
            Assert.Empty(new FindingsStore(file).Findings);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void Scans_and_findings_are_bounded()
    {
        var store = new FindingsStore();
        for (int i = 0; i < FindingsStore.MaxScans + 5; i++)
        {
            store.Record([App($"com.app{i}", ScanStatus.Clean)], "files", "scan", s_now.AddMinutes(i));
        }

        Assert.Equal(FindingsStore.MaxScans, store.Scans.Count);
    }

    [Fact]
    public void Home_says_apps_were_never_checked_until_the_first_scan()
    {
        var store = new FindingsStore();

        HomeState before = MobileScreens.Home(Inputs(store), store, "Update 7", "Automatic updates off");
        store.Record([App("com.maps", ScanStatus.Clean)], "apps", "scan", s_now.AddMinutes(-5), allApps: true);
        HomeState after = MobileScreens.Home(Inputs(store), store, "Update 7", "Automatic updates off");

        Assert.Equal(ProtectionLevel.AttentionRecommended, before.Status.Level);
        Assert.Equal(StatusActions.ScanApps, before.Status.PrimaryActionId);
        Assert.Equal(ProtectionLevel.Protected, after.Status.Level);
        Assert.Equal("No threats found", after.Status.Headline);
        Assert.Equal("1 apps checked 5 min ago", after.LastChecked);
    }

    [Fact]
    public void A_confirmed_finding_needs_action_and_notifications_off_is_a_dismissible_recommendation()
    {
        var store = new FindingsStore();
        store.Record([App("com.spy", ScanStatus.Detected)], "apps", "scan", s_now, allApps: true);

        StatusSnapshot status = MobileStatusEvaluator.Evaluate(Inputs(store, notifications: false));

        Assert.Equal(ProtectionLevel.ActionNeeded, status.Level);
        Assert.Equal(MobileStatusEvaluator.ConfirmedFindingsId, status.Items[0].Id);
        Assert.True(status.Items.Single(i => i.Id == MobileStatusEvaluator.NotificationsOffId).Dismissible);
    }

    [Fact]
    public void Apps_lists_findings_first_with_filters_and_search()
    {
        var store = new FindingsStore();
        store.Record([App("com.spy", ScanStatus.Detected), App("com.systemservice", ScanStatus.Suspicious), App("com.big.game", ScanStatus.NotScanned), App("com.maps", ScanStatus.Clean)], "apps", "scan", s_now, allApps: true);
        InstalledApp[] apps =
        [
            new("com.maps", "Maps", IsSystem: true),
            new("com.big.game", "Big Game", IsSystem: false, s_now.AddDays(-1)),
            new("com.spy", "Spy", IsSystem: false),
            new("com.systemservice", "System Service", IsSystem: false),
        ];

        AppsState all = MobileScreens.Apps(apps, store, AppsFilter.All, string.Empty, s_now);
        AppsState review = MobileScreens.Apps(apps, store, AppsFilter.NeedsReview, string.Empty, s_now);
        AppsState search = MobileScreens.Apps(apps, store, AppsFilter.All, "MAPS", s_now);

        Assert.Equal(["Spy", "System Service", "Big Game", "Maps"], all.Rows.Select(r => r.Label));
        Assert.Equal((4, 2, 1, 1), (all.Total, all.NeedsReview, all.NotChecked, all.Recent));
        Assert.Equal(2, review.Rows.Count);
        Assert.Equal("Maps", Assert.Single(search.Rows).Label);
        Assert.Contains("system app", search.Rows[0].Detail, StringComparison.Ordinal);
        Assert.Equal(ResultTone.Danger, all.Rows[0].Tone);
        Assert.Equal("app:com.spy", all.Rows[0].FindingKey);
    }

    [Fact]
    public void The_finding_sheet_warns_before_removing_a_monitoring_app()
    {
        var store = new FindingsStore();
        store.Record([App("com.systemservice", ScanStatus.Suspicious, "Android.Stalkerware.Example")], "apps", "scan", s_now, allApps: true);

        FindingSheet sheet = MobileScreens.Sheet(store.Find("app:com.systemservice")!);

        Assert.Equal("Possible monitoring app · suspicious", sheet.Verdict);
        Assert.Contains("weak evidence", sheet.Explanation, StringComparison.Ordinal);
        Assert.NotNull(sheet.SafetyNote);
        Assert.Contains("can alert them", sheet.SafetyNote, StringComparison.Ordinal);
        Assert.True(sheet.CanReviewApp);
    }

    [Fact]
    public void History_lists_findings_and_scans_newest_first()
    {
        var store = new FindingsStore();
        store.Record([App("com.maps", ScanStatus.Clean)], "apps", "scan", s_now.AddHours(-2), allApps: true);
        store.Record([App("com.spy", ScanStatus.Detected)], "new apps", "new app", s_now.AddMinutes(-10));

        IReadOnlyList<HistoryRow> rows = MobileScreens.History(store, s_now);

        Assert.Equal("com.spy", rows[0].Title); // the scan target's display name
        Assert.Equal("10 min ago", rows[0].When);
        Assert.Equal("New and updated apps checked", rows[1].Title);
        Assert.Equal("Apps checked", rows[2].Title);
    }
}
