using Kshatriya.App.Services;
using Kshatriya.App.ViewModels;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.Tests;

/// <summary>The unified History page and the "keep" choice (ADR 0021, slice 4).</summary>
public class HistoryTests
{
    private static DetectionRecordDto Finding(string path, string status = "detected", string action = "reported", string time = "2026-11-21T09:00:00Z") => new()
    {
        TimeUtc = time,
        Source = "real-time (file)",
        Path = path,
        Status = status,
        Names = [status == "detected" ? "Test.Sample" : "Kshatriya.Heuristic.DoubleExtension"],
        Action = action,
    };

    private static QuarantineItemDto Vaulted(string path, string time) => new()
    {
        Id = "q1",
        OriginalPath = path,
        Sha256 = new string('0', 64),
        SizeBytes = 10,
        QuarantinedUtc = time,
        User = "alice",
        Detections = ["Test.Sample"],
        Origin = "scan",
    };

    private static HistoryViewModel Page(FakeGateway gateway, IReviewStore? reviews = null, FakeDialogs? dialogs = null) =>
        new(gateway, dialogs ?? new FakeDialogs(), new FakeHost(), reviews ?? new InMemoryReviewStore());

    [Fact]
    public void Findings_quarantined_later_are_resolved_and_shown_once()
    {
        List<HistoryEntry> entries = HistoryViewModel.Build(
            [Finding(@"C:\a.exe"), Finding(@"C:\b.exe", action: "quarantined (q9)"), Finding(@"C:\c.exe", status: "suspicious")],
            [Vaulted(@"C:\a.exe", "2026-11-21T09:05:00Z")],
            new InMemoryReviewStore());

        Assert.DoesNotContain(entries, e => e.Kind == HistoryKind.Finding && e.Path == @"C:\a.exe"); // the vault entry tells it
        Assert.Contains(entries, e => e.Kind == HistoryKind.Quarantined && e.Path == @"C:\a.exe");
        Assert.False(entries.Single(e => e.Path == @"C:\b.exe").NeedsDecision);
        Assert.Equal((0, 1), HistoryViewModel.CountUnresolved(entries));
    }

    [Fact]
    public void A_vault_entry_older_than_the_finding_does_not_resolve_it()
    {
        List<HistoryEntry> entries = HistoryViewModel.Build(
            [Finding(@"C:\a.exe", time: "2026-11-21T10:00:00Z")],
            [Vaulted(@"C:\a.exe", "2026-11-20T10:00:00Z")],
            new InMemoryReviewStore());

        Assert.Equal((1, 0), HistoryViewModel.CountUnresolved(entries));
    }

    [Fact]
    public async Task Keeping_a_finding_stops_it_counting_without_an_exclusion()
    {
        var gateway = new FakeGateway { Detections = [Finding(@"C:\Users\alice\tool.exe", status: "suspicious")] };
        var reviews = new InMemoryReviewStore();
        HistoryViewModel page = Page(gateway, reviews);
        await page.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(1, page.NeedsDecisionCount);
        Assert.Equal(1, page.BadgeCount);

        page.KeepCommand.Execute(null);

        Assert.Equal(0, page.NeedsDecisionCount);
        Assert.Equal(0, page.BadgeCount);
        Assert.Equal(1, page.KeptCount);
        Assert.Empty(gateway.Exclusions); // keeping is not an exclusion
        Assert.Contains("not an exclusion", page.Message, StringComparison.Ordinal);

        // The choice survives a refresh (it is stored), and can be undone.
        await page.RefreshCommand.ExecuteAsync(null);
        Assert.True(page.Selected!.Kept);
        page.UnkeepCommand.Execute(null);
        Assert.Equal(1, page.NeedsDecisionCount);
    }

    [Fact]
    public async Task Quarantining_a_finding_asks_first_and_moves_it_to_the_vault()
    {
        var gateway = new FakeGateway { Detections = [Finding(@"C:\Users\alice\bad.exe")] };
        var dialogs = new FakeDialogs { Answer = false };
        HistoryViewModel page = Page(gateway, dialogs: dialogs);
        await page.RefreshCommand.ExecuteAsync(null);

        await page.QuarantineCommand.ExecuteAsync(null);
        Assert.Empty(gateway.Quarantined); // declined

        dialogs.Answer = true;
        await page.QuarantineCommand.ExecuteAsync(null);

        Assert.Equal([@"C:\Users\alice\bad.exe"], gateway.Quarantined);
        Assert.Equal(0, page.NeedsDecisionCount);
        Assert.Contains(page.Entries, e => e.Kind == HistoryKind.Quarantined && e.Path == @"C:\Users\alice\bad.exe");
    }

    [Fact]
    public async Task Filters_and_search_narrow_the_list()
    {
        var gateway = new FakeGateway { Detections = [Finding(@"C:\a.exe"), Finding(@"C:\tools\b.exe", status: "suspicious")] };
        HistoryViewModel page = Page(gateway);
        await page.RefreshCommand.ExecuteAsync(null);
        Assert.Equal(2, page.Entries.Count); // the actions log is its own filter

        page.Search = "tools";
        Assert.Equal(@"C:\tools\b.exe", Assert.Single(page.Entries).Path);

        page.Search = string.Empty;
        page.Filter = HistoryFilter.ActionsLog;
        Assert.All(page.Entries, e => Assert.Equal(HistoryKind.Action, e.Kind));
    }

    [Fact]
    public async Task Home_counts_unresolved_findings_and_offers_review()
    {
        var gateway = new FakeGateway(); // one confirmed finding, reported only
        var main = new MainViewModel(gateway, new FakeDialogs(), new FakeHost());
        main.Home.AntivirusSource = () => AntivirusHealth.Good;
        main.Home.FolderAccessSource = () => 1;

        await main.Home.RefreshCommand.ExecuteAsync(null);

        Assert.Equal(ProtectionLevel.ActionNeeded, main.Home.Status.Level);
        Assert.Contains(main.Home.Attention, a => a.Title == "1 threat needs your decision");
        Assert.Equal("Review", main.Home.PrimaryActionLabel);

        main.Home.PrimaryActionCommand.Execute(null);

        Assert.Same(main.History, main.Current);
        Assert.Equal(HistoryFilter.NeedsDecision, main.History.Filter);
    }

    [Fact]
    public void Kept_choices_are_stored_per_user_and_bounded()
    {
        string file = Path.Combine(Path.GetTempPath(), $"kshatriya-reviewed-{Guid.NewGuid():N}.json");
        try
        {
            var store = new FileReviewStore(file);
            string key = IReviewStore.KeyOf(@"C:\a.exe", ["B", "A"]);
            store.Keep(key);
            Assert.Equal(IReviewStore.KeyOf(@"c:\A.EXE", ["A", "B"]), key);
            Assert.True(new FileReviewStore(file).IsKept(key));

            for (int i = 0; i < FileReviewStore.MaxEntries; i++)
            {
                store.Keep($"k{i}");
            }

            Assert.False(new FileReviewStore(file).IsKept(key)); // the oldest went first

            File.WriteAllText(file, "{ not json");
            Assert.False(new FileReviewStore(file).IsKept("k5")); // a damaged file hides nothing
        }
        finally
        {
            File.Delete(file);
        }
    }
}
