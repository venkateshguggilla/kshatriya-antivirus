using Kshatriya.App.ViewModels;
using Kshatriya.Core;
using Kshatriya.Protocol;

namespace Kshatriya.App.Tests;

/// <summary>The app-level scan session and the grouped results (ADR 0021, slice 3).</summary>
public class ScanSessionTests
{
    private static ScanReport Report(params ScanItemResult[] items) => new()
    {
        Targets = [@"C:\Users\alice"],
        StartedUtc = DateTimeOffset.UtcNow,
        FinishedUtc = DateTimeOffset.UtcNow,
        Engines = [],
        Summary = new ScanSummary
        {
            ItemsSeen = 100,
            FilesScanned = 100,
            Detected = items.Count(i => i.Status == ScanStatus.Detected),
            Suspicious = items.Count(i => i.Status == ScanStatus.Suspicious),
            NotScanned = items.Count(i => i.Status == ScanStatus.NotScanned),
        },
        Items = items,
    };

    private static ScanItemResult Detected(string path, bool quarantined = false) => new()
    {
        Path = path,
        Kind = ScanItemKind.File,
        Status = ScanStatus.Detected,
        Detections = [new Detection("hash", "Kshatriya.Test.EICAR", DetectionCategory.TestFile, DetectionConfidence.High)],
        Action = quarantined ? ItemAction.Quarantined("q1") : null,
    };

    private static ScanItemResult Suspicious(string path) => new()
    {
        Path = path,
        Kind = ScanItemKind.File,
        Status = ScanStatus.Suspicious,
        Detections = [new Detection("pe-heuristics", "Kshatriya.Heuristic.DoubleExtension", DetectionCategory.Suspicious, DetectionConfidence.Medium)],
    };

    [Fact]
    public async Task A_session_reports_progress_and_ends_completed()
    {
        var session = new ScanSession(() => TimeSpan.FromSeconds(75));
        var tcs = new TaskCompletionSource<ScanReport>();
        IProgress<ScanProgressDto>? reporter = null;
        ScanSession? finished = null;
        session.Finished += s => finished = s;

        Task<ScanReport?> run = session.RunAsync("Quick scan", (p, _) => { reporter = p; return tcs.Task; });
        Assert.True(session.IsRunning);
        Assert.Contains("Quick scan", session.StatusLine, StringComparison.Ordinal);

        tcs.SetResult(Report(Detected(@"C:\a.exe", quarantined: true)));
        ScanReport? report = await run;

        Assert.NotNull(report);
        Assert.NotNull(reporter);
        Assert.Equal(ScanState.Completed, session.State);
        Assert.False(session.IsRunning);
        Assert.Same(session, finished);
        Assert.Equal("1:15", session.ElapsedText);
        Assert.Equal(string.Empty, session.StatusLine);
        (string title, _, bool warning) = session.Outcome();
        Assert.Equal("Quick scan found 1 threat(s)", title);
        Assert.True(warning);
    }

    [Fact]
    public async Task Cancelling_ends_the_session_as_cancelled()
    {
        var session = new ScanSession();
        Task<ScanReport?> run = session.RunAsync("Full scan", async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return Report();
        });

        session.Cancel();

        Assert.Null(await run);
        Assert.Equal(ScanState.Cancelled, session.State);
        Assert.Equal("Full scan stopped", session.Outcome().Title);
    }

    [Fact]
    public async Task Only_one_scan_runs_at_a_time()
    {
        var session = new ScanSession();
        var tcs = new TaskCompletionSource<ScanReport>();
        Task<ScanReport?> first = session.RunAsync("Quick scan", (_, _) => tcs.Task);
        bool secondStarted = false;

        ScanReport? second = await session.RunAsync("Full scan", (_, _) => { secondStarted = true; return Task.FromResult(Report()); });

        Assert.Null(second);
        Assert.False(secondStarted);
        tcs.SetResult(Report());
        await first;
    }

    [Theory]
    [InlineData(65, "1:05")]
    [InlineData(3725, "1:02:05")]
    public void Elapsed_time_reads_as_minutes_or_hours(int seconds, string expected) =>
        Assert.Equal(expected, ScanSession.Format(TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void Results_are_grouped_by_what_the_user_has_to_do()
    {
        var scan = new ScanViewModel(new FakeGateway(), new FakeDialogs(), () => []);

        scan.ShowReport(Report(
            Detected(@"C:\Users\alice\Desktop\eicar.com", quarantined: true),
            Suspicious(@"C:\Users\alice\Downloads\invoice.pdf.exe"),
            ScanItemResult.Fail(@"C:\Windows\a.sys", ScanItemKind.File, ScanReason.AccessDenied),
            ScanItemResult.Fail(@"C:\Windows\b.sys", ScanItemKind.File, ScanReason.AccessDenied),
            ScanItemResult.Fail(@"C:\Users\alice\big.iso", ScanItemKind.File, ScanReason.Locked)), "Quick scan");

        FindingCard threat = Assert.Single(scan.Threats);
        Assert.True(threat.Quarantined);
        Assert.Equal(Tone.Critical, threat.Tone);
        Assert.StartsWith("Test file", threat.Badge, StringComparison.Ordinal);
        FindingCard decision = Assert.Single(scan.NeedsDecision);
        Assert.Equal(Tone.Caution, decision.Tone);
        Assert.Contains("not a confirmed detection", decision.Outcome, StringComparison.Ordinal);
        Assert.Equal(3, scan.NotScannedTotal);
        Assert.Equal(2, scan.NotScanned[0].Count); // the biggest group first
        Assert.Contains("administrator", scan.NotScanned[0].Hint, StringComparison.Ordinal);
        Assert.Equal(2, scan.LastAccessDenied);
    }

    [Fact]
    public async Task The_shell_shows_a_strip_while_a_scan_runs_on_another_page()
    {
        var gateway = new FakeGateway { ScanDelay = TimeSpan.FromMilliseconds(300), NextReport = Report(ScanItemResult.Fail(@"C:\x", ScanItemKind.File, ScanReason.AccessDenied)) };
        var main = new MainViewModel(gateway, new FakeDialogs(), new FakeHost());
        main.Scan.AddTargets([@"C:\Users\alice\Downloads"]);

        Task running = main.Scan.StartCommand.ExecuteAsync(null);
        Assert.True(main.ShowScanStrip); // Home is shown
        main.OpenScanCommand.Execute(null);
        Assert.False(main.ShowScanStrip);
        main.Current = main.Protection;
        Assert.True(main.ShowScanStrip);
        await running;

        Assert.False(main.ShowScanStrip);
        Assert.Equal(1, main.Home.LastScanAccessDenied);
    }
}
