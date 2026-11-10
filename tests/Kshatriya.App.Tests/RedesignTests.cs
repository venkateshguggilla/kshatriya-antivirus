using Kshatriya.App.Services;
using Kshatriya.App.ViewModels;
using Kshatriya.Core;

namespace Kshatriya.App.Tests;

/// <summary>Behaviour behind the redesigned screens: the dashboard verdict, the scan choice and result tones.</summary>
public class RedesignTests
{
    private static ScanReport Report(int detected = 0, int suspicious = 0, int notScanned = 0) => new()
    {
        Targets = [@"C:\"],
        StartedUtc = DateTimeOffset.UtcNow,
        FinishedUtc = DateTimeOffset.UtcNow,
        Engines = [],
        Summary = new ScanSummary { ItemsSeen = 10, FilesScanned = 10, Detected = detected, Suspicious = suspicious, NotScanned = notScanned },
        Items = [],
    };

    [Fact]
    public async Task The_dashboard_gives_one_verdict_backed_by_status_rows()
    {
        var dashboard = new DashboardViewModel(new FakeGateway(), new FakeHost())
        {
            AntivirusSource = () => AntivirusHealth.Good,
            FolderAccessSource = () => 1,
        };

        await dashboard.RefreshCommand.ExecuteAsync(null);

        // The fake service reports an expired signature update, which needs attention.
        Assert.Equal("Attention needed", dashboard.Verdict);
        Assert.Equal(Tone.Caution, dashboard.VerdictTone);
        Assert.Contains(dashboard.Rows, r => r.Label == "Signatures" && r.Tone == Tone.Caution);
        Assert.Contains(dashboard.Rows, r => r.Label == "Real-time monitoring" && r.Tone == Tone.Success);
        Assert.Contains(dashboard.Rows, r => r.Label == "Audit log" && r.Value == "Intact");
        Assert.True(dashboard.QuickScanCommand.CanExecute(null));
    }

    [Fact]
    public async Task Without_the_service_the_verdict_says_so_and_scanning_is_unavailable()
    {
        var dashboard = new DashboardViewModel(new FakeGateway { Failure = new TimeoutException() }, new FakeHost())
        {
            AntivirusSource = () => AntivirusHealth.Good,
            FolderAccessSource = () => null,
        };

        await dashboard.RefreshCommand.ExecuteAsync(null);

        Assert.Equal("Kshatriya is not running", dashboard.Verdict);
        Assert.Equal(Tone.Critical, dashboard.VerdictTone);
        Assert.Contains(dashboard.Rows, r => r.Label == "Kshatriya service" && r.Tone == Tone.Critical);
        Assert.False(dashboard.QuickScanCommand.CanExecute(null));
    }

    [Fact]
    public async Task While_the_service_is_starting_the_dashboard_says_so_and_connects_when_it_is_up()
    {
        var gateway = new FakeGateway { Failure = new TimeoutException() };
        var dashboard = new DashboardViewModel(gateway, new FakeHost())
        {
            AntivirusSource = () => AntivirusHealth.Good,
            FolderAccessSource = () => null,
            ServiceStartingSource = () => true,
        };

        await dashboard.RefreshCommand.ExecuteAsync(null);

        Assert.Equal("Kshatriya is starting", dashboard.Verdict);
        Assert.Equal(Tone.Caution, dashboard.VerdictTone);
        Assert.Contains(dashboard.Rows, r => r.Label == "Kshatriya service" && r.Value == "Starting");

        // The service comes up: the next automatic retry connects without the user doing anything.
        gateway.Failure = null;
        await dashboard.RetryIfDisconnectedAsync();

        Assert.True(dashboard.IsConnected);
        Assert.NotEqual("Kshatriya is starting", dashboard.Verdict);
    }

    [Fact]
    public async Task Retrying_does_nothing_while_connected()
    {
        var gateway = new FakeGateway();
        var dashboard = new DashboardViewModel(gateway, new FakeHost()) { AntivirusSource = () => AntivirusHealth.Good, FolderAccessSource = () => null };
        await dashboard.RefreshCommand.ExecuteAsync(null);
        gateway.Failure = new TimeoutException(); // any further status query would now disconnect the page

        await dashboard.RetryIfDisconnectedAsync();

        Assert.True(dashboard.IsConnected);
    }

    [Theory]
    [InlineData(2u, 60, true)]      // start pending
    [InlineData(1u, 60, true)]      // stopped one minute after Windows started: delayed start
    [InlineData(1u, 600, false)]    // stopped ten minutes after Windows started: not running
    [InlineData(4u, 60, false)]     // running (yet unreachable): not "starting"
    [InlineData(null, 60, false)]   // not installed
    public void Starting_means_start_pending_or_stopped_soon_after_Windows_started(uint? state, int seconds, bool starting)
    {
        Assert.Equal(starting, ServiceStartup.IsStarting(state, TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public async Task Quick_scan_on_the_dashboard_opens_the_scan_page_and_starts_it()
    {
        var gateway = new FakeGateway { NextReport = Report() };
        var main = new MainViewModel(gateway, new FakeDialogs(), new FakeHost());
        main.Dashboard.AntivirusSource = () => AntivirusHealth.Good;
        main.Dashboard.FolderAccessSource = () => 1;
        await main.Dashboard.RefreshCommand.ExecuteAsync(null);

        main.Dashboard.QuickScanCommand.Execute(null);
        await Task.Delay(50);

        Assert.Same(main.Scan, main.Current);
        Assert.True(main.Scan.IsQuick);
        Assert.Contains("scan-kind:quick", gateway.Calls);
    }

    [Theory]
    [InlineData(ScanChoice.Quick, "scan-kind:quick")]
    [InlineData(ScanChoice.Full, "scan-kind:full")]
    [InlineData(ScanChoice.External, "scan-kind:external")]
    [InlineData(ScanChoice.Drive, @"scan:E:\")]
    [InlineData(ScanChoice.Custom, @"scan:C:\data")]
    public async Task Scan_now_runs_the_chosen_scan(ScanChoice choice, string expectedCall)
    {
        var gateway = new FakeGateway { NextReport = Report() };
        var scan = new ScanViewModel(gateway, new FakeDialogs(), () => [new DriveChoice(@"E:\", "E: External drive (USB)", IsExternal: true)]);
        scan.AddTargets([@"C:\data"]);

        scan.Choice = choice;
        await scan.ScanNowCommand.ExecuteAsync(null);

        Assert.Equal([expectedCall], gateway.Calls);
    }

    [Fact]
    public void Radio_buttons_select_exactly_one_scan_type()
    {
        var scan = new ScanViewModel(new FakeGateway(), new FakeDialogs(), () => []);
        Assert.True(scan.IsQuick);

        scan.IsCustom = true;

        Assert.Equal(ScanChoice.Custom, scan.Choice);
        Assert.False(scan.IsQuick);
        Assert.False(scan.ScanNowCommand.CanExecute(null)); // a custom scan needs at least one folder
        scan.IsExternal = false; // unchecking another option changes nothing
        Assert.Equal(ScanChoice.Custom, scan.Choice);
    }

    [Theory]
    [InlineData(1, 0, 0, Tone.Critical, "Threats found")]
    [InlineData(0, 2, 0, Tone.Caution, "Suspicious files found")]
    [InlineData(0, 0, 3, Tone.Caution, "Scan incomplete")]
    [InlineData(0, 0, 0, Tone.Success, "No threats found")]
    public void Results_are_labelled_by_what_was_found(int detected, int suspicious, int notScanned, Tone tone, string title)
    {
        var scan = new ScanViewModel(new FakeGateway(), new FakeDialogs(), () => []);

        scan.ShowReport(Report(detected, suspicious, notScanned), "Quick scan");

        Assert.Equal(tone, scan.SummaryTone);
        Assert.Equal(title, scan.SummaryTitle);
    }
}
