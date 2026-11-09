using Kshatriya.App.Services;
using Kshatriya.App.ViewModels;
using Kshatriya.Core;
using Kshatriya.Scanning.Targets;

namespace Kshatriya.App.Tests;

public class ExternalDriveTests
{
    private static readonly DriveDescription s_system = new(@"C:\", IsExternal: false, @"C:  Local disk, 512 GB");
    private static readonly DriveDescription s_stick = new(@"E:\", IsExternal: true, @"E:  External drive (USB) ""PHOTOS"" SanDisk Ultra, 64 GB");
    private static readonly DriveDescription s_card = new(@"F:\", IsExternal: true, @"F:  Memory card, 32 GB");

    private static ScanReport Clean() => new()
    {
        Targets = [@"E:\"],
        StartedUtc = DateTimeOffset.UtcNow,
        FinishedUtc = DateTimeOffset.UtcNow,
        Engines = [],
        Summary = new ScanSummary { ItemsSeen = 3, FilesScanned = 3 },
        Items = [],
    };

    [Fact]
    public void Drives_connected_at_start_are_not_announced_but_new_ones_are()
    {
        var watcher = new ExternalDriveWatcher();

        Assert.Empty(watcher.Update([s_system, s_stick]));
        Assert.Empty(watcher.Update([s_system, s_stick]));
        Assert.Equal([s_card], watcher.Update([s_system, s_stick, s_card]));
        Assert.Empty(watcher.Update([s_system, s_card]));             // E: removed
        Assert.Equal([s_stick], watcher.Update([s_system, s_stick, s_card])); // plugged in again
    }

    [Fact]
    public void Internal_drives_are_never_announced()
    {
        var watcher = new ExternalDriveWatcher();
        watcher.Update([]);

        Assert.Empty(watcher.Update([s_system, new DriveDescription(@"D:\", false, "D:  Local disk")]));
    }

    [Fact]
    public void The_connect_notification_says_who_scans_the_drive()
    {
        FindingNotice service = ExternalDriveWatcher.Describe(s_stick, ConnectAction.ServiceScans);
        FindingNotice app = ExternalDriveWatcher.Describe(s_stick, ConnectAction.AppScans);
        FindingNotice offer = ExternalDriveWatcher.Describe(s_stick, ConnectAction.Offer);

        Assert.Contains("Real-time protection is scanning it", service.Message, StringComparison.Ordinal);
        Assert.Equal("Scanning external drive", app.Title);
        Assert.Contains("SanDisk Ultra", app.Message, StringComparison.Ordinal);
        Assert.Contains("Click here to scan", offer.Message, StringComparison.Ordinal);
        Assert.False(offer.IsThreat);
    }

    [Fact]
    public async Task A_connected_drive_is_scanned_report_only_and_the_result_described()
    {
        var gateway = new FakeGateway { NextReport = Clean() };
        using var scanner = new ExternalDriveScanner(gateway);

        FindingNotice result = await scanner.ScanAsync(s_stick, CancellationToken.None);

        Assert.Equal([@"scan:E:\"], gateway.Calls);
        Assert.False(gateway.LastScanQuarantine); // never quarantines on its own
        Assert.Equal("External drive scanned", result.Title);
        Assert.Contains("nothing found in 3 file(s)", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Scan_results_name_threats_suspicious_files_and_gaps()
    {
        static ScanReport With(ScanSummary summary) => Clean() with { Summary = summary };

        FindingNotice threat = ExternalDriveScanner.Describe(s_stick, With(new ScanSummary { FilesScanned = 9, Detected = 2, Suspicious = 1 }));
        FindingNotice suspicious = ExternalDriveScanner.Describe(s_stick, With(new ScanSummary { FilesScanned = 9, Suspicious = 1 }));
        FindingNotice gaps = ExternalDriveScanner.Describe(s_stick, With(new ScanSummary { FilesScanned = 9, NotScanned = 4 }));

        Assert.True(threat.IsThreat);
        Assert.Contains("2 threat(s) found, 1 suspicious", threat.Message, StringComparison.Ordinal);
        Assert.Equal("Suspicious files on external drive", suspicious.Title);
        Assert.Contains("4 item(s) could not be scanned", gaps.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_unreachable_service_is_reported_instead_of_a_result()
    {
        using var scanner = new ExternalDriveScanner(new FakeGateway { Failure = new TimeoutException() });

        FindingNotice result = await scanner.ScanAsync(s_stick, CancellationToken.None);

        Assert.Equal("External drive not scanned", result.Title);
        Assert.Contains("not reachable", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Scanning_drives_on_connect_is_on_by_default_and_remembered()
    {
        using var temp = new Kshatriya.Tests.Shared.TempDirectory();
        string file = Path.Combine(temp.Path, "app-settings.json");

        Assert.True(new AppPreferences(file).ScanExternalDrives);
        new AppPreferences(file).SetScanExternalDrives(false);
        var reloaded = new AppPreferences(file);
        Assert.False(reloaded.ScanExternalDrives);
        Assert.True(reloaded.Notifications); // the other preference is kept
    }

    [Fact]
    public async Task External_drives_can_be_scanned_together_or_one_at_a_time()
    {
        var gateway = new FakeGateway { NextReport = Clean() };
        DriveChoice[] drives = [new(@"C:\", "C: Local disk"), new(@"E:\", "E: External drive (USB)", IsExternal: true)];
        var scan = new ScanViewModel(gateway, new FakeDialogs(), () => drives);

        Assert.True(scan.ExternalScanCommand.CanExecute(null));
        await scan.ExternalScanCommand.ExecuteAsync(null);
        await scan.ScanDriveAsync(@"e:\");

        Assert.Equal(["scan-kind:external", @"scan:E:\"], gateway.Calls);
        Assert.Equal(@"E:\", scan.SelectedDrive!.Root);
        Assert.StartsWith(@"Scan of E:\ finished.", scan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Without_external_drives_there_is_nothing_external_to_scan()
    {
        var gateway = new FakeGateway { NextReport = Clean() };
        var scan = new ScanViewModel(gateway, new FakeDialogs(), () => [new DriveChoice(@"C:\", "C: Local disk")]);

        Assert.False(scan.ExternalScanCommand.CanExecute(null));
        await scan.ScanDriveAsync(@"G:\"); // a drive that went away before the click

        Assert.Empty(gateway.Calls);
    }
}
