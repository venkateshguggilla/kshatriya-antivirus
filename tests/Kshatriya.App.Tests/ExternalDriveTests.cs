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
    public void The_notification_offers_a_scan_unless_real_time_protection_already_scans_it()
    {
        FindingNotice offer = ExternalDriveWatcher.Describe(s_stick, scannedAutomatically: false);
        FindingNotice automatic = ExternalDriveWatcher.Describe(s_stick, scannedAutomatically: true);

        Assert.Equal("External drive connected", offer.Title);
        Assert.Contains("SanDisk Ultra", offer.Message, StringComparison.Ordinal);
        Assert.Contains("Click here to scan", offer.Message, StringComparison.Ordinal);
        Assert.Contains("scanning it now", automatic.Message, StringComparison.Ordinal);
        Assert.False(offer.IsThreat);
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
