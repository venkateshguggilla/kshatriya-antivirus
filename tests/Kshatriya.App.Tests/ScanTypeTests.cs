using Kshatriya.App.ViewModels;
using Kshatriya.Core;
using Kshatriya.Protocol;

namespace Kshatriya.App.Tests;

public class ScanTypeTests
{
    private static ScanReport Report(int notScanned = 0, bool detection = false)
    {
        var items = new List<ScanItemResult>();
        for (int i = 0; i < notScanned; i++)
        {
            items.Add(ScanItemResult.Fail($@"C:\locked\{i:D5}.dat", ScanItemKind.File, ScanReason.AccessDenied, "access denied"));
        }

        if (detection)
        {
            items.Add(new ScanItemResult
            {
                Path = @"C:\x\bad.exe",
                Kind = ScanItemKind.File,
                Status = ScanStatus.Detected,
                Detections = [new Detection("hash", "Test.Sample", DetectionCategory.TestFile, DetectionConfidence.High)],
            });
        }

        return new ScanReport
        {
            Targets = [@"C:\"],
            StartedUtc = DateTimeOffset.UtcNow,
            FinishedUtc = DateTimeOffset.UtcNow,
            Engines = [],
            Summary = new ScanSummary { ItemsSeen = items.Count + 10, FilesScanned = 10, Detected = detection ? 1 : 0, NotScanned = notScanned },
            Items = items,
        };
    }

    [Theory]
    [InlineData("quick")]
    [InlineData("full")]
    public async Task Quick_and_full_scans_ask_the_service_for_that_kind(string kind)
    {
        var gateway = new FakeGateway { NextReport = Report() };
        var scan = new ScanViewModel(gateway, new FakeDialogs(), () => []) { Quarantine = true };

        await (kind == "quick" ? scan.QuickScanCommand : scan.FullScanCommand).ExecuteAsync(null);

        Assert.Equal(["scan-kind:" + kind], gateway.Calls);
        Assert.True(gateway.LastScanQuarantine);
        Assert.StartsWith(kind == "quick" ? "Quick scan finished." : "Full scan finished.", scan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_drive_scan_scans_the_selected_drive_root()
    {
        var gateway = new FakeGateway { NextReport = Report(detection: true) };
        var scan = new ScanViewModel(gateway, new FakeDialogs(), () => [new DriveChoice(@"C:\", "C: Local disk"), new DriveChoice(@"E:\", "E: Removable drive")]);
        Assert.Equal(@"C:\", scan.SelectedDrive!.Root);
        scan.SelectedDrive = scan.Drives[1];

        await scan.DriveScanCommand.ExecuteAsync(null);

        Assert.Equal([@"scan:E:\"], gateway.Calls);
        Assert.StartsWith(@"Scan of E:\ finished. 1 item(s) detected", scan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Without_drives_there_is_nothing_to_scan()
    {
        var scan = new ScanViewModel(new FakeGateway(), new FakeDialogs(), () => []);

        Assert.Null(scan.SelectedDrive);
        Assert.False(scan.DriveScanCommand.CanExecute(null));
    }

    [Fact]
    public void Long_result_lists_are_capped_with_findings_first()
    {
        var scan = new ScanViewModel(new FakeGateway(), new FakeDialogs(), () => []);

        scan.ShowReport(Report(notScanned: ScanViewModel.MaxRows + 50, detection: true), "Full scan");

        Assert.Equal(ScanViewModel.MaxRows, scan.Results.Count);
        Assert.Equal("Detected", scan.Results[0].Status);
        Assert.Contains($"Showing the first {ScanViewModel.MaxRows:N0}", scan.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Explorer_scan_arguments_are_read_from_the_command_line()
    {
        Assert.Equal([@"C:\Users\alice\file.exe", @"E:\"], App.ScanArguments(["--scan", @"C:\Users\alice\file.exe", "--dev", "--scan", @"E:\"]));
        Assert.Empty(App.ScanArguments(["--background"]));
        Assert.Empty(App.ScanArguments(["--scan"]));
    }
}
