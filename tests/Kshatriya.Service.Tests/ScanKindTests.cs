using System.Security.Principal;
using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Scanning.Targets;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

public sealed class ScanKindTests : IDisposable
{
    private readonly TempDirectory _quick = new();
    private readonly TempDirectory _full = new();
    private readonly List<(ScanKind Kind, QuickScanScope Scope)> _requests = [];

    public void Dispose()
    {
        _quick.Dispose();
        _full.Dispose();
    }

    /// <summary>External drives the fake target provider reports (none by default).</summary>
    private List<string> _external = [];

    private Task<RunningService> StartAsync(ServiceSettings? settings = null, TimeProvider? time = null) =>
        RunningService.StartAsync(settings, time, scanTargets: (kind, scope) =>
        {
            lock (_requests)
            {
                _requests.Add((kind, scope));
            }

            return kind switch
            {
                ScanKind.Quick => [_quick.Path],
                ScanKind.External => [.. _external],
                _ => [_full.Path],
            };
        });

    [Fact]
    public async Task An_external_drive_scan_scans_every_connected_external_drive()
    {
        using var usb = new TempDirectory();
        _external = [usb.Path];
        await using RunningService service = await StartAsync();
        string bad = usb.File(@"autorun\payload.bin", service.KnownBad);
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanKindAsync(ScanKinds.External, includeClean: false, quarantine: false);

        Assert.Equal(bad, Assert.Single(report.Items, i => i.Status == ScanStatus.Detected).Path);
        Assert.Equal(ScanKind.External, Assert.Single(_requests).Kind);
    }

    [Fact]
    public async Task Without_external_drives_the_scan_says_so()
    {
        await using RunningService service = await StartAsync();
        await using ServiceClient client = await service.ConnectAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.ScanKindAsync(ScanKinds.External, includeClean: false, quarantine: false));

        Assert.Equal(ErrorCodes.InvalidPath, ex.Code);
        Assert.Contains("No external drive", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_scheduled_external_scan_with_no_drive_connected_does_nothing()
    {
        var now = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTime(now);
        using var stateDir = new TempDirectory();
        var settings = new ServiceSettings
        {
            ScheduledScans = [new ScheduledScan("usb", Enum.GetValues<DayOfWeek>().ToHashSet(), new TimeOnly(3, 0), [], Kind: ScanKind.External)],
        };
        await using RunningService service = await StartAsync(settings, clock);
        var state = new ScheduleState(stateDir.Path);
        state.Set("usb", now.AddDays(-2), "clean");
        string reports = stateDir.Dir("reports");
        var scheduler = new Scheduler(service.Core, state, new ReportStore(reports, 5), clock, TimeZoneInfo.Utc, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        await scheduler.RunDueAsync(CancellationToken.None);

        Assert.Equal("nothing to scan", state.Get("usb")!.Value.Outcome);
        Assert.Empty(Directory.GetFiles(reports));
        Assert.Equal(0, await scheduler.RunDueAsync(CancellationToken.None)); // not retried until the next occurrence
    }

    [Fact]
    public async Task A_quick_scan_scans_the_targets_the_service_chooses_for_the_caller()
    {
        await using RunningService service = await StartAsync();
        string bad = _quick.File(@"Downloads\dropped.bin", service.KnownBad);
        _full.File("elsewhere.bin", service.KnownBad);
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanKindAsync(ScanKinds.Quick, includeClean: false, quarantine: false);

        Assert.Equal(bad, Assert.Single(report.Items, i => i.Status == ScanStatus.Detected).Path);
        (ScanKind kind, QuickScanScope scope) = Assert.Single(_requests);
        Assert.Equal(ScanKind.Quick, kind);
        Assert.Equal(WindowsIdentity.GetCurrent().User!.Value, scope.UserSid); // the caller's own profile only
    }

    [Fact]
    public async Task A_full_scan_scans_the_machine_wide_targets()
    {
        await using RunningService service = await StartAsync();
        string bad = _full.File(@"deep\x.bin", service.KnownBad);
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanKindAsync(ScanKinds.Full, includeClean: false, quarantine: false);

        Assert.Equal(bad, Assert.Single(report.Items, i => i.Status == ScanStatus.Detected).Path);
        Assert.Equal(ScanKind.Full, Assert.Single(_requests).Kind);
    }

    [Theory]
    [InlineData("quick", true)]   // quick and full scans choose their own targets
    [InlineData("full", true)]
    [InlineData("everything", false)]
    public async Task Malformed_scan_kinds_are_rejected(string kind, bool withPaths)
    {
        await using RunningService service = await StartAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => RawScanAsync(service, kind, withPaths ? [@"C:\Windows"] : []));

        Assert.Equal(ErrorCodes.BadRequest, ex.Code);
        Assert.Empty(_requests);
    }

    [Fact]
    public async Task A_scheduled_quick_scan_covers_the_whole_machine_when_it_runs()
    {
        var now = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTime(now);
        using var stateDir = new TempDirectory();
        var settings = new ServiceSettings
        {
            ScheduledScans = [new ScheduledScan("daily-quick", Enum.GetValues<DayOfWeek>().ToHashSet(), new TimeOnly(3, 0), [], Kind: ScanKind.Quick)],
        };
        await using RunningService service = await StartAsync(settings, clock);
        _quick.File("startup-item.bin", service.KnownBad);
        var state = new ScheduleState(stateDir.Path);
        state.Set("daily-quick", now.AddDays(-2), "clean");
        var scheduler = new Scheduler(service.Core, state, new ReportStore(stateDir.Dir("reports"), 5), clock, TimeZoneInfo.Utc, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        Assert.Equal(1, await scheduler.RunDueAsync(CancellationToken.None));

        (ScanKind kind, QuickScanScope scope) = Assert.Single(_requests);
        Assert.Equal(ScanKind.Quick, kind);
        Assert.Same(QuickScanScope.Machine, scope);
        Assert.Equal("detections", state.Get("daily-quick")!.Value.Outcome);
    }

    [Fact]
    public void Scheduled_scans_can_be_quick_or_full()
    {
        ServiceSettings settings = ServiceSettings.Parse("""
            { "schemaVersion": 1, "scheduledScans": [
              { "name": "daily-quick", "days": ["daily"], "time": "12:00", "scan": "quick" },
              { "name": "weekly-full", "days": ["sunday"], "time": "03:00", "scan": "full", "action": "quarantine" },
              { "name": "usb", "days": ["daily"], "time": "18:00", "scan": "external" },
              { "name": "downloads", "days": ["monday"], "time": "09:00", "paths": ["C:\\Users"] } ] }
            """);

        Assert.Equal([ScanKind.Quick, ScanKind.Full, ScanKind.External, ScanKind.Custom], settings.ScheduledScans.Select(s => s.Kind));
        Assert.Empty(settings.ScheduledScans[0].Paths);
        Assert.True(settings.ScheduledScans[1].Quarantine);

        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "scheduledScans": [ { "name": "x", "days": ["daily"], "time": "12:00", "scan": "quick", "paths": ["C:\\"] } ] }"""));
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "scheduledScans": [ { "name": "x", "days": ["daily"], "time": "12:00" } ] }"""));
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "scheduledScans": [ { "name": "x", "days": ["daily"], "time": "12:00", "scan": "deep" } ] }"""));
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static async Task RawScanAsync(RunningService service, string kind, List<string> paths)
    {
        using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", service.PipeName, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(5000);
        await FrameIO.WriteAsync(pipe, MessageType.Hello, ProtocolJson.Serialize(new HelloDto { Protocol = ProtocolVersion.Service, Client = "raw" }));
        ProtocolJson.Expect<HelloReplyDto>(await FrameIO.ReadAsync(pipe, FrameLimits.Control), MessageType.HelloReply);
        await FrameIO.WriteAsync(pipe, MessageType.Scan, ProtocolJson.Serialize(new ScanRequestDto { Paths = paths, Kind = kind, IncludeClean = false, Action = ScanActions.Report }));
        ErrorDto error = ProtocolJson.Expect<ErrorDto>(await FrameIO.ReadAsync(pipe, FrameLimits.Control), MessageType.Error);
        throw new ServiceException(error.Code, error.Message);
    }
}
