using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Service;
using Sentinel.Tests.Shared;

namespace Sentinel.Service.Tests;

/// <summary>End-to-end: CLI-side client ↔ pipe server ↔ sandboxed workers.</summary>
public class PipeServerTests
{
    [Fact]
    public async Task Handshake_reports_the_callers_identity_as_seen_through_impersonation()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using ServiceClient client = await service.ConnectAsync();

        Assert.Equal(WindowsIdentity.GetCurrent().Name, client.Hello.User);
        Assert.Equal(ProtocolVersion.Service, client.Hello.Protocol);
        Assert.StartsWith("Sentinel ", client.Hello.Service, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_reports_engines_workers_and_mode()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using ServiceClient client = await service.ConnectAsync();

        StatusReplyDto status = await client.GetStatusAsync();

        Assert.Equal("development", status.Mode);
        Assert.Contains(status.Engines, e => e.Id == "hash");
        Assert.Equal(2, status.Workers.Configured);
        Assert.True(status.Workers.Started >= 1);
        Assert.Equal(0, status.ActiveScans);
    }

    [Fact]
    public async Task Scan_runs_in_the_service_and_returns_a_report()
    {
        await using RunningService service = await RunningService.StartAsync();
        string folder = service.Temp.Dir("to-scan");
        service.Temp.File(@"to-scan\clean.bin", TestData.BenignBytes(1, 2000));
        service.Temp.File(@"to-scan\nested\flagged.bin", service.KnownBad);
        service.Temp.File(@"to-scan\archive.zip", ZipFactory.Create(("inner/flagged.bin", service.KnownBad)));
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanAsync([folder], includeClean: false);

        Assert.Equal(3, report.Summary.FilesScanned);
        Assert.Equal(2, report.Summary.Detected);
        Assert.True(report.IsComplete);
        Assert.Contains(report.Items, i => i.Path.EndsWith("archive.zip", StringComparison.Ordinal) && i.Detections[0].Location == "inner/flagged.bin");
        Assert.All(report.Items, i => Assert.Equal("Service.Test.Sample", i.Detections[0].Name));

        // The connection stays usable after a scan.
        StatusReplyDto status = await client.GetStatusAsync();
        Assert.Equal(0, status.ActiveScans);
    }

    [Theory]
    [InlineData(@"\\server\share")]
    [InlineData(@"relative\folder")]
    [InlineData(@"\\?\C:\Windows")]
    public async Task Non_local_or_relative_paths_are_refused(string path)
    {
        await using RunningService service = await RunningService.StartAsync();
        await using ServiceClient client = await service.ConnectAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.ScanAsync([path], includeClean: false));

        Assert.Equal(ErrorCodes.InvalidPath, ex.Code);
    }

    [Fact]
    public async Task Cancelling_stops_the_scan_and_keeps_the_connection_usable()
    {
        await using RunningService service = await RunningService.StartAsync();
        string folder = service.Temp.Dir("many");
        for (int i = 0; i < 4000; i++)
        {
            service.Temp.File($@"many\d{i % 40}\f{i}.bin", TestData.BenignBytes(i, 64));
        }

        await using ServiceClient client = await service.ConnectAsync();
        using var cancel = new CancellationTokenSource();
        var progress = new Progress<ScanProgressDto>(_ => cancel.Cancel());

        Task scan = client.ScanAsync([folder], includeClean: false, progress, cancel.Token);
        Task finished = await Task.WhenAny(scan, Task.Delay(TimeSpan.FromSeconds(60)));

        Assert.Same(scan, finished);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scan);
        StatusReplyDto status = await client.GetStatusAsync();
        Assert.Equal(0, status.ActiveScans);
    }

    [Fact]
    public async Task Client_refuses_a_server_that_is_not_the_installed_service()
    {
        await using RunningService service = await RunningService.StartAsync();
        var asProduction = new ServiceEndpoint(service.PipeName, ServerIdentityCheck.InstalledService, "SentinelServiceDoesNotExist");

        await Assert.ThrowsAsync<ServiceAuthenticationException>(() => ServiceClient.ConnectAsync(asProduction, "tests", TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task A_second_server_cannot_claim_the_same_pipe()
    {
        await using RunningService service = await RunningService.StartAsync();
        var second = new PipeServer(new PipeServerOptions(service.PipeName, Production: false), service.Core, NullLogger.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => second.RunAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Client_that_only_allows_identification_is_refused()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using var pipe = new NamedPipeClientStream(".", service.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000);

        await FrameIO.WriteAsync(pipe, MessageType.Hello, ProtocolJson.Serialize(new HelloDto { Protocol = ProtocolVersion.Service, Client = "raw" }));
        Frame? reply = await FrameIO.ReadAsync(pipe, FrameLimits.Control);

        ErrorDto error = ProtocolJson.Expect<ErrorDto>(reply, MessageType.Error);
        Assert.Equal(ErrorCodes.BadRequest, error.Code);
        Assert.Contains("impersonation", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Garbage_from_a_client_drops_only_that_connection()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using (var pipe = new NamedPipeClientStream(".", service.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation))
        {
            await pipe.ConnectAsync(5000);
            byte[] buffer = new byte[16];
            int read;
            try
            {
                // A frame header announcing ~2 GiB: rejected before any allocation, connection dropped.
                await pipe.WriteAsync(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3, 4, 5, 6 });
                read = await pipe.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            }
            catch (IOException)
            {
                read = 0; // "pipe is broken": the server closed the connection
            }

            Assert.Equal(0, read);
        }

        await using ServiceClient client = await service.ConnectAsync();
        Assert.NotNull(await client.GetStatusAsync());
    }

    [Fact]
    public async Task Version_mismatch_is_reported()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using var pipe = new NamedPipeClientStream(".", service.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(5000);

        await FrameIO.WriteAsync(pipe, MessageType.Hello, ProtocolJson.Serialize(new HelloDto { Protocol = 99, Client = "future" }));
        ErrorDto error = ProtocolJson.Expect<ErrorDto>(await FrameIO.ReadAsync(pipe, FrameLimits.Control), MessageType.Error);

        Assert.Equal(ErrorCodes.VersionMismatch, error.Code);
    }

    [Fact]
    public async Task Scheduled_scan_runs_when_due_and_saves_a_report()
    {
        var now = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
        var clock = new FixedTime(now);
        using var scanDir = new TempDirectory();
        using var stateDir = new TempDirectory();
        var settings = new ServiceSettings
        {
            ScheduledScans = [new ScheduledScan("nightly", Enum.GetValues<DayOfWeek>().ToHashSet(), new TimeOnly(3, 0), [scanDir.Path])],
        };
        await using RunningService service = await RunningService.StartAsync(settings, clock);
        scanDir.File("flagged.bin", service.KnownBad);

        var state = new ScheduleState(stateDir.Path);
        state.Set("nightly", now.AddDays(-2), "clean");
        string reports = stateDir.Dir("reports");
        var scheduler = new Scheduler(service.Core, state, new ReportStore(reports, 5), clock, TimeZoneInfo.Utc, NullLogger.Instance);

        int ran = await scheduler.RunDueAsync(CancellationToken.None);
        int ranAgain = await scheduler.RunDueAsync(CancellationToken.None);

        Assert.Equal(1, ran);
        Assert.Equal(0, ranAgain);
        string report = Assert.Single(Directory.GetFiles(reports, "scan-*-nightly.json"));
        Assert.Equal(1, ScanReportJson.Read(File.ReadAllText(report)).Summary.Detected);
        Assert.Equal("detections", state.Get("nightly")!.Value.Outcome);
    }

    [Fact]
    public async Task Status_lists_schedules_with_their_next_run()
    {
        var settings = new ServiceSettings
        {
            ScheduledScans = [new ScheduledScan("weekly", new HashSet<DayOfWeek> { DayOfWeek.Sunday }, new TimeOnly(3, 0), [@"C:\Users"])],
        };
        await using RunningService service = await RunningService.StartAsync(settings, new FixedTime(new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero)));
        await using ServiceClient client = await service.ConnectAsync();

        ScheduleStatusDto schedule = Assert.Single((await client.GetStatusAsync()).Schedules);

        Assert.Equal("weekly", schedule.Name);
        Assert.Equal("2026-11-08T03:00:00.0000000Z", schedule.NextRunUtc);
        Assert.Null(schedule.LastRunUtc);
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
