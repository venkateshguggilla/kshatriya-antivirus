using System.Security.Principal;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Tests.Shared;

namespace Sentinel.Service.Tests;

public class QuarantineServiceTests
{
    private static bool IsElevatedAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact]
    public async Task Service_scan_with_quarantine_removes_the_detection_and_restore_brings_it_back()
    {
        await using RunningService service = await RunningService.StartAsync();
        using var files = new TempDirectory();
        string bad = files.File(@"scan\bad.bin", service.KnownBad);
        files.File(@"scan\ok.bin", TestData.BenignBytes(3, 100));
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanAsync([Path.Combine(files.Path, "scan")], includeClean: false, quarantine: true);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.True(item.Action!.Succeeded, item.Action.Message);
        Assert.Equal(1, report.Summary.Quarantined);
        Assert.False(File.Exists(bad));

        QuarantineItemDto listed = Assert.Single((await client.ListQuarantineAsync()).Items);
        Assert.Equal(item.Action.QuarantineId, listed.Id);
        Assert.Equal(bad, listed.OriginalPath);
        Assert.Equal(["Service.Test.Sample"], listed.Detections);

        OperationReplyDto restored = await client.RestoreAsync(listed.Id, targetPath: null);
        Assert.True(restored.Succeeded, restored.Message);
        Assert.Equal(service.KnownBad, File.ReadAllBytes(bad));
        Assert.Empty((await client.ListQuarantineAsync()).Items);

        AuditReplyDto audit = await client.GetAuditAsync(10);
        Assert.True(audit.ChainValid);
        Assert.Equal(["restore", "quarantine"], audit.Records.Select(r => r.Action));
        Assert.Equal(WindowsIdentity.GetCurrent().Name, audit.Records[0].User);
    }

    [Fact]
    public async Task A_report_only_scan_changes_nothing()
    {
        await using RunningService service = await RunningService.StartAsync();
        using var files = new TempDirectory();
        string bad = files.File("bad.bin", service.KnownBad);
        await using ServiceClient client = await service.ConnectAsync();

        ScanReport report = await client.ScanAsync([files.Path], includeClean: false);

        Assert.Null(Assert.Single(report.Items).Action);
        Assert.True(File.Exists(bad));
        Assert.Empty((await client.ListQuarantineAsync()).Items);
    }

    [Fact]
    public async Task Manual_quarantine_and_delete_through_the_service()
    {
        await using RunningService service = await RunningService.StartAsync();
        using var files = new TempDirectory();
        string file = files.File("manual.txt", TestData.BenignBytes(4, 64));
        await using ServiceClient client = await service.ConnectAsync();

        OperationReplyDto added = await client.QuarantineFileAsync(file);
        OperationReplyDto missing = await client.QuarantineFileAsync(Path.Combine(files.Path, "nope.txt"));
        OperationReplyDto deleted = await client.DeleteQuarantinedAsync(added.QuarantineId!);
        OperationReplyDto again = await client.DeleteQuarantinedAsync(added.QuarantineId!);

        Assert.True(added.Succeeded, added.Message);
        Assert.False(File.Exists(file));
        Assert.Equal("notFound", missing.Code);
        Assert.True(deleted.Succeeded);
        Assert.False(again.Succeeded);
        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.QuarantineFileAsync(@"\\server\share\x.exe"));
        Assert.Equal(ErrorCodes.InvalidPath, ex.Code);
    }

    [Fact]
    public async Task Exclusions_are_persisted_and_reported_as_skipped()
    {
        await using RunningService service = await RunningService.StartAsync();
        using var files = new TempDirectory();
        string excludedDir = files.Dir("tools");
        string bad = files.File(@"tools\bad.bin", service.KnownBad);
        string other = files.File(@"other\bad-copy.bin", service.KnownBad);
        await using ServiceClient client = await service.ConnectAsync();

        ExclusionsReplyDto afterAdd = await client.ChangeExclusionAsync(add: true, excludedDir);
        ScanReport withPath = await client.ScanAsync([files.Path], includeClean: false);
        await client.ChangeExclusionAsync(add: true, "sha256:" + TestData.Sha256Hex(service.KnownBad));
        ScanReport withHash = await client.ScanAsync([files.Path], includeClean: false);
        ExclusionsReplyDto afterRemove = await client.ChangeExclusionAsync(add: false, excludedDir);

        Assert.Equal([excludedDir], afterAdd.Paths);
        Assert.Contains(withPath.Items, i => i.Path == excludedDir && i.Status == ScanStatus.Skipped && i.Reason == ScanReason.Excluded);
        Assert.Contains(withPath.Items, i => i.Path == other && i.Status == ScanStatus.Detected);
        Assert.DoesNotContain(withPath.Items, i => i.Path == bad);
        Assert.Contains(withHash.Items, i => i.Path == other && i.Reason == ScanReason.Excluded);
        Assert.Empty(afterRemove.Paths);
        Assert.Single(afterRemove.Sha256);
        Assert.True(File.Exists(Path.Combine(service.Temp.Path, "data", "config", "exclusions.json")));

        var tooBroad = await Assert.ThrowsAsync<ServiceException>(() => client.ChangeExclusionAsync(add: true, @"C:\"));
        Assert.Equal(ErrorCodes.BadRequest, tooBroad.Code);
        Assert.Equal(1, (await client.GetStatusAsync()).Exclusions);
    }

    [Fact]
    public async Task Management_requires_an_elevated_administrator_when_enforced()
    {
        await using RunningService service = await RunningService.StartAsync(requireAdministrator: true);
        using var files = new TempDirectory();
        string file = files.File("mine.txt", TestData.BenignBytes(5, 64));
        await using ServiceClient client = await service.ConnectAsync();
        OperationReplyDto added = await client.QuarantineFileAsync(file);
        Assert.True(added.Succeeded, "Quarantining your own file never needs administrator rights.");
        Assert.Single((await client.ListQuarantineAsync()).Items);

        if (IsElevatedAdmin)
        {
            Assert.True((await client.RestoreAsync(added.QuarantineId!, null)).Succeeded);
            Assert.True((await client.GetAuditAsync(5)).ChainValid);
            return;
        }

        var restore = await Assert.ThrowsAsync<ServiceException>(() => client.RestoreAsync(added.QuarantineId!, null));
        var exclusion = await Assert.ThrowsAsync<ServiceException>(() => client.ChangeExclusionAsync(add: true, files.Path));
        var audit = await Assert.ThrowsAsync<ServiceException>(() => client.GetAuditAsync(5));
        Assert.Equal(ErrorCodes.AccessDenied, restore.Code);
        Assert.Equal(ErrorCodes.AccessDenied, exclusion.Code);
        Assert.Equal(ErrorCodes.AccessDenied, audit.Code);
        Assert.False(File.Exists(file));

        // Refusals are audited.
        var records = service.Core.Quarantine.Audit.ReadRecent(10);
        Assert.Contains(records, r => r.Action == "restore" && r.Outcome == "denied");
        Assert.Contains(records, r => r.Action == "exclusionAdd" && r.Outcome == "denied");
    }

    [Fact]
    public async Task Unknown_scan_actions_are_rejected()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using ServiceClient client = await service.ConnectAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => RawScanAsync(service, "delete-everything"));
        Assert.Equal(ErrorCodes.BadRequest, ex.Code);
    }

    private static async Task RawScanAsync(RunningService service, string action)
    {
        using var pipe = new System.IO.Pipes.NamedPipeClientStream(".", service.PipeName, System.IO.Pipes.PipeDirection.InOut, System.IO.Pipes.PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(5000);
        await FrameIO.WriteAsync(pipe, MessageType.Hello, ProtocolJson.Serialize(new HelloDto { Protocol = ProtocolVersion.Service, Client = "raw" }));
        ProtocolJson.Expect<HelloReplyDto>(await FrameIO.ReadAsync(pipe, FrameLimits.Control), MessageType.HelloReply);
        await FrameIO.WriteAsync(pipe, MessageType.Scan, ProtocolJson.Serialize(new ScanRequestDto { Paths = [@"C:\Windows\win.ini"], IncludeClean = false, Action = action }));
        Frame? reply = await FrameIO.ReadAsync(pipe, FrameLimits.Control);
        ErrorDto error = ProtocolJson.Expect<ErrorDto>(reply, MessageType.Error);
        throw new ServiceException(error.Code, error.Message);
    }
}
