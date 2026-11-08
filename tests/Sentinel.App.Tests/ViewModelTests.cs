using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;

namespace Sentinel.App.Tests;

internal sealed class FakeGateway : IServiceGateway
{
    public List<QuarantineItemDto> Quarantine { get; } = [];

    public List<string> Exclusions { get; } = [];

    public List<string> Calls { get; } = [];

    public Exception? Failure { get; set; }

    public ScanReport? NextReport { get; set; }

    public bool LastScanQuarantine { get; private set; }

    public string EndpointDescription => "fake service";

    public Task<(HelloReplyDto Hello, StatusReplyDto Status)> GetStatusAsync(CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        return Task.FromResult((
            new HelloReplyDto { Protocol = 2, Service = "Sentinel 0.5.0", User = @"HOST\alice", IsAdmin = false },
            new StatusReplyDto
            {
                Version = "0.5.0",
                Mode = "service",
                StartedUtc = "2026-11-08T10:00:00Z",
                Engines = [new EngineInfoDto { Id = "hash", Version = "1.0.0", ContentVersion = "1-abc" }],
                Workers = new WorkerStatsDto { Configured = 2, Running = 2, Started = 2, Crashed = 0, TimedOut = 0 },
                Cache = new CacheStatsDto { Entries = 0, Hits = 0, Misses = 0 },
                Schedules = [new ScheduleStatusDto { Name = "nightly", NextRunUtc = "2026-11-09T03:00:00Z" }],
                ActiveScans = 0,
                QuarantineItems = Quarantine.Count,
                Exclusions = Exclusions.Count,
                AuditChainValid = true,
            }));
    }

    public Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        LastScanQuarantine = quarantine;
        Calls.Add("scan:" + string.Join("|", paths));
        return Task.FromResult(NextReport!);
    }

    public Task<QuarantineListReplyDto> ListQuarantineAsync(CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        return Task.FromResult(new QuarantineListReplyDto { Items = [.. Quarantine] });
    }

    public Task<OperationReplyDto> RestoreAsync(string id, string? targetPath, CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        Calls.Add($"restore:{id}:{targetPath}");
        QuarantineItemDto item = Quarantine.Single(q => q.Id == id);
        Quarantine.Remove(item);
        return Task.FromResult(new OperationReplyDto { Succeeded = true, Code = "none", QuarantineId = id, Path = targetPath ?? item.OriginalPath });
    }

    public Task<OperationReplyDto> DeleteQuarantinedAsync(string id, CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        Calls.Add("delete:" + id);
        Quarantine.RemoveAll(q => q.Id == id);
        return Task.FromResult(new OperationReplyDto { Succeeded = true, Code = "none", QuarantineId = id });
    }

    public Task<ExclusionsReplyDto> GetExclusionsAsync(CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        return Task.FromResult(new ExclusionsReplyDto { Paths = [.. Exclusions], Sha256 = [] });
    }

    public Task<ExclusionsReplyDto> ChangeExclusionAsync(bool add, string value, CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        if (add)
        {
            Exclusions.Add(value);
        }
        else
        {
            Exclusions.Remove(value);
        }

        return GetExclusionsAsync(cancellationToken);
    }

    public Task<AuditReplyDto> GetAuditAsync(int max, CancellationToken cancellationToken)
    {
        ThrowIfFailing();
        return Task.FromResult(new AuditReplyDto
        {
            Records = [new AuditRecordDto { Seq = 1, TimeUtc = "2026-11-08T10:00:00Z", User = "alice", Sid = "S-1", Action = "quarantine", Target = @"C:\x", Outcome = "succeeded" }],
            ChainValid = false,
            Problem = "Line 3 does not match its hash (modified).",
        });
    }

    private void ThrowIfFailing()
    {
        if (Failure is not null)
        {
            throw Failure;
        }
    }
}

internal sealed class FakeDialogs : IDialogs
{
    public bool Answer { get; set; } = true;

    public List<string> Folders { get; } = [];

    public string? RestoreLocation { get; set; }

    public int Confirmations { get; private set; }

    public IReadOnlyList<string> PickFolders() => Folders;

    public string? PickRestoreLocation(string suggestedFileName) => RestoreLocation;

    public bool Confirm(string title, string message)
    {
        Confirmations++;
        return Answer;
    }
}

internal sealed class FakeHost : IAppHost
{
    public bool IsElevated => false;

    public bool Restarted { get; private set; }

    public void RestartElevated() => Restarted = true;
}

public class ViewModelTests
{
    private static QuarantineItemDto Item(string id) => new()
    {
        Id = id,
        OriginalPath = @"C:\Users\alice\Downloads\bad.exe",
        Sha256 = new string('a', 64),
        SizeBytes = 10,
        QuarantinedUtc = "2026-11-08T10:00:00Z",
        User = @"HOST\alice",
        Detections = ["Test.Sample"],
        Origin = "scan",
    };

    [Fact]
    public async Task Dashboard_shows_status_and_reminds_about_defender()
    {
        var vm = new DashboardViewModel(new FakeGateway(), new FakeHost()) { AntivirusSource = () => AntivirusHealth.Poor };

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.True(vm.IsConnected);
        Assert.Contains("Sentinel 0.5.0 is running", vm.ServiceState, StringComparison.Ordinal);
        Assert.Contains("need an administrator", vm.ConnectedAs, StringComparison.Ordinal);
        Assert.True(vm.AntivirusNeedsAttention);
        Assert.Contains("Turn Microsoft Defender back on", vm.AntivirusText, StringComparison.Ordinal);
        Assert.Single(vm.Schedules);
        Assert.True(vm.CanRestartElevated);
    }

    [Fact]
    public async Task Dashboard_explains_an_unreachable_service_without_crashing()
    {
        var vm = new DashboardViewModel(new FakeGateway { Failure = new ServiceException("The Sentinel service is not reachable.") }, new FakeHost())
        {
            AntivirusSource = () => AntivirusHealth.Good,
        };

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.False(vm.IsConnected);
        Assert.True(vm.IsError);
        Assert.Contains("not reachable", vm.Message, StringComparison.Ordinal);
        Assert.Contains("fake service", vm.ServiceState, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_sends_targets_and_the_quarantine_choice_and_lists_findings_first()
    {
        var gateway = new FakeGateway
        {
            NextReport = new ScanReport
            {
                Targets = [@"C:\data"],
                StartedUtc = DateTimeOffset.UtcNow,
                FinishedUtc = DateTimeOffset.UtcNow,
                Engines = [],
                Summary = new ScanSummary { ItemsSeen = 3, FilesScanned = 2, Detected = 1, NotScanned = 1, Quarantined = 1 },
                Items =
                [
                    ScanItemResult.Fail(@"C:\data\locked.bin", ScanItemKind.File, ScanReason.Locked, "in use"),
                    new ScanItemResult
                    {
                        Path = @"C:\data\bad.bin",
                        Kind = ScanItemKind.File,
                        Status = ScanStatus.Detected,
                        Detections = [new Detection("hash", "Test.Bad", DetectionCategory.TestFile, DetectionConfidence.High)],
                        Action = ItemAction.Quarantined(new string('1', 32)),
                    },
                ],
            },
        };
        var vm = new ScanViewModel(gateway, new FakeDialogs());
        vm.AddTargets([@"C:\data", @"c:\DATA"]);
        vm.Quarantine = true;

        await vm.StartCommand.ExecuteAsync(null);

        Assert.Equal([@"C:\data"], vm.Targets);
        Assert.True(gateway.LastScanQuarantine);
        Assert.Equal("Detected", vm.Results[0].Status);
        Assert.Equal("Quarantined", vm.Results[0].Action);
        Assert.Equal("Not scanned", vm.Results[1].Status);
        Assert.Contains("1 quarantined", vm.Summary, StringComparison.Ordinal);
        Assert.False(vm.IsScanning);
    }

    [Fact]
    public void Quarantine_during_scan_is_off_by_default()
    {
        Assert.False(new ScanViewModel(new FakeGateway(), new FakeDialogs()).Quarantine);
    }

    [Fact]
    public async Task Restore_asks_for_confirmation_and_declining_changes_nothing()
    {
        var gateway = new FakeGateway();
        gateway.Quarantine.Add(Item("a1"));
        var dialogs = new FakeDialogs { Answer = false };
        var vm = new QuarantineViewModel(gateway, dialogs);
        await vm.RefreshCommand.ExecuteAsync(null);
        vm.Selected = vm.Items.Single();

        await vm.RestoreCommand.ExecuteAsync(null);
        Assert.Equal(1, dialogs.Confirmations);
        Assert.Empty(gateway.Calls);

        dialogs.Answer = true;
        dialogs.RestoreLocation = @"D:\safe\bad.exe";
        await vm.RestoreToCommand.ExecuteAsync(null);
        Assert.Equal([@"restore:a1:D:\safe\bad.exe"], gateway.Calls);
        Assert.Empty(vm.Items);
        Assert.Contains(@"D:\safe\bad.exe", vm.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Delete_is_confirmed_and_access_denied_is_explained()
    {
        var gateway = new FakeGateway();
        gateway.Quarantine.Add(Item("b2"));
        var vm = new QuarantineViewModel(gateway, new FakeDialogs());
        await vm.RefreshCommand.ExecuteAsync(null);
        vm.Selected = vm.Items.Single();

        await vm.DeleteCommand.ExecuteAsync(null);
        Assert.Equal(["delete:b2"], gateway.Calls);

        gateway.Quarantine.Add(Item("c3"));
        await vm.RefreshCommand.ExecuteAsync(null);
        vm.Selected = vm.Items.Single();
        gateway.Failure = new ServiceException(ErrorCodes.AccessDenied, "Restoring a quarantined file requires an elevated administrator.");
        await vm.RestoreCommand.ExecuteAsync(null);
        Assert.True(vm.IsError);
        Assert.Contains("Restart as administrator", vm.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Exclusions_are_confirmed_before_adding()
    {
        var gateway = new FakeGateway();
        var dialogs = new FakeDialogs();
        var vm = new ExclusionsViewModel(gateway, dialogs) { NewValue = @" C:\Tools\build " };

        await vm.AddValueCommand.ExecuteAsync(null);

        Assert.Equal([@"C:\Tools\build"], gateway.Exclusions);
        Assert.Equal(1, dialogs.Confirmations);
        Assert.Equal(string.Empty, vm.NewValue);
        vm.Selected = vm.Items.Single();
        await vm.RemoveCommand.ExecuteAsync(null);
        Assert.Empty(gateway.Exclusions);
    }

    [Fact]
    public async Task History_warns_when_the_audit_chain_is_broken()
    {
        var vm = new HistoryViewModel(new FakeGateway());

        await vm.RefreshCommand.ExecuteAsync(null);

        Assert.Single(vm.Records);
        Assert.Contains("FAILED", vm.ChainState, StringComparison.Ordinal);
    }

    [Fact]
    public void Navigation_refreshes_the_selected_page()
    {
        var gateway = new FakeGateway();
        gateway.Quarantine.Add(Item("d4"));
        var main = new MainViewModel(gateway, new FakeDialogs(), new FakeHost());

        main.Current = main.Quarantine;

        Assert.Single(main.Quarantine.Items);
        Assert.Equal(6, main.Pages.Count);
        Assert.Contains("prototype", main.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void About_states_the_prototype_status_honestly()
    {
        var about = new AboutViewModel(new FakeGateway());

        Assert.Contains("not a replacement for Microsoft Defender", about.Status, StringComparison.Ordinal);
        Assert.Contains("no real-time protection", about.Limitations, StringComparison.Ordinal);
    }
}
