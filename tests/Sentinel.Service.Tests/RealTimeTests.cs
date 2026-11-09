using System.Diagnostics;
using System.Management;
using System.Security.Principal;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Service.RealTime;
using Sentinel.Tests.Shared;

namespace Sentinel.Service.Tests;

public sealed class RealTimeTests : IDisposable
{
    private readonly TempDirectory _watched = new();

    public void Dispose() => _watched.Dispose();

    private ServiceSettings Settings(bool quarantine = false, bool processes = false, bool removable = false) => new()
    {
        RealTime = new RealTimeOptions
        {
            Enabled = true,
            Paths = [_watched.Path],
            Quarantine = quarantine,
            Processes = processes,
            RemovableMedia = removable,
            Debounce = TimeSpan.FromMilliseconds(200),
        },
    };

    private static async Task<DetectionRecord> WaitForDetectionAsync(RunningService service, string path)
    {
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < TimeSpan.FromSeconds(20))
        {
            if (service.Core.History.Recent(50).FirstOrDefault(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase)) is { } found)
            {
                return found;
            }

            await Task.Delay(100);
        }

        throw new TimeoutException($"No real-time detection for {path}.");
    }

    [Fact]
    public async Task A_file_written_into_a_watched_folder_is_scanned_and_reported()
    {
        await using RunningService service = await RunningService.StartAsync(Settings());
        await Task.Delay(300);
        string bad = _watched.File(@"downloads\new.bin", service.KnownBad);

        DetectionRecord record = await WaitForDetectionAsync(service, bad);

        Assert.StartsWith("real-time (file", record.Source, StringComparison.Ordinal);
        Assert.Equal("reported", record.Action);
        Assert.True(File.Exists(bad), "Report-only monitoring never changes files.");
        await using ServiceClient client = await service.ConnectAsync();
        StatusReplyDto status = await client.GetStatusAsync();
        Assert.True(status.RealTime.Enabled);
        Assert.Equal("off", status.RealTime.Processes);
        Assert.Contains((await client.GetDetectionsAsync(10)).Items, d => d.Path == bad);
    }

    [Fact]
    public async Task A_write_scans_only_the_written_file_not_its_whole_folder()
    {
        // Windows also reports the parent folder as changed; it must not be rescanned recursively.
        for (int i = 0; i < 40; i++)
        {
            _watched.File($@"busy\old{i}.bin", TestData.BenignBytes(i, 500));
        }

        await using RunningService service = await RunningService.StartAsync(Settings());
        await Task.Delay(300);
        string bad = _watched.File(@"busy\new.bin", service.KnownBad);

        await WaitForDetectionAsync(service, bad);
        await Task.Delay(1000); // let any (wrongly) queued folder scan run
        RealTimeStats stats = service.Core.RealTime!.Stats;

        Assert.Equal(0, stats.Queued);
        Assert.InRange(stats.Scanned, 1, 2); // the new file, possibly twice (created, then changed)
    }

    [Fact]
    public async Task A_long_folder_scan_does_not_hold_up_newly_written_files()
    {
        using var big = new TempDirectory();
        for (int i = 0; i < 4000; i++)
        {
            big.File($@"f{i / 100}\{i}.bin", TestData.BenignBytes(i, 64));
        }

        await using RunningService service = await RunningService.StartAsync(Settings());
        await Task.Delay(300);
        service.Core.RealTime!.Enqueue(big.Path, "file (moved in)", TimeSpan.Zero);
        await Task.Delay(500); // the folder scan is under way
        string bad = _watched.File("while-busy.bin", service.KnownBad);

        await WaitForDetectionAsync(service, bad);

        Assert.True(service.Core.RealTime.Stats.Scanned < 4000, "The new file was detected before the folder scan finished.");
    }

    [Fact]
    public async Task With_quarantine_enabled_a_high_confidence_detection_is_quarantined()
    {
        await using RunningService service = await RunningService.StartAsync(Settings(quarantine: true));
        await Task.Delay(300);
        string bad = _watched.File("dropped.bin", service.KnownBad);

        DetectionRecord record = await WaitForDetectionAsync(service, bad);

        Assert.StartsWith("quarantined", record.Action, StringComparison.Ordinal);
        Assert.False(File.Exists(bad));
        QuarantineEntryCheck(service, bad);
    }

    private static void QuarantineEntryCheck(RunningService service, string path)
    {
        var entry = Assert.Single(service.Core.Quarantine.List());
        Assert.Equal(path, entry.OriginalPath);
        Assert.Equal("real-time protection", entry.ActorName);
    }

    [Fact]
    public async Task A_newly_attached_removable_drive_is_scanned()
    {
        var drives = new List<string>();
        await using RunningService service = await RunningService.StartAsync(Settings(removable: true), removableDrives: () => [.. drives]);
        using var usb = new TempDirectory();
        string bad = usb.File(@"autorun\payload.bin", service.KnownBad);

        lock (drives)
        {
            drives.Add(usb.Path);
        }

        DetectionRecord record = await WaitForDetectionAsync(service, bad);
        Assert.Equal("real-time (removable)", record.Source);
    }

    [Fact]
    public async Task Started_programs_are_scanned_but_never_terminated()
    {
        var source = new FakeProcessSource();
        await using RunningService service = await RunningService.StartAsync(Settings(processes: true), processes: source);
        // Outside the watched folders, so only the process source can report it (the file watcher would
        // otherwise race it and record the detection as "real-time (file)").
        using var unwatched = new TempDirectory();
        string image = unwatched.File(@"apps\tool.exe", service.KnownBad);

        source.Raise(image);

        DetectionRecord record = await WaitForDetectionAsync(service, image);
        Assert.Contains("process", record.Source, StringComparison.Ordinal);
        Assert.True(source.IsListening);
    }

    [Fact]
    public async Task The_service_data_folder_is_never_monitored()
    {
        var settings = Settings();
        await using RunningService service = await RunningService.StartAsync(settings);
        string data = Path.Combine(service.Temp.Path, "data");
        service.Core.RealTime!.Enqueue(Path.Combine(data, "reports", "x.json"), "file");
        service.Core.RealTime.Enqueue(data, "file");

        Assert.Equal(0, service.Core.RealTime.Stats.Queued);
    }

    [Fact]
    public void Wmi_process_start_events_need_administrator_rights()
    {
        using var source = new WmiProcessStartSource();
        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        if (!admin)
        {
            // Only a genuine access refusal is acceptable here; any other error is a bug (for example a malformed query).
            var refused = Assert.Throws<ManagementException>(source.Start);
            Assert.Equal(ManagementStatus.AccessDenied, refused.ErrorCode);
            return;
        }

        string? seen = null;
        using var signal = new ManualResetEventSlim();
        source.Started += (path, _) =>
        {
            if (path.EndsWith("PING.EXE", StringComparison.OrdinalIgnoreCase))
            {
                seen = path;
                signal.Set();
            }
        };
        source.Start();
        using Process ping = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "PING.EXE"), "-n 3 127.0.0.1") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        Assert.True(signal.Wait(TimeSpan.FromSeconds(15)), "No process-start event arrived.");
        Assert.Equal(Path.Combine(Environment.SystemDirectory, "PING.EXE"), seen, ignoreCase: true);
        ping.WaitForExit();
    }

    [Fact]
    public void Real_time_settings_are_validated()
    {
        RealTimeOptions defaults = ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": {} }""").RealTime;
        Assert.True(defaults.Enabled);
        Assert.False(defaults.Quarantine);
        Assert.EndsWith(@"\Users", Assert.Single(defaults.Paths), StringComparison.OrdinalIgnoreCase);
        Assert.False(new ServiceSettings().RealTime.Enabled);

        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "paths": ["\\\\server\\share"] } }"""));
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "action": "delete" } }"""));
        Assert.Throws<FormatException>(() => ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "debounceSeconds": 600 } }"""));
        Assert.True(ServiceSettings.Parse("""{ "schemaVersion": 1, "realTime": { "action": "quarantine", "processes": false } }""").RealTime.Quarantine);
    }

    [Fact]
    public async Task Non_administrators_see_only_findings_under_their_own_profile()
    {
        await using RunningService service = await RunningService.StartAsync(requireAdministrator: true);
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        service.Core.History.Add(new DetectionRecord(DateTimeOffset.UtcNow, "scan", Path.Combine(profile, "Downloads", "a.exe"), ScanStatus.Detected, ["A"], "reported"));
        service.Core.History.Add(new DetectionRecord(DateTimeOffset.UtcNow, "scan", @"C:\Users\SomeoneElse\b.exe", ScanStatus.Detected, ["B"], "reported"));
        await using ServiceClient client = await service.ConnectAsync();

        DetectionsReplyDto reply = await client.GetDetectionsAsync(10);

        bool admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        Assert.Equal(admin ? 2 : 1, reply.Items.Count);
        Assert.Contains(reply.Items, d => d.Names.Contains("A"));
    }

    private sealed class FakeProcessSource : IProcessStartSource
    {
        public event Action<string, string?>? Started;

        public bool IsListening { get; private set; }

        public void Start() => IsListening = true;

        public void Raise(string path, string? commandLine = null) => Started?.Invoke(path, commandLine);

        public void Dispose()
        {
        }
    }
}
