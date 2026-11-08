using System.Collections.Concurrent;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Sentinel.Response;
using Sentinel.Scanning;

namespace Sentinel.Service.RealTime;

/// <summary>Real-time monitoring settings (service.json "realTime").</summary>
public sealed record RealTimeOptions
{
    public bool Enabled { get; init; }

    /// <summary>Folders watched for new and changed files (subfolders included).</summary>
    public IReadOnlyList<string> Paths { get; init; } = [];

    /// <summary>Quarantine high-confidence detections (default false: report only).</summary>
    public bool Quarantine { get; init; }

    /// <summary>Scan the image of every process that starts (needs the service's SYSTEM rights).</summary>
    public bool Processes { get; init; } = true;

    /// <summary>Scan removable drives when they are attached.</summary>
    public bool RemovableMedia { get; init; } = true;

    /// <summary>Quiet period after the last change before a file is scanned.</summary>
    public TimeSpan Debounce { get; init; } = TimeSpan.FromSeconds(2);
}

/// <summary>A finding recorded for the detections history.</summary>
public sealed record DetectionRecord(DateTimeOffset TimeUtc, string Source, string Path, ScanStatus Status, IReadOnlyList<string> Names, string Action);

/// <summary>Bounded in-memory history of recent findings (newest first).</summary>
public sealed class DetectionHistory(int capacity = 500)
{
    private readonly LinkedList<DetectionRecord> _items = new();
    private readonly Lock _gate = new();

    public void Add(DetectionRecord record)
    {
        lock (_gate)
        {
            _items.AddFirst(record);
            while (_items.Count > capacity)
            {
                _items.RemoveLast();
            }
        }
    }

    public IReadOnlyList<DetectionRecord> Recent(int max, Func<DetectionRecord, bool>? filter = null)
    {
        lock (_gate)
        {
            return [.. _items.Where(r => filter?.Invoke(r) ?? true).Take(max)];
        }
    }
}

/// <summary>Live counters for status.</summary>
public sealed record RealTimeStats(bool Enabled, IReadOnlyList<string> WatchedPaths, string Processes, string RemovableMedia, int Queued, long Scanned, long Findings, long Overflows);

/// <summary>Source of process-start notifications (image paths).</summary>
public interface IProcessStartSource : IDisposable
{
    event Action<string>? Started;

    /// <summary>Starts listening; throws if the platform refuses (for example without administrator rights).</summary>
    void Start();
}

/// <summary>
/// User-mode real-time monitoring. It reacts <em>after</em> the fact: new or changed files are scanned
/// shortly after they are written, process images shortly after they start, and removable drives when
/// they appear. It cannot block a file from being opened or a program from running (that needs a kernel
/// minifilter, an optional later phase). Scans run as the service, share its sandboxed worker pool and
/// verdict cache, honour exclusions, and never take a slot from user scans. Processes are never terminated.
/// </summary>
public sealed class RealTimeMonitor : IDisposable
{
    private const int MaxQueue = 10_000;
    private const int BatchSize = 64;
    private const int MaxAttempts = 5;
    private readonly ServiceCore _core;
    private readonly RealTimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _signal = new(0);
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly IProcessStartSource? _processes;
    private readonly Func<IEnumerable<string>> _removableDrives;
    private readonly string[] _ignoredRoots;
    private readonly HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);
    private string _processState = "off";
    private string _removableState = "off";
    private long _scanned;
    private long _findings;
    private long _overflows;

    public RealTimeMonitor(ServiceCore core, RealTimeOptions options, string serviceRoot, TimeProvider time, ILogger logger, IProcessStartSource? processes = null, Func<IEnumerable<string>>? removableDrives = null)
    {
        ArgumentNullException.ThrowIfNull(core);
        ArgumentNullException.ThrowIfNull(options);
        _core = core;
        _options = options;
        _time = time;
        _logger = logger;
        _processes = options.Processes ? processes ?? new WmiProcessStartSource() : null;
        _removableDrives = removableDrives ?? DefaultRemovableDrives;
        // The service's own data (quarantine vault, reports, audit) is never fed back into monitoring.
        _ignoredRoots = [Path.GetFullPath(serviceRoot).TrimEnd('\\')];
    }

    public RealTimeStats Stats => new(
        _options.Enabled,
        _options.Paths,
        _processState,
        _removableState,
        _pending.Count,
        Interlocked.Read(ref _scanned),
        Interlocked.Read(ref _findings),
        Interlocked.Read(ref _overflows));

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        StartWatchers();
        StartProcessMonitor();
        _removableState = _options.RemovableMedia ? "watching for removable drives" : "off";
        foreach (string drive in SafeDrives())
        {
            _knownDrives.Add(drive); // drives already present at start are covered by schedules, not rescanned
        }

        Task removable = _options.RemovableMedia ? PollRemovableAsync(cancellationToken) : Task.CompletedTask;
        try
        {
            await ProcessQueueAsync(cancellationToken);
        }
        finally
        {
            await removable.ContinueWith(_ => { }, TaskScheduler.Default);
        }
    }

    /// <summary>Queues a path (file or folder) for scanning after the debounce period.</summary>
    public void Enqueue(string path, string source, TimeSpan? delay = null)
    {
        if (string.IsNullOrEmpty(path) || IsIgnored(path))
        {
            return;
        }

        if (_pending.Count >= MaxQueue && !_pending.ContainsKey(path))
        {
            Interlocked.Increment(ref _overflows);
            return;
        }

        long due = _time.GetUtcNow().Add(delay ?? _options.Debounce).UtcTicks;
        _pending.AddOrUpdate(path, _ => new Pending(due, source, 0), (_, old) => old with { DueTicks = due });
        _signal.Release();
    }

    public void Dispose()
    {
        foreach (FileSystemWatcher watcher in _watchers)
        {
            watcher.Dispose();
        }

        _processes?.Dispose();
        _signal.Dispose();
    }

    private bool IsIgnored(string path)
    {
        string full = path.TrimEnd('\\');
        return _ignoredRoots.Any(root => full.Equals(root, StringComparison.OrdinalIgnoreCase) || full.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase));
    }

    private void StartWatchers()
    {
        foreach (string root in _options.Paths)
        {
            if (!Directory.Exists(root))
            {
                Log.RealTimeProblem(_logger, $"Real-time folder '{root}' does not exist; it is not watched.");
                continue;
            }

            var watcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
            };
            watcher.Created += (_, e) => Enqueue(e.FullPath, "file");
            watcher.Changed += (_, e) => Enqueue(e.FullPath, "file");
            watcher.Renamed += (_, e) => Enqueue(e.FullPath, "file");
            watcher.Error += (_, e) =>
            {
                // Events were lost (buffer overflow or the folder went away): rescan the whole root
                // instead of silently missing changes.
                Interlocked.Increment(ref _overflows);
                Log.RealTimeProblem(_logger, $"Change notifications for '{root}' were lost ({e.GetException().Message}); rescanning it.");
                Enqueue(root, "file (rescan after lost events)");
            };
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
    }

    private void StartProcessMonitor()
    {
        if (_processes is null)
        {
            return;
        }

        _processes.Started += path => Enqueue(path, "process", TimeSpan.Zero);
        try
        {
            _processes.Start();
            _processState = "scanning started programs";
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            _processState = $"unavailable: {ex.Message.Trim()}";
            Log.RealTimeProblem(_logger, $"Process-start monitoring is unavailable: {ex.Message.Trim()}");
        }
    }

    private async Task PollRemovableAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(3), _time);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            CheckRemovableDrives();
        }
    }

    /// <summary>Queues newly attached removable drives (exposed for tests).</summary>
    internal void CheckRemovableDrives()
    {
        var present = SafeDrives().ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (string drive in present.Where(d => _knownDrives.Add(d)))
        {
            Log.RemovableDrive(_logger, drive);
            Enqueue(drive, "removable", TimeSpan.Zero);
        }

        _knownDrives.RemoveWhere(d => !present.Contains(d));
    }

    private IEnumerable<string> SafeDrives()
    {
        try
        {
            return [.. _removableDrives()];
        }
        catch (IOException)
        {
            return [];
        }
    }

    private static IEnumerable<string> DefaultRemovableDrives() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Removable && d.IsReady).Select(d => d.RootDirectory.FullName);

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await _signal.WaitAsync(TimeSpan.FromMilliseconds(250), cancellationToken);
            long now = _time.GetUtcNow().UtcTicks;
            var due = _pending.Where(p => p.Value.DueTicks <= now).Take(BatchSize).ToList();
            if (due.Count == 0)
            {
                continue;
            }

            foreach (var item in due)
            {
                _pending.TryRemove(item.Key, out _);
            }

            await ScanBatchAsync(due, cancellationToken);
        }
    }

    private async Task ScanBatchAsync(List<KeyValuePair<string, Pending>> batch, CancellationToken cancellationToken)
    {
        IItemResponder? responder = _options.Quarantine ? new QuarantineResponder(_core.Quarantine, Actor.System("real-time protection")) : null;
        ScanReport report;
        try
        {
            report = await _core.Coordinator.ScanBackgroundAsync([.. batch.Select(b => b.Key)], responder, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            Log.RealTimeProblem(_logger, $"Real-time scan failed: {ex.Message}");
            return;
        }

        Interlocked.Add(ref _scanned, report.Summary.FilesScanned);
        var sources = batch.ToDictionary(b => b.Key, b => b.Value, StringComparer.OrdinalIgnoreCase);
        foreach (ScanItemResult item in report.Items)
        {
            if (item.Status == ScanStatus.NotScanned && item.Reason == ScanReason.Locked && sources.TryGetValue(item.Path, out Pending? pending) && pending.Attempts < MaxAttempts)
            {
                // Still being written by someone: try again later with backoff.
                TimeSpan delay = TimeSpan.FromSeconds(2 << pending.Attempts);
                _pending.TryAdd(item.Path, pending with { DueTicks = _time.GetUtcNow().Add(delay).UtcTicks, Attempts = pending.Attempts + 1 });
            }
        }

        string source = string.Join(", ", batch.Select(b => b.Value.Source).Distinct(StringComparer.Ordinal));
        Interlocked.Add(ref _findings, report.Summary.Detected + report.Summary.Suspicious);
        _core.RecordDetections(report, "real-time protection", $"real-time ({source})");
    }

    private sealed record Pending(long DueTicks, string Source, int Attempts);
}

/// <summary>
/// Process-start notifications from WMI <c>Win32_ProcessStartTrace</c> (backed by kernel process events;
/// requires administrator or SYSTEM). The image path is resolved from the process id; a process that
/// exits before it can be opened is missed.
/// </summary>
public sealed partial class WmiProcessStartSource : IProcessStartSource
{
    private ManagementEventWatcher? _watcher;

    public event Action<string>? Started;

    public void Start()
    {
        _watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID FROM Win32_ProcessStartTrace"));
        _watcher.EventArrived += (_, e) =>
        {
            if (e.NewEvent["ProcessID"] is uint pid && ImagePath(pid) is string path)
            {
                Started?.Invoke(path);
            }
        };
        _watcher.Start();
    }

    public void Dispose()
    {
        _watcher?.Stop();
        _watcher?.Dispose();
    }

    internal static unsafe string? ImagePath(uint pid)
    {
        IntPtr process = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new char[32768];
            int size = buffer.Length;
            fixed (char* name = buffer)
            {
                return QueryFullProcessImageNameW(process, 0, name, ref size) ? new string(buffer, 0, size) : null;
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* name, ref int size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}
