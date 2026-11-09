using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Kshatriya.Core;
using Kshatriya.Response;
using Kshatriya.Scanning;

namespace Kshatriya.Service.RealTime;

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

    /// <summary>Ransomware behaviour detection on top of the file and process events.</summary>
    public BehaviourOptions Behaviour { get; init; } = new();
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
public sealed record RealTimeStats(bool Enabled, IReadOnlyList<string> WatchedPaths, string Processes, string RemovableMedia, int Queued, long Scanned, long Findings, long Overflows, string Behaviour, long BehaviourAlerts);

/// <summary>Source of process-start notifications (image paths).</summary>
public interface IProcessStartSource : IDisposable
{
    /// <summary>Raised with the image path and, when it could be read, the command line.</summary>
    event Action<string, string?>? Started;

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
    private const int MaxRecovered = 5_000;
    private readonly ConcurrentQueue<(string Root, string Message)> _lost = new();
    private readonly Dictionary<string, RootJournal> _journals = new(StringComparer.OrdinalIgnoreCase);
    private long _lastCheckpoint = Environment.TickCount64;
    private readonly ServiceCore _core;
    private readonly RealTimeOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, Pending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _signal = new(0);
    private volatile bool _disposed;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly IProcessStartSource? _processes;
    private readonly Func<IEnumerable<string>> _removableDrives;
    private readonly string[] _ignoredRoots;
    private readonly HashSet<string> _knownDrives = new(StringComparer.OrdinalIgnoreCase);
    private readonly RansomwareDetector? _behaviour;
    private long _behaviourAlerts;
    private long _lastCanaryCheck;
    private string _processState = "off";
    private string _removableState = "off";
    private Task _folderScan = Task.CompletedTask;
    private long _folderScanStarted;
    private long _folderScanProgress;
    private bool _folderScanReported;
    private string _folderScanDescription = "";
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
        _behaviour = options.Behaviour.Enabled ? new RansomwareDetector(options.Behaviour, time) : null;
    }

    /// <summary>The behaviour detector, when enabled (tests feed it directly).</summary>
    internal RansomwareDetector? Behaviour => _behaviour;

    public RealTimeStats Stats => new(
        _options.Enabled,
        _options.Paths,
        _processState,
        _removableState,
        _pending.Count,
        Interlocked.Read(ref _scanned),
        Interlocked.Read(ref _findings),
        Interlocked.Read(ref _overflows),
        _behaviour is null ? "off" : _options.Behaviour.CanaryFolders.Count > 0 ? $"watching for mass changes, ransom notes, recovery tampering; {_options.Behaviour.CanaryFolders.Count} decoy folder(s)" : "watching for mass changes, ransom notes, recovery tampering",
        Interlocked.Read(ref _behaviourAlerts));

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        StartWatchers();
        StartProcessMonitor();
        if (_behaviour is not null)
        {
            foreach (string folder in _behaviour.EnsureCanaries())
            {
                Log.RealTimeProblem(_logger, $"Could not place a decoy file in '{folder}'.");
            }
        }

        _removableState = _options.RemovableMedia ? "watching for external drives (USB, memory cards)" : "off";
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
            await _folderScan.ContinueWith(_ => { }, TaskScheduler.Default);
        }
    }

    /// <summary>Queues a path (file or folder) for scanning after the debounce period.</summary>
    public void Enqueue(string path, string source, TimeSpan? delay = null)
    {
        if (_disposed || string.IsNullOrEmpty(path) || IsIgnored(path))
        {
            return;
        }

        if (_pending.Count >= MaxQueue && !_pending.ContainsKey(path))
        {
            Interlocked.Increment(ref _overflows);
            return;
        }

        long due = _time.GetUtcNow().Add(delay ?? _options.Debounce).UtcTicks;
        _pending.AddOrUpdate(path, _ => new Pending(due, source, 0, IsDirectory(path)), (_, old) => old with { DueTicks = due });
        Wake();
    }

    /// <summary>
    /// Wakes the queue. File-system callbacks already in flight can still arrive after <see cref="Dispose"/>;
    /// they must not throw on a thread-pool thread, which would end the service process.
    /// </summary>
    private void Wake()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            _signal.Release();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    public void Dispose()
    {
        _disposed = true;
        foreach (FileSystemWatcher watcher in _watchers)
        {
            watcher.Dispose();
        }

        foreach (RootJournal state in _journals.Values)
        {
            state.Journal?.Dispose();
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
            watcher.Created += (_, e) =>
            {
                _behaviour?.OnFileEvent(e.FullPath, FileEventKind.Created);
                Enqueue(e.FullPath, "file");
            };
            watcher.Changed += (_, e) =>
            {
                // A folder's last-write time changes whenever an entry inside it changes; the entry has
                // its own event. Queuing the folder would rescan it recursively on every write.
                if (IsDirectory(e.FullPath))
                {
                    return;
                }

                _behaviour?.OnFileEvent(e.FullPath, FileEventKind.Changed);
                Enqueue(e.FullPath, "file");
            };
            watcher.Renamed += (_, e) =>
            {
                _behaviour?.OnFileEvent(e.FullPath, FileEventKind.Renamed, e.OldFullPath);
                Enqueue(e.FullPath, "file");
            };
            watcher.Deleted += (_, e) => _behaviour?.OnFileEvent(e.FullPath, FileEventKind.Deleted);
            // Events were lost (buffer overflow or the folder went away): never silently miss changes.
            watcher.Error += (_, e) => OnLostEvents(root, e.GetException().Message);
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);

            UsnJournal? journal = UsnJournal.TryOpen(root, out string unavailable);
            var state = new RootJournal(journal, unavailable);
            if (journal?.Current(out unavailable) is UsnCheckpoint start)
            {
                state.Older = state.Newer = start;
            }
            else
            {
                state.Unavailable = unavailable;
            }

            _journals[root] = state;
        }
    }

    /// <summary>Records that change notifications for <paramref name="root"/> were lost (tests call it directly).</summary>
    internal void OnLostEvents(string root, string message)
    {
        Interlocked.Increment(ref _overflows);
        _lost.Enqueue((root, message));
        Wake();
    }

    /// <summary>
    /// Finds what changed while notifications were lost. With the NTFS change journal, only the paths
    /// changed since a checkpoint 30-60 seconds before the loss are queued; without it (not
    /// administrator, not NTFS, entries overwritten, too many changes) the whole root is rescanned.
    /// </summary>
    private void RecoverLostEvents()
    {
        var handled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (_lost.TryDequeue(out (string Root, string Message) lost))
        {
            if (!handled.Add(lost.Root))
            {
                continue;
            }

            _journals.TryGetValue(lost.Root, out RootJournal? state);
            string why = state?.Unavailable ?? "no change journal";
            if (state?.Journal is { } journal && state.Older is UsnCheckpoint from
                && journal.ChangedSince(from, MaxRecovered, out why) is { } changed)
            {
                string prefix = lost.Root.TrimEnd('\\') + "\\";
                int queued = 0;
                foreach (string path in changed.Where(p => p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    Enqueue(path, "file (recovered from change journal)");
                    queued++;
                }

                Log.RealTimeProblem(_logger, $"Change notifications for '{lost.Root}' were lost ({lost.Message}); {queued} changed path(s) recovered from the NTFS change journal and queued.");
                continue;
            }

            Log.RealTimeProblem(_logger, $"Change notifications for '{lost.Root}' were lost ({lost.Message}); rescanning it in full ({why}).");
            Enqueue(lost.Root, "file (rescan after lost events)");
        }
    }

    /// <summary>Rotates journal checkpoints every 30 s, so recovery always starts at least 30 s before a loss.</summary>
    private void RefreshCheckpoints()
    {
        long now = Environment.TickCount64;
        if (now - _lastCheckpoint < 30_000)
        {
            return;
        }

        _lastCheckpoint = now;
        foreach (RootJournal state in _journals.Values)
        {
            if (state.Journal?.Current(out _) is UsnCheckpoint current)
            {
                state.Older = state.Newer;
                state.Newer = current;
            }
        }
    }

    private static bool IsDirectory(string path)
    {
        try
        {
            // Reads attributes only: never follows the reparse point or recalls a cloud placeholder.
            return (File.GetAttributes(path) & FileAttributes.Directory) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false; // gone or unreadable: let the scan report it
        }
    }

    private void StartProcessMonitor()
    {
        if (_processes is null)
        {
            return;
        }

        _processes.Started += (path, commandLine) =>
        {
            _behaviour?.OnProcessStart(path, commandLine);
            Enqueue(path, "process", TimeSpan.Zero);
        };
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

    /// <summary>
    /// External drives: removable media and disks attached over USB, SD/MMC or FireWire (USB hard disks and
    /// SSDs report themselves as fixed drives, so the bus type decides).
    /// </summary>
    private static IEnumerable<string> DefaultRemovableDrives() => Kshatriya.Scanning.Targets.Drives.ExternalRoots();

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await _signal.WaitAsync(TimeSpan.FromMilliseconds(250), cancellationToken);
            RecoverLostEvents();
            RefreshCheckpoints();
            CollectBehaviour();
            long now = _time.GetUtcNow().UtcTicks;
            StartFolderScan(now, cancellationToken);
            var due = _pending.Where(p => p.Value.DueTicks <= now && !p.Value.Folder).Take(BatchSize).ToList();
            if (due.Count == 0)
            {
                continue;
            }

            foreach (var item in due)
            {
                _pending.TryRemove(item.Key, out _);
            }

            await ScanBatchAsync(due, folders: false, cancellationToken);
        }
    }

    /// <summary>
    /// Whole folders (created or moved in, removable drives, rescans after lost events) are scanned in
    /// their own lane, one batch at a time, so newly written files and started programs are never stuck
    /// behind them. A folder scan that runs for over a minute is logged with its folders and progress.
    /// </summary>
    private void StartFolderScan(long now, CancellationToken cancellationToken)
    {
        if (!_folderScan.IsCompleted)
        {
            TimeSpan running = Stopwatch.GetElapsedTime(_folderScanStarted);
            if (!_folderScanReported && running > TimeSpan.FromMinutes(1))
            {
                _folderScanReported = true;
                Log.RealTimeLongFolderScan(_logger, _folderScanDescription, running.TotalSeconds, Interlocked.Read(ref _folderScanProgress));
            }

            return;
        }

        var folders = _pending.Where(p => p.Value.DueTicks <= now && p.Value.Folder).Take(8).ToList();
        if (folders.Count == 0)
        {
            return;
        }

        foreach (var item in folders)
        {
            _pending.TryRemove(item.Key, out _);
        }

        _folderScanDescription = string.Join("; ", folders.Select(f => $"{f.Key} ({f.Value.Source})"));
        _folderScanStarted = Stopwatch.GetTimestamp();
        _folderScanReported = false;
        Interlocked.Exchange(ref _folderScanProgress, 0);
        _folderScan = ScanBatchAsync(folders, folders: true, cancellationToken).ContinueWith(
            t => Log.RealTimeProblem(_logger, $"Real-time folder scan failed: {t.Exception!.GetBaseException().Message}"),
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    private void CollectBehaviour()
    {
        if (_behaviour is null)
        {
            return;
        }

        IReadOnlyList<BehaviourAlert> alerts = _behaviour.Collect();
        foreach (BehaviourAlert alert in alerts)
        {
            Interlocked.Increment(ref _behaviourAlerts);
            _core.RecordBehaviour(alert);
        }

        // Decoys are restored whenever they go missing, independent of alert cooldowns.
        long now = Environment.TickCount64;
        if (alerts.Any(a => a.Name == RansomwareDetector.CanaryTouched) || now - _lastCanaryCheck > 5000)
        {
            _lastCanaryCheck = now;
            _behaviour.EnsureCanaries();
        }
    }

    private async Task ScanBatchAsync(List<KeyValuePair<string, Pending>> batch, bool folders, CancellationToken cancellationToken)
    {
        IItemResponder? responder = _options.Quarantine ? new QuarantineResponder(_core.Quarantine, Actor.System("real-time protection")) : null;
        ScanReport report;
        long started = Stopwatch.GetTimestamp();
        long reported = 0;
        // Counts items as they finish so status shows progress during long folder scans; corrected to the
        // exact number of scanned files when the batch completes.
        var progress = new CallbackProgress(() =>
        {
            Interlocked.Increment(ref reported);
            Interlocked.Increment(ref _scanned);
            if (folders)
            {
                Interlocked.Increment(ref _folderScanProgress);
            }
        });
        try
        {
            report = await _core.Coordinator.ScanBackgroundAsync([.. batch.Select(b => b.Key)], responder, cancellationToken, folders, progress);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            Log.RealTimeProblem(_logger, $"Real-time scan failed: {ex.Message}");
            return;
        }
        catch (OperationCanceledException) when (folders && cancellationToken.IsCancellationRequested)
        {
            return; // service stopping
        }

        TimeSpan took = Stopwatch.GetElapsedTime(started);
        if (!folders && took > TimeSpan.FromSeconds(10))
        {
            Log.RealTimeSlowBatch(_logger, took.TotalSeconds, report.Summary.FilesScanned, batch.Count);
        }

        Interlocked.Add(ref _scanned, report.Summary.FilesScanned - Interlocked.Read(ref reported));
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

    private sealed record Pending(long DueTicks, string Source, int Attempts, bool Folder);

    private sealed class RootJournal(UsnJournal? journal, string unavailable)
    {
        public UsnJournal? Journal { get; } = journal;

        public string Unavailable { get; set; } = unavailable;

        public UsnCheckpoint? Older { get; set; }

        public UsnCheckpoint? Newer { get; set; }
    }

    /// <summary>Synchronous progress (unlike <see cref="Progress{T}"/>, which posts to a context).</summary>
    private sealed class CallbackProgress(Action onItem) : IProgress<ScanProgress>
    {
        public void Report(ScanProgress value) => onItem();
    }
}

/// <summary>
/// Process-start notifications from WMI <c>Win32_ProcessStartTrace</c> (backed by kernel process events;
/// requires administrator or SYSTEM). The image path is resolved from the process id; a process that
/// exits before it can be opened is missed.
/// </summary>
public sealed partial class WmiProcessStartSource : IProcessStartSource
{
    private ManagementEventWatcher? _watcher;

    public event Action<string, string?>? Started;

    public void Start()
    {
        _watcher = new ManagementEventWatcher(new EventQuery("SELECT ProcessID FROM Win32_ProcessStartTrace"));
        _watcher.EventArrived += (_, e) =>
        {
            if (e.NewEvent["ProcessID"] is uint pid && ImagePath(pid) is string path)
            {
                Started?.Invoke(path, CommandLine(pid));
            }
        };
        _watcher.Start();
    }

    public void Dispose()
    {
        _watcher?.Stop();
        _watcher?.Dispose();
    }

    internal static string? CommandLine(uint pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using ManagementObjectCollection results = searcher.Get();
            return results.Cast<ManagementBaseObject>().Select(o => o["CommandLine"] as string).FirstOrDefault();
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            return null;
        }
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
