using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Scanning.Archives;
using Sentinel.Scanning.Trust;

namespace Sentinel.Scanning;

/// <summary>Options for a scan run.</summary>
public sealed record ScanOptions
{
    public ScanLimits Limits { get; init; } = new();

    /// <summary>When false (default) clean items are counted but not listed in the report.</summary>
    public bool IncludeCleanItems { get; init; }

    /// <summary>Optional code-signing check for executables. Null disables trust evaluation.</summary>
    public ITrustProvider? TrustProvider { get; init; }
}

/// <summary>Live progress counters.</summary>
public readonly record struct ScanProgress(long ItemsCompleted, long Detected, long BytesScanned, string? CurrentPath);

/// <summary>
/// Read-only scan pipeline: enumerate → open safely → hash → trust check → engines → archive expansion → report.
/// It never modifies, moves or deletes any file; responding to detections is a separate, later component.
/// </summary>
public sealed class ScanRunner
{
    private const int BufferSize = 128 * 1024;

    private readonly IReadOnlyList<IDetectionEngine> _engines;
    private readonly ScanOptions _options;

    public ScanRunner(IReadOnlyList<IDetectionEngine> engines, ScanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(engines);
        if (engines.Count == 0)
        {
            throw new ArgumentException("At least one engine is required.", nameof(engines));
        }

        _engines = engines;
        _options = options ?? new ScanOptions();
        if (_options.Limits.MaxDegreeOfParallelism < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxDegreeOfParallelism must be at least 1.");
        }
    }

    public async Task<ScanReport> ScanPathsAsync(
        IReadOnlyList<string> targets,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        DateTimeOffset started = DateTimeOffset.UtcNow;
        var results = new ConcurrentBag<ScanItemResult>();
        long completed = 0, detected = 0, bytes = 0;

        var channel = Channel.CreateBounded<WalkEntry>(new BoundedChannelOptions(1024)
        {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });

        Task producer = Task.Run(
            async () =>
            {
                try
                {
                    foreach (string target in targets)
                    {
                        foreach (WalkEntry entry in SafeFileEnumerator.Walk(target, cancellationToken))
                        {
                            await channel.Writer.WriteAsync(entry, cancellationToken);
                        }
                    }

                    channel.Writer.Complete();
                }
                catch (Exception ex)
                {
                    channel.Writer.Complete(ex);
                }
            },
            cancellationToken);

        var parallel = new ParallelOptions
        {
            MaxDegreeOfParallelism = _options.Limits.MaxDegreeOfParallelism,
            CancellationToken = cancellationToken,
        };

        await Parallel.ForEachAsync(channel.Reader.ReadAllAsync(cancellationToken), parallel, async (entry, ct) =>
        {
            ScanItemResult result = entry.Result ?? await ScanFileAsync(entry.Path, entry.Length, ct);
            results.Add(result);

            if (result.Status is ScanStatus.Detected or ScanStatus.Suspicious)
            {
                Interlocked.Increment(ref detected);
            }

            if (result.Sha256 is not null && result.SizeBytes is long size)
            {
                Interlocked.Add(ref bytes, size);
            }

            long done = Interlocked.Increment(ref completed);
            progress?.Report(new ScanProgress(done, Interlocked.Read(ref detected), Interlocked.Read(ref bytes), result.Path));
        });

        await producer;
        return BuildReport(targets, started, results);
    }

    /// <summary>Scans an in-memory or piped stream (for example standard input). The stream is buffered up to the size limit.</summary>
    public async Task<ScanItemResult> ScanStreamAsync(Stream input, string displayName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrEmpty(displayName);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Limits.PerItemTimeout);

        using var buffer = new MemoryStream();
        var collector = new ItemCollector();
        try
        {
            byte[] chunk = ArrayPool<byte>.Shared.Rent(BufferSize);
            try
            {
                int read;
                while ((read = await input.ReadAsync(chunk.AsMemory(0, BufferSize), timeout.Token)) > 0)
                {
                    if (buffer.Length + read > _options.Limits.MaxFileSizeBytes)
                    {
                        return ScanItemResult.Fail(displayName, ScanItemKind.Stream, ScanReason.TooLarge, "Stream exceeds the maximum scan size.");
                    }

                    buffer.Write(chunk, 0, read);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(chunk);
            }

            buffer.Position = 0;
            string sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(buffer, timeout.Token));
            buffer.Position = 0;
            var subject = new ScanSubject(displayName, buffer.Length, sha256, buffer);
            collector.Size = buffer.Length;
            collector.Sha256 = sha256;
            await AnalyzeAsync(subject, depth: 0, new ArchiveBudget(_options.Limits.Archives), collector, timeout.Token);
            return collector.ToResult(displayName, ScanItemKind.Stream);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            collector.SetFailure(ScanReason.Timeout, "Per-item time limit exceeded.");
            return collector.ToResult(displayName, ScanItemKind.Stream);
        }
    }

    private async Task<ScanItemResult> ScanFileAsync(string path, long enumeratedLength, CancellationToken cancellationToken)
    {
        long maxSize = _options.Limits.MaxFileSizeBytes;
        if (enumeratedLength > maxSize)
        {
            return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.TooLarge, $"File is larger than the {maxSize}-byte limit.", enumeratedLength);
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Limits.PerItemTimeout);

        OpenResult open = SafeFileOpener.Open(path);
        if (!open.Success)
        {
            return open.FailureReason is ScanReason.ReparsePoint or ScanReason.CloudPlaceholder
                ? ScanItemResult.Skip(path, ScanItemKind.File, open.FailureReason, open.Message)
                : ScanItemResult.Fail(path, ScanItemKind.File, open.FailureReason, open.Message, enumeratedLength);
        }

        var collector = new ItemCollector { Size = enumeratedLength };
        using SafeFileHandle handle = open.Handle!;
        try
        {
            await using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
            long length = stream.Length;
            collector.Size = length;
            if (length > maxSize)
            {
                return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.TooLarge, $"File is larger than the {maxSize}-byte limit.", length);
            }

            string sha256 = await HashAsync(stream, timeout.Token);
            collector.Sha256 = sha256;
            stream.Position = 0;

            FileTrust? trust = EvaluateTrust(handle, stream, path);
            collector.Trust = trust;
            stream.Position = 0;

            var subject = new ScanSubject(path, length, sha256, stream, trust);
            await AnalyzeAsync(subject, depth: 0, new ArchiveBudget(_options.Limits.Archives), collector, timeout.Token);
            return collector.ToResult(path, ScanItemKind.File);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            collector.SetFailure(ScanReason.Timeout, "Per-item time limit exceeded.");
            return collector.ToResult(path, ScanItemKind.File);
        }
        catch (UnauthorizedAccessException ex)
        {
            collector.SetFailure(ScanReason.AccessDenied, ex.Message);
            return collector.ToResult(path, ScanItemKind.File);
        }
        catch (IOException ex)
        {
            ScanReason reason = ex.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021) ? ScanReason.Locked : ScanReason.IoError;
            collector.SetFailure(reason, ex.Message);
            return collector.ToResult(path, ScanItemKind.File);
        }
    }

    /// <summary>Runs every engine on the subject, then recurses into archive entries within the shared budget.</summary>
    private async Task AnalyzeAsync(ScanSubject subject, int depth, ArchiveBudget budget, ItemCollector collector, CancellationToken cancellationToken)
    {
        foreach (IDetectionEngine engine in _engines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            subject.Content.Position = 0;
            try
            {
                IReadOnlyList<Detection> found = await engine.ScanAsync(subject, cancellationToken);
                foreach (Detection d in found)
                {
                    collector.Add(subject.Location is null ? d : d with { Location = subject.Location });
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (EngineTimeoutException ex)
            {
                collector.SetFailure(ScanReason.Timeout, $"Engine '{engine.Descriptor.Id}' timed out{At(subject)}: {ex.Message}");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A faulty engine must not take down the scan; the item is reported as incomplete.
                collector.SetFailure(ScanReason.EngineError, $"Engine '{engine.Descriptor.Id}' failed{At(subject)}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        if (depth >= budget.Limits.MaxDepth || !ZipExpander.LooksLikeZip(subject.Content))
        {
            return;
        }

        (ScanReason reason, string? message) = await ZipExpander.ExpandAsync(
            subject.Content,
            subject.Location,
            budget,
            entry => AnalyzeAsync(
                new ScanSubject(subject.DisplayPath, entry.Content.Length, entry.Sha256, entry.Content, trust: null, entry.Location),
                depth + 1,
                budget,
                collector,
                cancellationToken),
            cancellationToken);

        if (reason != ScanReason.None)
        {
            collector.SetFailure(reason, message);
        }

        subject.Content.Position = 0;
    }

    private FileTrust? EvaluateTrust(SafeFileHandle handle, Stream stream, string path)
    {
        if (_options.TrustProvider is null || !LooksLikePortableExecutable(stream))
        {
            return null;
        }

        try
        {
            return _options.TrustProvider.Evaluate(handle, path);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Trust is an input to heuristics only; failing to evaluate it must never hide the file.
            return null;
        }
    }

    private static bool LooksLikePortableExecutable(Stream stream)
    {
        if (stream.Length < 64)
        {
            return false;
        }

        Span<byte> magic = stackalloc byte[2];
        stream.Position = 0;
        int read = stream.ReadAtLeast(magic, 2, throwOnEndOfStream: false);
        stream.Position = 0;
        return read == 2 && magic[0] == (byte)'M' && magic[1] == (byte)'Z';
    }

    private static string At(ScanSubject subject) => subject.Location is null ? string.Empty : $" on '{subject.Location}'";

    private static async Task<string> HashAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken)) > 0)
            {
                hash.AppendData(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private ScanReport BuildReport(IReadOnlyList<string> targets, DateTimeOffset started, IEnumerable<ScanItemResult> results)
    {
        long seen = 0, scanned = 0, detected = 0, suspicious = 0, skipped = 0, notScanned = 0, partial = 0, bytes = 0;
        var listed = new List<ScanItemResult>();
        foreach (ScanItemResult r in results)
        {
            seen++;
            switch (r.Status)
            {
                case ScanStatus.Clean:
                    scanned++;
                    break;
                case ScanStatus.Detected:
                    scanned++;
                    detected++;
                    break;
                case ScanStatus.Suspicious:
                    scanned++;
                    suspicious++;
                    break;
                case ScanStatus.Skipped:
                    skipped++;
                    break;
                case ScanStatus.NotScanned:
                    notScanned++;
                    break;
            }

            if (r.Status is ScanStatus.Detected or ScanStatus.Suspicious && r.Reason != ScanReason.None)
            {
                partial++;
            }

            if (r.Status is ScanStatus.Clean or ScanStatus.Detected or ScanStatus.Suspicious)
            {
                bytes += r.SizeBytes ?? 0;
            }

            if (r.Status != ScanStatus.Clean || _options.IncludeCleanItems)
            {
                listed.Add(r);
            }
        }

        listed.Sort(static (a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Path, b.Path));

        return new ScanReport
        {
            Targets = targets.Select(Path.GetFullPath).ToArray(),
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            Engines = _engines.Select(e => e.Descriptor.ToInfo()).ToArray(),
            Summary = new ScanSummary
            {
                ItemsSeen = seen,
                FilesScanned = scanned,
                Detected = detected,
                Suspicious = suspicious,
                Skipped = skipped,
                NotScanned = notScanned,
                Partial = partial,
                BytesScanned = bytes,
            },
            Items = listed,
            CleanItemsIncluded = _options.IncludeCleanItems,
        };
    }

    /// <summary>
    /// Accumulates findings for one top-level item so that detections found before a timeout or
    /// archive limit are still reported, together with the reason the scan was incomplete.
    /// </summary>
    private sealed class ItemCollector
    {
        private readonly List<Detection> _detections = [];
        private readonly Lock _gate = new();

        public long? Size { get; set; }

        public string? Sha256 { get; set; }

        public FileTrust? Trust { get; set; }

        public ScanReason Reason { get; private set; }

        public string? Message { get; private set; }

        public void Add(Detection detection)
        {
            lock (_gate)
            {
                _detections.Add(detection);
            }
        }

        /// <summary>Records why the item is incomplete. A timeout overrides other reasons; otherwise the first reason wins.</summary>
        public void SetFailure(ScanReason reason, string? message)
        {
            lock (_gate)
            {
                if (Reason == ScanReason.None || (reason == ScanReason.Timeout && Reason != ScanReason.Timeout))
                {
                    Reason = reason;
                    Message = message;
                }
            }
        }

        public ScanItemResult ToResult(string path, ScanItemKind kind)
        {
            lock (_gate)
            {
                bool confirmed = _detections.Exists(d => d.Category != DetectionCategory.Suspicious);
                ScanStatus status = confirmed ? ScanStatus.Detected
                    : _detections.Count > 0 ? ScanStatus.Suspicious
                    : Reason != ScanReason.None ? ScanStatus.NotScanned
                    : ScanStatus.Clean;

                return new ScanItemResult
                {
                    Path = path,
                    Kind = kind,
                    Status = status,
                    Reason = Reason,
                    SizeBytes = Size,
                    Sha256 = Sha256,
                    Trust = Trust,
                    Detections = [.. _detections],
                    Message = Message,
                };
            }
        }
    }
}
