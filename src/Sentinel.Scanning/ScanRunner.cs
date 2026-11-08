using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using Sentinel.Core;
using Sentinel.Engines;

namespace Sentinel.Scanning;

/// <summary>Options for a scan run.</summary>
public sealed record ScanOptions
{
    public ScanLimits Limits { get; init; } = new();

    /// <summary>When false (default) clean items are counted but not listed in the report.</summary>
    public bool IncludeCleanItems { get; init; }
}

/// <summary>Live progress counters.</summary>
public readonly record struct ScanProgress(long ItemsCompleted, long Detected, long BytesScanned, string? CurrentPath);

/// <summary>
/// Read-only scan pipeline: enumerate → open safely → hash → run engines → report.
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

            if (result.Status == ScanStatus.Detected)
            {
                Interlocked.Increment(ref detected);
            }

            if (result.Status is ScanStatus.Clean or ScanStatus.Detected && result.SizeBytes is long size)
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
            return await RunEnginesAsync(new ScanSubject(displayName, buffer.Length, sha256, buffer), ScanItemKind.Stream, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ScanItemResult.Fail(displayName, ScanItemKind.Stream, ScanReason.Timeout, "Per-item time limit exceeded.");
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

        using SafeFileHandle handle = open.Handle!;
        try
        {
            await using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
            long length = stream.Length;
            if (length > maxSize)
            {
                return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.TooLarge, $"File is larger than the {maxSize}-byte limit.", length);
            }

            string sha256 = await HashAsync(stream, timeout.Token);
            stream.Position = 0;
            return await RunEnginesAsync(new ScanSubject(path, length, sha256, stream), ScanItemKind.File, timeout.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.Timeout, "Per-item time limit exceeded.", enumeratedLength);
        }
        catch (UnauthorizedAccessException ex)
        {
            return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.AccessDenied, ex.Message, enumeratedLength);
        }
        catch (IOException ex)
        {
            ScanReason reason = ex.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021) ? ScanReason.Locked : ScanReason.IoError;
            return ScanItemResult.Fail(path, ScanItemKind.File, reason, ex.Message, enumeratedLength);
        }
    }

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

    private async Task<ScanItemResult> RunEnginesAsync(ScanSubject subject, ScanItemKind kind, CancellationToken cancellationToken)
    {
        var detections = new List<Detection>();
        foreach (IDetectionEngine engine in _engines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            subject.Content.Position = 0;
            try
            {
                detections.AddRange(await engine.ScanAsync(subject, cancellationToken));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A faulty engine must not take down the scan; the item is reported as incomplete.
                return new ScanItemResult
                {
                    Path = subject.DisplayPath,
                    Kind = kind,
                    Status = ScanStatus.NotScanned,
                    Reason = ScanReason.EngineError,
                    SizeBytes = subject.Length,
                    Sha256 = subject.Sha256,
                    Detections = detections,
                    Message = $"Engine '{engine.Descriptor.Id}' failed: {ex.GetType().Name}: {ex.Message}",
                };
            }
        }

        return new ScanItemResult
        {
            Path = subject.DisplayPath,
            Kind = kind,
            Status = detections.Count > 0 ? ScanStatus.Detected : ScanStatus.Clean,
            SizeBytes = subject.Length,
            Sha256 = subject.Sha256,
            Detections = detections,
        };
    }

    private ScanReport BuildReport(IReadOnlyList<string> targets, DateTimeOffset started, IEnumerable<ScanItemResult> results)
    {
        long seen = 0, scanned = 0, detected = 0, skipped = 0, notScanned = 0, bytes = 0;
        var listed = new List<ScanItemResult>();
        foreach (ScanItemResult r in results)
        {
            seen++;
            switch (r.Status)
            {
                case ScanStatus.Clean:
                    scanned++;
                    bytes += r.SizeBytes ?? 0;
                    break;
                case ScanStatus.Detected:
                    scanned++;
                    detected++;
                    bytes += r.SizeBytes ?? 0;
                    break;
                case ScanStatus.Skipped:
                    skipped++;
                    break;
                case ScanStatus.NotScanned:
                    notScanned++;
                    break;
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
                Skipped = skipped,
                NotScanned = notScanned,
                BytesScanned = bytes,
            },
            Items = listed,
            CleanItemsIncluded = _options.IncludeCleanItems,
        };
    }
}
