using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using Kshatriya.Core;
using Kshatriya.Engines;
using Kshatriya.Scanning.Trust;

namespace Kshatriya.Scanning;

/// <summary>Options for a scan run.</summary>
public sealed record ScanOptions
{
    public ScanLimits Limits { get; init; } = new();

    /// <summary>When false (default) clean items are counted but not listed in the report.</summary>
    public bool IncludeCleanItems { get; init; }

    /// <summary>Optional code-signing check for executables. Null disables trust evaluation.</summary>
    public ITrustProvider? TrustProvider { get; init; }

    /// <summary>Optional cache of clean verdicts for unchanged files. Null (default) rescans everything.</summary>
    public VerdictCache? Cache { get; init; }

    /// <summary>Paths and hashes not to scan (reported as skipped). Null excludes nothing.</summary>
    public ExclusionSet? Exclusions { get; init; }

    /// <summary>
    /// Optional response component (quarantine) invoked for detected files after their scan handle is
    /// closed. Null (default) keeps the scan strictly read-only.
    /// </summary>
    public IItemResponder? Responder { get; init; }
}

/// <summary>Live progress counters.</summary>
public readonly record struct ScanProgress(long ItemsCompleted, long Detected, long BytesScanned, string? CurrentPath);

/// <summary>
/// Read-only scan pipeline: enumerate → open safely → (cache) → hash → trust check → analyzer → report.
/// The analyzer runs the engines and archive expansion, in-process or in sandboxed workers.
/// The runner itself never modifies, moves or deletes any file; responding to detections is delegated to
/// an optional <see cref="IItemResponder"/> (Kshatriya.Response), which re-verifies each file before acting.
/// </summary>
public sealed class ScanRunner
{
    private const int BufferSize = 128 * 1024;

    private readonly IContentAnalyzer _analyzer;
    private readonly ScanOptions _options;

    /// <summary>Creates a runner that analyses content in-process with the given engines.</summary>
    public ScanRunner(IReadOnlyList<IDetectionEngine> engines, ScanOptions? options = null)
        : this(CreateInProcess(engines, options ?? new ScanOptions()), options)
    {
    }

    /// <summary>Creates a runner around any analyzer. The caller owns (and disposes) the analyzer.</summary>
    public ScanRunner(IContentAnalyzer analyzer, ScanOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(analyzer);
        _analyzer = analyzer;
        _options = options ?? new ScanOptions();
        if (_options.Limits.MaxDegreeOfParallelism < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxDegreeOfParallelism must be at least 1.");
        }
    }

    public IReadOnlyList<EngineInfo> Engines => _analyzer.Engines;

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
                        foreach (WalkEntry entry in SafeFileEnumerator.Walk(target, _options.Exclusions, cancellationToken))
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
            if (_options.Responder is { } responder && result.Status == ScanStatus.Detected && result.Kind == ScanItemKind.File)
            {
                ItemAction? action = await responder.RespondAsync(result, ct);
                if (action is not null)
                {
                    result = result with { Action = action };
                }
            }

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

        var clock = Stopwatch.StartNew();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Limits.PerItemTimeout);

        using var buffer = new MemoryStream();
        long? size = null;
        string? sha256 = null;
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

            size = buffer.Length;
            buffer.Position = 0;
            sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(buffer, timeout.Token));
            buffer.Position = 0;
            AnalysisResult analysis = await AnalyzeAsync(displayName, buffer.Length, sha256, buffer, trust: null, clock, timeout.Token, cancellationToken);
            return ToResult(displayName, ScanItemKind.Stream, size, sha256, trust: null, analysis);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ToResult(displayName, ScanItemKind.Stream, size, sha256, trust: null, AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded."));
        }
    }

    private static InProcessAnalyzer CreateInProcess(IReadOnlyList<IDetectionEngine> engines, ScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(engines);
        return new InProcessAnalyzer(engines, options.Limits.Archives, options.Limits.MaxFileSizeBytes);
    }

    private async Task<ScanItemResult> ScanFileAsync(string path, long enumeratedLength, CancellationToken cancellationToken)
    {
        long maxSize = _options.Limits.MaxFileSizeBytes;
        if (enumeratedLength > maxSize)
        {
            return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.TooLarge, $"File is larger than the {maxSize}-byte limit.", enumeratedLength);
        }

        var clock = Stopwatch.StartNew();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Limits.PerItemTimeout);

        OpenResult open = SafeFileOpener.Open(path);
        if (!open.Success)
        {
            return open.FailureReason is ScanReason.ReparsePoint or ScanReason.CloudPlaceholder
                ? ScanItemResult.Skip(path, ScanItemKind.File, open.FailureReason, open.Message)
                : ScanItemResult.Fail(path, ScanItemKind.File, open.FailureReason, open.Message, enumeratedLength);
        }

        long length = enumeratedLength;
        string? sha256 = null;
        FileTrust? trust = null;
        using SafeFileHandle handle = open.Handle!;
        try
        {
            await using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
            length = stream.Length;
            if (length > maxSize)
            {
                return ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.TooLarge, $"File is larger than the {maxSize}-byte limit.", length);
            }

            // The cache is consulted only after the file was opened through the safe opener, so a cached
            // verdict is never returned for a file the caller could not open.
            VerdictCache? cache = _options.Cache;
            FileIdentity? identity = cache is null ? null : SafeFileOpener.TryGetIdentity(handle, length);
            if (identity is { } id && cache!.TryGet(id, _analyzer.ConfigurationFingerprint, out CachedVerdict? cached))
            {
                return new ScanItemResult
                {
                    Path = path,
                    Kind = ScanItemKind.File,
                    Status = ScanStatus.Clean,
                    SizeBytes = length,
                    Sha256 = cached!.Sha256,
                    Trust = cached.Trust,
                };
            }

            sha256 = await HashAsync(stream, timeout.Token);
            stream.Position = 0;

            if (_options.Exclusions?.IsHashExcluded(sha256) == true)
            {
                return ScanItemResult.Skip(path, ScanItemKind.File, ScanReason.Excluded, "SHA-256 exclusion.") with { SizeBytes = length, Sha256 = sha256 };
            }

            trust = EvaluateTrust(handle, stream, path);
            stream.Position = 0;

            AnalysisResult analysis = await AnalyzeAsync(path, length, sha256, stream, trust, clock, timeout.Token, cancellationToken);
            ScanItemResult result = ToResult(path, ScanItemKind.File, length, sha256, trust, analysis);

            // Cache only complete clean results, and only if the file did not change while it was read.
            if (identity is { } before && result.Status == ScanStatus.Clean
                && SafeFileOpener.TryGetIdentity(handle, stream.Length) is { } after && after == before)
            {
                cache!.Store(before, _analyzer.ConfigurationFingerprint, new CachedVerdict(sha256, trust));
            }

            return result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return ToResult(path, ScanItemKind.File, length, sha256, trust, AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded."));
        }
        catch (UnauthorizedAccessException ex)
        {
            return ToResult(path, ScanItemKind.File, length, sha256, trust, AnalysisResult.Failed(ScanReason.AccessDenied, ex.Message));
        }
        catch (IOException ex)
        {
            return ToResult(path, ScanItemKind.File, length, sha256, trust, AnalysisResult.Failed(SafeFileOpener.MapIOException(ex), ex.Message));
        }
    }

    private async Task<AnalysisResult> AnalyzeAsync(
        string path,
        long length,
        string sha256,
        Stream content,
        FileTrust? trust,
        Stopwatch clock,
        CancellationToken itemToken,
        CancellationToken scanToken)
    {
        TimeSpan budget = _options.Limits.PerItemTimeout - clock.Elapsed;
        if (budget <= TimeSpan.Zero)
        {
            return AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded.");
        }

        AnalysisResult result = await _analyzer.AnalyzeAsync(new AnalysisRequest(path, length, sha256, content, trust, budget), itemToken);

        // Analyzers report cancellation as a timeout; if the whole scan was cancelled, stop instead.
        scanToken.ThrowIfCancellationRequested();
        return result;
    }

    /// <summary>
    /// Builds the item result. Detections decide the status even when the scan was partial: confirmed
    /// categories make it detected, heuristics alone make it suspicious; otherwise any reason makes it not scanned.
    /// </summary>
    private static ScanItemResult ToResult(string path, ScanItemKind kind, long? size, string? sha256, FileTrust? trust, AnalysisResult analysis)
    {
        bool confirmed = analysis.Detections.Any(d => d.Category != DetectionCategory.Suspicious);
        ScanStatus status = confirmed ? ScanStatus.Detected
            : analysis.Detections.Count > 0 ? ScanStatus.Suspicious
            : analysis.Reason != ScanReason.None ? ScanStatus.NotScanned
            : ScanStatus.Clean;

        return new ScanItemResult
        {
            Path = path,
            Kind = kind,
            Status = status,
            Reason = analysis.Reason,
            SizeBytes = size,
            Sha256 = sha256,
            Trust = trust,
            Detections = analysis.Detections,
            Message = analysis.Message,
        };
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
        long seen = 0, scanned = 0, detected = 0, suspicious = 0, skipped = 0, notScanned = 0, partial = 0, bytes = 0, quarantined = 0, quarantineFailed = 0;
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

            if (r.Action is { } action)
            {
                if (action.Succeeded)
                {
                    quarantined++;
                }
                else
                {
                    quarantineFailed++;
                }
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
            Engines = _analyzer.Engines,
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
                Quarantined = quarantined,
                QuarantineFailed = quarantineFailed,
            },
            Items = listed,
            CleanItemsIncluded = _options.IncludeCleanItems,
        };
    }
}
