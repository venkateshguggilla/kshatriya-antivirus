using System.Security.Cryptography;
using Kshatriya.Core;
using Kshatriya.Engines;

namespace Kshatriya.Mobile;

/// <summary>Something the Android app asks to scan: an installed app's APK or a file the user picked.</summary>
/// <param name="DisplayName">What the user sees, for example an app label or a file name.</param>
/// <param name="Location">The path or content URI, used only for reporting.</param>
/// <param name="Size">Size in bytes when the platform reports it.</param>
/// <param name="Open">Opens the content for reading. The scanner disposes the stream.</param>
/// <param name="PackageName">For installed apps: the package the APK belongs to.</param>
/// <param name="App">For an installed app's base APK: its identity, checked against app indicators.</param>
/// <param name="CacheKey">When set, the file's hash may be reused from the cache under this key.</param>
public sealed record MobileScanTarget(string DisplayName, string Location, long? Size, Func<Stream> Open, string? PackageName = null, AppIdentity? App = null, string? CacheKey = null);

/// <summary>The result for one target, with the target it belongs to.</summary>
public sealed record MobileScanResult(MobileScanTarget Target, ScanItemResult Item);

/// <summary>
/// Scans whole files by exact SHA-256 (ADR 0020). No file format is parsed: the content is only hashed,
/// with a size limit, and every item that could not be scanned is reported with its reason.
/// </summary>
public sealed class MobileScanner
{
    /// <summary>Default limit per file (512 MiB).</summary>
    public const long DefaultMaxBytes = 512L * 1024 * 1024;

    private readonly IReadOnlyList<IDetectionEngine> _engines;
    private readonly AppIndicatorSet _indicators;
    private readonly IHashCache? _cache;

    public MobileScanner(IReadOnlyList<IDetectionEngine> engines, long maxBytes = DefaultMaxBytes, AppIndicatorSet? indicators = null, IHashCache? cache = null)
    {
        ArgumentNullException.ThrowIfNull(engines);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);
        _engines = engines;
        MaxBytes = maxBytes;
        _indicators = indicators ?? AppIndicatorSet.Empty;
        _cache = cache;
    }

    /// <summary>How many hashes came from the cache instead of reading the file.</summary>
    public int CacheHits => _cacheHits;

    private int _cacheHits;

    public long MaxBytes { get; }

    public IReadOnlyList<EngineDescriptor> Engines => [.. _engines.Select(e => e.Descriptor)];

    public async Task<MobileScanResult> ScanAsync(MobileScanTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        return new MobileScanResult(target, await ScanItemAsync(target, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Scans the targets one after another, reporting each result as it completes.</summary>
    public async Task<IReadOnlyList<MobileScanResult>> ScanAllAsync(IEnumerable<MobileScanTarget> targets, IProgress<MobileScanResult>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var results = new List<MobileScanResult>();
        foreach (MobileScanTarget target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            MobileScanResult result = await ScanAsync(target, cancellationToken).ConfigureAwait(false);
            results.Add(result);
            progress?.Report(result);
        }

        return results;
    }

    private async Task<ScanItemResult> ScanItemAsync(MobileScanTarget target, CancellationToken cancellationToken)
    {
        // The app's identity needs no file access: check it first, so a listed app is reported even if its
        // file cannot be read.
        IReadOnlyList<Detection> byIdentity = target.App is { } app ? _indicators.Match(app) : [];
        (string? sha256, long length, ScanItemResult? failure) = await HashTargetAsync(target, cancellationToken).ConfigureAwait(false);
        if (failure is not null)
        {
            return byIdentity.Count == 0 ? failure : Result(target, byIdentity, null, null) with { Message = $"Its file was not scanned: {failure.Message}" };
        }

        // The engines get the hash; no engine used here reads the bytes again (nothing is parsed).
        var subject = new ScanSubject(target.Location, length, sha256!, Stream.Null);
        var detections = new List<Detection>(byIdentity);
        foreach (IDetectionEngine engine in _engines)
        {
            try
            {
                detections.AddRange(await engine.ScanAsync(subject, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
            {
                return NotScanned(target, ScanReason.EngineError, $"The {engine.Descriptor.Id} engine failed: {ex.Message}", length, sha256);
            }
        }

        return Result(target, detections, length, sha256);
    }

    private static ScanItemResult Result(MobileScanTarget target, IReadOnlyList<Detection> detections, long? length, string? sha256)
    {
        ScanStatus status = detections.Any(d => d.Category != DetectionCategory.Suspicious) ? ScanStatus.Detected
            : detections.Count > 0 ? ScanStatus.Suspicious
            : ScanStatus.Clean;
        return new ScanItemResult
        {
            Path = target.Location,
            Kind = ScanItemKind.File,
            Status = status,
            SizeBytes = length ?? target.Size,
            Sha256 = sha256,
            Detections = detections,
        };
    }

    /// <summary>The file's SHA-256 and length, from the cache when possible, or the reason it could not be read.</summary>
    private async Task<(string? Sha256, long Length, ScanItemResult? Failure)> HashTargetAsync(MobileScanTarget target, CancellationToken cancellationToken)
    {
        if (target.Size > MaxBytes)
        {
            return (null, 0, NotScanned(target, ScanReason.TooLarge, $"Larger than the {MaxBytes / (1024 * 1024)} MiB limit."));
        }

        if (target.CacheKey is { } key && _cache is not null && _cache.TryGet(key, out string cached, out long cachedLength))
        {
            Interlocked.Increment(ref _cacheHits);
            return (cached, cachedLength, null);
        }

        try
        {
            await using Stream stream = target.Open();
            (string sha256, long length) = await HashAsync(stream, cancellationToken).ConfigureAwait(false);
            if (target.CacheKey is { } newKey)
            {
                _cache?.Store(newKey, sha256, length);
            }

            return (sha256, length, null);
        }
        catch (TooLargeException)
        {
            return (null, 0, NotScanned(target, ScanReason.TooLarge, $"Larger than the {MaxBytes / (1024 * 1024)} MiB limit."));
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return (null, 0, NotScanned(target, ScanReason.NotFound, "It was moved or deleted before the scan."));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return (null, 0, NotScanned(target, ScanReason.AccessDenied, "Kshatriya is not allowed to read it."));
        }
        catch (IOException ex)
        {
            return (null, 0, NotScanned(target, ScanReason.IoError, ex.Message));
        }
    }

    private async Task<(string Sha256, long Length)> HashAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > MaxBytes)
            {
                throw new TooLargeException();
            }

            hash.AppendData(buffer, 0, read);
        }

        return (Convert.ToHexStringLower(hash.GetHashAndReset()), total);
    }

    private static ScanItemResult NotScanned(MobileScanTarget target, ScanReason reason, string message, long? size = null, string? sha256 = null) => new()
    {
        Path = target.Location,
        Kind = ScanItemKind.File,
        Status = ScanStatus.NotScanned,
        Reason = reason,
        SizeBytes = size ?? target.Size,
        Sha256 = sha256,
        Message = message,
    };

    private sealed class TooLargeException : Exception
    {
    }
}
