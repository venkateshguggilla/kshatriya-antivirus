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
public sealed record MobileScanTarget(string DisplayName, string Location, long? Size, Func<Stream> Open, string? PackageName = null);

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

    public MobileScanner(IReadOnlyList<IDetectionEngine> engines, long maxBytes = DefaultMaxBytes)
    {
        ArgumentNullException.ThrowIfNull(engines);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);
        _engines = engines;
        MaxBytes = maxBytes;
    }

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
        if (target.Size > MaxBytes)
        {
            return NotScanned(target, ScanReason.TooLarge, $"Larger than the {MaxBytes / (1024 * 1024)} MiB limit.");
        }

        string sha256;
        long length;
        try
        {
            await using Stream stream = target.Open();
            (sha256, length) = await HashAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        catch (TooLargeException)
        {
            return NotScanned(target, ScanReason.TooLarge, $"Larger than the {MaxBytes / (1024 * 1024)} MiB limit.");
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return NotScanned(target, ScanReason.NotFound, "It was moved or deleted before the scan.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return NotScanned(target, ScanReason.AccessDenied, "Kshatriya is not allowed to read it.");
        }
        catch (IOException ex)
        {
            return NotScanned(target, ScanReason.IoError, ex.Message);
        }

        // The engines get the hash; no engine used here reads the bytes again (nothing is parsed).
        var subject = new ScanSubject(target.Location, length, sha256, Stream.Null);
        var detections = new List<Detection>();
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

        ScanStatus status = detections.Any(d => d.Category != DetectionCategory.Suspicious) ? ScanStatus.Detected
            : detections.Count > 0 ? ScanStatus.Suspicious
            : ScanStatus.Clean;
        return new ScanItemResult
        {
            Path = target.Location,
            Kind = ScanItemKind.File,
            Status = status,
            SizeBytes = length,
            Sha256 = sha256,
            Detections = detections,
        };
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
