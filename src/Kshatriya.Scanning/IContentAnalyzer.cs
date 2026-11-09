using System.Globalization;
using System.Text;
using Kshatriya.Core;

namespace Kshatriya.Scanning;

/// <summary>Content handed to an analyzer. The pipeline has already opened, size-checked and hashed it.</summary>
/// <param name="DisplayPath">Used only for reporting; analyzers never open it.</param>
/// <param name="Length">Content length in bytes.</param>
/// <param name="Sha256">Lower-case hexadecimal SHA-256 of the content.</param>
/// <param name="Content">Readable, seekable stream positioned anywhere; analyzers rewind it.</param>
/// <param name="Trust">Authenticode result for the top-level file, if checked.</param>
/// <param name="TimeBudget">Time left for this item. Analyzers should stop and report partial results within it.</param>
/// <param name="File">The opened file behind <paramref name="Content"/>, when there is one: analyzers map it read-only
/// instead of copying it (required for content larger than a byte array can hold). Never used to reopen the path.</param>
/// <param name="Memory">The content already mapped into this process (inside a worker).</param>
public sealed record AnalysisRequest(
    string DisplayPath,
    long Length,
    string Sha256,
    Stream Content,
    FileTrust? Trust,
    TimeSpan TimeBudget,
    Microsoft.Win32.SafeHandles.SafeFileHandle? File = null,
    Kshatriya.Engines.ContentMemory? Memory = null);

/// <summary>
/// Findings for one item plus the reason it could only be partially analysed (or
/// <see cref="ScanReason.None"/>). Detections found before a limit or timeout are kept.
/// </summary>
public sealed record AnalysisResult(IReadOnlyList<Detection> Detections, ScanReason Reason, string? Message)
{
    public static AnalysisResult Failed(ScanReason reason, string message) => new([], reason, message);
}

/// <summary>
/// Runs the detection engines (and archive expansion) over content. Implementations: in-process
/// (<see cref="InProcessAnalyzer"/>) or sandboxed worker processes (Kshatriya.Runtime).
/// </summary>
public interface IContentAnalyzer
{
    /// <summary>Engines that take part, for reports.</summary>
    IReadOnlyList<EngineInfo> Engines { get; }

    /// <summary>
    /// Identifies everything that can change a verdict (engines, content versions, limits). Cached
    /// verdicts are only reused when this matches exactly.
    /// </summary>
    string ConfigurationFingerprint { get; }

    /// <summary>
    /// Analyses one item. When <paramref name="cancellationToken"/> is cancelled the analyzer stops
    /// and returns what it found so far with <see cref="ScanReason.Timeout"/>; the caller decides whether
    /// the cancellation was a timeout or the whole scan being cancelled.
    /// </summary>
    Task<AnalysisResult> AnalyzeAsync(AnalysisRequest request, CancellationToken cancellationToken);
}

/// <summary>Helpers shared by analyzer implementations.</summary>
public static class AnalyzerFingerprint
{
    public static string Compute(IEnumerable<EngineInfo> engines, ArchiveLimits archives, long maxScanBytes)
    {
        ArgumentNullException.ThrowIfNull(engines);
        ArgumentNullException.ThrowIfNull(archives);
        var sb = new StringBuilder();
        foreach (EngineInfo e in engines)
        {
            sb.Append(e.Id).Append('/').Append(e.Version).Append('/').Append(e.ContentVersion).Append(';');
        }

        sb.Append(CultureInfo.InvariantCulture, $"archives={archives.MaxDepth},{archives.MaxEntries},{archives.MaxEntryBytes},{archives.MaxTotalBytes},{archives.MaxCompressionRatio};");
        sb.Append(CultureInfo.InvariantCulture, $"max={maxScanBytes}");
        return sb.ToString();
    }
}
