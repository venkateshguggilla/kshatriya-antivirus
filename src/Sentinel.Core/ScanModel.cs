namespace Sentinel.Core;

/// <summary>What kind of object a scan result describes.</summary>
public enum ScanItemKind
{
    File,
    Directory,
    Stream,
}

/// <summary>Outcome of scanning a single item.</summary>
public enum ScanStatus
{
    /// <summary>Fully scanned by every engine; nothing found.</summary>
    Clean,

    /// <summary>At least one engine reported a detection.</summary>
    Detected,

    /// <summary>Intentionally not scanned because of policy (for example a reparse point or cloud placeholder).</summary>
    Skipped,

    /// <summary>Should have been scanned but could not be (locked, denied, too large, timed out, I/O error).</summary>
    NotScanned,
}

/// <summary>Why an item was skipped or not scanned. <see cref="None"/> for clean or detected items.</summary>
public enum ScanReason
{
    None,
    ReparsePoint,
    CloudPlaceholder,
    LoopDetected,
    TooLarge,
    Timeout,
    AccessDenied,
    Locked,
    NotFound,
    IoError,
    EngineError,
}

/// <summary>Broad classification of a detection.</summary>
public enum DetectionCategory
{
    Malware,
    PotentiallyUnwanted,
    Suspicious,
    TestFile,
}

/// <summary>How certain the engine is. Only <see cref="High"/> confidence detections may ever drive automatic actions.</summary>
public enum DetectionConfidence
{
    Low,
    Medium,
    High,
}

/// <summary>A single finding produced by a detection engine.</summary>
public sealed record Detection(
    string EngineId,
    string Name,
    DetectionCategory Category,
    DetectionConfidence Confidence,
    string? Description = null);

/// <summary>The result for one scanned (or not scanned) item.</summary>
public sealed record ScanItemResult
{
    public required string Path { get; init; }

    public required ScanItemKind Kind { get; init; }

    public required ScanStatus Status { get; init; }

    public ScanReason Reason { get; init; } = ScanReason.None;

    public long? SizeBytes { get; init; }

    /// <summary>Lower-case hexadecimal SHA-256 of the content, when the content was read completely.</summary>
    public string? Sha256 { get; init; }

    public IReadOnlyList<Detection> Detections { get; init; } = [];

    /// <summary>Optional human-readable detail, such as an OS error message.</summary>
    public string? Message { get; init; }

    /// <summary>True when the item counts against scan completeness (see <see cref="ScanStatus.NotScanned"/>).</summary>
    public bool IsIncomplete => Status == ScanStatus.NotScanned;

    public static ScanItemResult Skip(string path, ScanItemKind kind, ScanReason reason, string? message = null) =>
        new() { Path = path, Kind = kind, Status = ScanStatus.Skipped, Reason = reason, Message = message };

    public static ScanItemResult Fail(string path, ScanItemKind kind, ScanReason reason, string? message = null, long? size = null) =>
        new() { Path = path, Kind = kind, Status = ScanStatus.NotScanned, Reason = reason, Message = message, SizeBytes = size };
}

/// <summary>Resource limits applied to every scanned item.</summary>
public sealed record ScanLimits
{
    /// <summary>Files larger than this are reported as <see cref="ScanReason.TooLarge"/> instead of being read.</summary>
    public long MaxFileSizeBytes { get; init; } = 256L * 1024 * 1024;

    /// <summary>Wall-clock budget for reading and scanning one item.</summary>
    public TimeSpan PerItemTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Number of items scanned concurrently.</summary>
    public int MaxDegreeOfParallelism { get; init; } = Math.Clamp(Environment.ProcessorCount, 1, 16);
}

/// <summary>Identity and content version of an engine that took part in a scan.</summary>
public sealed record EngineInfo(string Id, string Version, string ContentVersion);

/// <summary>Aggregate counters for a scan.</summary>
public sealed record ScanSummary
{
    public long ItemsSeen { get; init; }

    public long FilesScanned { get; init; }

    public long Detected { get; init; }

    public long Skipped { get; init; }

    public long NotScanned { get; init; }

    public long BytesScanned { get; init; }
}

/// <summary>The complete outcome of a scan.</summary>
public sealed record ScanReport
{
    public required IReadOnlyList<string> Targets { get; init; }

    public required DateTimeOffset StartedUtc { get; init; }

    public required DateTimeOffset FinishedUtc { get; init; }

    public required IReadOnlyList<EngineInfo> Engines { get; init; }

    public required ScanSummary Summary { get; init; }

    /// <summary>Item results, sorted by path. Clean items are included only when requested.</summary>
    public required IReadOnlyList<ScanItemResult> Items { get; init; }

    public bool CleanItemsIncluded { get; init; }

    public TimeSpan Duration => FinishedUtc - StartedUtc;

    public bool HasDetections => Summary.Detected > 0;

    public bool IsComplete => Summary.NotScanned == 0;
}
