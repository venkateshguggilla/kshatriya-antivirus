namespace Kshatriya.Core;

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

    /// <summary>At least one engine reported a detection other than <see cref="DetectionCategory.Suspicious"/>.</summary>
    Detected,

    /// <summary>Only heuristic (suspicious) findings; never treated as confirmed malware.</summary>
    Suspicious,

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

    /// <summary>An archive limit (depth, entries, size, compression ratio) stopped expansion.</summary>
    ArchiveLimit,

    /// <summary>The archive contains encrypted entries that cannot be inspected.</summary>
    ArchiveEncrypted,

    /// <summary>The archive is corrupt or uses an unsupported feature.</summary>
    ArchiveError,

    /// <summary>Matched a path or SHA-256 exclusion (status <see cref="ScanStatus.Skipped"/>).</summary>
    Excluded,

    /// <summary>
    /// Windows refused to open or read the file because a security product (normally Microsoft Defender)
    /// detected it: ERROR_VIRUS_INFECTED or ERROR_VIRUS_DELETED.
    /// </summary>
    BlockedBySecurityProduct,
}

/// <summary>Why a response action (quarantine) could not be completed.</summary>
public enum ActionFailure
{
    None,

    /// <summary>The file's content no longer matches what was scanned.</summary>
    Changed,

    /// <summary>Another process has the file open for writing or deleting.</summary>
    Locked,

    /// <summary>The file could be read but not removed (for example a running program).</summary>
    InUse,

    AccessDenied,
    NotFound,

    /// <summary>The file has more than one hard link; removing one name would leave the content reachable.</summary>
    HardLinked,

    TooLarge,

    /// <summary>The path is a directory, link, cloud placeholder or other non-regular file.</summary>
    NotRegularFile,

    /// <summary>The quarantine vault could not store the file; nothing was removed.</summary>
    VaultError,

    IoError,
}

/// <summary>Outcome of the response action taken for an item (only present when an action was attempted).</summary>
/// <param name="QuarantineId">Vault identifier when the file was quarantined; null when the action failed.</param>
/// <param name="Failure">Why the action failed, or <see cref="ActionFailure.None"/>.</param>
/// <param name="Message">Optional detail.</param>
public sealed record ItemAction(string? QuarantineId, ActionFailure Failure = ActionFailure.None, string? Message = null)
{
    public bool Succeeded => QuarantineId is not null;

    public static ItemAction Quarantined(string id) => new(id);

    public static ItemAction Failed(ActionFailure failure, string? message = null) => new(null, failure, message);
}

/// <summary>Result of an Authenticode signature check.</summary>
public enum TrustStatus
{
    /// <summary>No embedded or catalog signature was found.</summary>
    NotSigned,

    /// <summary>A signature was found and chains to a trusted root; the content matches it.</summary>
    Valid,

    /// <summary>A signature was found but failed verification (tampered, untrusted root, distrusted, ...).</summary>
    Invalid,
}

/// <summary>Where a valid signature came from.</summary>
public enum TrustSource
{
    None,
    Embedded,
    Catalog,
}

/// <summary>Code-signing information for a file.</summary>
public sealed record FileTrust(TrustStatus Status, TrustSource Source = TrustSource.None, string? Signer = null)
{
    public static FileTrust NotSigned { get; } = new(TrustStatus.NotSigned);

    public bool IsValid => Status == TrustStatus.Valid;
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
    string? Description = null)
{
    /// <summary>Path inside a container (for example <c>docs/a.zip&gt;payload.exe</c>), or null for the item itself.</summary>
    public string? Location { get; init; }
}

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

    /// <summary>Signature information, when the item is a signed-capable executable that was checked.</summary>
    public FileTrust? Trust { get; init; }

    /// <summary>Response action taken for this item (quarantine), or null when none was attempted.</summary>
    public ItemAction? Action { get; init; }

    /// <summary>
    /// True when the item counts against scan completeness: it was not scanned, or it has findings
    /// but could only be partially scanned (a non-<see cref="ScanReason.None"/> reason).
    /// </summary>
    public bool IsIncomplete => Status == ScanStatus.NotScanned
        || (Status is ScanStatus.Detected or ScanStatus.Suspicious && Reason != ScanReason.None);

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

    /// <summary>Archive expansion limits.</summary>
    public ArchiveLimits Archives { get; init; } = new();
}

/// <summary>Limits that protect against archive bombs. All limits apply per top-level item.</summary>
public sealed record ArchiveLimits
{
    /// <summary>Maximum nesting depth. 0 disables archive expansion.</summary>
    public int MaxDepth { get; init; } = 3;

    /// <summary>Maximum number of entries inspected across all nested archives of one item.</summary>
    public int MaxEntries { get; init; } = 10_000;

    /// <summary>Maximum decompressed size of a single entry.</summary>
    public long MaxEntryBytes { get; init; } = 64L * 1024 * 1024;

    /// <summary>Maximum total decompressed bytes across all nested archives of one item.</summary>
    public long MaxTotalBytes { get; init; } = 256L * 1024 * 1024;

    /// <summary>Maximum decompressed-to-compressed ratio for entries larger than 1 MiB.</summary>
    public int MaxCompressionRatio { get; init; } = 200;
}

/// <summary>Identity and content version of an engine that took part in a scan.</summary>
public sealed record EngineInfo(string Id, string Version, string ContentVersion);

/// <summary>Aggregate counters for a scan.</summary>
public sealed record ScanSummary
{
    public long ItemsSeen { get; init; }

    public long FilesScanned { get; init; }

    public long Detected { get; init; }

    public long Suspicious { get; init; }

    /// <summary>Items with findings that could only be partially scanned.</summary>
    public long Partial { get; init; }

    public long Skipped { get; init; }

    public long NotScanned { get; init; }

    public long BytesScanned { get; init; }

    /// <summary>Items moved to quarantine during this scan.</summary>
    public long Quarantined { get; init; }

    /// <summary>Items for which quarantine was attempted but failed.</summary>
    public long QuarantineFailed { get; init; }
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

    public bool HasSuspicious => Summary.Suspicious > 0;

    public bool IsComplete => Summary.NotScanned == 0 && Summary.Partial == 0;
}
