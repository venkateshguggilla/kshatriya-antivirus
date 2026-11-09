namespace Kshatriya.Core;

/// <summary>
/// Explicit mapping between enum members and the names used in every public or inter-process format
/// (reports, IPC, worker protocol). Renaming a C# member can therefore never silently change a format,
/// and unknown wire names are rejected rather than guessed.
/// </summary>
public static class WireNames
{
    public static string Of(ScanItemKind kind) => kind switch
    {
        ScanItemKind.File => "file",
        ScanItemKind.Directory => "directory",
        ScanItemKind.Stream => "stream",
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public static string Of(ScanStatus status) => status switch
    {
        ScanStatus.Clean => "clean",
        ScanStatus.Detected => "detected",
        ScanStatus.Suspicious => "suspicious",
        ScanStatus.Skipped => "skipped",
        ScanStatus.NotScanned => "notScanned",
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    public static string Of(ScanReason reason) => reason switch
    {
        ScanReason.None => "none",
        ScanReason.ReparsePoint => "reparsePoint",
        ScanReason.CloudPlaceholder => "cloudPlaceholder",
        ScanReason.LoopDetected => "loopDetected",
        ScanReason.TooLarge => "tooLarge",
        ScanReason.Timeout => "timeout",
        ScanReason.AccessDenied => "accessDenied",
        ScanReason.Locked => "locked",
        ScanReason.NotFound => "notFound",
        ScanReason.IoError => "ioError",
        ScanReason.BlockedBySecurityProduct => "blockedBySecurityProduct",
        ScanReason.EngineError => "engineError",
        ScanReason.ArchiveLimit => "archiveLimit",
        ScanReason.ArchiveEncrypted => "archiveEncrypted",
        ScanReason.ArchiveError => "archiveError",
        ScanReason.Excluded => "excluded",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    public static string Of(DetectionCategory category) => category switch
    {
        DetectionCategory.Malware => "malware",
        DetectionCategory.PotentiallyUnwanted => "pua",
        DetectionCategory.Suspicious => "suspicious",
        DetectionCategory.TestFile => "test",
        _ => throw new ArgumentOutOfRangeException(nameof(category)),
    };

    public static string Of(DetectionConfidence confidence) => confidence switch
    {
        DetectionConfidence.Low => "low",
        DetectionConfidence.Medium => "medium",
        DetectionConfidence.High => "high",
        _ => throw new ArgumentOutOfRangeException(nameof(confidence)),
    };

    public static string Of(TrustStatus status) => status switch
    {
        TrustStatus.NotSigned => "notSigned",
        TrustStatus.Valid => "valid",
        TrustStatus.Invalid => "invalid",
        _ => throw new ArgumentOutOfRangeException(nameof(status)),
    };

    public static string Of(TrustSource source) => source switch
    {
        TrustSource.None => "none",
        TrustSource.Embedded => "embedded",
        TrustSource.Catalog => "catalog",
        _ => throw new ArgumentOutOfRangeException(nameof(source)),
    };

    public static ScanItemKind ParseKind(string value) => value switch
    {
        "file" => ScanItemKind.File,
        "directory" => ScanItemKind.Directory,
        "stream" => ScanItemKind.Stream,
        _ => throw Unknown("kind", value),
    };

    public static ScanStatus ParseStatus(string value) => value switch
    {
        "clean" => ScanStatus.Clean,
        "detected" => ScanStatus.Detected,
        "suspicious" => ScanStatus.Suspicious,
        "skipped" => ScanStatus.Skipped,
        "notScanned" => ScanStatus.NotScanned,
        _ => throw Unknown("status", value),
    };

    public static ScanReason ParseReason(string value) => value switch
    {
        "none" => ScanReason.None,
        "reparsePoint" => ScanReason.ReparsePoint,
        "cloudPlaceholder" => ScanReason.CloudPlaceholder,
        "loopDetected" => ScanReason.LoopDetected,
        "tooLarge" => ScanReason.TooLarge,
        "timeout" => ScanReason.Timeout,
        "accessDenied" => ScanReason.AccessDenied,
        "locked" => ScanReason.Locked,
        "notFound" => ScanReason.NotFound,
        "ioError" => ScanReason.IoError,
        "blockedBySecurityProduct" => ScanReason.BlockedBySecurityProduct,
        "engineError" => ScanReason.EngineError,
        "archiveLimit" => ScanReason.ArchiveLimit,
        "archiveEncrypted" => ScanReason.ArchiveEncrypted,
        "archiveError" => ScanReason.ArchiveError,
        "excluded" => ScanReason.Excluded,
        _ => throw Unknown("reason", value),
    };

    public static DetectionCategory ParseCategory(string value) => value switch
    {
        "malware" => DetectionCategory.Malware,
        "pua" => DetectionCategory.PotentiallyUnwanted,
        "suspicious" => DetectionCategory.Suspicious,
        "test" => DetectionCategory.TestFile,
        _ => throw Unknown("category", value),
    };

    public static DetectionConfidence ParseConfidence(string value) => value switch
    {
        "low" => DetectionConfidence.Low,
        "medium" => DetectionConfidence.Medium,
        "high" => DetectionConfidence.High,
        _ => throw Unknown("confidence", value),
    };

    public static TrustStatus ParseTrustStatus(string value) => value switch
    {
        "notSigned" => TrustStatus.NotSigned,
        "valid" => TrustStatus.Valid,
        "invalid" => TrustStatus.Invalid,
        _ => throw Unknown("trust status", value),
    };

    public static TrustSource ParseTrustSource(string value) => value switch
    {
        "none" => TrustSource.None,
        "embedded" => TrustSource.Embedded,
        "catalog" => TrustSource.Catalog,
        _ => throw Unknown("trust source", value),
    };

    public static string Of(ActionFailure failure) => failure switch
    {
        ActionFailure.None => "none",
        ActionFailure.Changed => "changed",
        ActionFailure.Locked => "locked",
        ActionFailure.InUse => "inUse",
        ActionFailure.AccessDenied => "accessDenied",
        ActionFailure.NotFound => "notFound",
        ActionFailure.HardLinked => "hardLinked",
        ActionFailure.TooLarge => "tooLarge",
        ActionFailure.NotRegularFile => "notRegularFile",
        ActionFailure.VaultError => "vaultError",
        ActionFailure.IoError => "ioError",
        _ => throw new ArgumentOutOfRangeException(nameof(failure)),
    };

    public static ActionFailure ParseActionFailure(string value) => value switch
    {
        "none" => ActionFailure.None,
        "changed" => ActionFailure.Changed,
        "locked" => ActionFailure.Locked,
        "inUse" => ActionFailure.InUse,
        "accessDenied" => ActionFailure.AccessDenied,
        "notFound" => ActionFailure.NotFound,
        "hardLinked" => ActionFailure.HardLinked,
        "tooLarge" => ActionFailure.TooLarge,
        "notRegularFile" => ActionFailure.NotRegularFile,
        "vaultError" => ActionFailure.VaultError,
        "ioError" => ActionFailure.IoError,
        _ => throw Unknown("action failure", value),
    };

    private static FormatException Unknown(string field, string value) => new($"Unknown {field} '{value}'.");
}
