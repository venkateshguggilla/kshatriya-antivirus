using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.Protocol;

/// <summary>Frame type bytes. Worker messages are 0x01–0x0F, service messages 0x20–0x3F.</summary>
public static class MessageType
{
    public const byte WorkerInit = 0x01;
    public const byte WorkerInitReply = 0x02;
    public const byte Analyze = 0x03;
    public const byte AnalyzeReply = 0x04;
    public const byte Probe = 0x05;
    public const byte ProbeReply = 0x06;

    public const byte Hello = 0x20;
    public const byte HelloReply = 0x21;
    public const byte Status = 0x22;
    public const byte StatusReply = 0x23;
    public const byte Scan = 0x24;
    public const byte ScanProgress = 0x25;
    public const byte ScanResult = 0x26;
    public const byte Cancel = 0x27;
    public const byte Error = 0x2F;

    public const byte QuarantineList = 0x30;
    public const byte QuarantineListReply = 0x31;
    public const byte QuarantineAdd = 0x32;
    public const byte QuarantineRestore = 0x33;
    public const byte QuarantineDelete = 0x34;
    public const byte OperationReply = 0x35;
    public const byte ExclusionsList = 0x36;
    public const byte ExclusionsChange = 0x37;
    public const byte ExclusionsReply = 0x38;
    public const byte AuditQuery = 0x39;
    public const byte AuditReply = 0x3A;
    public const byte ContentImport = 0x3B;
    public const byte ContentImportReply = 0x3C;
    public const byte DetectionsQuery = 0x3D;
    public const byte DetectionsReply = 0x3E;
}

/// <summary>Protocol versions. A peer that sees a different version refuses to continue.</summary>
public static class ProtocolVersion
{
    public const int Worker = 1;
    public const int Service = 4;
}

// ---- Shared ----

public sealed class EngineInfoDto
{
    public required string Id { get; init; }

    public required string Version { get; init; }

    public required string ContentVersion { get; init; }
}

public sealed class DetectionDto
{
    public required string Engine { get; init; }

    public required string Name { get; init; }

    public required string Category { get; init; }

    public required string Confidence { get; init; }

    public string? Description { get; init; }

    public string? Location { get; init; }
}

public sealed class TrustDto
{
    public required string Status { get; init; }

    public string? Source { get; init; }

    public string? Signer { get; init; }
}

// ---- Worker protocol ----

public sealed class TextSourceDto
{
    public required string Origin { get; init; }

    public required string Text { get; init; }
}

public sealed class ArchiveLimitsDto
{
    public required int MaxDepth { get; init; }

    public required int MaxEntries { get; init; }

    public required long MaxEntryBytes { get; init; }

    public required long MaxTotalBytes { get; init; }

    public required int MaxCompressionRatio { get; init; }
}

/// <summary>Everything a worker needs to build its engines. The broker reads all files; the worker opens none.</summary>
public sealed class EngineConfigDto
{
    public required List<TextSourceDto> HashDatabases { get; init; }

    public required List<TextSourceDto> YaraRules { get; init; }

    public required bool YaraRequired { get; init; }

    public required bool Heuristics { get; init; }

    public required bool HeuristicsIncludeSigned { get; init; }

    public required long MaxScanBytes { get; init; }

    public required ArchiveLimitsDto Archives { get; init; }
}

public sealed class WorkerInitDto
{
    public required int Protocol { get; init; }

    public required EngineConfigDto Engines { get; init; }
}

public sealed class WorkerInitReplyDto
{
    public required int Protocol { get; init; }

    public required List<EngineInfoDto> Engines { get; init; }

    public required string Fingerprint { get; init; }

    /// <summary>Mandatory integrity level of the worker's own token: untrusted, low, medium, high or system.</summary>
    public required string IntegrityLevel { get; init; }

    public required List<string> Warnings { get; init; }

    public string? Error { get; init; }
}

public sealed class AnalyzeDto
{
    public required long Id { get; init; }

    public required string DisplayPath { get; init; }

    public required long Length { get; init; }

    public required string Sha256 { get; init; }

    public TrustDto? Trust { get; init; }

    public required long BudgetMs { get; init; }
}

public sealed class AnalyzeReplyDto
{
    public required long Id { get; init; }

    public required List<DetectionDto> Detections { get; init; }

    public required string Reason { get; init; }

    public string? Message { get; init; }
}

/// <summary>Diagnostics used by sandbox tests; only honoured by workers started with test hooks enabled.</summary>
public sealed class ProbeDto
{
    public required string Kind { get; init; }

    public string? Argument { get; init; }
}

public sealed class ProbeReplyDto
{
    public required bool Succeeded { get; init; }

    public required string Detail { get; init; }
}

// ---- Service protocol ----

public sealed class HelloDto
{
    public required int Protocol { get; init; }

    public required string Client { get; init; }
}

public sealed class HelloReplyDto
{
    public required int Protocol { get; init; }

    public required string Service { get; init; }

    /// <summary>The caller's identity as the service sees it through pipe impersonation.</summary>
    public required string User { get; init; }

    public required bool IsAdmin { get; init; }
}

public sealed class EmptyDto
{
}

public sealed class WorkerStatsDto
{
    public required int Configured { get; init; }

    public required int Running { get; init; }

    public required long Started { get; init; }

    public required long Crashed { get; init; }

    public required long TimedOut { get; init; }
}

public sealed class CacheStatsDto
{
    public required int Entries { get; init; }

    public required long Hits { get; init; }

    public required long Misses { get; init; }
}

public sealed class ScheduleStatusDto
{
    public required string Name { get; init; }

    public string? NextRunUtc { get; init; }

    public string? LastRunUtc { get; init; }

    public string? LastOutcome { get; init; }
}

public sealed class StatusReplyDto
{
    public required string Version { get; init; }

    public required string Mode { get; init; }

    public required string StartedUtc { get; init; }

    public required List<EngineInfoDto> Engines { get; init; }

    public required WorkerStatsDto Workers { get; init; }

    public required CacheStatsDto Cache { get; init; }

    public required List<ScheduleStatusDto> Schedules { get; init; }

    public required int ActiveScans { get; init; }

    public required int QuarantineItems { get; init; }

    public required int Exclusions { get; init; }

    public required bool AuditChainValid { get; init; }

    public required ContentStatusDto Content { get; init; }

    public required RealTimeStatusDto RealTime { get; init; }
}

public sealed class RealTimeStatusDto
{
    public required bool Enabled { get; init; }

    public required List<string> Paths { get; init; }

    /// <summary>State of process-start monitoring (for example "off" or "unavailable: ...").</summary>
    public required string Processes { get; init; }

    public required string RemovableMedia { get; init; }

    public required int Queued { get; init; }

    public required long Scanned { get; init; }

    public required long Findings { get; init; }

    /// <summary>How often change notifications were lost and a folder had to be rescanned.</summary>
    public required long LostEvents { get; init; }
}

public sealed class DetectionsQueryDto
{
    public required int Max { get; init; }
}

public sealed class DetectionRecordDto
{
    public required string TimeUtc { get; init; }

    /// <summary>Where it was found: "scan", "schedule '...'" or "real-time (file|process|removable)".</summary>
    public required string Source { get; init; }

    public required string Path { get; init; }

    /// <summary>"detected" or "suspicious".</summary>
    public required string Status { get; init; }

    public required List<string> Names { get; init; }

    public required string Action { get; init; }
}

public sealed class DetectionsReplyDto
{
    public required List<DetectionRecordDto> Items { get; init; }
}

public sealed class ContentStatusDto
{
    /// <summary>Active package sequence; 0 when only built-in and configured content is loaded.</summary>
    public required long Sequence { get; init; }

    public string? Channel { get; init; }

    public string? ExpiresUtc { get; init; }

    /// <summary>True when the active package has passed its expiry (updates may be blocked).</summary>
    public required bool Expired { get; init; }

    public string? Problem { get; init; }
}

public sealed class ContentImportDto
{
    /// <summary>Fully qualified local path of a .sntu package; the service reads it as the caller.</summary>
    public required string Path { get; init; }
}

public sealed class ContentImportReplyDto
{
    public required bool Succeeded { get; init; }

    /// <summary>"none" or a content error code (malformed, untrustedKey, badSignature, hashMismatch, expired, rollback, ...).</summary>
    public required string Code { get; init; }

    public string? Message { get; init; }

    public long Sequence { get; init; }

    public string? ExpiresUtc { get; init; }
}

public sealed class ScanRequestDto
{
    public required List<string> Paths { get; init; }

    public required bool IncludeClean { get; init; }

    /// <summary>"report" (read-only) or "quarantine" (quarantine high-confidence detections).</summary>
    public required string Action { get; init; }
}

/// <summary>Values of <see cref="ScanRequestDto.Action"/>.</summary>
public static class ScanActions
{
    public const string Report = "report";
    public const string Quarantine = "quarantine";
}

public sealed class QuarantineItemDto
{
    public required string Id { get; init; }

    public required string OriginalPath { get; init; }

    public required string Sha256 { get; init; }

    public required long SizeBytes { get; init; }

    public required string QuarantinedUtc { get; init; }

    public required string User { get; init; }

    public required List<string> Detections { get; init; }

    /// <summary>"scan" or "manual".</summary>
    public required string Origin { get; init; }
}

public sealed class QuarantineListReplyDto
{
    public required List<QuarantineItemDto> Items { get; init; }
}

public sealed class QuarantineAddDto
{
    public required string Path { get; init; }
}

public sealed class QuarantineRestoreDto
{
    public required string Id { get; init; }

    /// <summary>Where to restore; null restores to the original path.</summary>
    public string? TargetPath { get; init; }
}

public sealed class QuarantineDeleteDto
{
    public required string Id { get; init; }
}

/// <summary>Outcome of a quarantine, restore or delete request.</summary>
public sealed class OperationReplyDto
{
    public required bool Succeeded { get; init; }

    /// <summary>"none" on success; otherwise a failure wire name (for example "locked", "targetExists", "notFound").</summary>
    public required string Code { get; init; }

    public string? Message { get; init; }

    public string? QuarantineId { get; init; }

    public string? Path { get; init; }
}

public sealed class ExclusionsReplyDto
{
    public required List<string> Paths { get; init; }

    public required List<string> Sha256 { get; init; }
}

public sealed class ExclusionChangeDto
{
    /// <summary>"add" or "remove".</summary>
    public required string Operation { get; init; }

    /// <summary>A fully qualified local path, or a SHA-256 value (optionally prefixed with "sha256:").</summary>
    public required string Value { get; init; }
}

public sealed class AuditQueryDto
{
    public required int Max { get; init; }
}

public sealed class AuditRecordDto
{
    public required long Seq { get; init; }

    public required string TimeUtc { get; init; }

    public required string User { get; init; }

    public required string Sid { get; init; }

    public required string Action { get; init; }

    public required string Target { get; init; }

    public required string Outcome { get; init; }

    public string? Detail { get; init; }

    public string? QuarantineId { get; init; }
}

public sealed class AuditReplyDto
{
    public required List<AuditRecordDto> Records { get; init; }

    public required bool ChainValid { get; init; }

    public string? Problem { get; init; }
}

public sealed class ScanProgressDto
{
    public required long ItemsCompleted { get; init; }

    public required long Detected { get; init; }

    public required long BytesScanned { get; init; }
}

public sealed class ScanResultDto
{
    /// <summary>The scan report as JSON (schema v2).</summary>
    public required string Report { get; init; }
}

public sealed class ErrorDto
{
    public required string Code { get; init; }

    public required string Message { get; init; }
}

/// <summary>Stable error codes sent in <see cref="ErrorDto.Code"/>.</summary>
public static class ErrorCodes
{
    public const string BadRequest = "badRequest";
    public const string VersionMismatch = "versionMismatch";
    public const string Busy = "busy";
    public const string InvalidPath = "invalidPath";
    public const string Cancelled = "cancelled";
    public const string Internal = "internal";
    public const string AccessDenied = "accessDenied";
    public const string NotFound = "notFound";
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    MaxDepth = 16)]
[JsonSerializable(typeof(WorkerInitDto))]
[JsonSerializable(typeof(WorkerInitReplyDto))]
[JsonSerializable(typeof(AnalyzeDto))]
[JsonSerializable(typeof(AnalyzeReplyDto))]
[JsonSerializable(typeof(ProbeDto))]
[JsonSerializable(typeof(ProbeReplyDto))]
[JsonSerializable(typeof(HelloDto))]
[JsonSerializable(typeof(HelloReplyDto))]
[JsonSerializable(typeof(EmptyDto))]
[JsonSerializable(typeof(StatusReplyDto))]
[JsonSerializable(typeof(ScanRequestDto))]
[JsonSerializable(typeof(ScanProgressDto))]
[JsonSerializable(typeof(ScanResultDto))]
[JsonSerializable(typeof(ErrorDto))]
[JsonSerializable(typeof(QuarantineListReplyDto))]
[JsonSerializable(typeof(QuarantineAddDto))]
[JsonSerializable(typeof(QuarantineRestoreDto))]
[JsonSerializable(typeof(QuarantineDeleteDto))]
[JsonSerializable(typeof(OperationReplyDto))]
[JsonSerializable(typeof(ExclusionsReplyDto))]
[JsonSerializable(typeof(ExclusionChangeDto))]
[JsonSerializable(typeof(AuditQueryDto))]
[JsonSerializable(typeof(AuditReplyDto))]
[JsonSerializable(typeof(ContentImportDto))]
[JsonSerializable(typeof(ContentImportReplyDto))]
[JsonSerializable(typeof(DetectionsQueryDto))]
[JsonSerializable(typeof(DetectionsReplyDto))]
internal sealed partial class ProtocolJsonContext : JsonSerializerContext
{
}

/// <summary>Strict JSON encoding of protocol DTOs (unknown members, missing required members and nulls are rejected).</summary>
public static class ProtocolJson
{
    public static byte[] Serialize<T>(T value)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.SerializeToUtf8Bytes(value, typeof(T), ProtocolJsonContext.Default);
    }

    public static T Deserialize<T>(ReadOnlyMemory<byte> json)
        where T : class
    {
        try
        {
            return JsonSerializer.Deserialize(json.Span, typeof(T), ProtocolJsonContext.Default) as T
                ?? throw new ProtocolException($"Empty {typeof(T).Name} message.");
        }
        catch (JsonException ex)
        {
            throw new ProtocolException($"Malformed {typeof(T).Name} message: {ex.Message}", ex);
        }
        catch (NotSupportedException ex)
        {
            throw new ProtocolException($"Malformed {typeof(T).Name} message: {ex.Message}", ex);
        }
    }

    /// <summary>Reads a frame of the expected type, or throws if the peer sent anything else.</summary>
    public static T Expect<T>(Frame? frame, byte type)
        where T : class
    {
        if (frame is null)
        {
            throw new ProtocolException("Connection closed by peer.");
        }

        if (frame.Type != type)
        {
            throw new ProtocolException($"Expected message 0x{type:X2} but received 0x{frame.Type:X2}.");
        }

        return Deserialize<T>(frame.Json);
    }
}

/// <summary>Conversions between protocol DTOs and the domain model (wire names via <see cref="WireNames"/>).</summary>
public static class DtoMapping
{
    public static DetectionDto ToDto(this Detection d)
    {
        ArgumentNullException.ThrowIfNull(d);
        return new DetectionDto
        {
            Engine = d.EngineId,
            Name = d.Name,
            Category = WireNames.Of(d.Category),
            Confidence = WireNames.Of(d.Confidence),
            Description = d.Description,
            Location = d.Location,
        };
    }

    public static Detection ToDomain(this DetectionDto d)
    {
        ArgumentNullException.ThrowIfNull(d);
        try
        {
            return new Detection(d.Engine, d.Name, WireNames.ParseCategory(d.Category), WireNames.ParseConfidence(d.Confidence), d.Description)
            {
                Location = d.Location,
            };
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ex.Message, ex);
        }
    }

    public static EngineInfoDto ToDto(this EngineInfo e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return new EngineInfoDto { Id = e.Id, Version = e.Version, ContentVersion = e.ContentVersion };
    }

    public static EngineInfo ToDomain(this EngineInfoDto e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return new EngineInfo(e.Id, e.Version, e.ContentVersion);
    }

    public static TrustDto ToDto(this FileTrust t)
    {
        ArgumentNullException.ThrowIfNull(t);
        return new TrustDto
        {
            Status = WireNames.Of(t.Status),
            Source = t.Source == TrustSource.None ? null : WireNames.Of(t.Source),
            Signer = t.Signer,
        };
    }

    public static FileTrust ToDomain(this TrustDto t)
    {
        ArgumentNullException.ThrowIfNull(t);
        try
        {
            return new FileTrust(
                WireNames.ParseTrustStatus(t.Status),
                t.Source is null ? TrustSource.None : WireNames.ParseTrustSource(t.Source),
                t.Signer);
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ex.Message, ex);
        }
    }

    public static ArchiveLimitsDto ToDto(this ArchiveLimits a)
    {
        ArgumentNullException.ThrowIfNull(a);
        return new ArchiveLimitsDto
        {
            MaxDepth = a.MaxDepth,
            MaxEntries = a.MaxEntries,
            MaxEntryBytes = a.MaxEntryBytes,
            MaxTotalBytes = a.MaxTotalBytes,
            MaxCompressionRatio = a.MaxCompressionRatio,
        };
    }

    public static ArchiveLimits ToDomain(this ArchiveLimitsDto a)
    {
        ArgumentNullException.ThrowIfNull(a);
        return new ArchiveLimits
        {
            MaxDepth = a.MaxDepth,
            MaxEntries = a.MaxEntries,
            MaxEntryBytes = a.MaxEntryBytes,
            MaxTotalBytes = a.MaxTotalBytes,
            MaxCompressionRatio = a.MaxCompressionRatio,
        };
    }

    public static ScanReason ParseReason(string reason)
    {
        try
        {
            return WireNames.ParseReason(reason);
        }
        catch (FormatException ex)
        {
            throw new ProtocolException(ex.Message, ex);
        }
    }
}
