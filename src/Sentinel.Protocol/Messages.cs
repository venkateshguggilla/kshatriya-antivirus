using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.Protocol;

/// <summary>Frame type bytes. Worker messages are 0x01–0x0F, service messages 0x20–0x2F.</summary>
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
}

/// <summary>Protocol versions. A peer that sees a different version refuses to continue.</summary>
public static class ProtocolVersion
{
    public const int Worker = 1;
    public const int Service = 1;
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
}

public sealed class ScanRequestDto
{
    public required List<string> Paths { get; init; }

    public required bool IncludeClean { get; init; }
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
