using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Service;

/// <summary>A recurring scan run by the service itself (as LocalSystem).</summary>
/// <param name="Name">Unique name, used in reports and status.</param>
/// <param name="Days">Days of the week it runs on.</param>
/// <param name="Time">Local time of day.</param>
/// <param name="Paths">Fully qualified local paths.</param>
/// <param name="Quarantine">True to quarantine high-confidence detections ("action": "quarantine"); false only reports.</param>
public sealed record ScheduledScan(string Name, IReadOnlySet<DayOfWeek> Days, TimeOnly Time, IReadOnlyList<string> Paths, bool Quarantine = false);

/// <summary>Validated service configuration (config/service.json, schema version 1).</summary>
public sealed record ServiceSettings
{
    public const int SchemaVersion = 1;

    public int Workers { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    public IReadOnlyList<string> SignatureFiles { get; init; } = [];

    public IReadOnlyList<string> RuleFiles { get; init; } = [];

    public bool Heuristics { get; init; } = true;

    public bool HeuristicsIncludeSigned { get; init; }

    public long MaxFileSizeBytes { get; init; } = 256L * 1024 * 1024;

    public int ReportRetention { get; init; } = 30;

    public int MaxConcurrentScans { get; init; } = 2;

    public IReadOnlyList<ScheduledScan> ScheduledScans { get; init; } = [];

    /// <summary>Parses and validates settings. Any unknown member or invalid value rejects the whole file.</summary>
    public static ServiceSettings Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        ServiceSettingsDto dto;
        try
        {
            dto = JsonSerializer.Deserialize(json, ServiceSettingsJsonContext.Default.ServiceSettingsDto)
                ?? throw new FormatException("Settings file is empty.");
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Settings file is not valid: {ex.Message}", ex);
        }

        if (dto.SchemaVersion != SchemaVersion)
        {
            throw new FormatException($"Unsupported settings schemaVersion {dto.SchemaVersion}; expected {SchemaVersion}.");
        }

        var defaults = new ServiceSettings();
        var schedules = new List<ScheduledScan>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (ScheduleDto s in dto.ScheduledScans ?? [])
        {
            if (string.IsNullOrWhiteSpace(s.Name) || s.Name.Length > 64 || !s.Name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                throw new FormatException($"Schedule name '{s.Name}' must be 1-64 letters, digits, '-' or '_'.");
            }

            if (!names.Add(s.Name))
            {
                throw new FormatException($"Duplicate schedule name '{s.Name}'.");
            }

            if (!TimeOnly.TryParseExact(s.Time, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out TimeOnly time))
            {
                throw new FormatException($"Schedule '{s.Name}': time '{s.Time}' must be HH:mm (24-hour, local time).");
            }

            bool quarantine = s.Action switch
            {
                null or "report" => false,
                "quarantine" => true,
                _ => throw new FormatException($"Schedule '{s.Name}': action '{s.Action}' must be \"report\" or \"quarantine\"."),
            };
            schedules.Add(new ScheduledScan(s.Name, ParseDays(s.Name, s.Days), time, ValidatePaths(s.Name, s.Paths), quarantine));
        }

        return new ServiceSettings
        {
            Workers = Range(dto.Workers, defaults.Workers, 1, 16, "workers"),
            SignatureFiles = ValidateFiles(dto.SignatureFiles, "signatureFiles"),
            RuleFiles = ValidateFiles(dto.RuleFiles, "ruleFiles"),
            Heuristics = dto.Heuristics ?? defaults.Heuristics,
            HeuristicsIncludeSigned = dto.HeuristicsIncludeSigned ?? defaults.HeuristicsIncludeSigned,
            MaxFileSizeBytes = Range(dto.MaxFileSizeMiB, (int)(defaults.MaxFileSizeBytes >> 20), 1, 1024, "maxFileSizeMiB") * 1024L * 1024,
            ReportRetention = Range(dto.ReportRetention, defaults.ReportRetention, 1, 1000, "reportRetention"),
            MaxConcurrentScans = Range(dto.MaxConcurrentScans, defaults.MaxConcurrentScans, 1, 8, "maxConcurrentScans"),
            ScheduledScans = schedules,
        };
    }

    private static int Range(int? value, int fallback, int min, int max, string name)
    {
        int v = value ?? fallback;
        return v >= min && v <= max ? v : throw new FormatException($"'{name}' must be between {min} and {max}.");
    }

    private static string[] ValidateFiles(List<string>? files, string name)
    {
        string[] list = [.. files ?? []];
        foreach (string f in list)
        {
            if (!ScanPathPolicy.IsLocalAbsolutePath(f))
            {
                throw new FormatException($"'{name}' entry '{f}' must be a fully qualified local path.");
            }
        }

        return list;
    }

    private static string[] ValidatePaths(string schedule, List<string> paths)
    {
        if (paths.Count == 0)
        {
            throw new FormatException($"Schedule '{schedule}' needs at least one path.");
        }

        foreach (string p in paths)
        {
            if (!ScanPathPolicy.IsLocalAbsolutePath(p))
            {
                throw new FormatException($"Schedule '{schedule}': path '{p}' must be a fully qualified local path.");
            }
        }

        return [.. paths];
    }

    private static HashSet<DayOfWeek> ParseDays(string schedule, List<string> days)
    {
        var result = new HashSet<DayOfWeek>();
        foreach (string d in days)
        {
            if (string.Equals(d, "daily", StringComparison.OrdinalIgnoreCase))
            {
                result.UnionWith(Enum.GetValues<DayOfWeek>());
                continue;
            }

            DayOfWeek day = d.ToLowerInvariant() switch
            {
                "sunday" => DayOfWeek.Sunday,
                "monday" => DayOfWeek.Monday,
                "tuesday" => DayOfWeek.Tuesday,
                "wednesday" => DayOfWeek.Wednesday,
                "thursday" => DayOfWeek.Thursday,
                "friday" => DayOfWeek.Friday,
                "saturday" => DayOfWeek.Saturday,
                _ => throw new FormatException($"Schedule '{schedule}': unknown day '{d}'."),
            };
            result.Add(day);
        }

        return result.Count > 0 ? result : throw new FormatException($"Schedule '{schedule}' needs at least one day.");
    }
}

internal sealed class ServiceSettingsDto
{
    public required int SchemaVersion { get; init; }

    public int? Workers { get; init; }

    public List<string>? SignatureFiles { get; init; }

    public List<string>? RuleFiles { get; init; }

    public bool? Heuristics { get; init; }

    public bool? HeuristicsIncludeSigned { get; init; }

    public int? MaxFileSizeMiB { get; init; }

    public int? ReportRetention { get; init; }

    public int? MaxConcurrentScans { get; init; }

    public List<ScheduleDto>? ScheduledScans { get; init; }
}

internal sealed class ScheduleDto
{
    public required string Name { get; init; }

    public required List<string> Days { get; init; }

    public required string Time { get; init; }

    public required List<string> Paths { get; init; }

    public string? Action { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(ServiceSettingsDto))]
internal sealed partial class ServiceSettingsJsonContext : JsonSerializerContext
{
}
