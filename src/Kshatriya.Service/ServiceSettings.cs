using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Core;
using Kshatriya.Scanning.Targets;

namespace Kshatriya.Service;

/// <summary>A recurring scan run by the service itself (as LocalSystem).</summary>
/// <param name="Name">Unique name, used in reports and status.</param>
/// <param name="Days">Days of the week it runs on.</param>
/// <param name="Time">Local time of day.</param>
/// <param name="Paths">Fully qualified local paths (custom scans); empty for quick and full scans.</param>
/// <param name="Quarantine">True to quarantine high-confidence detections ("action": "quarantine"); false only reports.</param>
/// <param name="Kind">"scan": "custom" (default, uses Paths), "quick" (all profiles) or "full" (all fixed drives).</param>
public sealed record ScheduledScan(string Name, IReadOnlySet<DayOfWeek> Days, TimeOnly Time, IReadOnlyList<string> Paths, bool Quarantine = false, ScanKind Kind = ScanKind.Custom);

/// <summary>Validated service configuration (config/service.json, schema version 1).</summary>
public sealed record ServiceSettings
{
    public const int SchemaVersion = 1;

    public int Workers { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    public IReadOnlyList<string> SignatureFiles { get; init; } = [];

    public IReadOnlyList<string> RuleFiles { get; init; } = [];

    public bool Heuristics { get; init; } = true;

    public bool HeuristicsIncludeSigned { get; init; }

    public long MaxFileSizeBytes { get; init; } = ScanLimits.DefaultMaxFileSizeBytes;

    public int ReportRetention { get; init; } = 30;

    public int MaxConcurrentScans { get; init; } = 2;

    public IReadOnlyList<ScheduledScan> ScheduledScans { get; init; } = [];

    /// <summary>Block outbound connections to addresses in installed blocklists (WFP, off by default).</summary>
    public bool NetworkProtection { get; init; }

    /// <summary>Use machine-learning models from installed content (off by default; results are suspicious only).</summary>
    public bool MachineLearning { get; init; }

    /// <summary>Real-time monitoring (disabled unless configured).</summary>
    public RealTime.RealTimeOptions RealTime { get; init; } = new();

    /// <summary>Additional content signing public keys (base64 SubjectPublicKeyInfo, ECDSA P-256).</summary>
    public IReadOnlyList<string> ContentKeys { get; init; } = [];

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
            ScanKind kind = ScanKindNames.Parse(s.Scan)
                ?? throw new FormatException($"Schedule '{s.Name}': scan '{s.Scan}' must be \"custom\", \"quick\" or \"full\".");
            string[] paths = kind == ScanKind.Custom
                ? ValidatePaths(s.Name, s.Paths ?? [])
                : s.Paths is { Count: > 0 }
                    ? throw new FormatException($"Schedule '{s.Name}': a {ScanKindNames.Of(kind)} scan takes no paths.")
                    : [];
            schedules.Add(new ScheduledScan(s.Name, ParseDays(s.Name, s.Days), time, paths, quarantine, kind));
        }

        return new ServiceSettings
        {
            Workers = Range(dto.Workers, defaults.Workers, 1, 16, "workers"),
            SignatureFiles = ValidateFiles(dto.SignatureFiles, "signatureFiles"),
            RuleFiles = ValidateFiles(dto.RuleFiles, "ruleFiles"),
            Heuristics = dto.Heuristics ?? defaults.Heuristics,
            HeuristicsIncludeSigned = dto.HeuristicsIncludeSigned ?? defaults.HeuristicsIncludeSigned,
            MaxFileSizeBytes = Range(dto.MaxFileSizeMiB, (int)(defaults.MaxFileSizeBytes >> 20), 1, 65536, "maxFileSizeMiB") * 1024L * 1024,
            ReportRetention = Range(dto.ReportRetention, defaults.ReportRetention, 1, 1000, "reportRetention"),
            MaxConcurrentScans = Range(dto.MaxConcurrentScans, defaults.MaxConcurrentScans, 1, 8, "maxConcurrentScans"),
            ScheduledScans = schedules,
            ContentKeys = ValidateKeys(dto.ContentKeys),
            RealTime = ParseRealTime(dto.RealTime),
            MachineLearning = dto.MachineLearning ?? false,
            NetworkProtection = dto.NetworkProtection ?? false,
        };
    }

    private static RealTime.RealTimeOptions ParseRealTime(RealTimeDto? dto)
    {
        if (dto is null)
        {
            return new RealTime.RealTimeOptions();
        }

        string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        List<string> paths = dto.Paths is { Count: > 0 } p ? p : [Path.Combine(systemDrive, "Users")];
        if (paths.Count > 32)
        {
            throw new FormatException("'realTime.paths' may list at most 32 folders.");
        }

        foreach (string path in paths)
        {
            if (!ScanPathPolicy.IsLocalAbsolutePath(path))
            {
                throw new FormatException($"'realTime.paths' entry '{path}' must be a fully qualified local path.");
            }
        }

        bool quarantine = dto.Action switch
        {
            null or "report" => false,
            "quarantine" => true,
            _ => throw new FormatException($"'realTime.action' must be \"report\" or \"quarantine\"."),
        };
        int debounce = dto.DebounceSeconds ?? 2;
        if (debounce is < 0 or > 60)
        {
            throw new FormatException("'realTime.debounceSeconds' must be between 0 and 60.");
        }

        return new RealTime.RealTimeOptions
        {
            Enabled = dto.Enabled ?? true,
            Paths = [.. paths],
            Quarantine = quarantine,
            Processes = dto.Processes ?? true,
            RemovableMedia = dto.RemovableMedia ?? true,
            Debounce = TimeSpan.FromSeconds(debounce),
            Behaviour = ParseBehaviour(dto.Ransomware, paths),
        };
    }

    private static RealTime.BehaviourOptions ParseBehaviour(RansomwareDto? dto, List<string> watched)
    {
        if (dto is null)
        {
            return new RealTime.BehaviourOptions();
        }

        int threshold = dto.Threshold ?? 40;
        int window = dto.WindowSeconds ?? 30;
        if (threshold is < 5 or > 10_000 || window is < 5 or > 600)
        {
            throw new FormatException("'ransomware.threshold' must be 5-10000 and 'ransomware.windowSeconds' 5-600.");
        }

        List<string> canaries = dto.CanaryFolders ?? [];
        foreach (string folder in canaries)
        {
            bool inside = watched.Any(w => folder.StartsWith(w.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) || folder.Equals(w, StringComparison.OrdinalIgnoreCase));
            if (!ScanPathPolicy.IsLocalAbsolutePath(folder) || !inside)
            {
                throw new FormatException($"'ransomware.canaryFolders' entry '{folder}' must be a local folder inside a real-time path.");
            }
        }

        return new RealTime.BehaviourOptions
        {
            Enabled = dto.Enabled ?? true,
            Threshold = threshold,
            Window = TimeSpan.FromSeconds(window),
            CanaryFolders = [.. canaries],
        };
    }

    private static string[] ValidateKeys(List<string>? keys)
    {
        string[] list = [.. keys ?? []];
        foreach (string key in list)
        {
            try
            {
                _ = Kshatriya.Updates.ContentKey.Parse(key);
            }
            catch (Exception ex) when (ex is FormatException or System.Security.Cryptography.CryptographicException)
            {
                throw new FormatException($"'contentKeys' entry is not a base64 ECDSA P-256 public key: {ex.Message}", ex);
            }
        }

        return list;
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

    public List<string>? ContentKeys { get; init; }

    public RealTimeDto? RealTime { get; init; }

    public bool? MachineLearning { get; init; }

    public bool? NetworkProtection { get; init; }
}

internal sealed class RealTimeDto
{
    public bool? Enabled { get; init; }

    public List<string>? Paths { get; init; }

    public string? Action { get; init; }

    public bool? Processes { get; init; }

    public bool? RemovableMedia { get; init; }

    public int? DebounceSeconds { get; init; }

    public RansomwareDto? Ransomware { get; init; }
}

internal sealed class RansomwareDto
{
    public bool? Enabled { get; init; }

    public int? Threshold { get; init; }

    public int? WindowSeconds { get; init; }

    public List<string>? CanaryFolders { get; init; }
}

internal sealed class ScheduleDto
{
    public required string Name { get; init; }

    public required List<string> Days { get; init; }

    public required string Time { get; init; }

    /// <summary>Required for custom scans; must be absent or empty for quick and full scans.</summary>
    public List<string>? Paths { get; init; }

    /// <summary>"custom" (default), "quick" or "full".</summary>
    public string? Scan { get; init; }

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
