using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Scanning;

namespace Kshatriya.Service;

/// <summary>
/// The service's persistent exclusions (config/exclusions.json). The file is written only by the
/// service, on behalf of elevated administrators, and is refused at startup unless only SYSTEM and
/// Administrators can change it. Exclusions affect Kshatriya scans only, never Microsoft Defender.
/// </summary>
public sealed class ExclusionStore
{
    public const int MaxEntries = 1000;
    private readonly string _file;
    private readonly bool _production;
    private readonly Lock _gate = new();
    private ExclusionSet _current;

    private ExclusionStore(string file, bool production, ExclusionSet current)
    {
        _file = file;
        _production = production;
        _current = current;
    }

    public ExclusionSet Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    /// <summary>Loads the exclusions file, verifying that only trusted accounts can modify it.</summary>
    public static ExclusionStore Load(string file, bool production)
    {
        ArgumentException.ThrowIfNullOrEmpty(file);
        if (!File.Exists(file))
        {
            return new ExclusionStore(file, production, ExclusionSet.Empty);
        }

        string? problem = SecureStorage.CheckTrustedFile(file, production);
        if (problem is not null)
        {
            throw new InvalidOperationException($"Refusing to use the exclusions file: {problem}");
        }

        return new ExclusionStore(file, production, Parse(File.ReadAllText(file)));
    }

    public static ExclusionSet Parse(string json)
    {
        ExclusionsFileDto dto;
        try
        {
            dto = JsonSerializer.Deserialize(json, ExclusionsJsonContext.Default.ExclusionsFileDto)
                ?? throw new FormatException("Exclusions file is empty.");
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Exclusions file is not valid: {ex.Message}", ex);
        }

        if (dto.SchemaVersion != 1)
        {
            throw new FormatException($"Unsupported exclusions schemaVersion {dto.SchemaVersion}; expected 1.");
        }

        try
        {
            return new ExclusionSet(dto.Paths, dto.Sha256);
        }
        catch (ArgumentException ex)
        {
            throw new FormatException(ex.Message, ex);
        }
    }

    /// <summary>Adds a path or SHA-256 exclusion. Returns null on success or the reason it was rejected.</summary>
    public string? Add(string value) => Change(value, add: true);

    /// <summary>Removes a path or SHA-256 exclusion. Returns null on success or the reason it was rejected.</summary>
    public string? Remove(string value) => Change(value, add: false);

    private string? Change(string value, bool add)
    {
        ArgumentNullException.ThrowIfNull(value);
        lock (_gate)
        {
            var paths = _current.Paths.ToList();
            var hashes = _current.Hashes.ToList();
            if (ExclusionSet.NormalizeHash(value) is string hash)
            {
                if (add ? hashes.Contains(hash) : !hashes.Remove(hash))
                {
                    return add ? "That SHA-256 is already excluded." : "That SHA-256 is not excluded.";
                }

                if (add)
                {
                    hashes.Add(hash);
                }
            }
            else
            {
                string? problem = ExclusionSet.ValidatePath(value);
                if (problem is not null)
                {
                    return problem + " Exclusions are fully qualified local paths or SHA-256 values.";
                }

                string path = ExclusionSet.NormalizePath(value);
                int index = paths.FindIndex(p => string.Equals(p, path, StringComparison.OrdinalIgnoreCase));
                if (add ? index >= 0 : index < 0)
                {
                    return add ? "That path is already excluded." : "That path is not excluded.";
                }

                if (add)
                {
                    paths.Add(path);
                }
                else
                {
                    paths.RemoveAt(index);
                }
            }

            if (paths.Count + hashes.Count > MaxEntries)
            {
                return $"At most {MaxEntries} exclusions are supported.";
            }

            var next = new ExclusionSet(paths, hashes);
            Save(next);
            _current = next;
            return null;
        }
    }

    private void Save(ExclusionSet set)
    {
        var dto = new ExclusionsFileDto { SchemaVersion = 1, Paths = [.. set.Paths], Sha256 = [.. set.Hashes.Order(StringComparer.Ordinal)] };
        SecureStorage.WriteProtectedFile(_file, JsonSerializer.Serialize(dto, ExclusionsJsonContext.Default.ExclusionsFileDto), _production);
    }
}

internal sealed class ExclusionsFileDto
{
    public required int SchemaVersion { get; init; }

    public required List<string> Paths { get; init; }

    public required List<string> Sha256 { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true,
    WriteIndented = true,
    MaxDepth = 8)]
[JsonSerializable(typeof(ExclusionsFileDto))]
internal sealed partial class ExclusionsJsonContext : JsonSerializerContext
{
}
