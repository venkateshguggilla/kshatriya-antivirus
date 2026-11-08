using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Updates;

namespace Sentinel.Service;

/// <summary>
/// Installed signature/rule content (content/). Keeps the signed packages themselves, not extracted
/// files, so every start re-verifies the active package's signature and hashes. state.json records the
/// active sequence and the highest sequence ever installed; a package must exceed the latter
/// (anti-rollback). The newest two packages are kept.
/// </summary>
public sealed class ContentStore
{
    private readonly string _directory;
    private readonly bool _production;

    public ContentStore(string directory, bool production)
    {
        _directory = directory;
        _production = production;
        Directory.CreateDirectory(directory);
    }

    public long ActiveSequence => ReadState().Active;

    public long HighestSequence => ReadState().Highest;

    /// <summary>Loads and re-verifies the active package (expired content is loaded but flagged). Null when none is installed.</summary>
    public VerifiedContent? LoadActive(IReadOnlyCollection<ContentKey> keys, DateTimeOffset now)
    {
        long active = ReadState().Active;
        if (active == 0)
        {
            return null;
        }

        VerifiedContent content = ContentPackage.Verify(File.ReadAllBytes(PackagePath(active)), keys, now, allowExpired: true);
        return content.Manifest.Sequence == active
            ? content
            : throw new ContentVerificationException(ContentErrors.Malformed, "The installed package does not match the recorded sequence.");
    }

    /// <summary>Refuses packages that do not move forward. Call before activating.</summary>
    public void CheckForward(ContentManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        long highest = ReadState().Highest;
        if (manifest.Sequence <= highest)
        {
            throw new ContentVerificationException(ContentErrors.Rollback, $"Package sequence {manifest.Sequence} is not newer than the installed sequence {highest}; older content is refused.");
        }
    }

    /// <summary>Stores the package file (not yet active). Returns its path.</summary>
    public string Stage(long sequence, byte[] package)
    {
        string path = PackagePath(sequence);
        string temp = path + ".tmp";
        File.WriteAllBytes(temp, package);
        File.Move(temp, path, overwrite: true);
        return path;
    }

    public void Discard(long sequence) => File.Delete(PackagePath(sequence));

    /// <summary>Makes a staged package active and prunes old packages.</summary>
    public void Activate(long sequence)
    {
        var state = ReadState();
        WriteState(sequence, Math.Max(state.Highest, sequence));
        foreach (string old in Directory.EnumerateFiles(_directory, "*.sntu")
                     .Select(p => (Path: p, Seq: long.TryParse(Path.GetFileNameWithoutExtension(p), out long s) ? s : 0))
                     .Where(p => p.Seq != sequence)
                     .OrderByDescending(p => p.Seq)
                     .Skip(1)
                     .Select(p => p.Path))
        {
            File.Delete(old);
        }
    }

    private string PackagePath(long sequence) => Path.Combine(_directory, $"{sequence}.sntu");

    private string StatePath => Path.Combine(_directory, "state.json");

    private (long Active, long Highest) ReadState()
    {
        if (!File.Exists(StatePath))
        {
            return (0, 0);
        }

        ContentStateDto dto = JsonSerializer.Deserialize(File.ReadAllText(StatePath), ContentStateJsonContext.Default.ContentStateDto)
            ?? throw new FormatException("Empty content state.");
        return dto.SchemaVersion == 1 && dto.ActiveSequence >= 0 && dto.HighestSequence >= dto.ActiveSequence
            ? (dto.ActiveSequence, dto.HighestSequence)
            : throw new FormatException("Invalid content state.");
    }

    private void WriteState(long active, long highest) =>
        SecureStorage.WriteProtectedFile(
            StatePath,
            JsonSerializer.Serialize(new ContentStateDto { SchemaVersion = 1, ActiveSequence = active, HighestSequence = highest }, ContentStateJsonContext.Default.ContentStateDto),
            _production);
}

internal sealed class ContentStateDto
{
    public required int SchemaVersion { get; init; }

    public required long ActiveSequence { get; init; }

    public required long HighestSequence { get; init; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    RespectNullableAnnotations = true)]
[JsonSerializable(typeof(ContentStateDto))]
internal sealed partial class ContentStateJsonContext : JsonSerializerContext
{
}
