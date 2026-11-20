using System.Text.Json;

namespace Kshatriya.App.Services;

/// <summary>
/// Findings the user chose to keep ("Keep file", ADR 0021). This is the user's acknowledgement inside the
/// app only: it is not an exclusion, changes nothing in the service, and the file is still reported by every
/// scan. It only stops the finding counting toward Home's status.
/// </summary>
public interface IReviewStore
{
    bool IsKept(string key);

    void Keep(string key);

    void Unkeep(string key);

    /// <summary>The key of a finding: its path and detection names, so a different detection of the same file is new.</summary>
    static string KeyOf(string path, IEnumerable<string> names) =>
        path.ToUpperInvariant() + "|" + string.Join(",", names.Order(StringComparer.Ordinal));
}

/// <summary>Kept findings in memory only (tests).</summary>
public sealed class InMemoryReviewStore : IReviewStore
{
    private readonly HashSet<string> _kept = new(StringComparer.Ordinal);

    public bool IsKept(string key) => _kept.Contains(key);

    public void Keep(string key) => _kept.Add(key);

    public void Unkeep(string key) => _kept.Remove(key);
}

/// <summary>Kept findings in %LocalAppData%\Kshatriya\reviewed.json (per user, at most <see cref="MaxEntries"/>).</summary>
public sealed class FileReviewStore : IReviewStore
{
    public const int MaxEntries = 1000;

    private readonly string _path;
    private readonly List<string> _kept = [];

    public FileReviewStore(string? path = null)
    {
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kshatriya", "reviewed.json");
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement e in document.RootElement.EnumerateArray().Take(MaxEntries))
                {
                    if (e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 and <= 4096 } key)
                    {
                        _kept.Add(key);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // Missing or damaged: start empty (nothing is hidden by a broken file).
        }
    }

    public bool IsKept(string key) => _kept.Contains(key, StringComparer.Ordinal);

    public void Keep(string key)
    {
        if (!IsKept(key))
        {
            _kept.Add(key);
            if (_kept.Count > MaxEntries)
            {
                _kept.RemoveAt(0); // the oldest choice goes first
            }

            Save();
        }
    }

    public void Unkeep(string key)
    {
        if (_kept.Remove(key))
        {
            Save();
        }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(_kept));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not persisted; the choice still applies until the app exits.
        }
    }
}
