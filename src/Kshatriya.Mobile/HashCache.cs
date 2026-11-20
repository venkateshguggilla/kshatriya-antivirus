using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kshatriya.Mobile;

/// <summary>Remembers file hashes between scans (ADR 0020, point 11).</summary>
public interface IHashCache
{
    bool TryGet(string key, out string sha256, out long length);

    void Store(string key, string sha256, long length);
}

/// <summary>
/// A hash cache in one app-private JSON file. Keys combine path, size and modification time, so a changed
/// file gets a new key. Holds at most <see cref="MaxEntries"/> entries (the oldest are dropped); a damaged
/// file is discarded.
/// </summary>
public sealed class FileHashCache : IHashCache
{
    public const int MaxEntries = 20_000;
    private readonly string _path;
    private readonly object _gate = new();
    private readonly Dictionary<string, CacheEntry> _entries;
    private long _clock;
    private bool _dirty;

    public FileHashCache(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        _path = path;
        _entries = Load(path);
        _clock = _entries.Count == 0 ? 0 : _entries.Values.Max(e => e.Used);
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>The cache key for a file: path, size and last write time.</summary>
    public static string KeyFor(string path, long size, DateTime lastWriteUtc) =>
        $"{path}|{size}|{lastWriteUtc.Ticks}";

    public bool TryGet(string key, out string sha256, out long length)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out CacheEntry? entry))
            {
                entry.Used = ++_clock;
                _dirty = true;
                (sha256, length) = (entry.Sha256, entry.Length);
                return true;
            }
        }

        (sha256, length) = (string.Empty, 0);
        return false;
    }

    public void Store(string key, string sha256, long length)
    {
        lock (_gate)
        {
            _entries[key] = new CacheEntry { Sha256 = sha256, Length = length, Used = ++_clock };
            if (_entries.Count > MaxEntries)
            {
                foreach (string old in _entries.OrderBy(e => e.Value.Used).Take(_entries.Count - MaxEntries).Select(e => e.Key).ToList())
                {
                    _entries.Remove(old);
                }
            }

            _dirty = true;
        }
    }

    /// <summary>Writes the cache if it changed (write to a temporary file, then replace).</summary>
    public void Save()
    {
        lock (_gate)
        {
            if (!_dirty)
            {
                return;
            }

            string temporary = _path + ".new";
            File.WriteAllText(temporary, JsonSerializer.Serialize(_entries, HashCacheJsonContext.Default.DictionaryStringCacheEntry));
            File.Move(temporary, _path, overwrite: true);
            _dirty = false;
        }
    }

    private static Dictionary<string, CacheEntry> Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                Dictionary<string, CacheEntry>? loaded = JsonSerializer.Deserialize(File.ReadAllText(path), HashCacheJsonContext.Default.DictionaryStringCacheEntry);
                if (loaded is not null && loaded.Values.All(e => e.Sha256.Length == 64 && e.Length >= 0))
                {
                    return new Dictionary<string, CacheEntry>(loaded, StringComparer.Ordinal);
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            // A damaged cache only costs time: start empty.
        }

        return new Dictionary<string, CacheEntry>(StringComparer.Ordinal);
    }
}

internal sealed class CacheEntry
{
    public string Sha256 { get; set; } = string.Empty;

    public long Length { get; set; }

    public long Used { get; set; }
}

[JsonSerializable(typeof(Dictionary<string, CacheEntry>))]
internal sealed partial class HashCacheJsonContext : JsonSerializerContext
{
}
