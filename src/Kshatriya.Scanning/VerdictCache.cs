using System.Collections.Concurrent;
using Kshatriya.Core;

namespace Kshatriya.Scanning;

/// <summary>What is remembered about a file that scanned clean.</summary>
public sealed record CachedVerdict(string Sha256, FileTrust? Trust);

/// <summary>
/// Remembers files that scanned completely clean so unchanged files are not read again. Only clean,
/// complete results are cached; detections, suspicious and partial results are always rescanned.
/// An entry is reused only when the file identity, length, last-write and change times and the
/// analyzer configuration fingerprint all match exactly.
/// </summary>
/// <remarks>
/// Limitation (documented in the threat model): a process that can write a file can also reset its
/// timestamps, so a cached verdict can be stale for a file deliberately modified to look unchanged.
/// Scheduled full scans bypass the cache to bound that window.
/// </remarks>
public sealed class VerdictCache
{
    private readonly ConcurrentDictionary<FileIdentity, Entry> _entries = new();
    private readonly int _maxEntries;
    private long _hits;
    private long _misses;

    /// <param name="maxEntries">Upper bound on remembered files.</param>
    /// <param name="racyWindow">
    /// Files changed more recently than this are never cached. File-system timestamps advance in clock
    /// ticks (about 15.6 ms), so a same-size rewrite within one tick can leave every stamp unchanged; a
    /// file is only trusted to be stable once its stamps are clearly in the past. Default 2 seconds.
    /// </param>
    public VerdictCache(int maxEntries = 500_000, TimeSpan? racyWindow = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _maxEntries = maxEntries;
        RacyWindow = racyWindow ?? TimeSpan.FromSeconds(2);
    }

    public TimeSpan RacyWindow { get; }

    public long Hits => Interlocked.Read(ref _hits);

    public long Misses => Interlocked.Read(ref _misses);

    public int Count => _entries.Count;

    public bool TryGet(FileIdentity identity, string fingerprint, out CachedVerdict? verdict)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        if (_entries.TryGetValue(identity, out Entry entry) && string.Equals(entry.Fingerprint, fingerprint, StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _hits);
            verdict = entry.Verdict;
            return true;
        }

        Interlocked.Increment(ref _misses);
        verdict = null;
        return false;
    }

    /// <summary>Remembers a clean verdict. Returns false (and stores nothing) for recently changed files.</summary>
    public bool Store(FileIdentity identity, string fingerprint, CachedVerdict verdict)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        ArgumentNullException.ThrowIfNull(verdict);
        if (IsRacy(identity))
        {
            return false;
        }

        if (_entries.Count >= _maxEntries)
        {
            // Simple bound: start over rather than track recency. Correctness never depends on the cache.
            _entries.Clear();
        }

        _entries[identity] = new Entry(fingerprint, verdict);
        return true;
    }

    public void Clear() => _entries.Clear();

    private bool IsRacy(FileIdentity identity)
    {
        long newest = Math.Max(identity.LastWriteTime, identity.ChangeTime);
        if (newest <= 0)
        {
            return true;
        }

        DateTime changed = DateTime.FromFileTimeUtc(newest);
        return DateTime.UtcNow - changed < RacyWindow;
    }

    private readonly record struct Entry(string Fingerprint, CachedVerdict Verdict);
}
