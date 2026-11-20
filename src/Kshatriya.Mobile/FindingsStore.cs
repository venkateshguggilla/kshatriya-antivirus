using System.Text.Json;
using System.Text.Json.Serialization;
using Kshatriya.Core;

namespace Kshatriya.Mobile;

/// <summary>A finding the Android app remembers (ADR 0021, section 5): an app or a file that matched.</summary>
public sealed class MobileFinding
{
    /// <summary>"app:&lt;package&gt;" or "file:&lt;location&gt;".</summary>
    public string Key { get; set; } = string.Empty;

    public bool IsApp { get; set; }

    public string DisplayName { get; set; } = string.Empty;

    public string? PackageName { get; set; }

    public string Location { get; set; } = string.Empty;

    /// <summary>True for a confirmed detection; false for a suspicious one (for example a package name alone).</summary>
    public bool Confirmed { get; set; }

    public string DetectionName { get; set; } = string.Empty;

    /// <summary>Wire name of the category (malware, pua, test, suspicious).</summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>Wire name of the confidence (low, medium, high).</summary>
    public string Confidence { get; set; } = string.Empty;

    /// <summary>"scan", "new app" or "update".</summary>
    public string Source { get; set; } = string.Empty;

    public DateTimeOffset FirstSeenUtc { get; set; }

    public DateTimeOffset LastSeenUtc { get; set; }

    /// <summary>The user chose to keep it: it no longer counts on Home (it is still reported by scans).</summary>
    public bool Kept { get; set; }

    /// <summary>Why it no longer applies ("app removed", "no longer matches"), or null while it does.</summary>
    public string? ResolvedReason { get; set; }

    [JsonIgnore]
    public bool NeedsReview => ResolvedReason is null && !Kept;
}

/// <summary>One finished scan, for History and Home's "last checked".</summary>
public sealed class ScanRecord
{
    /// <summary>"apps", "files", "folder", "new apps" or "update".</summary>
    public string Kind { get; set; } = string.Empty;

    public DateTimeOffset FinishedUtc { get; set; }

    public int Checked { get; set; }

    public int Threats { get; set; }

    public int Suspicious { get; set; }

    public int NotScanned { get; set; }
}

/// <summary>
/// Findings and recent scans, kept in app-private storage so History and Home survive a restart. Bounded
/// (<see cref="MaxFindings"/>, <see cref="MaxScans"/>); a damaged file is discarded. Thread-safe.
/// </summary>
public sealed class FindingsStore
{
    public const int MaxFindings = 1000;
    public const int MaxScans = 50;

    private readonly object _gate = new();
    private readonly string? _path;
    private readonly StoredFindings _data;

    /// <summary>A store kept in <paramref name="path"/>, or only in memory when it is null.</summary>
    public FindingsStore(string? path = null)
    {
        _path = path;
        _data = path is null ? new StoredFindings() : Load(path);
    }

    public IReadOnlyList<MobileFinding> Findings
    {
        get
        {
            lock (_gate)
            {
                return [.. _data.Findings];
            }
        }
    }

    public IReadOnlyList<ScanRecord> Scans
    {
        get
        {
            lock (_gate)
            {
                return [.. _data.Scans];
            }
        }
    }

    /// <summary>When installed apps were last all checked; null when never.</summary>
    public DateTimeOffset? LastAppScanUtc
    {
        get
        {
            lock (_gate)
            {
                return _data.LastAppScanUtc;
            }
        }
    }

    /// <summary>Packages the last full app scan could not read (the Apps page's "Not checked").</summary>
    public IReadOnlySet<string> NotScannedApps
    {
        get
        {
            lock (_gate)
            {
                return new HashSet<string>(_data.NotScannedApps, StringComparer.Ordinal);
            }
        }
    }

    public (int Confirmed, int Suspicious) CountUnresolved()
    {
        lock (_gate)
        {
            return (_data.Findings.Count(f => f.NeedsReview && f.Confirmed), _data.Findings.Count(f => f.NeedsReview && !f.Confirmed));
        }
    }

    public static string KeyOf(MobileScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.PackageName is { } package ? "app:" + package : "file:" + target.Location;
    }

    /// <summary>
    /// Records the results of a scan. Detected and suspicious items are added or refreshed; an app or file that
    /// was flagged before and is now clean is marked "no longer matches". Returns the findings seen for the
    /// first time (or flagged again after being resolved), for a notification.
    /// </summary>
    public IReadOnlyList<MobileFinding> Record(IEnumerable<MobileScanResult> results, string kind, string source, DateTimeOffset now, bool allApps = false)
    {
        ArgumentNullException.ThrowIfNull(results);
        var fresh = new List<MobileFinding>();
        int count = 0, threats = 0, suspicious = 0, notScanned = 0;
        var notScannedApps = new List<string>();
        lock (_gate)
        {
            foreach (MobileScanResult result in results)
            {
                count++;
                string key = KeyOf(result.Target);
                MobileFinding? existing = _data.Findings.FirstOrDefault(f => f.Key == key);
                switch (result.Item.Status)
                {
                    case ScanStatus.Detected or ScanStatus.Suspicious:
                        bool confirmed = result.Item.Status == ScanStatus.Detected;
                        threats += confirmed ? 1 : 0;
                        suspicious += confirmed ? 0 : 1;
                        Detection first = result.Item.Detections.FirstOrDefault(d => d.Category != DetectionCategory.Suspicious) ?? result.Item.Detections[0];
                        if (existing is null)
                        {
                            existing = new MobileFinding { Key = key, FirstSeenUtc = now };
                            _data.Findings.Add(existing);
                            fresh.Add(existing);
                        }
                        else if (existing.ResolvedReason is not null)
                        {
                            existing.ResolvedReason = null;
                            existing.Kept = false;
                            fresh.Add(existing);
                        }

                        existing.IsApp = result.Target.PackageName is not null;
                        existing.DisplayName = result.Target.DisplayName;
                        existing.PackageName = result.Target.PackageName;
                        existing.Location = result.Target.Location;
                        existing.Confirmed = confirmed;
                        existing.DetectionName = first.Name;
                        existing.Category = WireNames.Of(first.Category);
                        existing.Confidence = WireNames.Of(first.Confidence);
                        existing.Source = source;
                        existing.LastSeenUtc = now;
                        break;
                    case ScanStatus.Clean when existing is { ResolvedReason: null }:
                        existing.ResolvedReason = "no longer matches";
                        existing.LastSeenUtc = now;
                        break;
                    case ScanStatus.NotScanned or ScanStatus.Skipped:
                        notScanned++;
                        if (result.Target.PackageName is { } package)
                        {
                            notScannedApps.Add(package);
                        }

                        break;
                }
            }

            if (allApps)
            {
                _data.LastAppScanUtc = now;
                _data.NotScannedApps = notScannedApps;
            }

            _data.Scans.Add(new ScanRecord { Kind = kind, FinishedUtc = now, Checked = count - notScanned, Threats = threats, Suspicious = suspicious, NotScanned = notScanned });
            Trim();
            SaveLocked();
        }

        return fresh;
    }

    /// <summary>Marks findings of apps that are no longer installed as resolved ("app removed").</summary>
    public void AppsRemoved(IReadOnlySet<string> installedPackages)
    {
        ArgumentNullException.ThrowIfNull(installedPackages);
        lock (_gate)
        {
            bool changed = false;
            foreach (MobileFinding f in _data.Findings.Where(f => f.IsApp && f.ResolvedReason is null && f.PackageName is { } p && !installedPackages.Contains(p)))
            {
                f.ResolvedReason = "app removed";
                changed = true;
            }

            if (changed)
            {
                SaveLocked();
            }
        }
    }

    /// <summary>Keeps (or stops keeping) a finding. Returns false when there is no such finding.</summary>
    public bool SetKept(string key, bool kept)
    {
        lock (_gate)
        {
            if (_data.Findings.FirstOrDefault(f => f.Key == key) is not { } finding)
            {
                return false;
            }

            finding.Kept = kept;
            SaveLocked();
            return true;
        }
    }

    public MobileFinding? Find(string key)
    {
        lock (_gate)
        {
            return _data.Findings.FirstOrDefault(f => f.Key == key);
        }
    }

    private void Trim()
    {
        if (_data.Findings.Count > MaxFindings)
        {
            // Resolved findings go first, oldest first; open ones only if there is no other way.
            foreach (MobileFinding old in _data.Findings.OrderBy(f => f.ResolvedReason is null).ThenBy(f => f.LastSeenUtc).Take(_data.Findings.Count - MaxFindings).ToList())
            {
                _data.Findings.Remove(old);
            }
        }

        if (_data.Scans.Count > MaxScans)
        {
            _data.Scans.RemoveRange(0, _data.Scans.Count - MaxScans);
        }
    }

    private void SaveLocked()
    {
        if (_path is null)
        {
            return;
        }

        try
        {
            string temporary = _path + ".new";
            File.WriteAllText(temporary, JsonSerializer.Serialize(_data, FindingsJsonContext.Default.StoredFindings));
            File.Move(temporary, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not persisted this time; the next change tries again.
        }
    }

    private static StoredFindings Load(string path)
    {
        try
        {
            if (File.Exists(path) && JsonSerializer.Deserialize(File.ReadAllText(path), FindingsJsonContext.Default.StoredFindings) is { } loaded
                && loaded.Findings.All(f => f.Key.Length is > 0 and <= 4096) && loaded.Findings.Count <= MaxFindings && loaded.Scans.Count <= MaxScans)
            {
                return loaded;
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Damaged: start empty.
        }

        return new StoredFindings();
    }
}

internal sealed class StoredFindings
{
    public List<MobileFinding> Findings { get; set; } = [];

    public List<ScanRecord> Scans { get; set; } = [];

    public DateTimeOffset? LastAppScanUtc { get; set; }

    public List<string> NotScannedApps { get; set; } = [];
}

[JsonSerializable(typeof(StoredFindings))]
internal sealed partial class FindingsJsonContext : JsonSerializerContext
{
}
