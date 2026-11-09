using System.Security.Cryptography;

namespace Kshatriya.Service.RealTime;

/// <summary>Ransomware behaviour settings (service.json "ransomware"; requires real-time monitoring).</summary>
public sealed record BehaviourOptions
{
    public bool Enabled { get; init; }

    /// <summary>Distinct existing files rewritten, renamed or deleted within <see cref="Window"/> that triggers an evaluation.</summary>
    public int Threshold { get; init; } = 40;

    public TimeSpan Window { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Folders that get a hidden decoy file (opt-in: this creates files in those folders).</summary>
    public IReadOnlyList<string> CanaryFolders { get; init; } = [];
}

public enum FileEventKind
{
    Created,
    Changed,
    Renamed,
    Deleted,
}

/// <summary>A behaviour finding. Always reported as suspicious; never acted on automatically.</summary>
public sealed record BehaviourAlert(string Name, string Path, string Detail);

/// <summary>
/// Heuristic ransomware behaviour detection on top of user-mode file and process events. Signals:
/// <list type="bullet">
/// <item>mass modification: many <em>existing</em> files rewritten, renamed or deleted in a short window,
/// confirmed by sampled content that looks encrypted (entropy) or by renames to unfamiliar extensions;</item>
/// <item>ransom-note-like files appearing;</item>
/// <item>commands that delete shadow copies or disable recovery;</item>
/// <item>a decoy (canary) file being changed, renamed or deleted.</item>
/// </list>
/// File events carry no process identity in user mode, so alerts name recently started programs from
/// user-writable folders as <em>possible</em> sources. Alerts are suspicious findings only: nothing is
/// terminated, blocked or quarantined because of them.
/// </summary>
public sealed class RansomwareDetector
{
    public const string MassModification = "Behavior:Ransomware.MassModification";
    public const string RansomNote = "Behavior:Ransomware.Note";
    public const string RecoveryTampering = "Behavior:Ransomware.RecoveryTampering";
    public const string CanaryTouched = "Behavior:Ransomware.DecoyModified";
    public const string CanaryFileName = "~$Kshatriya decoy - do not modify.docx";

    private static readonly TimeSpan s_alertCooldown = TimeSpan.FromMinutes(5);
    private static readonly HashSet<string> s_commonExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mp3", ".mp4", ".mov", ".zip", ".7z", ".rar", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".log",
        ".tmp", ".bak", ".exe", ".dll", ".cs", ".py", ".js", ".ts", ".ini", ".cfg", ".config", ".dat", ".db", ".sqlite",
    };

    private readonly BehaviourOptions _options;
    private readonly TimeProvider _time;
    private readonly Func<string, double?> _entropyOf;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (DateTimeOffset Time, FileEventKind Kind, bool UnusualRename)> _destructive = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _created = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _lastAlert = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<(DateTimeOffset Time, string Image)> _recentProcesses = new();
    private readonly List<BehaviourAlert> _pending = [];
    private readonly HashSet<string> _canaries;

    public RansomwareDetector(BehaviourOptions options, TimeProvider time, Func<string, double?>? entropyOf = null)
    {
        _options = options;
        _time = time;
        _entropyOf = entropyOf ?? SampleEntropy;
        _canaries = new HashSet<string>(options.CanaryFolders.Select(f => Path.Combine(f, CanaryFileName)), StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyCollection<string> CanaryPaths => _canaries;

    public void OnFileEvent(string path, FileEventKind kind, string? oldPath = null)
    {
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            if (_canaries.Contains(path) || (oldPath is not null && _canaries.Contains(oldPath)))
            {
                if (kind != FileEventKind.Created)
                {
                    Raise(CanaryTouched, oldPath ?? path, $"A decoy file was {kind.ToString().ToLowerInvariant()}. Something is modifying files it does not own.", now, key: "canary:" + (oldPath ?? path));
                }

                return;
            }

            if (kind == FileEventKind.Created)
            {
                _created[path] = now;
                if (LooksLikeRansomNote(Path.GetFileName(path)))
                {
                    Raise(RansomNote, path, "A file named like a ransom note appeared.", now, key: "note:" + Path.GetDirectoryName(path));
                }

                return;
            }

            // Writes to files that were just created (downloads, unzip, builds) are not destruction.
            if (kind == FileEventKind.Changed && _created.TryGetValue(path, out DateTimeOffset createdAt) && now - createdAt < _options.Window)
            {
                return;
            }

            bool unusualRename = kind == FileEventKind.Renamed && oldPath is not null && IsUnusualRename(oldPath, path);
            _destructive[path] = (now, kind, unusualRename);
        }
    }

    public void OnProcessStart(string image, string? commandLine)
    {
        DateTimeOffset now = _time.GetUtcNow();
        lock (_gate)
        {
            _recentProcesses.AddFirst((now, image));
            while (_recentProcesses.Count > 100)
            {
                _recentProcesses.RemoveLast();
            }

            if (commandLine is not null && IsRecoveryTampering(commandLine))
            {
                Raise(RecoveryTampering, image, $"A program ran a command that deletes backups or disables recovery: {Clip(commandLine)}", now, key: "recovery:" + image);
            }
        }
    }

    /// <summary>Evaluates the window and returns alerts raised since the last call.</summary>
    public IReadOnlyList<BehaviourAlert> Collect()
    {
        DateTimeOffset now = _time.GetUtcNow();
        List<(string Path, FileEventKind Kind, bool UnusualRename)> window;
        lock (_gate)
        {
            Prune(now);
            window = [.. _destructive.Select(d => (d.Key, d.Value.Kind, d.Value.UnusualRename))];
        }

        if (window.Count >= _options.Threshold)
        {
            int unusual = window.Count(w => w.UnusualRename);
            var samples = window.Where(w => w.Kind != FileEventKind.Deleted).Select(w => w.Path).Take(12).Select(_entropyOf).Where(e => e is not null).Select(e => e!.Value).ToList();
            int encrypted = samples.Count(e => e >= 7.5);
            bool confirmed = unusual * 2 >= window.Count || (samples.Count >= 3 && encrypted * 2 >= samples.Count);
            if (confirmed)
            {
                string folder = CommonFolder(window.Select(w => w.Path));
                lock (_gate)
                {
                    Raise(
                        MassModification,
                        folder,
                        $"{window.Count} existing files were rewritten, renamed or deleted within {_options.Window.TotalSeconds:0} s; {encrypted} of {samples.Count} sampled files look encrypted, {unusual} renamed to unfamiliar extensions.",
                        now,
                        key: "mass:" + folder);
                    _destructive.Clear();
                }
            }
        }

        lock (_gate)
        {
            BehaviourAlert[] alerts = [.. _pending];
            _pending.Clear();
            return alerts;
        }
    }

    /// <summary>Creates (or re-creates) the hidden decoy files. Returns the folders where that failed.</summary>
    public IReadOnlyList<string> EnsureCanaries()
    {
        var failed = new List<string>();
        foreach (string path in _canaries)
        {
            try
            {
                if (!File.Exists(path))
                {
                    File.WriteAllText(path, DecoyText);
                    File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failed.Add(Path.GetDirectoryName(path)!);
            }
        }

        return failed;
    }

    public static bool LooksLikeRansomNote(string fileName)
    {
        string n = fileName.ToLowerInvariant();
        string ext = Path.GetExtension(n);
        if (ext is not (".txt" or ".html" or ".htm" or ".hta" or ".url" or ".rtf"))
        {
            return false;
        }

        bool threat = n.Contains("decrypt", StringComparison.Ordinal) || n.Contains("ransom", StringComparison.Ordinal)
            || n.Contains("restore", StringComparison.Ordinal) || n.Contains("recover", StringComparison.Ordinal) || n.Contains("encrypted", StringComparison.Ordinal);
        bool instruction = n.Contains("files", StringComparison.Ordinal) || n.Contains("readme", StringComparison.Ordinal) || n.Contains("read_me", StringComparison.Ordinal)
            || n.Contains("how", StringComparison.Ordinal) || n.Contains("instruction", StringComparison.Ordinal) || n.Contains("help", StringComparison.Ordinal);
        return threat && instruction;
    }

    public static bool IsRecoveryTampering(string commandLine)
    {
        string c = commandLine.ToLowerInvariant();
        bool Has(params string[] words) => words.All(w => c.Contains(w, StringComparison.Ordinal));
        return Has("vssadmin", "delete", "shadows")
            || Has("vssadmin", "resize", "shadowstorage")
            || Has("wmic", "shadowcopy", "delete")
            || Has("bcdedit", "recoveryenabled", "no")
            || Has("bcdedit", "bootstatuspolicy", "ignoreallfailures")
            || Has("wbadmin", "delete", "catalog")
            || Has("wbadmin", "delete", "systemstatebackup")
            || (Has("win32_shadowcopy") && (c.Contains("delete", StringComparison.Ordinal) || c.Contains("remove-", StringComparison.Ordinal)));
    }

    /// <summary>Shannon entropy (bits per byte) of the first 4 KiB, read without following links. Null if unreadable.</summary>
    public static double? SampleEntropy(string path)
    {
        Scanning.OpenResult open = Scanning.SafeFileOpener.Open(path);
        if (!open.Success)
        {
            return null;
        }

        using Microsoft.Win32.SafeHandles.SafeFileHandle handle = open.Handle!;
        Span<byte> buffer = stackalloc byte[4096];
        int read;
        try
        {
            read = RandomAccess.Read(handle, buffer, 0);
        }
        catch (IOException)
        {
            return null;
        }

        return read < 256 ? null : Entropy(buffer[..read]);
    }

    public static double Entropy(ReadOnlySpan<byte> data)
    {
        Span<int> counts = stackalloc int[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }

        double entropy = 0;
        foreach (int count in counts)
        {
            if (count > 0)
            {
                double p = (double)count / data.Length;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy;
    }

    private static bool IsUnusualRename(string oldPath, string newPath)
    {
        string oldExt = Path.GetExtension(oldPath), newExt = Path.GetExtension(newPath);
        return !string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase) && !s_commonExtensions.Contains(newExt);
    }

    private void Raise(string name, string path, string detail, DateTimeOffset now, string key)
    {
        if (_lastAlert.TryGetValue(key, out DateTimeOffset last) && now - last < s_alertCooldown)
        {
            return;
        }

        _lastAlert[key] = now;
        string[] suspects = [.. _recentProcesses
            .Where(p => now - p.Time < TimeSpan.FromMinutes(10) && IsUserWritable(p.Image))
            .Select(p => p.Image)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)];
        string sources = suspects.Length == 0 ? string.Empty : $" Programs recently started from user-writable folders: {string.Join(", ", suspects)}.";
        _pending.Add(new BehaviourAlert(name, path, detail + sources));
    }

    private static bool IsUserWritable(string image)
    {
        string i = image.ToLowerInvariant();
        return i.Contains(@"\users\", StringComparison.Ordinal) || i.Contains(@"\programdata\", StringComparison.Ordinal)
            || i.Contains(@"\temp\", StringComparison.Ordinal) || i.Contains(@"\downloads\", StringComparison.Ordinal);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (string key in _destructive.Where(d => now - d.Value.Time > _options.Window).Select(d => d.Key).ToList())
        {
            _destructive.Remove(key);
        }

        foreach (string key in _created.Where(c => now - c.Value > _options.Window).Select(c => c.Key).ToList())
        {
            _created.Remove(key);
        }
    }

    private static string CommonFolder(IEnumerable<string> paths) =>
        paths.Select(p => Path.GetDirectoryName(p) ?? p)
            .GroupBy(d => d, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .First().Key;

    private static string Clip(string value) => value.Length <= 300 ? value : value[..300] + "…";

    private static string DecoyText { get; } =
        "Kshatriya decoy file. Kshatriya watches this hidden file to notice programs that modify many files (for example ransomware). "
        + "Please leave it in place; deleting it is harmless. Nonce " + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)) + "\r\n"
        + string.Concat(Enumerable.Repeat("This document contains no personal data. ", 60));
}
