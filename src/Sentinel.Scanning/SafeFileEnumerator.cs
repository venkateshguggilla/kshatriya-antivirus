using System.IO.Enumeration;
using Sentinel.Core;

namespace Sentinel.Scanning;

/// <summary>A file the enumerator considers safe to open, or a pre-computed result for an entry it will not open.</summary>
public readonly record struct WalkEntry(string Path, long Length, ScanItemResult? Result)
{
    public bool IsCandidate => Result is null;

    public static WalkEntry Candidate(string path, long length) => new(path, length, null);

    public static WalkEntry Report(ScanItemResult result) => new(result.Path, result.SizeBytes ?? 0, result);
}

/// <summary>
/// Walks scan targets without following reparse points (symbolic links, junctions, mount points),
/// skips files whose data is not present locally, supports paths longer than MAX_PATH, and guards
/// against directory cycles by tracking directory identities. Every entry it does not hand out as a
/// candidate is reported, never silently dropped.
/// </summary>
public static class SafeFileEnumerator
{
    private static readonly EnumerationOptions s_options = new()
    {
        RecurseSubdirectories = false,
        IgnoreInaccessible = false,
        AttributesToSkip = 0,
        ReturnSpecialDirectories = false,
        MatchType = MatchType.Simple,
    };

    public static IEnumerable<WalkEntry> Walk(string target, CancellationToken cancellationToken = default) =>
        Walk(target, exclusions: null, cancellationToken);

    /// <summary>
    /// Walks <paramref name="target"/>. Excluded files and folders are reported as skipped
    /// (<see cref="ScanReason.Excluded"/>) and excluded folders are not descended into.
    /// </summary>
    public static IEnumerable<WalkEntry> Walk(string target, ExclusionSet? exclusions, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(target);
        string full = Path.GetFullPath(target);
        exclusions ??= ExclusionSet.Empty;

        FileAttributes attributes;
        try
        {
            attributes = File.GetAttributes(full);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return [WalkEntry.Report(ScanItemResult.Fail(full, ScanItemKind.File, ScanReason.NotFound, ex.Message))];
        }
        catch (UnauthorizedAccessException ex)
        {
            return [WalkEntry.Report(ScanItemResult.Fail(full, ScanItemKind.File, ScanReason.AccessDenied, ex.Message))];
        }
        catch (IOException ex)
        {
            return [WalkEntry.Report(ScanItemResult.Fail(full, ScanItemKind.File, ScanReason.IoError, ex.Message))];
        }

        if ((attributes & FileAttributes.Directory) == 0)
        {
            return exclusions.IsPathExcluded(full)
                ? [WalkEntry.Report(ScanItemResult.Skip(full, ScanItemKind.File, ScanReason.Excluded) with { SizeBytes = SafeLength(full) })]
                : [ClassifyFile(full, attributes, SafeLength(full))];
        }

        if (exclusions.IsPathExcluded(full))
        {
            return [WalkEntry.Report(ScanItemResult.Skip(full, ScanItemKind.Directory, ScanReason.Excluded))];
        }

        string root = full;
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            // The user explicitly named this link as a target, so resolve it once. Links found *inside*
            // the tree are still never followed.
            FileSystemInfo? resolved = TryResolve(full);
            if (resolved is not DirectoryInfo dir || !dir.Exists)
            {
                return [WalkEntry.Report(ScanItemResult.Skip(full, ScanItemKind.Directory, ScanReason.ReparsePoint, "Link target could not be resolved."))];
            }

            root = dir.FullName;
        }

        return WalkDirectoryTree(root, exclusions, cancellationToken);
    }

    private static IEnumerable<WalkEntry> WalkDirectoryTree(string root, ExclusionSet exclusions, CancellationToken cancellationToken)
    {
        var visited = new HashSet<(uint, ulong)>();
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string directory = pending.Pop();

            var identity = SafeFileOpener.TryGetDirectoryIdentity(directory);
            if (identity is { } id && !visited.Add(id))
            {
                yield return WalkEntry.Report(ScanItemResult.Skip(directory, ScanItemKind.Directory, ScanReason.LoopDetected));
                continue;
            }

            var entries = new List<WalkEntry>();
            var subdirectories = new List<string>();
            ScanItemResult? failure = ReadDirectory(directory, exclusions, entries, subdirectories);
            if (failure is not null)
            {
                yield return WalkEntry.Report(failure);
            }

            foreach (WalkEntry entry in entries)
            {
                yield return entry;
            }

            // Push in reverse so traversal order is alphabetical-ish and stable.
            for (int i = subdirectories.Count - 1; i >= 0; i--)
            {
                pending.Push(subdirectories[i]);
            }
        }
    }

    /// <summary>Reads one directory level. Returns a failure result if the directory could not be (fully) listed.</summary>
    private static ScanItemResult? ReadDirectory(string directory, ExclusionSet exclusions, List<WalkEntry> entries, List<string> subdirectories)
    {
        // The directory handle is opened when the enumerable is constructed, so construction can fail
        // (for example access denied) just like MoveNext; both are guarded.
        IEnumerator<(string Path, FileAttributes Attributes, long Length)> enumerator;
        try
        {
            enumerator = new FileSystemEnumerable<(string Path, FileAttributes Attributes, long Length)>(
                directory,
                static (ref FileSystemEntry e) => (e.ToFullPath(), e.Attributes, e.IsDirectory ? 0 : e.Length),
                s_options).GetEnumerator();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return DirectoryFailure(directory, ex);
        }

        using (enumerator)
        {
            return ReadEntries(directory, exclusions, enumerator, entries, subdirectories);
        }
    }

    private static ScanItemResult DirectoryFailure(string directory, Exception ex) => ex switch
    {
        UnauthorizedAccessException => ScanItemResult.Fail(directory, ScanItemKind.Directory, ScanReason.AccessDenied, ex.Message),
        DirectoryNotFoundException => ScanItemResult.Fail(directory, ScanItemKind.Directory, ScanReason.NotFound, ex.Message),
        _ => ScanItemResult.Fail(directory, ScanItemKind.Directory, ScanReason.IoError, ex.Message),
    };

    private static ScanItemResult? ReadEntries(
        string directory,
        ExclusionSet exclusions,
        IEnumerator<(string Path, FileAttributes Attributes, long Length)> enumerator,
        List<WalkEntry> entries,
        List<string> subdirectories)
    {
        while (true)
        {
            try
            {
                if (!enumerator.MoveNext())
                {
                    return null;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                return DirectoryFailure(directory, ex);
            }

            var (path, attributes, length) = enumerator.Current;
            bool isDirectory = (attributes & FileAttributes.Directory) != 0;

            if (exclusions.IsPathExcluded(path))
            {
                ScanItemResult skipped = ScanItemResult.Skip(path, isDirectory ? ScanItemKind.Directory : ScanItemKind.File, ScanReason.Excluded);
                entries.Add(WalkEntry.Report(isDirectory ? skipped : skipped with { SizeBytes = length }));
            }
            else if (isDirectory)
            {
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    entries.Add(WalkEntry.Report(ScanItemResult.Skip(path, ScanItemKind.Directory, ScanReason.ReparsePoint)));
                }
                else
                {
                    subdirectories.Add(path);
                }
            }
            else
            {
                entries.Add(ClassifyFile(path, attributes, length));
            }
        }
    }

    private static WalkEntry ClassifyFile(string path, FileAttributes attributes, long length)
    {
        ScanReason reason = PathPolicy.Classify(attributes);
        return reason == ScanReason.None
            ? WalkEntry.Candidate(path, length)
            : WalkEntry.Report(ScanItemResult.Skip(path, ScanItemKind.File, reason) with { SizeBytes = length });
    }

    private static long SafeLength(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (IOException)
        {
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static FileSystemInfo? TryResolve(string path)
    {
        try
        {
            return new DirectoryInfo(path).ResolveLinkTarget(returnFinalTarget: true);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
