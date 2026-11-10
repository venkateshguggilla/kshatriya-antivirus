using System.Security.Cryptography;

namespace Kshatriya.App.Services;

/// <summary>
/// Keeps a per-user copy of the browser extension (ADR 0018). Edge and Chrome write the compiled
/// blocklist into an unpacked extension's own folder, so the read-only copy under Program Files cannot be
/// loaded directly. The copy in Documents is refreshed from the installed one whenever they differ; it is
/// kept there rather than in the hidden AppData folder because people have to find it in a folder picker.
/// </summary>
public static class BrowserExtensionCopy
{
    /// <summary>Folder the browser writes into; kept across refreshes so the browser need not rebuild it.</summary>
    private const string BrowserMetadata = "_metadata";

    public static string InstalledFolder => Path.Combine(AppContext.BaseDirectory, "browser-extension");

    public static string UserFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Kshatriya browser extension");

    /// <summary>
    /// Makes <paramref name="target"/> an exact copy of <paramref name="source"/> (apart from the browser's
    /// own metadata). Returns false when there is no extension to copy. Links are never followed.
    /// </summary>
    public static bool Sync(string source, string target)
    {
        if (!File.Exists(Path.Combine(source, "manifest.json")))
        {
            return false;
        }

        Dictionary<string, string> wanted = Files(source);
        if (Directory.Exists(target) && !IsLink(target))
        {
            Dictionary<string, string> present = Files(target);
            present.Remove(BrowserMetadata);
            if (present.Count == wanted.Count && wanted.All(f => present.TryGetValue(f.Key, out string? p) && SameContent(f.Value, p)))
            {
                return true;
            }

            foreach (string stale in present.Where(p => !wanted.ContainsKey(p.Key)).Select(p => p.Value))
            {
                File.Delete(stale);
            }
        }
        else if (Directory.Exists(target) || File.Exists(target))
        {
            throw new IOException($"{target} is a link or a file; not replacing it.");
        }

        foreach ((string relative, string from) in wanted)
        {
            string to = Path.Combine(target, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            if (File.Exists(to) && IsLink(to))
            {
                File.Delete(to);
            }

            File.Copy(from, to, overwrite: true);
        }

        return true;
    }

    /// <summary>Relative path -> full path of every regular file, skipping links and the browser's metadata.</summary>
    private static Dictionary<string, string> Files(string root)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<string>([root]);
        while (pending.Count > 0)
        {
            string folder = pending.Pop();
            foreach (string entry in Directory.EnumerateFileSystemEntries(folder))
            {
                if (IsLink(entry))
                {
                    continue;
                }

                string relative = Path.GetRelativePath(root, entry);
                if (Directory.Exists(entry))
                {
                    if (relative.Equals(BrowserMetadata, StringComparison.OrdinalIgnoreCase))
                    {
                        files[BrowserMetadata] = entry;
                    }
                    else
                    {
                        pending.Push(entry);
                    }
                }
                else
                {
                    files[relative] = entry;
                }
            }
        }

        return files;
    }

    private static bool IsLink(string path) => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static bool SameContent(string a, string b)
    {
        if (new FileInfo(a).Length != new FileInfo(b).Length)
        {
            return false;
        }

        using FileStream first = File.OpenRead(a);
        using FileStream second = File.OpenRead(b);
        return SHA256.HashData(first).AsSpan().SequenceEqual(SHA256.HashData(second));
    }
}
