using System.Globalization;
using Sentinel.Core;

namespace Sentinel.Scanning;

/// <summary>
/// Items a scan must not inspect: folders or files (by full path, no wildcards) and exact SHA-256 values.
/// Excluded items are still reported, as <see cref="ScanStatus.Skipped"/> with <see cref="ScanReason.Excluded"/>,
/// so an exclusion is never a silent blind spot. Exclusions apply to Sentinel only; they never touch
/// Microsoft Defender or any other product.
/// </summary>
public sealed class ExclusionSet
{
    private readonly string[] _paths;
    private readonly HashSet<string> _hashes;

    public ExclusionSet(IEnumerable<string>? paths = null, IEnumerable<string>? sha256 = null)
    {
        var normalized = new List<string>();
        foreach (string path in paths ?? [])
        {
            string? problem = ValidatePath(path);
            if (problem is not null)
            {
                throw new ArgumentException(problem, nameof(paths));
            }

            normalized.Add(NormalizePath(path));
        }

        _paths = [.. normalized.Distinct(StringComparer.OrdinalIgnoreCase)];
        _hashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (string hash in sha256 ?? [])
        {
            _hashes.Add(NormalizeHash(hash) ?? throw new ArgumentException($"'{hash}' is not a SHA-256 value (64 hexadecimal characters).", nameof(sha256)));
        }
    }

    public static ExclusionSet Empty { get; } = new();

    public IReadOnlyList<string> Paths => _paths;

    public IReadOnlyCollection<string> Hashes => _hashes;

    public bool IsEmpty => _paths.Length == 0 && _hashes.Count == 0;

    /// <summary>True when <paramref name="fullPath"/> is an excluded path or lies beneath an excluded folder.</summary>
    public bool IsPathExcluded(string fullPath)
    {
        if (_paths.Length == 0 || string.IsNullOrEmpty(fullPath))
        {
            return false;
        }

        string candidate = fullPath.TrimEnd('\\');
        foreach (string excluded in _paths)
        {
            if (candidate.Equals(excluded, StringComparison.OrdinalIgnoreCase)
                || (candidate.Length > excluded.Length
                    && candidate[excluded.Length] == '\\'
                    && candidate.StartsWith(excluded, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    public bool IsHashExcluded(string? sha256) => sha256 is not null && _hashes.Contains(sha256);

    /// <summary>
    /// Returns null if <paramref name="path"/> may be excluded, or the reason it may not. Only fully
    /// qualified local paths are accepted, and never a drive root or the Windows directory: an
    /// exclusion that broad would switch scanning off rather than carve out an exception.
    /// </summary>
    public static string? ValidatePath(string? path)
    {
        if (!PathPolicy.IsLocalAbsolutePath(path))
        {
            return $"'{path}' is not a fully qualified local path (for example C:\\Tools\\build).";
        }

        string normalized = NormalizePath(path!);
        if (normalized.Length <= 2)
        {
            return $"'{path}' is a drive root; excluding a whole drive is not allowed.";
        }

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        if (windows.Length > 0 && normalized.Equals(windows, StringComparison.OrdinalIgnoreCase))
        {
            return $"'{path}' is the Windows directory; excluding it is not allowed.";
        }

        return null;
    }

    /// <summary>Returns the canonical lower-case form of a SHA-256 value, or null if it is not one.</summary>
    public static string? NormalizeHash(string? value)
    {
        if (value is null)
        {
            return null;
        }

        string v = value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? value[7..] : value;
        return v.Length == 64 && v.All(char.IsAsciiHexDigit) ? v.ToLower(CultureInfo.InvariantCulture) : null;
    }

    public static string NormalizePath(string path) => Path.GetFullPath(path).TrimEnd('\\');
}

/// <summary>
/// Reacts to a finished item (for example by quarantining it). Called by <see cref="ScanRunner"/> for
/// <see cref="ScanStatus.Detected"/> files after their scan handle is closed; implementations decide
/// eligibility themselves and must re-verify the file before changing it. Scanning code itself stays read-only.
/// </summary>
public interface IItemResponder
{
    /// <summary>Returns the action taken, or null when the item is not eligible for any action.</summary>
    ValueTask<ItemAction?> RespondAsync(ScanItemResult item, CancellationToken cancellationToken);
}
