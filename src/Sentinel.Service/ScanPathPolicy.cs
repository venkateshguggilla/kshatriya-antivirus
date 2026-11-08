namespace Sentinel.Service;

/// <summary>
/// Which paths the service accepts. Only fully qualified local drive paths (<c>C:\...</c>): no UNC
/// shares, no device or <c>\\?\</c> namespaces, no wildcards, no relative paths. The service never
/// reaches off the machine on a caller's behalf.
/// </summary>
public static class ScanPathPolicy
{
    public const int MaxPathsPerRequest = 64;

    public static bool IsLocalAbsolutePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32_000 || path.Length < 3)
        {
            return false;
        }

        if (!char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
        {
            return false;
        }

        if (path.AsSpan(2).Contains(':') || path.AsSpan().IndexOfAny('*', '?', '"') >= 0 || path.Contains('\0', StringComparison.Ordinal))
        {
            return false;
        }

        return Path.IsPathFullyQualified(path);
    }

    /// <summary>Returns an error message, or null if every path is acceptable.</summary>
    public static string? Validate(IReadOnlyList<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (paths.Count == 0)
        {
            return "No paths were given.";
        }

        if (paths.Count > MaxPathsPerRequest)
        {
            return $"At most {MaxPathsPerRequest} paths can be scanned in one request.";
        }

        foreach (string path in paths)
        {
            if (!IsLocalAbsolutePath(path))
            {
                return $"'{path}' is not a fully qualified local path (for example C:\\Users\\me\\Downloads).";
            }
        }

        return null;
    }
}
