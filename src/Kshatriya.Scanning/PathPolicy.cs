using Kshatriya.Core;

namespace Kshatriya.Scanning;

/// <summary>Pure rules that decide whether an entry may be opened, based only on its attributes.</summary>
public static class PathPolicy
{
    // Values from WinNT.h that are not named in System.IO.FileAttributes.
    internal const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;
    internal const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;

    /// <summary>
    /// Returns the reason an entry must not be opened, or <see cref="ScanReason.None"/> when it may be.
    /// Reparse points (symbolic links, junctions, cloud-file placeholders, and others) are never followed,
    /// and files whose data is not present locally are never read, so a scan cannot trigger a cloud download.
    /// </summary>
    public static ScanReason Classify(FileAttributes attributes)
    {
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            return ScanReason.ReparsePoint;
        }

        if ((attributes & (FileAttributes.Offline | RecallOnOpen | RecallOnDataAccess)) != 0)
        {
            return ScanReason.CloudPlaceholder;
        }

        return ScanReason.None;
    }

    /// <summary>
    /// True for fully qualified local drive paths (<c>C:\...</c>) only: no UNC shares, no device or
    /// <c>\\?\</c> namespaces, no alternate data streams, wildcards, quotes or relative paths.
    /// </summary>
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

    /// <summary>
    /// Converts a full path to the Win32 extended-length form (<c>\\?\</c>) so that paths longer than
    /// MAX_PATH can be opened through Win32 APIs directly.
    /// </summary>
    public static string ToExtendedLengthPath(string fullPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(fullPath);
        if (fullPath.StartsWith(@"\\?\", StringComparison.Ordinal) || fullPath.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            return fullPath;
        }

        if (!Path.IsPathFullyQualified(fullPath))
        {
            throw new ArgumentException("Path must be fully qualified.", nameof(fullPath));
        }

        return fullPath.StartsWith(@"\\", StringComparison.Ordinal)
            ? @"\\?\UNC\" + fullPath[2..]
            : @"\\?\" + fullPath;
    }
}
