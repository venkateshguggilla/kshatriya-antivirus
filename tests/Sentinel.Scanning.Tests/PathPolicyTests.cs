using Sentinel.Core;
using Sentinel.Scanning;

namespace Sentinel.Scanning.Tests;

public class PathPolicyTests
{
    [Theory]
    [InlineData(FileAttributes.Normal, ScanReason.None)]
    [InlineData(FileAttributes.Archive | FileAttributes.ReadOnly, ScanReason.None)]
    [InlineData(FileAttributes.ReparsePoint, ScanReason.ReparsePoint)]
    [InlineData(FileAttributes.ReparsePoint | FileAttributes.Offline, ScanReason.ReparsePoint)]
    [InlineData(FileAttributes.Offline, ScanReason.CloudPlaceholder)]
    [InlineData((FileAttributes)0x00040000, ScanReason.CloudPlaceholder)] // RECALL_ON_OPEN
    [InlineData((FileAttributes)0x00400000, ScanReason.CloudPlaceholder)] // RECALL_ON_DATA_ACCESS
    public void Classify_never_allows_links_or_non_resident_data(FileAttributes attributes, ScanReason expected)
    {
        Assert.Equal(expected, PathPolicy.Classify(attributes));
    }

    [Theory]
    [InlineData(@"C:\data\file.txt", @"\\?\C:\data\file.txt")]
    [InlineData(@"\\server\share\file.txt", @"\\?\UNC\server\share\file.txt")]
    [InlineData(@"\\?\C:\already", @"\\?\C:\already")]
    public void ToExtendedLengthPath_handles_drive_unc_and_prefixed_paths(string input, string expected)
    {
        Assert.Equal(expected, PathPolicy.ToExtendedLengthPath(input));
    }

    [Theory]
    [InlineData(@"relative\path")]
    [InlineData(@"C:relative")]
    public void ToExtendedLengthPath_rejects_relative_paths(string input)
    {
        Assert.Throws<ArgumentException>(() => PathPolicy.ToExtendedLengthPath(input));
    }

    [Theory]
    [InlineData(2, ScanReason.NotFound)]
    [InlineData(3, ScanReason.NotFound)]
    [InlineData(5, ScanReason.AccessDenied)]
    [InlineData(32, ScanReason.Locked)]
    [InlineData(33, ScanReason.Locked)]
    [InlineData(1117, ScanReason.IoError)]
    public void MapError_translates_win32_errors(int error, ScanReason expected)
    {
        Assert.Equal(expected, SafeFileOpener.MapError(error));
    }
}
