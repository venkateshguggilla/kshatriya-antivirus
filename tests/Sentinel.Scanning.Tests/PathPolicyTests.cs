using Sentinel.Core;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;

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
    [InlineData(225, ScanReason.BlockedBySecurityProduct)]
    [InlineData(226, ScanReason.BlockedBySecurityProduct)]
    public void MapError_translates_win32_errors(int error, ScanReason expected)
    {
        Assert.Equal(expected, SafeFileOpener.MapError(error));
    }

    [Theory]
    [InlineData(unchecked((int)0x800700E1), ScanReason.BlockedBySecurityProduct)]
    [InlineData(unchecked((int)0x800700E2), ScanReason.BlockedBySecurityProduct)]
    [InlineData(unchecked((int)0x80070020), ScanReason.Locked)]
    [InlineData(unchecked((int)0x80070005), ScanReason.IoError)]
    [InlineData(unchecked((int)0x80131620), ScanReason.IoError)]
    public void Read_errors_map_to_scan_reasons(int hresult, ScanReason expected)
    {
        Assert.Equal(expected, SafeFileOpener.MapIOException(new IOException("read failed", hresult)));
    }

    [Fact]
    public async Task Blocked_by_security_product_round_trips_in_reports_and_v3_stays_readable()
    {
        using var temp = new TempDirectory();
        ScanReport empty = await new ScanRunner([Sentinel.Engines.Hash.HashEngine.CreateDefault()]).ScanPathsAsync([temp.Path]);
        string path = Path.Combine(temp.Path, "blocked.com");
        ScanReport report = empty with { Items = [ScanItemResult.Fail(path, ScanItemKind.File, ScanReason.BlockedBySecurityProduct, "Operation did not complete successfully because the file contains a virus.")] };

        string json = ScanReportJson.Write(report, "test");
        Assert.Contains("\"blockedBySecurityProduct\"", json, StringComparison.Ordinal);
        Assert.Equal(ScanReason.BlockedBySecurityProduct, ScanReportJson.Read(json).Items.Single().Reason);

        // Readers still accept version 3 reports.
        string v3 = ScanReportJson.Write(empty, "test").Replace("\"schemaVersion\": 4", "\"schemaVersion\": 3", StringComparison.Ordinal);
        Assert.Contains("\"schemaVersion\": 3", v3, StringComparison.Ordinal);
        Assert.Empty(ScanReportJson.Read(v3).Items);
    }
}
