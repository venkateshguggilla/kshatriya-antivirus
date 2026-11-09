using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Scanning.Tests;

public class ExclusionTests
{
    [Fact]
    public async Task Excluded_folders_are_reported_once_and_not_descended()
    {
        using var temp = new TempDirectory();
        temp.File(@"keep\a.bin", [1]);
        temp.File(@"skip\b.bin", [2]);
        temp.File(@"skip\deep\c.bin", [3]);
        string skip = Path.Combine(temp.Path, "skip");

        ScanReport report = await new ScanRunner([HashEngine.CreateDefault()], new ScanOptions { Exclusions = new ExclusionSet([skip]) })
            .ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(skip, item.Path);
        Assert.Equal(ScanStatus.Skipped, item.Status);
        Assert.Equal(ScanReason.Excluded, item.Reason);
        Assert.Equal(1, report.Summary.FilesScanned);
        Assert.True(report.IsComplete, "Exclusions are policy skips, not missing coverage.");
    }

    [Fact]
    public async Task Excluded_files_and_hashes_are_skipped()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(42, 1000);
        var db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(sample), "Test.Excluded", "test")));
        string byPath = temp.File("by-path.bin", sample);
        string byHash = temp.File(@"sub\by-hash.bin", sample);

        var exclusions = new ExclusionSet([byPath], [TestData.Sha256Hex(sample).ToUpperInvariant()]);
        ScanReport report = await new ScanRunner([HashEngine.CreateDefault(db)], new ScanOptions { Exclusions = exclusions })
            .ScanPathsAsync([temp.Path]);

        Assert.Equal(0, report.Summary.Detected);
        Assert.Equal(2, report.Summary.Skipped);
        Assert.All(report.Items, i => Assert.Equal(ScanReason.Excluded, i.Reason));
        Assert.Equal(TestData.Sha256Hex(sample), report.Items.Single(i => i.Path == byHash).Sha256);
        Assert.Null(report.Items.Single(i => i.Path == byPath).Sha256);
    }

    [Fact]
    public void Path_matching_respects_segment_boundaries_and_case()
    {
        var set = new ExclusionSet([@"C:\Tools\Build\"]);

        Assert.True(set.IsPathExcluded(@"C:\Tools\Build"));
        Assert.True(set.IsPathExcluded(@"c:\tools\build\x\y.exe"));
        Assert.False(set.IsPathExcluded(@"C:\Tools\BuildServer\x.exe"));
        Assert.False(set.IsPathExcluded(@"C:\Tools"));
    }

    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"D:\")]
    [InlineData(@"\\server\share\x")]
    [InlineData(@"relative\path")]
    [InlineData(@"C:\x\*.exe")]
    [InlineData(@"C:\file.txt:stream")]
    public void Unsafe_or_overly_broad_exclusions_are_rejected(string path)
    {
        Assert.NotNull(ExclusionSet.ValidatePath(path));
        Assert.Throws<ArgumentException>(() => new ExclusionSet([path]));
    }

    [Fact]
    public void The_windows_directory_cannot_be_excluded()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.NotNull(ExclusionSet.ValidatePath(windows));
        Assert.Null(ExclusionSet.ValidatePath(Path.Combine(windows, "Temp", "build")));
    }

    [Theory]
    [InlineData("sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", true)]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", true)]
    [InlineData("abc", false)]
    [InlineData("zzcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false)]
    public void Hash_values_are_normalised(string value, bool valid)
    {
        string? normalized = ExclusionSet.NormalizeHash(value);
        Assert.Equal(valid, normalized is not null);
        Assert.True(normalized is null || normalized.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f'));
    }
}
