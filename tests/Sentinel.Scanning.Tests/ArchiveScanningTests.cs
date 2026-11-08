using System.IO.Compression;
using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;

namespace Sentinel.Scanning.Tests;

public class ArchiveScanningTests
{
    private static readonly byte[] s_sample = TestData.BenignBytes(4242, 3000);

    private static HashEngine Engine() =>
        HashEngine.CreateDefault(HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(s_sample), "Sentinel.Test.Custom", "test"))));

    private static Task<ScanReport> Scan(string path, ArchiveLimits? limits = null) =>
        new ScanRunner([Engine()], new ScanOptions { Limits = new ScanLimits { Archives = limits ?? new ArchiveLimits() } })
            .ScanPathsAsync([path]);

    [Fact]
    public async Task Detection_inside_zip_reports_entry_location()
    {
        using var temp = new TempDirectory();
        string zip = temp.File("bundle.zip", ZipFactory.Create(("readme.txt", "hello"u8.ToArray()), ("bin/payload.dat", s_sample)));

        ScanReport report = await Scan(zip);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(ScanReason.None, item.Reason);
        Detection d = Assert.Single(item.Detections);
        Assert.Equal("bin/payload.dat", d.Location);
        Assert.True(report.IsComplete);
    }

    [Fact]
    public async Task Nested_archives_chain_locations()
    {
        using var temp = new TempDirectory();
        byte[] inner = ZipFactory.Create(("deep/x.bin", s_sample));
        string zip = temp.File("outer.zip", ZipFactory.Create(("level1/inner.zip", inner)));

        ScanReport report = await Scan(zip);

        Assert.Equal("level1/inner.zip>deep/x.bin", Assert.Single(Assert.Single(report.Items).Detections).Location);
    }

    [Fact]
    public async Task Depth_limit_stops_expansion_silently_at_zero_and_counts_as_policy()
    {
        using var temp = new TempDirectory();
        string zip = temp.File("a.zip", ZipFactory.Create(("x.bin", s_sample)));

        ScanReport report = await Scan(zip, new ArchiveLimits { MaxDepth = 0 });

        Assert.Empty(report.Items);
        Assert.Equal(1, report.Summary.FilesScanned);
    }

    [Fact]
    public async Task Entry_limit_marks_item_incomplete()
    {
        using var temp = new TempDirectory();
        var entries = Enumerable.Range(0, 20).Select(i => ($"f{i}.txt", new[] { (byte)i })).ToArray();
        string zip = temp.File("many.zip", ZipFactory.Create(entries));

        ScanReport report = await Scan(zip, new ArchiveLimits { MaxEntries = 5 });

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.ArchiveLimit, item.Reason);
        Assert.False(report.IsComplete);
    }

    [Fact]
    public async Task Detection_is_kept_when_archive_is_only_partially_scanned()
    {
        using var temp = new TempDirectory();
        var entries = new List<(string, byte[])> { ("a-first.bin", s_sample) };
        entries.AddRange(Enumerable.Range(0, 20).Select(i => ($"z{i}.txt", new[] { (byte)i })));
        string zip = temp.File("mixed.zip", ZipFactory.Create([.. entries]));

        ScanReport report = await Scan(zip, new ArchiveLimits { MaxEntries = 3 });

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(ScanReason.ArchiveLimit, item.Reason);
        Assert.True(item.IsIncomplete);
        Assert.Equal(1, report.Summary.Partial);
        Assert.False(report.IsComplete);
    }

    [Fact]
    public async Task Highly_compressed_entry_is_treated_as_possible_bomb()
    {
        using var temp = new TempDirectory();
        string zip = temp.File("bomb.zip", ZipFactory.Create(CompressionLevel.SmallestSize, ("zeros.bin", new byte[8 * 1024 * 1024])));

        ScanReport report = await Scan(zip);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanReason.ArchiveLimit, item.Reason);
        Assert.Contains("ratio", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Total_decompressed_budget_is_enforced()
    {
        using var temp = new TempDirectory();
        string zip = temp.File("big.zip", ZipFactory.Create(CompressionLevel.NoCompression,
            ("a.bin", TestData.BenignBytes(1, 600_000)), ("b.bin", TestData.BenignBytes(2, 600_000))));

        ScanReport report = await Scan(zip, new ArchiveLimits { MaxTotalBytes = 1_000_000 });

        Assert.Equal(ScanReason.ArchiveLimit, Assert.Single(report.Items).Reason);
    }

    [Fact]
    public async Task Encrypted_entries_are_reported()
    {
        using var temp = new TempDirectory();
        string zip = temp.File("enc.zip", ZipFactory.MarkAllEncrypted(ZipFactory.Create(("secret.bin", TestData.BenignBytes(3, 100)))));

        ScanReport report = await Scan(zip);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.ArchiveEncrypted, item.Reason);
    }

    [Fact]
    public async Task Corrupt_archive_is_reported_not_crashing()
    {
        using var temp = new TempDirectory();
        byte[] zip = ZipFactory.Create(("a.txt", TestData.BenignBytes(4, 5000)));
        Array.Fill(zip, (byte)0xEE, 40, zip.Length - 80); // trash the middle, keep the magic
        string path = temp.File("corrupt.zip", zip);

        ScanReport report = await Scan(path);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.ArchiveError, item.Reason);
    }

    [Fact]
    public async Task Path_traversal_entry_names_never_touch_the_file_system()
    {
        using var temp = new TempDirectory();
        string scanDir = temp.Dir("scan");
        string zip = temp.File(@"scan\slip.zip", ZipFactory.Create(("../../escaped.bin", s_sample), ("C:/abs.bin", [1])));
        var before = Directory.GetFileSystemEntries(temp.Path, "*", SearchOption.AllDirectories).Order().ToArray();

        ScanReport report = await Scan(scanDir);

        var after = Directory.GetFileSystemEntries(temp.Path, "*", SearchOption.AllDirectories).Order().ToArray();
        Assert.Equal(before, after);
        Assert.Equal("../../escaped.bin", Assert.Single(Assert.Single(report.Items).Detections).Location);
    }

    [Fact]
    public async Task Office_style_zip_documents_are_inspected()
    {
        using var temp = new TempDirectory();
        string docx = temp.File("report.docx", ZipFactory.Create(("[Content_Types].xml", "<Types/>"u8.ToArray()), ("word/embeddings/oleObject1.bin", s_sample)));

        ScanReport report = await Scan(docx);

        Assert.Equal("word/embeddings/oleObject1.bin", Assert.Single(Assert.Single(report.Items).Detections).Location);
    }

    [Fact]
    public void Entry_names_are_sanitized_for_display()
    {
        Assert.Equal("a?b", Archives.ZipExpander.SanitizeName("a\u0007b"));
        Assert.Equal("?", Archives.ZipExpander.SanitizeName(""));
        Assert.True(Archives.ZipExpander.SanitizeName(new string('x', 1000)).Length <= 261);
    }
}
