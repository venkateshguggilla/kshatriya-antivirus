using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Engines.Hash;
using Sentinel.Scanning;
using Sentinel.Tests.Shared;

namespace Sentinel.Scanning.Tests;

public class ScanRunnerTests
{
    private static (HashEngine Engine, byte[] Sample) EngineWithCustomSignature()
    {
        byte[] sample = TestData.BenignBytes(1234, 2048);
        var db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(sample), "Sentinel.Test.Custom", "test")));
        return (HashEngine.CreateDefault(db), sample);
    }

    [Fact]
    public async Task Detects_custom_test_signature_on_disk_and_counts_everything()
    {
        using var temp = new TempDirectory();
        var (engine, sample) = EngineWithCustomSignature();
        string bad = temp.File(@"nested\flagged.bin", sample);
        temp.File("clean1.bin", TestData.BenignBytes(1, 100));
        temp.File(@"nested\clean2.bin", TestData.BenignBytes(2, 100));

        ScanReport report = await new ScanRunner([engine]).ScanPathsAsync([temp.Path]);

        Assert.Equal(3, report.Summary.FilesScanned);
        Assert.Equal(1, report.Summary.Detected);
        Assert.True(report.IsComplete);
        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(bad, item.Path);
        Assert.Equal(ScanStatus.Detected, item.Status);
        Assert.Equal(TestData.Sha256Hex(sample), item.Sha256);
        Assert.Equal("Sentinel.Test.Custom", Assert.Single(item.Detections).Name);
    }

    [Fact]
    public async Task Detects_eicar_from_an_in_memory_stream()
    {
        var runner = new ScanRunner([HashEngine.CreateDefault()]);

        ScanItemResult result = await runner.ScanStreamAsync(new MemoryStream(TestData.EicarBytes()), "eicar-stream");

        Assert.Equal(ScanStatus.Detected, result.Status);
        Assert.Equal(ScanItemKind.Stream, result.Kind);
        Assert.Equal(BuiltInSignatures.EicarName, Assert.Single(result.Detections).Name);
    }

    [Fact]
    public async Task Clean_items_are_listed_only_on_request()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1]);
        temp.File("b.bin", [2]);

        ScanReport hidden = await new ScanRunner([HashEngine.CreateDefault()]).ScanPathsAsync([temp.Path]);
        ScanReport shown = await new ScanRunner([HashEngine.CreateDefault()], new ScanOptions { IncludeCleanItems = true }).ScanPathsAsync([temp.Path]);

        Assert.Empty(hidden.Items);
        Assert.Equal(2, hidden.Summary.FilesScanned);
        Assert.Equal(2, shown.Items.Count);
        Assert.All(shown.Items, i => Assert.Equal(ScanStatus.Clean, i.Status));
        Assert.Equal(["a.bin", "b.bin"], shown.Items.Select(i => Path.GetFileName(i.Path)));
    }

    [Fact]
    public async Task Files_over_the_size_limit_are_reported_not_scanned()
    {
        using var temp = new TempDirectory();
        string big = temp.File("big.bin", new byte[4096]);
        var options = new ScanOptions { Limits = new ScanLimits { MaxFileSizeBytes = 1024 } };

        ScanReport report = await new ScanRunner([HashEngine.CreateDefault()], options).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(big, item.Path);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.TooLarge, item.Reason);
        Assert.Equal(4096, item.SizeBytes);
        Assert.False(report.IsComplete);
    }

    [Fact]
    public async Task Slow_engine_hits_the_per_item_timeout()
    {
        using var temp = new TempDirectory();
        temp.File("slow.bin", [1, 2, 3]);
        var options = new ScanOptions { Limits = new ScanLimits { PerItemTimeout = TimeSpan.FromMilliseconds(200) } };

        ScanReport report = await new ScanRunner([new SlowEngine()], options).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.Timeout, item.Reason);
    }

    [Fact]
    public async Task Faulty_engine_marks_item_incomplete_without_stopping_the_scan()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", [1]);
        temp.File("b.bin", [2]);

        ScanReport report = await new ScanRunner([new ThrowingEngine()]).ScanPathsAsync([temp.Path]);

        Assert.Equal(2, report.Summary.NotScanned);
        Assert.All(report.Items, i => Assert.Equal(ScanReason.EngineError, i.Reason));
        Assert.All(report.Items, i => Assert.Contains("boom", i.Message, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Exclusively_locked_file_is_reported_locked()
    {
        using var temp = new TempDirectory();
        string locked = temp.File("locked.bin", [1, 2, 3]);
        using var holder = new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        ScanReport report = await new ScanRunner([HashEngine.CreateDefault()]).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(ScanStatus.NotScanned, item.Status);
        Assert.Equal(ScanReason.Locked, item.Reason);
    }

    [Fact]
    public async Task Long_path_files_are_scanned_and_detected()
    {
        using var temp = new TempDirectory();
        var (engine, sample) = EngineWithCustomSignature();
        string deep = temp.Path;
        while (deep.Length < 400)
        {
            deep = Path.Combine(deep, new string('p', 60));
        }

        Directory.CreateDirectory(deep);
        string file = Path.Combine(deep, "flagged.bin");
        File.WriteAllBytes(file, sample);

        ScanReport report = await new ScanRunner([engine]).ScanPathsAsync([temp.Path]);

        ScanItemResult item = Assert.Single(report.Items);
        Assert.Equal(file, item.Path);
        Assert.Equal(ScanStatus.Detected, item.Status);
    }

    [Fact]
    public async Task Scanning_never_changes_files()
    {
        using var temp = new TempDirectory();
        var (engine, sample) = EngineWithCustomSignature();
        temp.File(@"d1\flagged.bin", sample);
        temp.File("readonly.bin", TestData.BenignBytes(5, 300));
        File.SetAttributes(Path.Combine(temp.Path, "readonly.bin"), FileAttributes.ReadOnly);
        for (int i = 0; i < 20; i++)
        {
            temp.File($@"d{i % 4}\f{i}.bin", TestData.BenignBytes(i, 100 + i));
        }

        var before = Snapshot(temp.Path);
        await new ScanRunner([engine], new ScanOptions { IncludeCleanItems = true }).ScanPathsAsync([temp.Path]);
        var after = Snapshot(temp.Path);

        Assert.Equal(before, after);
        File.SetAttributes(Path.Combine(temp.Path, "readonly.bin"), FileAttributes.Normal);
    }

    [Fact]
    public async Task Cancellation_stops_the_scan()
    {
        using var temp = new TempDirectory();
        for (int i = 0; i < 50; i++)
        {
            temp.File($"f{i}.bin", [(byte)i]);
        }

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new ScanRunner([HashEngine.CreateDefault()]).ScanPathsAsync([temp.Path], cancellationToken: cts.Token));
    }

    private static SortedDictionary<string, string> Snapshot(string root)
    {
        var map = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (string path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            var info = new FileInfo(path);
            string state = (info.Attributes & FileAttributes.Directory) != 0
                ? $"dir|{info.Attributes}|{info.LastWriteTimeUtc.Ticks}"
                : $"file|{info.Attributes}|{info.Length}|{info.LastWriteTimeUtc.Ticks}|{info.CreationTimeUtc.Ticks}|{TestData.Sha256Hex(File.ReadAllBytes(path))}";
            map[path] = state;
        }

        return map;
    }

    private sealed class SlowEngine : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new("slow", "1", "none");

        public async ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
            return [];
        }
    }

    private sealed class ThrowingEngine : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new("throws", "1", "none");

        public ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("boom");
    }
}
