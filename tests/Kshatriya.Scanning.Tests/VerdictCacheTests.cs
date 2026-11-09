using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Scanning;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Scanning.Tests;

public class VerdictCacheTests
{
    [Fact]
    public async Task Unchanged_clean_file_is_served_from_the_cache_with_the_same_result()
    {
        using var temp = new TempDirectory();
        temp.File("clean.bin", TestData.BenignBytes(1, 5000));
        var cache = new VerdictCache(racyWindow: TimeSpan.Zero);
        ScanRunner runner = Runner(cache);

        ScanReport first = await runner.ScanPathsAsync([temp.Path]);
        ScanReport second = await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(1, cache.Misses);
        Assert.Equal(1, cache.Hits);
        ScanItemResult a = first.Items.Single(), b = second.Items.Single();
        Assert.Equal((a.Path, a.Status, a.Reason, a.SizeBytes, a.Sha256, a.Trust), (b.Path, b.Status, b.Reason, b.SizeBytes, b.Sha256, b.Trust));
        Assert.Empty(b.Detections);
        Assert.Equal(1, second.Summary.FilesScanned);
        Assert.True(second.IsComplete);
    }

    [Fact]
    public async Task Modified_file_is_rescanned_and_its_new_content_detected()
    {
        using var temp = new TempDirectory();
        byte[] bad = TestData.BenignBytes(7, 3000);
        string file = temp.File("changing.bin", TestData.BenignBytes(1, 3000));
        var cache = new VerdictCache(racyWindow: TimeSpan.Zero);
        ScanRunner runner = Runner(cache, (TestData.Sha256Hex(bad), "Test.Changed", "test"));

        await runner.ScanPathsAsync([temp.Path]);
        Assert.Equal(1, cache.Count);
        await Task.Delay(100); // move past the file-system timestamp tick
        File.WriteAllBytes(file, bad);
        ScanReport after = await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(0, cache.Hits);
        Assert.Equal(ScanStatus.Detected, after.Items.Single().Status);
    }

    [Fact]
    public async Task Changing_only_the_timestamp_invalidates_the_entry()
    {
        using var temp = new TempDirectory();
        string file = temp.File("touched.bin", TestData.BenignBytes(1, 3000));
        var cache = new VerdictCache(racyWindow: TimeSpan.Zero);
        ScanRunner runner = Runner(cache);

        await runner.ScanPathsAsync([temp.Path]);
        File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(-5));
        await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(0, cache.Hits);
        Assert.Equal(2, cache.Misses);
    }

    [Fact]
    public async Task Detections_are_never_cached()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(3, 2000);
        temp.File("hit.bin", sample);
        var cache = new VerdictCache();
        ScanRunner runner = Runner(cache, (TestData.Sha256Hex(sample), "Test.Hit", "test"));

        await runner.ScanPathsAsync([temp.Path]);
        ScanReport second = await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(0, cache.Hits);
        Assert.Equal(0, cache.Count);
        Assert.Equal(ScanStatus.Detected, second.Items.Single().Status);
    }

    [Fact]
    public async Task A_different_engine_configuration_does_not_reuse_entries()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(4, 2000);
        temp.File("file.bin", sample);
        var cache = new VerdictCache(racyWindow: TimeSpan.Zero);

        await Runner(cache).ScanPathsAsync([temp.Path]);
        ScanReport withNewSignature = await Runner(cache, (TestData.Sha256Hex(sample), "Test.New", "test")).ScanPathsAsync([temp.Path]);

        Assert.Equal(0, cache.Hits);
        Assert.Equal(ScanStatus.Detected, withNewSignature.Items.Single().Status);
    }

    [Fact]
    public async Task Recently_changed_files_are_not_cached()
    {
        // A same-size rewrite inside one timestamp tick leaves every stamp unchanged, so fresh files are never trusted.
        using var temp = new TempDirectory();
        temp.File("fresh.bin", TestData.BenignBytes(1, 3000));
        var cache = new VerdictCache();
        ScanRunner runner = Runner(cache);

        await runner.ScanPathsAsync([temp.Path]);
        await runner.ScanPathsAsync([temp.Path]);

        Assert.Equal(0, cache.Count);
        Assert.Equal(0, cache.Hits);
    }

    [Fact]
    public void Cache_is_bounded()
    {
        var cache = new VerdictCache(maxEntries: 2, racyWindow: TimeSpan.Zero);
        for (int i = 0; i < 5; i++)
        {
            Assert.True(cache.Store(new FileIdentity(1, (UInt128)i, 10, 116444736000000000, 0), "fp", new CachedVerdict("00", null)));
        }

        Assert.InRange(cache.Count, 1, 2);
    }

    [Fact]
    public void Directory_identity_reads_the_volume_serial_from_the_right_offset()
    {
        // Regression test: BY_HANDLE_FILE_INFORMATION must be packed to 4 bytes. With natural alignment
        // the volume serial was read from the file-size field (always 0 for directories).
        using var temp = new TempDirectory();
        string file = temp.File("probe.bin", [1, 2, 3]);
        OpenResult open = SafeFileOpener.Open(file);
        using var handle = open.Handle!;

        FileIdentity? fileIdentity = SafeFileOpener.TryGetIdentity(handle, 3);
        (uint Volume, ulong Index)? directoryIdentity = SafeFileOpener.TryGetDirectoryIdentity(temp.Path);

        Assert.NotNull(fileIdentity);
        Assert.NotNull(directoryIdentity);
        Assert.NotEqual(0u, directoryIdentity.Value.Volume);
        Assert.Equal((uint)fileIdentity.Value.Volume, directoryIdentity.Value.Volume);
        Assert.NotEqual(SafeFileOpener.TryGetDirectoryIdentity(temp.Dir("other")), directoryIdentity);
    }

    private static ScanRunner Runner(VerdictCache cache, params (string Sha256, string Name, string Category)[] signatures)
    {
        HashEngine engine = signatures.Length == 0
            ? HashEngine.CreateDefault()
            : HashEngine.CreateDefault(HashSignatureDatabase.Parse(TestData.HashDb(signatures)));
        return new ScanRunner([engine], new ScanOptions { Cache = cache, IncludeCleanItems = true });
    }
}
