using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Mobile;
using Kshatriya.Tests.Shared;
using Kshatriya.Updates;

namespace Kshatriya.Mobile.Tests;

public sealed class IndicatorTests
{
    private const string Cert = "31a6ececd97cf39bc4126b8745cd94a7c30bf81c";

    private static readonly AppIndicatorSet s_set = new(AppBlockList.Parse(
        "# kshatriya-appblock v1\npackage com.thetruth Android.Stalkerware.TheTruthSpy pua\n"
        + $"cert-sha1 {Cert} Android.Stalkerware.TheTruthSpy pua\n", "test"));

    private static AppIdentity App(string package, params string[] sha1) => new(package, sha1, []);

    [Fact]
    public void A_listed_signing_certificate_is_a_confident_finding_even_under_another_package_name()
    {
        Detection detection = Assert.Single(s_set.Match(App("com.renamed.copy", Cert.ToUpperInvariant())));

        Assert.Equal(DetectionCategory.PotentiallyUnwanted, detection.Category);
        Assert.Equal(DetectionConfidence.High, detection.Confidence);
        Assert.Equal("Android.Stalkerware.TheTruthSpy", detection.Name);
    }

    [Fact]
    public void A_listed_package_name_alone_is_only_suspicious()
    {
        Detection detection = Assert.Single(s_set.Match(App("com.thetruth", new string('0', 40))));

        Assert.Equal(DetectionCategory.Suspicious, detection.Category);
        Assert.Equal(DetectionConfidence.Medium, detection.Confidence);
    }

    [Fact]
    public void Unlisted_apps_match_nothing()
    {
        Assert.Empty(s_set.Match(App("com.example.notes", new string('1', 40))));
    }

    [Fact]
    public async Task Identity_findings_are_reported_on_the_base_apk_even_when_its_file_cannot_be_read()
    {
        var scanner = new MobileScanner([HashEngine.CreateDefault()], indicators: s_set);
        var target = new MobileScanTarget("Spy", "/data/app/spy/base.apk", 10, () => throw new UnauthorizedAccessException(), "com.thetruth", App("com.thetruth", Cert));

        MobileScanResult result = await scanner.ScanAsync(target, CancellationToken.None);

        Assert.Equal(ScanStatus.Detected, result.Item.Status);
        Assert.Contains("was not scanned", result.Item.Message, StringComparison.Ordinal);
        Assert.Equal((ResultTone.Danger, "Spy: Android.Stalkerware.TheTruthSpy (a potentially unwanted app)"), MobileText.Describe(result));
    }

    [Fact]
    public async Task A_package_name_match_shows_as_a_warning_not_a_threat()
    {
        var scanner = new MobileScanner([HashEngine.CreateDefault()], indicators: s_set);
        var target = new MobileScanTarget("Maybe", "/data/app/x/base.apk", 3, () => new MemoryStream([1, 2, 3]), "com.thetruth", App("com.thetruth"));

        MobileScanResult result = await scanner.ScanAsync(target, CancellationToken.None);

        Assert.Equal(ScanStatus.Suspicious, result.Item.Status);
        Assert.Equal(ResultTone.Warn, MobileText.Describe(result).Tone);
    }
}

public sealed class HashCacheTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "kshatriya-cache-" + Guid.NewGuid().ToString("N"));

    public HashCacheTests() => Directory.CreateDirectory(_folder);

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private string CachePath => Path.Combine(_folder, "hashes.json");

    [Fact]
    public async Task A_rescan_reuses_hashes_and_still_applies_the_current_signatures()
    {
        byte[] apk = TestData.BenignBytes(9, 4096);
        int opens = 0;
        var target = new MobileScanTarget("App", "/data/app/a/base.apk", apk.Length, () => { opens++; return new MemoryStream(apk); }, CacheKey: "/data/app/a/base.apk|4096|1");

        var cache = new FileHashCache(CachePath);
        await new MobileScanner([HashEngine.CreateDefault()], cache: cache).ScanAsync(target, CancellationToken.None);
        cache.Save();

        // A new list arrives that names the file: the rescan reads nothing but finds it.
        HashSignatureDatabase db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(apk), "Android.Test.Known", "pua")));
        var reloaded = new FileHashCache(CachePath);
        var scanner = new MobileScanner([HashEngine.CreateDefault(db)], cache: reloaded);
        MobileScanResult rescan = await scanner.ScanAsync(target, CancellationToken.None);

        Assert.Equal(1, opens);
        Assert.Equal(1, scanner.CacheHits);
        Assert.Equal(ScanStatus.Detected, rescan.Item.Status);
    }

    [Fact]
    public void Keys_change_when_the_file_changes()
    {
        DateTime when = new(2026, 11, 20, 0, 0, 0, DateTimeKind.Utc);
        Assert.NotEqual(FileHashCache.KeyFor("/a", 10, when), FileHashCache.KeyFor("/a", 11, when));
        Assert.NotEqual(FileHashCache.KeyFor("/a", 10, when), FileHashCache.KeyFor("/a", 10, when.AddSeconds(1)));
    }

    [Fact]
    public void A_damaged_cache_file_is_discarded()
    {
        File.WriteAllText(CachePath, "{ not json");
        Assert.Equal(0, new FileHashCache(CachePath).Count);

        File.WriteAllText(CachePath, """{"k":{"Sha256":"short","Length":1,"Used":1}}""");
        Assert.Equal(0, new FileHashCache(CachePath).Count);
    }

    [Fact]
    public void The_cache_is_bounded_and_drops_the_least_recently_used_entries()
    {
        var cache = new FileHashCache(CachePath);
        string sha = new('a', 64);
        for (int i = 0; i < FileHashCache.MaxEntries + 10; i++)
        {
            cache.Store($"k{i}", sha, i);
        }

        Assert.Equal(FileHashCache.MaxEntries, cache.Count);
        Assert.False(cache.TryGet("k0", out _, out _));
        Assert.True(cache.TryGet($"k{FileHashCache.MaxEntries + 9}", out _, out _));
    }
}
