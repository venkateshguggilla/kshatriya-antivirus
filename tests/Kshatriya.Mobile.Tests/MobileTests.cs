using System.Security.Cryptography;
using System.Text;
using Kshatriya.Core;
using Kshatriya.Engines;
using Kshatriya.Engines.Hash;
using Kshatriya.Mobile;
using Kshatriya.Tests.Shared;
using Kshatriya.Updates;

namespace Kshatriya.Mobile.Tests;

public sealed class ScannerTests
{
    private static MobileScanTarget Target(string name, byte[] data, long? size = null) =>
        new(name, $"/data/app/{name}", size ?? data.Length, () => new MemoryStream(data));

    private static MobileScanner Scanner(long maxBytes = MobileScanner.DefaultMaxBytes) =>
        new([HashEngine.CreateDefault()], maxBytes);

    [Fact]
    public async Task The_EICAR_test_file_is_detected_and_benign_content_is_clean()
    {
        MobileScanResult eicar = await Scanner().ScanAsync(Target("eicar.com", TestData.EicarBytes()), CancellationToken.None);
        MobileScanResult benign = await Scanner().ScanAsync(Target("photo.jpg", TestData.BenignBytes(1, 4096)), CancellationToken.None);

        Assert.Equal(ScanStatus.Detected, eicar.Item.Status);
        Assert.Equal(DetectionCategory.TestFile, Assert.Single(eicar.Item.Detections).Category);
        Assert.Equal(TestData.Sha256Hex(TestData.EicarBytes()), eicar.Item.Sha256);
        Assert.Equal(ScanStatus.Clean, benign.Item.Status);
        Assert.Equal(4096, benign.Item.SizeBytes);
    }

    [Fact]
    public async Task Signatures_from_a_signed_package_detect_their_files()
    {
        byte[] app = TestData.BenignBytes(7, 2048); // stands in for a known-bad APK
        HashSignatureDatabase db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(app), "Android.Test.Known", "malware")));
        var scanner = new MobileScanner([HashEngine.CreateDefault(db)]);

        MobileScanResult result = await scanner.ScanAsync(Target("base.apk", app) with { PackageName = "com.example.bad" }, CancellationToken.None);

        Assert.Equal(ScanStatus.Detected, result.Item.Status);
        Assert.Equal("Android.Test.Known", result.Item.Detections[0].Name);
        Assert.Equal("com.example.bad", result.Target.PackageName);
    }

    [Fact]
    public async Task Files_over_the_limit_are_reported_whether_or_not_their_size_is_known()
    {
        byte[] data = TestData.BenignBytes(2, 5000);

        MobileScanResult known = await Scanner(4096).ScanAsync(Target("big.bin", data), CancellationToken.None);
        MobileScanResult unknown = await Scanner(4096).ScanAsync(new MobileScanTarget("big.bin", "content://x/big", null, () => new MemoryStream(data)), CancellationToken.None);

        Assert.Equal((ScanStatus.NotScanned, ScanReason.TooLarge), (known.Item.Status, known.Item.Reason));
        Assert.Equal((ScanStatus.NotScanned, ScanReason.TooLarge), (unknown.Item.Status, unknown.Item.Reason));
    }

    [Theory]
    [InlineData("missing", ScanReason.NotFound)]
    [InlineData("denied", ScanReason.AccessDenied)]
    [InlineData("io", ScanReason.IoError)]
    public async Task Unreadable_items_are_reported_with_their_reason(string failure, ScanReason reason)
    {
        Exception error = failure switch
        {
            "missing" => new FileNotFoundException(),
            "denied" => new UnauthorizedAccessException(),
            _ => new IOException("device error"),
        };

        MobileScanResult result = await Scanner().ScanAsync(new MobileScanTarget("x", "/x", 10, () => throw error), CancellationToken.None);

        Assert.Equal(ScanStatus.NotScanned, result.Item.Status);
        Assert.Equal(reason, result.Item.Reason);
    }

    [Fact]
    public async Task A_failing_engine_is_reported_not_hidden()
    {
        var scanner = new MobileScanner([new FailingEngine()]);

        MobileScanResult result = await scanner.ScanAsync(Target("a.bin", [1, 2, 3]), CancellationToken.None);

        Assert.Equal((ScanStatus.NotScanned, ScanReason.EngineError), (result.Item.Status, result.Item.Reason));
    }

    [Fact]
    public async Task Results_are_reported_as_they_complete_and_summarised()
    {
        var seen = new List<string>();
        IReadOnlyList<MobileScanResult> results = await Scanner().ScanAllAsync(
            [Target("eicar.com", TestData.EicarBytes()), Target("ok.txt", [1, 2]), new MobileScanTarget("gone", "/gone", 1, () => throw new FileNotFoundException())],
            new SyncProgress(r => seen.Add(r.Target.DisplayName)),
            CancellationToken.None);

        Assert.Equal(["eicar.com", "ok.txt", "gone"], seen);
        Assert.Equal("Scanned 2 of 3: 1 threat(s). 1 could not be scanned.", MobileText.Summary(results));
        Assert.Equal((ResultTone.Danger, "eicar.com: Kshatriya.Test.EICAR (a test file)"), MobileText.Describe(results[0]));
        Assert.Equal(ResultTone.Ok, MobileText.Describe(results[1]).Tone);
        Assert.Equal((ResultTone.Info, "gone was not scanned because it was moved or deleted before the scan"), MobileText.Describe(results[2]));
    }

    private sealed class FailingEngine : IDetectionEngine
    {
        public EngineDescriptor Descriptor { get; } = new("failing", "1", "1");

        public ValueTask<IReadOnlyList<Detection>> ScanAsync(ScanSubject subject, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("broken");
    }

    private sealed class SyncProgress(Action<MobileScanResult> report) : IProgress<MobileScanResult>
    {
        public void Report(MobileScanResult value) => report(value);
    }
}

public sealed class ContentStoreTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "kshatriya-mobile-" + Guid.NewGuid().ToString("N"));
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly DateTimeOffset _now = DateTimeOffset.UtcNow;

    public void Dispose()
    {
        _key.Dispose();
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private ContentKey PublicKey => ContentKey.FromSpki(_key.ExportSubjectPublicKeyInfo());

    private byte[] Package(long sequence, string hashdb, ECDsa? signer = null) => ContentPackage.Create(
        "stable", sequence, _now.AddMinutes(-1), _now.AddDays(30), [("android.hashdb", Encoding.UTF8.GetBytes(hashdb))], signer ?? _key);

    private static string Db(string sha) => TestData.HashDb((sha, "Android.Test.Known", "malware"));

    [Fact]
    public void Packages_are_accepted_only_from_keys_the_user_trusted()
    {
        var store = new MobileContentStore(_folder, builtInKeys: []);
        string sha = TestData.Sha256Hex([1, 2, 3]);

        ContentImportResult before = store.Import(Package(1, Db(sha)), _now);
        Assert.True(store.AddTrustedKey(MobileContentStore.ReadKey(Convert.ToBase64String(_key.ExportSubjectPublicKeyInfo()) + "\n")));
        Assert.False(store.AddTrustedKey(PublicKey)); // already trusted
        ContentImportResult after = store.Import(Package(1, Db(sha)), _now);

        Assert.Equal(ContentErrors.NoTrustedKeys, before.Code);
        Assert.True(after.Succeeded, after.Message);
        VerifiedContent active = store.LoadActive(_now)!;
        Assert.Equal(1, active.Manifest.Sequence);
        Assert.NotNull(MobileContentStore.SignaturesOf(active).Find(sha));
    }

    [Fact]
    public void Older_or_repeated_updates_are_refused_and_state_survives_a_restart()
    {
        var store = new MobileContentStore(_folder, [PublicKey]);
        Assert.True(store.Import(Package(5, Db(TestData.Sha256Hex([5]))), _now).Succeeded);

        var restarted = new MobileContentStore(_folder, [PublicKey]);
        ContentImportResult same = restarted.Import(Package(5, Db(TestData.Sha256Hex([6]))), _now);
        ContentImportResult older = restarted.Import(Package(4, Db(TestData.Sha256Hex([4]))), _now);

        Assert.Equal(ContentErrors.Rollback, same.Code);
        Assert.Equal(ContentErrors.Rollback, older.Code);
        Assert.Equal(5, restarted.LoadActive(_now)!.Manifest.Sequence);
    }

    [Fact]
    public void Bad_packages_leave_the_installed_content_in_place()
    {
        var store = new MobileContentStore(_folder, [PublicKey]);
        Assert.True(store.Import(Package(1, Db(TestData.Sha256Hex([1]))), _now).Succeeded);
        using ECDsa stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        ContentImportResult untrusted = store.Import(Package(2, Db(TestData.Sha256Hex([2])), stranger), _now);
        ContentImportResult invalid = store.Import(Package(3, "# kshatriya-hashdb v1\nnot a signature line\n"), _now);
        ContentImportResult garbage = store.Import([1, 2, 3], _now);

        Assert.Equal(ContentErrors.UntrustedKey, untrusted.Code);
        Assert.Equal(ContentErrors.ContentInvalid, invalid.Code);
        Assert.Equal(ContentErrors.Malformed, garbage.Code);
        Assert.Equal(1, store.LoadActive(_now)!.Manifest.Sequence);
    }

    [Fact]
    public void No_package_installed_means_built_in_signatures_only()
    {
        Assert.Null(new MobileContentStore(_folder, [PublicKey]).LoadActive(_now));
    }
}
