using Kshatriya.Core;
using Kshatriya.Engines.Hash;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Engines.Hash.Tests;

public class HashEngineTests
{
    private static ScanSubject Subject(byte[] data) =>
        new("memory", data.Length, TestData.Sha256Hex(data), new MemoryStream(data, writable: false));

    [Fact]
    public async Task Detects_eicar_from_builtin_signatures()
    {
        HashEngine engine = HashEngine.CreateDefault();

        IReadOnlyList<Detection> result = await engine.ScanAsync(Subject(TestData.EicarBytes()), CancellationToken.None);

        Detection d = Assert.Single(result);
        Assert.Equal(BuiltInSignatures.EicarName, d.Name);
        Assert.Equal(DetectionCategory.TestFile, d.Category);
        Assert.Equal(DetectionConfidence.High, d.Confidence);
        Assert.Equal(HashEngine.EngineId, d.EngineId);
    }

    [Fact]
    public async Task Clean_content_produces_no_detections()
    {
        HashEngine engine = HashEngine.CreateDefault();
        Assert.Empty(await engine.ScanAsync(Subject(TestData.BenignBytes(1, 4096)), CancellationToken.None));
    }

    [Fact]
    public async Task Additional_database_signatures_are_detected()
    {
        byte[] sample = TestData.BenignBytes(42, 1000);
        var db = HashSignatureDatabase.Parse(TestData.HashDb((TestData.Sha256Hex(sample), "Kshatriya.Test.Custom", "test")));
        HashEngine engine = HashEngine.CreateDefault(db);

        Assert.Equal(2, engine.SignatureCount);
        Detection d = Assert.Single(await engine.ScanAsync(Subject(sample), CancellationToken.None));
        Assert.Equal("Kshatriya.Test.Custom", d.Name);
    }

    [Fact]
    public void Descriptor_reports_content_version()
    {
        HashEngine engine = HashEngine.CreateDefault();
        Assert.Equal("hash", engine.Descriptor.Id);
        Assert.StartsWith("1-", engine.Descriptor.ContentVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Honours_cancellation()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await HashEngine.CreateDefault().ScanAsync(Subject([1, 2, 3]), cts.Token));
    }
}
