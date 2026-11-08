using System.Text;
using Sentinel.Core;
using Sentinel.Engines.Yara;
using Sentinel.Tests.Shared;

namespace Sentinel.Engines.Yara.Tests;

public class YaraEngineTests
{
    private const string CustomRule = """
        rule Test_Marker
        {
            meta:
                name = "Sentinel.Test.Marker"
                category = "malware"
                confidence = "high"
                description = "Contains the Sentinel test marker."
            strings:
                $m = "SENTINEL-TEST-MARKER-7f3a"
            condition:
                $m
        }
        """;

    private static ScanSubject Subject(byte[] data) =>
        new("memory", data.Length, TestData.Sha256Hex(data), new MemoryStream(data, writable: false));

    private static YaraEngine Engine(params string[] rules) =>
        YaraEngine.Create([YaraEngine.BuiltInRules(), .. rules.Select((r, i) => new YaraSource(r, $"test{i}.yar"))]);

    [Fact]
    public void Native_library_is_available_in_test_output()
    {
        Assert.True(YaraEngine.IsAvailable(out string? reason), reason);
    }

    [Fact]
    public async Task Builtin_rule_detects_eicar()
    {
        using YaraEngine engine = Engine();

        Detection d = Assert.Single(await engine.ScanAsync(Subject(TestData.EicarBytes()), CancellationToken.None));

        Assert.Equal("Sentinel.Test.EICAR.Yara", d.Name);
        Assert.Equal(DetectionCategory.TestFile, d.Category);
        Assert.Equal(DetectionConfidence.High, d.Confidence);
        Assert.Equal(YaraEngine.EngineId, d.EngineId);
    }

    [Fact]
    public async Task Builtin_rule_does_not_match_eicar_with_trailing_content()
    {
        using YaraEngine engine = Engine();
        byte[] padded = [.. TestData.EicarBytes(), .. new byte[200]];

        Assert.Empty(await engine.ScanAsync(Subject(padded), CancellationToken.None));
    }

    [Fact]
    public async Task Custom_rule_metadata_maps_to_detection()
    {
        using YaraEngine engine = Engine(CustomRule);
        byte[] data = Encoding.ASCII.GetBytes("prefix SENTINEL-TEST-MARKER-7f3a suffix");

        Detection d = Assert.Single(await engine.ScanAsync(Subject(data), CancellationToken.None));

        Assert.Equal("Sentinel.Test.Marker", d.Name);
        Assert.Equal(DetectionCategory.Malware, d.Category);
        Assert.Equal(DetectionConfidence.High, d.Confidence);
        Assert.Equal("Contains the Sentinel test marker.", d.Description);
        Assert.Equal(2, engine.RuleCount);
    }

    [Fact]
    public async Task Clean_data_has_no_matches()
    {
        using YaraEngine engine = Engine(CustomRule);
        Assert.Empty(await engine.ScanAsync(Subject(TestData.BenignBytes(5, 50_000)), CancellationToken.None));
        Assert.Empty(await engine.ScanAsync(Subject([]), CancellationToken.None));
    }

    [Fact]
    public void Syntax_errors_are_reported_with_origin()
    {
        var ex = Assert.Throws<YaraCompileException>(() => YaraEngine.Create([new YaraSource("rule broken { condition: ", "broken.yar")]));
        Assert.Contains("broken.yar", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Include_statements_are_rejected()
    {
        Assert.Throws<YaraCompileException>(() =>
            YaraEngine.Create([new YaraSource("include \"C:/Windows/win.ini\"\nrule x { condition: true }", "inc.yar")]));
    }

    [Fact]
    public void Content_version_changes_with_rules()
    {
        using YaraEngine a = Engine();
        using YaraEngine b = Engine(CustomRule);
        Assert.NotEqual(a.Descriptor.ContentVersion, b.Descriptor.ContentVersion);
        Assert.StartsWith("1-", a.Descriptor.ContentVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Concurrent_scans_are_isolated()
    {
        using YaraEngine engine = Engine(CustomRule);
        byte[] hit = Encoding.ASCII.GetBytes("xx SENTINEL-TEST-MARKER-7f3a xx");
        byte[] miss = TestData.BenignBytes(9, 4096);

        var tasks = Enumerable.Range(0, 200).Select(i => Task.Run(async () =>
        {
            byte[] data = i % 2 == 0 ? hit : miss;
            var result = await engine.ScanAsync(Subject(data), CancellationToken.None);
            return (i, result.Count);
        }));

        foreach (var (i, count) in await Task.WhenAll(tasks))
        {
            Assert.Equal(i % 2 == 0 ? 1 : 0, count);
        }
    }

    [Fact]
    public async Task Disposed_engine_refuses_to_scan()
    {
        YaraEngine engine = Engine();
        engine.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await engine.ScanAsync(Subject([1]), CancellationToken.None));
    }

    [Theory]
    [InlineData("", "rule1", null, null, null, "rule1", DetectionCategory.Suspicious, DetectionConfidence.Medium)]
    [InlineData("ns", "r", null, null, null, "ns.r", DetectionCategory.Suspicious, DetectionConfidence.Medium)]
    [InlineData("default", "r", "Good.Name", "pua", "low", "Good.Name", DetectionCategory.PotentiallyUnwanted, DetectionConfidence.Low)]
    [InlineData("default", "r", "bad name!", "MALWARE", "HIGH", "r", DetectionCategory.Malware, DetectionConfidence.High)]
    [InlineData("default", "r", null, "nonsense", "nonsense", "r", DetectionCategory.Suspicious, DetectionConfidence.Medium)]
    public void Rule_metadata_is_validated(string ns, string id, string? name, string? category, string? confidence,
        string expectedName, DetectionCategory expectedCategory, DetectionConfidence expectedConfidence)
    {
        var meta = new Dictionary<string, string>();
        if (name is not null)
        {
            meta["name"] = name;
        }

        if (category is not null)
        {
            meta["category"] = category;
        }

        if (confidence is not null)
        {
            meta["confidence"] = confidence;
        }

        Detection d = RuleMapping.ToDetection(ns, id, meta);

        Assert.Equal(expectedName, d.Name);
        Assert.Equal(expectedCategory, d.Category);
        Assert.Equal(expectedConfidence, d.Confidence);
    }
}
