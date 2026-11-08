using System.Globalization;
using System.Text;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Engines.Pe;
using Sentinel.Tests.Shared;

namespace Sentinel.Engines.Pe.Tests;

public class MachineLearningTests
{
    /// <summary>Feature index of "number of writable and executable sections".</summary>
    private const int WritableExecutableSections = 280;

    internal static string LogisticModel(double bias = -3, double weight = 2, double threshold = 0.6)
    {
        var weights = new double[PeFeatures.Count];
        weights[WritableExecutableSections] = weight;
        return $$"""
            { "schemaVersion": 1, "name": "test-logistic", "detectionName": "Sentinel.ML.Test", "featureSet": "pe-v1", "featureCount": {{PeFeatures.Count}},
              "kind": "logistic", "bias": {{bias.ToString(CultureInfo.InvariantCulture)}}, "threshold": {{threshold.ToString(CultureInfo.InvariantCulture)}},
              "weights": [{{string.Join(",", weights.Select(w => w.ToString(CultureInfo.InvariantCulture)))}}] }
            """;
    }

    internal static string TreeModel(string nodes = "[[280, 0.5, 1, 2], [-2.0], [3.0]]") => $$"""
        { "schemaVersion": 1, "name": "test-trees", "detectionName": "Sentinel.ML.TreeTest", "featureSet": "pe-v1", "featureCount": {{PeFeatures.Count}},
          "kind": "trees", "bias": 0, "threshold": 0.9, "trees": [ {{nodes}} ] }
        """;

    private static float[] Features(byte[] pe)
    {
        Assert.True(PeImage.TryParse(pe, out PeImage? image, out _));
        return PeFeatures.Extract(pe, image!, trust: null);
    }

    private static async Task<IReadOnlyList<Detection>> Scan(MlEngine engine, byte[] data, FileTrust? trust = null) =>
        await engine.ScanAsync(new ScanSubject("x.exe", data.Length, new string('a', 64), new MemoryStream(data), trust), CancellationToken.None);

    [Fact]
    public void Features_have_a_fixed_length_and_are_deterministic()
    {
        byte[] pe = PeBuilder.PackedLike().Build();

        float[] a = Features(pe);
        float[] b = Features(pe);

        Assert.Equal(PeFeatures.Count, a.Length);
        Assert.Equal(a, b);
        Assert.Equal(1.0, a.Take(256).Sum(), 3);
        Assert.Equal(2, a[WritableExecutableSections]);
        Assert.Equal(0, Features(PeBuilder.Benign().Build())[WritableExecutableSections]);
        Assert.All(a, v => Assert.True(float.IsFinite(v)));
    }

    [Fact]
    public async Task A_logistic_model_scores_packed_like_files_as_suspicious_only()
    {
        var engine = new MlEngine(MlModel.Parse(LogisticModel()));

        Detection d = Assert.Single(await Scan(engine, PeBuilder.PackedLike().Build()));
        Assert.Empty(await Scan(engine, PeBuilder.Benign().Build()));

        Assert.Equal("Sentinel.ML.Test", d.Name);
        Assert.Equal(DetectionCategory.Suspicious, d.Category);
        Assert.Equal(DetectionConfidence.Low, d.Confidence);
        Assert.StartsWith("test-logistic-", engine.Descriptor.ContentVersion, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_tree_model_is_evaluated()
    {
        var engine = new MlEngine(MlModel.Parse(TreeModel()));

        Detection d = Assert.Single(await Scan(engine, PeBuilder.PackedLike().Build()));
        Assert.Equal(DetectionConfidence.Medium, d.Confidence);
        Assert.Empty(await Scan(engine, PeBuilder.Benign().Build()));
    }

    [Fact]
    public async Task Signed_and_non_PE_files_are_not_scored()
    {
        var engine = new MlEngine(MlModel.Parse(LogisticModel(bias: 10)));

        Assert.Empty(await Scan(engine, PeBuilder.PackedLike().Build(), new FileTrust(TrustStatus.Valid, TrustSource.Embedded, "Vendor")));
        Assert.Empty(await Scan(engine, TestData.BenignBytes(5, 4096)));
        Assert.Empty(await Scan(engine, Encoding.ASCII.GetBytes("MZ but not really a PE file at all, just text that is long enough to pass size")));
    }

    [Theory]
    [InlineData("[[280, 0.5, 0, 2], [-1.0], [1.0]]")] // child points back at its parent (cycle)
    [InlineData("[[280, 0.5, 1, 9], [-1.0], [1.0]]")] // child out of range
    [InlineData("[[999, 0.5, 1, 2], [-1.0], [1.0]]")] // feature out of range
    [InlineData("[[280.5, 0.5, 1, 2], [-1.0], [1.0]]")] // non-integer feature index
    [InlineData("[[280, 0.5, 1]]")] // malformed node
    [InlineData("[]")] // empty tree
    public void Invalid_trees_are_rejected(string nodes) => Assert.Throws<FormatException>(() => MlModel.Parse(TreeModel(nodes)));

    [Theory]
    [InlineData("\"featureSet\": \"pe-v1\"", "\"featureSet\": \"pe-v9\"")]
    [InlineData("\"detectionName\": \"Sentinel.ML.Test\"", "\"detectionName\": \"Trojan.Fake\"")]
    [InlineData("\"threshold\": 0.6", "\"threshold\": 1.5")]
    [InlineData("\"kind\": \"logistic\"", "\"kind\": \"neural\"")]
    [InlineData("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"extra\": true")]
    public void Invalid_models_are_rejected(string from, string to)
    {
        string model = LogisticModel().Replace(from, to, StringComparison.Ordinal);
        Assert.NotEqual(LogisticModel(), model);
        Assert.Throws<FormatException>(() => MlModel.Parse(model));
    }

    [Fact]
    public void A_model_with_the_wrong_number_of_weights_is_rejected()
    {
        string model = LogisticModel().Replace("\"weights\": [0,", "\"weights\": [", StringComparison.Ordinal);
        Assert.Throws<FormatException>(() => MlModel.Parse(model));
    }
}
