using System.Globalization;
using System.Text;
using System.Text.Json;
using Sentinel.Cli;
using Sentinel.Tests.Shared;

namespace Sentinel.Cli.Tests;

public class CliMilestone9Tests
{
    private static async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        using var input = new MemoryStream();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int code = await CliApp.RunAsync(args, input, stdout, stderr);
        return (code, stdout.ToString(), stderr.ToString());
    }

    private static string Model()
    {
        var weights = new double[296];
        weights[280] = 2; // writable + executable sections
        return $$"""
            { "schemaVersion": 1, "name": "cli-test", "detectionName": "Sentinel.ML.CliTest", "featureSet": "pe-v1", "featureCount": 296,
              "kind": "logistic", "bias": -3, "threshold": 0.6, "weights": [{{string.Join(",", weights.Select(w => w.ToString(CultureInfo.InvariantCulture)))}}] }
            """;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_model_runs_in_the_sandboxed_worker_and_in_process_with_the_same_result(bool noSandbox)
    {
        using var temp = new TempDirectory();
        string model = temp.File("test.model.json", Encoding.UTF8.GetBytes(Model()));
        temp.File(@"t\packed.exe", PeBuilder.PackedLike().Build());
        temp.File(@"t\benign.exe", PeBuilder.Benign().Build());
        string[] args = ["scan", Path.Combine(temp.Path, "t"), "--model", model, "--no-heuristics", "--json"];

        var (code, output, _) = await Run(noSandbox ? [.. args, "--no-sandbox"] : args);

        Assert.Equal(ExitCodes.Suspicious, code);
        using JsonDocument doc = JsonDocument.Parse(output);
        JsonElement item = Assert.Single(doc.RootElement.GetProperty("items").EnumerateArray());
        Assert.EndsWith("packed.exe", item.GetProperty("path").GetString(), StringComparison.Ordinal);
        JsonElement detection = Assert.Single(item.GetProperty("detections").EnumerateArray());
        Assert.Equal("ml", detection.GetProperty("engine").GetString());
        Assert.Equal("suspicious", detection.GetProperty("category").GetString());
        Assert.Contains(doc.RootElement.GetProperty("engines").EnumerateArray(), e => e.GetProperty("id").GetString() == "ml");
    }

    [Fact]
    public async Task An_invalid_model_is_a_fatal_configuration_error()
    {
        using var temp = new TempDirectory();
        string model = temp.File("bad.model.json", "{ \"schemaVersion\": 1 }"u8.ToArray());

        var (code, _, err) = await Run("scan", temp.Path, "--model", model);

        Assert.Equal(ExitCodes.Fatal, code);
        Assert.Contains("model", err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Models_cannot_be_passed_to_the_service()
    {
        var (code, _, _) = await Run("scan", "--service", @"C:\x", "--model", "m.model.json");
        Assert.Equal(ExitCodes.Usage, code);
    }
}
