using System.Text.Json;
using NJsonSchema;
using Sentinel.Cli;
using Sentinel.Tests.Shared;

namespace Sentinel.Cli.Tests;

public class CliMilestone2Tests
{
    private static readonly Lazy<JsonSchema> s_schema = new(() =>
        JsonSchema.FromFileAsync(Path.Combine(AppContext.BaseDirectory, "schemas", "scan-report.v3.schema.json")).GetAwaiter().GetResult());

    private static async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        using var input = new MemoryStream();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int code = await CliApp.RunAsync(args, input, stdout, stderr);
        return (code, stdout.ToString(), stderr.ToString());
    }

    private static void AssertValidReport(string json)
    {
        var errors = s_schema.Value.Validate(json);
        Assert.True(errors.Count == 0, "Schema errors: " + string.Join("; ", errors.Select(e => $"{e.Path}: {e.Kind}")));
    }

    [Fact]
    public async Task Packed_like_executable_exits_five_as_suspicious()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\packed.exe", PeBuilder.PackedLike().Build());
        temp.File(@"t\plain.exe", PeBuilder.Benign().Build());

        var (code, output, _) = await Run("scan", Path.Combine(temp.Path, "t"), "--json");

        Assert.Equal(ExitCodes.Suspicious, code);
        AssertValidReport(output);
        using var doc = JsonDocument.Parse(output);
        JsonElement item = Assert.Single(doc.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("suspicious", item.GetProperty("status").GetString());
        Assert.Equal("notSigned", item.GetProperty("trust").GetProperty("status").GetString());
        Assert.Equal("pe-heuristics", item.GetProperty("detections")[0].GetProperty("engine").GetString());
        Assert.Equal(1, doc.RootElement.GetProperty("summary").GetProperty("suspicious").GetInt32());
    }

    [Fact]
    public async Task No_heuristics_option_disables_pe_engine()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\packed.exe", PeBuilder.PackedLike().Build());

        var (code, output, _) = await Run("scan", Path.Combine(temp.Path, "t"), "--no-heuristics", "--json");

        Assert.Equal(ExitCodes.Clean, code);
        Assert.DoesNotContain("pe-heuristics", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Suspicious_text_output_is_calm()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\packed.exe", PeBuilder.PackedLike().Build());

        var (_, output, _) = await Run("scan", Path.Combine(temp.Path, "t"));

        Assert.Contains("SUSPICIOUS  Sentinel.Heuristic.SuspiciousPE", output, StringComparison.Ordinal);
        Assert.Contains("not confirmed malware", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Custom_yara_rules_detect_inside_archives_with_location()
    {
        using var temp = new TempDirectory();
        string rules = temp.File("custom.yar", """
            rule Marker { meta: name = "Sentinel.Test.Marker" category = "test" confidence = "high"
              strings: $m = "SENTINEL-CLI-MARKER-91c2" condition: $m }
            """u8.ToArray());
        temp.File(@"t\bundle.zip", ZipFactory.Create(("docs/inner.txt", "xx SENTINEL-CLI-MARKER-91c2 xx"u8.ToArray())));

        var (code, output, err) = await Run("scan", Path.Combine(temp.Path, "t"), "--rules", rules, "--json");

        Assert.True(code == ExitCodes.Detections, err);
        AssertValidReport(output);
        using var doc = JsonDocument.Parse(output);
        JsonElement detection = doc.RootElement.GetProperty("items")[0].GetProperty("detections")[0];
        Assert.Equal("Sentinel.Test.Marker", detection.GetProperty("name").GetString());
        Assert.Equal("docs/inner.txt", detection.GetProperty("location").GetString());
    }

    [Fact]
    public async Task Invalid_yara_rules_are_fatal()
    {
        using var temp = new TempDirectory();
        string rules = temp.File("bad.yar", "rule { nope"u8.ToArray());

        var (code, _, err) = await Run("scan", temp.Path, "--rules", rules);

        Assert.Equal(ExitCodes.Fatal, code);
        Assert.Contains("bad.yar", err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Archive_depth_zero_disables_expansion()
    {
        using var temp = new TempDirectory();
        string rules = temp.File("custom.yar", """
            rule Marker { strings: $m = "SENTINEL-CLI-MARKER-91c2" condition: $m }
            """u8.ToArray());
        temp.File(@"t\bundle.zip", ZipFactory.Create(CompressionLevelStore, ("inner.txt", "SENTINEL-CLI-MARKER-91c2"u8.ToArray())));

        var (_, deepJson, _) = await Run("scan", Path.Combine(temp.Path, "t"), "--rules", rules, "--json");
        var (_, shallowJson, _) = await Run("scan", Path.Combine(temp.Path, "t"), "--rules", rules, "--archive-depth", "0", "--json");

        // A stored (uncompressed) entry is visible to YARA in the raw archive bytes too. With expansion the
        // entry itself is also scanned and reported with its location; with depth 0 it is not.
        static string[] Locations(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("items")[0].GetProperty("detections").EnumerateArray()
                .Select(d => d.TryGetProperty("location", out JsonElement l) ? l.GetString()! : "(none)").ToArray();
        }

        Assert.Equal(["(none)", "inner.txt"], Locations(deepJson));
        Assert.Equal(["(none)"], Locations(shallowJson));
    }

    [Fact]
    public async Task Encrypted_archive_makes_scan_incomplete_with_valid_report()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\enc.zip", ZipFactory.MarkAllEncrypted(ZipFactory.Create(("x.bin", TestData.BenignBytes(1, 64)))));

        var (code, output, _) = await Run("scan", Path.Combine(temp.Path, "t"), "--json");

        Assert.Equal(ExitCodes.Incomplete, code);
        AssertValidReport(output);
        Assert.Contains("\"archiveEncrypted\"", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--archive-depth", "11")]
    [InlineData("--archive-depth", "-1")]
    [InlineData("--rules")]
    public async Task Invalid_m2_options_are_usage_errors(params string[] extra)
    {
        var (code, _, _) = await Run(["scan", ".", .. extra]);
        Assert.Equal(ExitCodes.Usage, code);
    }

    private const System.IO.Compression.CompressionLevel CompressionLevelStore = System.IO.Compression.CompressionLevel.NoCompression;
}
