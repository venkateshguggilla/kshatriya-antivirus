using System.Text.Json;
using NJsonSchema;
using Sentinel.Cli;
using Sentinel.Engines.Hash;
using Sentinel.Tests.Shared;

namespace Sentinel.Cli.Tests;

public class CliAppTests
{
    private static readonly Lazy<JsonSchema> s_schema = new(() =>
        JsonSchema.FromFileAsync(Path.Combine(AppContext.BaseDirectory, "schemas", "scan-report.v4.schema.json")).GetAwaiter().GetResult());

    private static async Task<(int Code, string Out, string Err)> Run(byte[]? stdin, params string[] args)
    {
        using var input = new MemoryStream(stdin ?? []);
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

    private static string WriteCustomDb(TempDirectory temp, byte[] sample) =>
        temp.File("custom.hashdb", System.Text.Encoding.UTF8.GetBytes(
            TestData.HashDb((TestData.Sha256Hex(sample), "Sentinel.Test.Custom", "test"))));

    [Theory]
    [InlineData]
    [InlineData("help")]
    [InlineData("--help")]
    public async Task Help_prints_usage_and_exits_zero(params string[] args)
    {
        var (code, output, _) = await Run(null, args);
        Assert.Equal(ExitCodes.Clean, code);
        Assert.Contains("Usage:", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Version_prints_tool_version()
    {
        var (code, output, _) = await Run(null, "version");
        Assert.Equal(ExitCodes.Clean, code);
        Assert.StartsWith("sentinel 0.12.0", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("frobnicate")]
    [InlineData("scan")]
    [InlineData("scan", "--bogus", "x")]
    [InlineData("scan", "x", "--timeout")]
    [InlineData("scan", "x", "--timeout", "0")]
    [InlineData("scan", "x", "--max-file-size", "-5")]
    [InlineData("scan", "--stdin", "x")]
    public async Task Invalid_command_lines_exit_with_usage_error(params string[] args)
    {
        var (code, _, err) = await Run(null, args);
        Assert.Equal(ExitCodes.Usage, code);
        Assert.StartsWith("error:", err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Clean_directory_exits_zero_with_valid_json()
    {
        using var temp = new TempDirectory();
        temp.File("a.bin", TestData.BenignBytes(1, 10));
        temp.File(@"s\b.bin", TestData.BenignBytes(2, 10));

        var (code, output, _) = await Run(null, "scan", temp.Path, "--json", "--include-clean");

        Assert.Equal(ExitCodes.Clean, code);
        AssertValidReport(output);
        using var doc = JsonDocument.Parse(output);
        Assert.Equal(2, doc.RootElement.GetProperty("summary").GetProperty("filesScanned").GetInt32());
        Assert.True(doc.RootElement.GetProperty("complete").GetBoolean());
    }

    [Fact]
    public async Task Directory_with_custom_signature_match_exits_one_with_valid_json()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(99, 512);
        string db = WriteCustomDb(temp, sample);
        string target = temp.Dir("target");
        temp.File(@"target\x\flagged.bin", sample);
        temp.File(@"target\clean.bin", TestData.BenignBytes(3, 20));

        var (code, output, _) = await Run(null, "scan", target, "--signatures", db, "--json");

        Assert.Equal(ExitCodes.Detections, code);
        AssertValidReport(output);
        using var doc = JsonDocument.Parse(output);
        JsonElement item = Assert.Single(doc.RootElement.GetProperty("items").EnumerateArray());
        Assert.Equal("detected", item.GetProperty("status").GetString());
        Assert.Equal("Sentinel.Test.Custom", item.GetProperty("detections")[0].GetProperty("name").GetString());
        Assert.Equal("test", item.GetProperty("detections")[0].GetProperty("category").GetString());
    }

    [Fact]
    public async Task Text_mode_reports_detection_calmly()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(5, 64);
        string db = WriteCustomDb(temp, sample);
        temp.File(@"t\f.bin", sample);

        var (code, output, _) = await Run(null, "scan", Path.Combine(temp.Path, "t"), "--signatures", db);

        Assert.Equal(ExitCodes.Detections, code);
        Assert.Contains("DETECTED  Sentinel.Test.Custom", output, StringComparison.Ordinal);
        Assert.Contains("No files were changed", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Eicar_piped_on_stdin_is_detected()
    {
        var (code, output, _) = await Run(TestData.EicarBytes(), "scan", "--stdin", "--name", "eicar", "--json");

        Assert.Equal(ExitCodes.Detections, code);
        AssertValidReport(output);
        Assert.Contains(BuiltInSignatures.EicarName, output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Clean_stdin_exits_zero()
    {
        var (code, output, _) = await Run(TestData.BenignBytes(8, 100), "scan", "--stdin", "--json");
        Assert.Equal(ExitCodes.Clean, code);
        AssertValidReport(output);
    }

    [Fact]
    public async Task Oversized_file_makes_scan_incomplete_with_exit_two()
    {
        using var temp = new TempDirectory();
        temp.File("big.bin", new byte[(1024 * 1024) + 1]);

        var (code, output, _) = await Run(null, "scan", temp.Path, "--max-file-size", "1", "--json");

        Assert.Equal(ExitCodes.Incomplete, code);
        AssertValidReport(output);
        using var doc = JsonDocument.Parse(output);
        Assert.False(doc.RootElement.GetProperty("complete").GetBoolean());
        Assert.Equal("tooLarge", doc.RootElement.GetProperty("items")[0].GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Detections_take_precedence_over_incompleteness()
    {
        using var temp = new TempDirectory();
        byte[] sample = TestData.BenignBytes(11, 64);
        string db = WriteCustomDb(temp, sample);
        temp.File(@"t\f.bin", sample);
        temp.File(@"t\big.bin", new byte[(1024 * 1024) + 1]);

        var (code, _, _) = await Run(null, "scan", Path.Combine(temp.Path, "t"), "--signatures", db, "--max-file-size", "1");

        Assert.Equal(ExitCodes.Detections, code);
    }

    [Fact]
    public async Task Invalid_signature_database_is_fatal()
    {
        using var temp = new TempDirectory();
        string db = temp.File("bad.hashdb", "not a database"u8.ToArray());

        var (code, _, err) = await Run(null, "scan", temp.Path, "--signatures", db);

        Assert.Equal(ExitCodes.Fatal, code);
        Assert.Contains("could not load signatures", err, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Output_option_writes_report_file()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\a.bin", [1]);
        string reportPath = Path.Combine(temp.Path, "report.json");

        var (code, output, _) = await Run(null, "scan", Path.Combine(temp.Path, "t"), "--json", "--output", reportPath);

        Assert.Equal(ExitCodes.Clean, code);
        Assert.Equal(string.Empty, output);
        AssertValidReport(await File.ReadAllTextAsync(reportPath));
    }

    [Fact]
    public async Task Skipped_link_appears_in_valid_report()
    {
        using var temp = new TempDirectory();
        temp.File(@"t\a.bin", [1]);
        Assert.True(TempDirectory.TryCreateJunction(Path.Combine(temp.Path, "t", "link"), temp.Path));

        var (code, output, _) = await Run(null, "scan", Path.Combine(temp.Path, "t"), "--json");

        Assert.Equal(ExitCodes.Clean, code); // policy skips do not make a scan incomplete
        AssertValidReport(output);
        Assert.Contains("\"reparsePoint\"", output, StringComparison.Ordinal);
    }
}
