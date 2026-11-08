using System.Text.Json;
using Sentinel.Cli;
using Sentinel.Tests.Shared;

namespace Sentinel.Cli.Tests;

public class CliMilestone3Tests
{
    private static async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        using var input = new MemoryStream();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int code = await CliApp.RunAsync(args, input, stdout, stderr);
        return (code, stdout.ToString(), stderr.ToString());
    }

    [Theory]
    [InlineData("scan", "--service", "C:\\x", "--rules", "a.yar")]
    [InlineData("scan", "--service", "C:\\x", "--no-sandbox")]
    [InlineData("scan", "--service", "C:\\x", "--timeout", "5")]
    [InlineData("scan", "--service", "--stdin")]
    [InlineData("scan", "--dev", "C:\\x")]
    [InlineData("status", "--json")]
    [InlineData("scan", "C:\\x", "--max-file-size", "2048")]
    public async Task Invalid_milestone_3_option_combinations_are_usage_errors(params string[] args)
    {
        var (code, _, err) = await Run(args);

        Assert.Equal(ExitCodes.Usage, code);
        Assert.StartsWith("error:", err, StringComparison.Ordinal);
    }

    [Fact]
    public void Large_files_are_allowed_without_the_sandbox()
    {
        CliOptions options = CliOptions.Parse(["scan", @"C:\x", "--max-file-size", "2048", "--no-sandbox"]);

        Assert.True(options.NoSandbox);
        Assert.Equal(2048L * 1024 * 1024, options.MaxFileSizeBytes);
    }

    [Fact]
    public async Task Sandboxed_and_in_process_scans_produce_the_same_findings()
    {
        using var temp = new TempDirectory();
        byte[] marked = TestData.BenignBytes(11, 3000);
        string db = temp.File("db.hashdb", System.Text.Encoding.UTF8.GetBytes(TestData.HashDb((TestData.Sha256Hex(marked), "Sentinel.Test.Parity", "test"))));
        temp.File(@"t\a.bin", marked);
        temp.File(@"t\b.zip", ZipFactory.Create(("x/a.bin", marked)));
        temp.File(@"t\packed.exe", PeBuilder.PackedLike().Build());
        string target = Path.Combine(temp.Path, "t");

        var sandboxed = await Run("scan", target, "--signatures", db, "--json");
        var local = await Run("scan", target, "--signatures", db, "--json", "--no-sandbox");

        Assert.Equal(ExitCodes.Detections, sandboxed.Code);
        Assert.Equal(sandboxed.Code, local.Code);
        Assert.Equal(Findings(sandboxed.Out), Findings(local.Out));
    }

    [Fact]
    public async Task Status_reports_an_unreachable_service_as_a_fatal_error()
    {
        CliApp.EndpointOverride = new Sentinel.Runtime.Ipc.ServiceEndpoint($"Sentinel.Tests.Missing.{Guid.NewGuid():N}", Sentinel.Runtime.Ipc.ServerIdentityCheck.CurrentUser, "x");
        try
        {
            var (code, _, err) = await Run("status");

            Assert.Equal(ExitCodes.Fatal, code);
            Assert.Contains("not reachable", err, StringComparison.Ordinal);
        }
        finally
        {
            CliApp.EndpointOverride = null;
        }
    }

    [Fact]
    public void Help_describes_the_service_and_sandbox_options()
    {
        Assert.Contains("--no-sandbox", CliOptions.HelpText, StringComparison.Ordinal);
        Assert.Contains("sentinel status", CliOptions.HelpText, StringComparison.Ordinal);
        Assert.Contains("milestone 10", CliOptions.HelpText, StringComparison.Ordinal);
    }

    private static string[] Findings(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return [.. doc.RootElement.GetProperty("items").EnumerateArray()
            .SelectMany(i => i.GetProperty("detections").EnumerateArray().Select(d =>
                $"{Path.GetFileName(i.GetProperty("path").GetString())}|{i.GetProperty("status").GetString()}|{d.GetProperty("engine").GetString()}|{d.GetProperty("name").GetString()}|{(d.TryGetProperty("location", out JsonElement l) ? l.GetString() : "")}"))
            .Order(StringComparer.Ordinal)];
    }
}
