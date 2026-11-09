using System.Text.Json;
using Kshatriya.Cli;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

/// <summary>The real CLI talking to a real (development-mode) service. Runs sequentially: it sets a static endpoint override.</summary>
public class CliServiceTests
{
    private static async Task<(int Code, string Out, string Err)> Run(RunningService service, params string[] args)
    {
        CliApp.EndpointOverride = service.Endpoint;
        try
        {
            using var input = new MemoryStream();
            using var stdout = new StringWriter();
            using var stderr = new StringWriter();
            int code = await CliApp.RunAsync(args, input, stdout, stderr);
            return (code, stdout.ToString(), stderr.ToString());
        }
        finally
        {
            CliApp.EndpointOverride = null;
        }
    }

    [Fact]
    public async Task Status_command_prints_service_state()
    {
        await using RunningService service = await RunningService.StartAsync();

        var (code, output, _) = await Run(service, "status");

        Assert.Equal(ExitCodes.Clean, code);
        Assert.Contains("(development)", output, StringComparison.Ordinal);
        Assert.Contains("Connected as: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name, output, StringComparison.Ordinal);
        Assert.Contains("Sandboxed workers: 2 configured", output, StringComparison.Ordinal);
        Assert.Contains("Scheduled scans: none configured", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Service_scan_returns_a_schema_v2_report_and_the_right_exit_code()
    {
        await using RunningService service = await RunningService.StartAsync();
        service.Temp.File(@"scan\flagged.bin", service.KnownBad);
        service.Temp.File(@"scan\clean.bin", TestData.BenignBytes(2, 100));

        var (code, output, _) = await Run(service, "scan", "--service", Path.Combine(service.Temp.Path, "scan"), "--json");

        Assert.Equal(ExitCodes.Detections, code);
        using var doc = JsonDocument.Parse(output);
        Assert.Equal(4, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(1, doc.RootElement.GetProperty("summary").GetProperty("detected").GetInt32());
    }

    [Fact]
    public async Task Service_scan_of_a_clean_folder_exits_zero_with_text_output()
    {
        await using RunningService service = await RunningService.StartAsync();
        service.Temp.File(@"clean\a.bin", TestData.BenignBytes(3, 100));

        var (code, output, _) = await Run(service, "scan", "--service", Path.Combine(service.Temp.Path, "clean"));

        Assert.Equal(ExitCodes.Clean, code);
        Assert.Contains("Nothing detected.", output, StringComparison.Ordinal);
    }
}
