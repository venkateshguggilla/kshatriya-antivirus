using System.Text.Json;
using Kshatriya.Cli;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Cli.Tests;

/// <summary>Local quarantine through the CLI. One class, so tests sharing the local-data override run sequentially.</summary>
public sealed class CliMilestone4Tests : IDisposable
{
    private readonly TempDirectory _temp = new();

    public CliMilestone4Tests() => ManagementCommands.LocalDataOverride = Path.Combine(_temp.Path, "localdata");

    public void Dispose()
    {
        ManagementCommands.LocalDataOverride = null;
        _temp.Dispose();
    }

    private static async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        using var input = new MemoryStream();
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int code = await CliApp.RunAsync(args, input, stdout, stderr);
        return (code, stdout.ToString(), stderr.ToString());
    }

    [Fact]
    public async Task Scan_quarantine_list_restore_and_audit_locally()
    {
        byte[] marked = TestData.BenignBytes(21, 4000);
        string db = _temp.File("db.hashdb", System.Text.Encoding.UTF8.GetBytes(TestData.HashDb((TestData.Sha256Hex(marked), "Kshatriya.Test.M4", "test"))));
        string bad = _temp.File(@"t\bad.bin", marked);
        _temp.File(@"t\fine.bin", TestData.BenignBytes(22, 100));

        var scan = await Run("scan", Path.Combine(_temp.Path, "t"), "--signatures", db, "--quarantine", "--json");

        Assert.Equal(ExitCodes.Detections, scan.Code);
        Assert.False(File.Exists(bad));
        using JsonDocument doc = JsonDocument.Parse(scan.Out);
        Assert.Equal(4, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        JsonElement action = doc.RootElement.GetProperty("items")[0].GetProperty("action");
        Assert.Equal("quarantined", action.GetProperty("outcome").GetString());
        string id = action.GetProperty("quarantineId").GetString()!;

        var list = await Run("quarantine", "list");
        Assert.Equal(ExitCodes.Clean, list.Code);
        Assert.Contains(id, list.Out, StringComparison.Ordinal);
        Assert.Contains("Kshatriya.Test.M4", list.Out, StringComparison.Ordinal);

        string elsewhere = Path.Combine(_temp.Path, "restored.bin");
        var restore = await Run("quarantine", "restore", id, "--to", elsewhere);
        Assert.Equal(ExitCodes.Clean, restore.Code);
        Assert.Equal(marked, File.ReadAllBytes(elsewhere));

        var audit = await Run("audit");
        Assert.Equal(ExitCodes.Clean, audit.Code);
        Assert.Contains("restore succeeded", audit.Out, StringComparison.Ordinal);
        Assert.Contains("quarantine succeeded", audit.Out, StringComparison.Ordinal);
        Assert.Contains("integrity check passed", audit.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Text_report_shows_the_action_taken()
    {
        byte[] marked = TestData.BenignBytes(23, 4000);
        string db = _temp.File("db2.hashdb", System.Text.Encoding.UTF8.GetBytes(TestData.HashDb((TestData.Sha256Hex(marked), "Kshatriya.Test.Text", "test"))));
        _temp.File(@"text\bad.bin", marked);

        var scan = await Run("scan", Path.Combine(_temp.Path, "text"), "--signatures", db, "--quarantine", "--no-sandbox");

        Assert.Contains("-> quarantined (id ", scan.Out, StringComparison.Ordinal);
        Assert.Contains("1 item(s) detected: 1 quarantined, 0 could not be quarantined.", scan.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Exclude_skips_paths_for_one_local_scan()
    {
        _temp.File(@"ex\keep.bin", [1]);
        string skipped = _temp.Dir(@"ex\skip");

        var scan = await Run("scan", Path.Combine(_temp.Path, "ex"), "--exclude", skipped, "--no-sandbox");

        Assert.Equal(ExitCodes.Clean, scan.Code);
        Assert.Contains($"skipped  [excluded]  {skipped}", scan.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Manual_quarantine_and_delete_locally()
    {
        string file = _temp.File("manual.bin", [1, 2, 3]);

        var add = await Run("quarantine", "add", file);
        string id = add.Out.Split("(id ")[1].Split(')')[0];
        var delete = await Run("quarantine", "delete", id);
        var deleteAgain = await Run("quarantine", "delete", id);

        Assert.Equal(ExitCodes.Clean, add.Code);
        Assert.False(File.Exists(file));
        Assert.Equal(ExitCodes.Clean, delete.Code);
        Assert.Equal(ExitCodes.Fatal, deleteAgain.Code);
        Assert.Contains("[notFound]", deleteAgain.Err, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("scan", "--stdin", "--quarantine")]
    [InlineData("scan", "--service", "C:\\x", "--exclude", "C:\\y")]
    [InlineData("scan", "C:\\x", "--exclude", "C:\\")]
    [InlineData("exclusions", "list")]
    [InlineData("exclusions", "add", "C:\\x")]
    [InlineData("quarantine")]
    [InlineData("quarantine", "list", "extra")]
    [InlineData("quarantine", "restore")]
    [InlineData("quarantine", "add", "a", "--to", "b")]
    [InlineData("quarantine", "list", "--dev")]
    [InlineData("audit", "--last", "0")]
    [InlineData("audit", "x")]
    public async Task Invalid_milestone_4_command_lines_are_usage_errors(params string[] args)
    {
        var (code, _, err) = await Run(args);

        Assert.Equal(ExitCodes.Usage, code);
        Assert.StartsWith("error:", err, StringComparison.Ordinal);
    }
}
