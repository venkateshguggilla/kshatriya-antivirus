using Kshatriya.Scanning.Targets;

namespace Kshatriya.Cli.Tests;

public class ScanKindOptionTests
{
    [Theory]
    [InlineData("--quick", ScanKind.Quick)]
    [InlineData("--full", ScanKind.Full)]
    [InlineData("--external", ScanKind.External)]
    public void Quick_full_and_external_scans_need_no_paths(string option, ScanKind expected)
    {
        Assert.Equal(expected, CliOptions.Parse(["scan", option]).ScanKind);
        CliOptions service = CliOptions.Parse(["scan", option, "--service", "--json"]);
        Assert.Equal(expected, service.ScanKind);
        Assert.True(service.UseService);
    }

    [Fact]
    public void Paths_alone_are_a_custom_scan_and_a_drive_root_is_a_path()
    {
        CliOptions options = CliOptions.Parse(["scan", @"E:\"]);

        Assert.Equal(ScanKind.Custom, options.ScanKind);
        Assert.Equal([@"E:\"], options.Targets);
    }

    [Theory]
    [InlineData("scan", "--quick", "--full")]
    [InlineData("scan", "--external", "--quick")]
    [InlineData("scan", "--external", @"E:\")]
    [InlineData("scan", "--quick", @"C:\Users")]
    [InlineData("scan", "--full", "--stdin")]
    [InlineData("scan")]
    public void Conflicting_or_missing_targets_are_usage_errors(params string[] args)
    {
        Assert.Throws<CliUsageException>(() => CliOptions.Parse(args));
    }

    [Fact]
    public void Help_describes_the_scan_types()
    {
        Assert.Contains("--quick", CliOptions.HelpText, StringComparison.Ordinal);
        Assert.Contains("--full", CliOptions.HelpText, StringComparison.Ordinal);
        Assert.Contains("--external", CliOptions.HelpText, StringComparison.Ordinal);
        Assert.Contains("drive root", CliOptions.HelpText, StringComparison.Ordinal);
    }
}
