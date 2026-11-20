using Kshatriya.Protocol;

namespace Kshatriya.Cli.Tests;

public sealed class SecurityOptionTests
{
    [Fact]
    public void ParsesSecurityCommands()
    {
        CliOptions check = CliOptions.Parse(["check", "--json", "--dev"]);
        Assert.Equal(CliCommand.Check, check.Command);
        Assert.True(check.Json && check.DevService && check.UseService);

        CliOptions harden = CliOptions.Parse(["harden", "asr.usb", "--block"]);
        Assert.Equal(("apply", "asr.usb", true, false), (harden.Action, harden.Argument, harden.Block, harden.Undo));

        Assert.Equal("list", CliOptions.Parse(["harden", "list"]).Action);
        Assert.True(CliOptions.Parse(["harden", "network.llmnr", "--undo"]).Undo);

        CliOptions unlock = CliOptions.Parse(["lock", "unlock", @"USBSTOR\DISK&VEN_X\1", "--stdin"]);
        Assert.Equal(("unlock", @"USBSTOR\DISK&VEN_X\1", true), (unlock.Action, unlock.Argument, unlock.ReadStdin));

        Assert.Equal("set", CliOptions.Parse(["password", "set"]).Action);
    }

    [Theory]
    [InlineData("check", "extra")]
    [InlineData("harden")]
    [InlineData("harden", "asr.usb", "--block", "--undo")]
    [InlineData("lock", "unlock")]
    [InlineData("lock", "open")]
    [InlineData("password")]
    [InlineData("check", "--undo")]
    public void RejectsBadUsage(params string[] args)
    {
        Assert.Throws<CliUsageException>(() => CliOptions.Parse(args));
    }

    [Fact]
    public void FormatsChecksWithFixHints()
    {
        var reply = new PostureReplyDto
        {
            CheckedUtc = "2026-11-21T00:00:00Z",
            Checks =
            [
                new() { Id = "uac.adminPrompt", Area = "installs", State = "attention", Title = "Installs need only a click", Detail = "d", Fix = "uac.credentialPrompt", FixApplied = false },
                new() { Id = "network.llmnr", Area = "network", State = "ok", Title = "LLMNR off", Detail = "d", Fix = "network.llmnr", FixApplied = true },
            ],
        };

        string text = SecurityCommands.Format(reply);

        Assert.Contains("App installs", text, StringComparison.Ordinal);
        Assert.Contains("fix: kshatriya harden uac.credentialPrompt", text, StringComparison.Ordinal);
        Assert.Contains("undo: kshatriya harden network.llmnr --undo", text, StringComparison.Ordinal);
        Assert.Contains("1 item(s) need your attention", text, StringComparison.Ordinal);
    }
}
