using Kshatriya.App.ViewModels;
using Kshatriya.Posture;
using Kshatriya.Protocol;

namespace Kshatriya.App.Tests;

/// <summary>The security check and USB drive lock on the Protection page (ADR 0022, ADR 0023).</summary>
public sealed class SecurityPageTests
{
    private static ProtectionViewModel Page(FakeGateway gateway, FakeHost host, FakeDialogs dialogs, WifiSnapshot? wifi = null) =>
        new(gateway, host, dialogs)
        {
            AntivirusSource = () => Services.AntivirusHealth.Good,
            FolderAccessSource = () => 0,
            WifiSource = () => wifi,
        };

    [Fact]
    public async Task Shows_what_needs_attention_first_and_all_on_request()
    {
        var page = Page(new FakeGateway(), new FakeHost(), new FakeDialogs(), new WifiSnapshot("Cafe", "Open", "None"));

        await page.RefreshCommand.ExecuteAsync(null);

        // Risks first (firewall, open Wi-Fi), then attention; the applied ASR fix stays visible for undo/block.
        Assert.Equal(["network.firewall.public", "network.wifi", "uac.adminPrompt", "asr.usb"], page.Checks.Select(c => c.Id));
        Assert.Contains("3 of 5 checks need your attention, 2 of them a risk", page.CheckSummary, StringComparison.Ordinal);
        SecurityCheckRow asr = page.Checks.Single(c => c.Id == "asr.usb");
        Assert.True(asr.CanBlock && asr.CanUndo && !asr.CanFix);
        Assert.True(page.Checks.Single(c => c.Id == "uac.adminPrompt").CanFix);
        Assert.False(page.Checks.Single(c => c.Id == "network.firewall.public").HasActions); // no fix: Windows Security owns it

        page.ShowAllChecks = true;
        Assert.Equal(5, page.Checks.Count);
    }

    [Fact]
    public async Task Fixing_without_administrator_rights_offers_a_restart_and_changes_nothing()
    {
        var gateway = new FakeGateway();
        var host = new FakeHost();
        var page = Page(gateway, host, new FakeDialogs());
        await page.RefreshCommand.ExecuteAsync(null);

        await page.FixCommand.ExecuteAsync(page.Checks.Single(c => c.Id == "uac.adminPrompt"));

        Assert.True(host.Restarted);
        Assert.DoesNotContain(gateway.Calls, c => c.StartsWith("harden:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Administrators_fix_block_and_undo_after_confirming()
    {
        var gateway = new FakeGateway();
        var dialogs = new FakeDialogs();
        var page = Page(gateway, new FakeHost { IsElevated = true }, dialogs);
        await page.RefreshCommand.ExecuteAsync(null);

        await page.FixCommand.ExecuteAsync(page.Checks.Single(c => c.Id == "uac.adminPrompt"));
        await page.BlockCommand.ExecuteAsync(page.Checks.Single(c => c.Id == "asr.usb"));
        await page.UndoCommand.ExecuteAsync(page.Checks.Single(c => c.Id == "asr.usb"));

        Assert.Equal(["harden:uac.credentialPrompt:apply", "harden:asr.usb:block", "harden:asr.usb:undo"], gateway.Calls.Where(c => c.StartsWith("harden:", StringComparison.Ordinal)));
        Assert.Equal(3, dialogs.Confirmations);

        dialogs.Answer = false;
        await page.FixCommand.ExecuteAsync(page.Checks.Single(c => c.Id == "uac.adminPrompt"));
        Assert.Equal(3, gateway.Calls.Count(c => c.StartsWith("harden:", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task The_lock_needs_a_password_before_it_can_be_turned_on()
    {
        var gateway = new FakeGateway();
        var dialogs = new FakeDialogs { Password = "correct horse" };
        var page = Page(gateway, new FakeHost { IsElevated = true }, dialogs);
        await page.RefreshCommand.ExecuteAsync(null);
        Assert.Equal("Off", page.LockState);
        Assert.Equal("Set password…", page.PasswordButtonLabel);

        await page.ToggleLockCommand.ExecuteAsync(null);
        Assert.True(page.IsError);
        Assert.DoesNotContain("lock:True", gateway.Calls);

        await page.SetPasswordCommand.ExecuteAsync(null);
        await page.ToggleLockCommand.ExecuteAsync(null);

        Assert.Equal(["password", "lock:True"], gateway.Calls.Where(c => c is "password" or "lock:True"));
        Assert.Equal("On", page.LockState);
        Assert.Equal("Turn off…", page.LockButtonLabel);
    }

    [Fact]
    public async Task Locked_drives_unlock_with_the_password()
    {
        var gateway = new FakeGateway
        {
            Lock = new DeviceLockReplyDto
            {
                Enabled = true,
                PasswordSet = true,
                State = "on",
                RetryAfterSeconds = 0,
                Drives = [new LockedDriveDto { Id = @"USBSTOR\X\1", Name = "Stick", SizeBytes = 16_000_000_000, State = "locked", ArrivedUtc = "2026-11-21T10:00:00Z" }],
            },
        };
        var dialogs = new FakeDialogs { Password = "wrong" };
        var page = Page(gateway, new FakeHost(), dialogs);
        await page.RefreshCommand.ExecuteAsync(null);

        LockedDriveRow row = Assert.Single(page.Drives);
        Assert.True(row.CanUnlock);
        Assert.Contains("16.0 GB", row.Detail, StringComparison.Ordinal);

        await page.UnlockCommand.ExecuteAsync(row);
        Assert.True(page.IsError);

        dialogs.Password = "correct horse";
        await page.UnlockCommand.ExecuteAsync(row);
        Assert.False(page.IsError);
        Assert.Equal(2, gateway.Calls.Count(c => c.StartsWith("unlock:", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData(1, false, "Open")]
    [InlineData(1, true, "WEP")]
    [InlineData(7, true, "WPA2PSK")]
    [InlineData(9, true, "WPA3SAE")]
    public void Wifi_algorithms_map_to_rule_names(int auth, bool secured, string expected)
    {
        Assert.Equal(expected, Services.WifiReader.Authentication(auth, secured));
    }
}
