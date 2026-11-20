using System.Security.Principal;
using Kshatriya.Posture;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Service.Posture;
using Kshatriya.Tests.Shared;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kshatriya.Service.Tests;

/// <summary>In-memory system settings for the security check (tests never read the real machine).</summary>
internal sealed class FakePostureSource : IPostureSource
{
    public int? ConsentPromptBehaviorAdmin { get; set; } = 5;

    public List<StartupEntry> Startup { get; } =
    [
        new(StartupKinds.RunKey, "machine", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Tray", "\"C:\\Program Files\\Tray\\tray.exe\""),
    ];

    public List<GatewayObservation> Gateways { get; } = [new("Home", "192.168.1.1", "AA-BB-CC-DD-EE-FF")];

    public DefenderSnapshot ReadDefender() =>
        new(true, true, true, true, DateTimeOffset.UtcNow.AddHours(-2), new Dictionary<string, int>());

    public InstallSnapshot ReadInstalls(string? userSid) => new(1, ConsentPromptBehaviorAdmin, 1, null, null, null);

    public int? ReadAutoRunPolicy() => null;

    public NetworkSnapshot ReadNetwork() =>
        new([new("Public", true, false)], [new("Home", "Private", "Wi-Fi")], false, [], false, true, null, 0, ["192.168.1.1"], [], false, "192.168.1.1");

    public IReadOnlyList<GatewayObservation> ReadGateways() => [.. Gateways];

    public IReadOnlyList<StartupEntry> ReadStartup(IReadOnlySet<string>? userSids) => [.. Startup];
}

/// <summary>An in-memory registry and Defender ASR store.</summary>
internal sealed class FakeHardeningTarget : IHardeningTarget
{
    public Dictionary<(string Key, string Name), int> Values { get; } = [];

    public Dictionary<string, int> Asr { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool IsManaged { get; set; }

    public int? ReadDword(string key, string name) => Values.TryGetValue((key, name), out int v) ? v : null;

    public void WriteDword(string key, string name, int value) => Values[(key, name)] = value;

    public void DeleteValue(string key, string name) => Values.Remove((key, name));

    public int? ReadAsr(string ruleId) => Asr.TryGetValue(ruleId, out int v) ? v : null;

    public void SetAsr(string ruleId, int state) => Asr[ruleId] = state;

    public void RemoveAsr(string ruleId) => Asr.Remove(ruleId);
}

public sealed class HardeningServiceTests
{
    private const string UacKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    [Fact]
    public void ApplyRecordsPreviousValuesAndUndoRestoresThem()
    {
        using var temp = new TempDirectory();
        var target = new FakeHardeningTarget();
        target.WriteDword(UacKey, "ConsentPromptBehaviorAdmin", 5);
        var hardening = new HardeningService(target, temp.Path, production: false, TimeProvider.System);

        HardeningResult applied = hardening.Apply(Fixes.UacCredentialPrompt, block: false);

        Assert.True(applied.Succeeded, applied.Message);
        Assert.Equal(1, target.ReadDword(UacKey, "ConsentPromptBehaviorAdmin"));
        Assert.Equal(1, target.ReadDword(UacKey, "PromptOnSecureDesktop"));
        Assert.Contains(Fixes.UacCredentialPrompt, hardening.Applied);

        // State survives a restart of the service.
        var reloaded = new HardeningService(target, temp.Path, production: false, TimeProvider.System);
        HardeningResult undone = reloaded.Undo(Fixes.UacCredentialPrompt);

        Assert.True(undone.Succeeded, undone.Message);
        Assert.Equal(5, target.ReadDword(UacKey, "ConsentPromptBehaviorAdmin"));
        Assert.Null(target.ReadDword(UacKey, "PromptOnSecureDesktop")); // absent before, absent again
        Assert.Empty(reloaded.Applied);
    }

    [Fact]
    public void UndoRefusesWhenSomeoneElseChangedTheValue()
    {
        using var temp = new TempDirectory();
        var target = new FakeHardeningTarget();
        var hardening = new HardeningService(target, temp.Path, production: false, TimeProvider.System);
        Assert.True(hardening.Apply(Fixes.Llmnr, block: false).Succeeded);
        target.WriteDword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 1);

        HardeningResult undone = hardening.Undo(Fixes.Llmnr);

        Assert.False(undone.Succeeded);
        Assert.Equal("changed", undone.Code);
        Assert.Equal(1, target.ReadDword(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"));
    }

    [Fact]
    public void AutoRunKeepsOtherBits()
    {
        using var temp = new TempDirectory();
        var target = new FakeHardeningTarget();
        target.WriteDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0x91);
        var hardening = new HardeningService(target, temp.Path, production: false, TimeProvider.System);

        Assert.True(hardening.Apply(Fixes.AutoRunRemovable, block: false).Succeeded);
        Assert.Equal(0x95, target.ReadDword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"));
    }

    [Fact]
    public void AsrGoesAuditThenBlockAndNeverWeakens()
    {
        using var temp = new TempDirectory();
        var target = new FakeHardeningTarget();
        var hardening = new HardeningService(target, temp.Path, production: false, TimeProvider.System);
        string usb = Fixes.AsrRules.Single(r => r.Key == "usb").Id;
        string lsass = Fixes.AsrRules.Single(r => r.Key == "lsass").Id;

        Assert.True(hardening.Apply("asr.usb", block: false).Succeeded);
        Assert.Equal(AsrState.Audit, target.Asr[usb]);
        Assert.True(hardening.Apply("asr.usb", block: true).Succeeded);
        Assert.Equal(AsrState.Block, target.Asr[usb]);

        // Asking for audit on a blocking rule never weakens it.
        target.Asr[lsass] = AsrState.Block;
        HardeningResult weaker = hardening.Apply("asr.lsass", block: false);
        Assert.True(weaker.Succeeded);
        Assert.Equal(AsrState.Block, target.Asr[lsass]);
        Assert.DoesNotContain("asr.lsass", hardening.Applied);

        // Undo returns to "not configured", the state before Kshatriya.
        Assert.True(hardening.Undo("asr.usb").Succeeded);
        Assert.False(target.Asr.ContainsKey(usb));
    }

    [Fact]
    public void ManagedMachinesAndUnknownFixesAreRefused()
    {
        using var temp = new TempDirectory();
        var target = new FakeHardeningTarget { IsManaged = true };
        var hardening = new HardeningService(target, temp.Path, production: false, TimeProvider.System);

        Assert.Equal("managed", hardening.Apply(Fixes.Llmnr, block: false).Code);
        Assert.Equal("unknownFix", hardening.Apply("defender.off", block: false).Code);
        Assert.Equal("notFound", hardening.Undo(Fixes.Llmnr).Code);
        Assert.Empty(target.Values);
    }
}

public sealed class SecurityCheckServiceTests
{
    private static bool IsElevatedAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    [Fact]
    public async Task Check_reports_and_a_fix_round_trips_with_audit()
    {
        var hardening = new FakeHardeningTarget();
        await using RunningService service = await RunningService.StartAsync(hardening: hardening);
        await using ServiceClient client = await service.ConnectAsync();

        PostureReplyDto before = await client.GetPostureAsync();
        PostureCheckDto prompt = before.Checks.Single(c => c.Id == "uac.adminPrompt");
        Assert.Equal("attention", prompt.State);
        Assert.Equal("installs", prompt.Area);
        Assert.Equal(Fixes.UacCredentialPrompt, prompt.Fix);
        Assert.Contains(before.Checks, c => c.Id == "asr.usb" && c.Area == "usb");

        OperationReplyDto applied = await client.HardenAsync(Fixes.UacCredentialPrompt, undo: false);
        Assert.True(applied.Succeeded, applied.Message);
        Assert.True((await client.GetPostureAsync()).Checks.Single(c => c.Id == "uac.adminPrompt").FixApplied);

        OperationReplyDto undone = await client.HardenAsync(Fixes.UacCredentialPrompt, undo: true);
        Assert.True(undone.Succeeded, undone.Message);

        AuditReplyDto audit = await client.GetAuditAsync(10);
        Assert.True(audit.ChainValid);
        Assert.Equal(["hardeningUndo", "hardeningApply"], audit.Records.Select(r => r.Action));
    }

    [Fact]
    public async Task Unknown_fixes_are_rejected()
    {
        await using RunningService service = await RunningService.StartAsync();
        await using ServiceClient client = await service.ConnectAsync();
        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.HardenAsync("defender.realTime", undo: false));
        Assert.Equal(ErrorCodes.BadRequest, ex.Code);
    }

    [Fact]
    public async Task Non_administrators_cannot_apply_fixes_and_the_refusal_is_audited()
    {
        if (IsElevatedAdmin)
        {
            return; // covered on non-elevated runs; CI runs elevated
        }

        var hardening = new FakeHardeningTarget();
        await using RunningService service = await RunningService.StartAsync(requireAdministrator: true, hardening: hardening);
        await using ServiceClient client = await service.ConnectAsync();

        var ex = await Assert.ThrowsAsync<ServiceException>(() => client.HardenAsync(Fixes.Llmnr, undo: false));
        Assert.Equal(ErrorCodes.AccessDenied, ex.Code);
        Assert.Empty(hardening.Values);
        Assert.Contains(service.Core.Quarantine.Audit.ReadRecent(5), r => r.Action == "hardeningApply" && r.Outcome == "denied");
    }

    [Fact]
    public async Task Baseline_changes_become_suspicious_findings()
    {
        var source = new FakePostureSource();
        await using RunningService service = await RunningService.StartAsync(posture: source);

        Assert.Empty(await service.Core.Posture.RefreshBaselineAsync(network: true, CancellationToken.None));
        source.Startup.Add(new(StartupKinds.RunKey, "machine", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", "\"C:\\Users\\Public\\u.exe\""));
        source.Gateways[0] = source.Gateways[0] with { HardwareAddress = "11-22-33-44-55-66" };

        IReadOnlyList<PostureChange> changes = await service.Core.Posture.RefreshBaselineAsync(network: true, CancellationToken.None);

        Assert.Equal(2, changes.Count);
        await using ServiceClient client = await service.ConnectAsync();
        DetectionsReplyDto detections = await client.GetDetectionsAsync(10);
        Assert.All(detections.Items, d => Assert.Equal("suspicious", d.Status));
        Assert.Contains(detections.Items, d => d.Path == "C:\\Users\\Public\\u.exe" && d.Source == "security check");
    }

    [Fact]
    public void Task_commands_are_read_from_untrusted_xml_safely()
    {
        const string xml = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Actions Context="Author">
                <Exec><Command>C:\Tools\a.exe</Command><Arguments>--run</Arguments></Exec>
                <Exec><Command>C:\Tools\b.exe</Command></Exec>
              </Actions>
            </Task>
            """;
        Assert.Equal([@"C:\Tools\a.exe --run", @"C:\Tools\b.exe"], WindowsPostureSource.TaskCommands(xml));
        Assert.Empty(WindowsPostureSource.TaskCommands("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///c:/windows/win.ini'>]><Task>&e;</Task>"));
        Assert.Empty(WindowsPostureSource.TaskCommands("not xml"));
        _ = NullLogger.Instance;
    }
}
