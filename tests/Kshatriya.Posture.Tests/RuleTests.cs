using Kshatriya.Posture;

namespace Kshatriya.Posture.Tests;

public sealed class WindowsRuleTests
{
    private static readonly IReadOnlySet<string> None = new HashSet<string>();
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);

    private static DefenderSnapshot Healthy(Dictionary<string, int>? asr = null) =>
        new(true, true, true, true, Now.AddHours(-5), asr ?? Fixes.AsrRules.ToDictionary(r => r.Id, _ => AsrState.Block));

    [Fact]
    public void HealthyDefenderIsAllOk()
    {
        var checks = WindowsRules.Defender(Healthy(), Now, None).ToList();
        Assert.All(checks, c => Assert.Equal(PostureState.Ok, c.State));
        Assert.Contains(checks, c => c.Id == "asr.usb" && c.Area == PostureArea.Usb);
    }

    [Fact]
    public void RealTimeOffIsRiskAndHasNoFix()
    {
        var check = WindowsRules.Defender(Healthy() with { RealTime = false }, Now, None).Single(c => c.Id == "defender.realTime");
        Assert.Equal(PostureState.Risk, check.State);
        Assert.Null(check.FixId); // Kshatriya never changes Defender's own switches
    }

    [Theory]
    [InlineData(2, PostureState.Ok)]
    [InlineData(5, PostureState.Attention)]
    [InlineData(9, PostureState.Risk)]
    public void SignatureAge(int days, PostureState expected)
    {
        var check = WindowsRules.Defender(Healthy() with { SignaturesUpdatedUtc = Now.AddDays(-days) }, Now, None).Single(c => c.Id == "defender.signatures");
        Assert.Equal(expected, check.State);
    }

    [Fact]
    public void AsrRuleOffOffersFixAndAuditIsInfo()
    {
        var asr = new Dictionary<string, int> { [Fixes.AsrRules[1].Id] = AsrState.Audit };
        var checks = WindowsRules.Defender(Healthy(asr), Now, new HashSet<string> { "asr.lsass" }).ToList();
        PostureCheck usb = checks.Single(c => c.Id == "asr.usb");
        Assert.Equal(PostureState.Attention, usb.State);
        Assert.Equal("asr.usb", usb.FixId);
        PostureCheck lsass = checks.Single(c => c.Id == "asr.lsass");
        Assert.Equal(PostureState.Info, lsass.State);
        Assert.True(lsass.FixApplied);
    }

    [Fact]
    public void CloudRulesAreOnlyInfoWithoutCloudProtection()
    {
        var checks = WindowsRules.Defender(Healthy([]) with { CloudProtection = false }, Now, None).ToList();
        Assert.Equal(PostureState.Info, checks.Single(c => c.Id == "asr.ransomware").State);
        Assert.Equal(PostureState.Attention, checks.Single(c => c.Id == "asr.lsass").State);
    }

    [Theory]
    [InlineData(null, PostureState.Attention)]
    [InlineData(5, PostureState.Attention)]
    [InlineData(0, PostureState.Risk)]
    [InlineData(1, PostureState.Ok)]
    [InlineData(3, PostureState.Ok)]
    public void AdminPrompt(int? consent, PostureState expected)
    {
        var check = WindowsRules.Installs(new InstallSnapshot(1, consent, 1, null, null, null), None).Single(c => c.Id == "uac.adminPrompt");
        Assert.Equal(expected, check.State);
        Assert.Equal(Fixes.UacCredentialPrompt, check.FixId);
    }

    [Fact]
    public void AlwaysInstallElevatedBothIsRisk()
    {
        var checks = WindowsRules.Installs(new InstallSnapshot(1, 1, 1, 1, 1, null), None).ToList();
        Assert.Equal(PostureState.Risk, checks.Single(c => c.Id == "msi.alwaysInstallElevated").State);
        checks = WindowsRules.Installs(new InstallSnapshot(1, 1, 1, 1, null, null), None).ToList();
        Assert.Equal(PostureState.Attention, checks.Single(c => c.Id == "msi.alwaysInstallElevated").State);
    }

    [Fact]
    public void UacOffIsRisk()
    {
        Assert.Contains(WindowsRules.Installs(new InstallSnapshot(0, 5, 1, null, null, null), None),
            c => c.Id == "uac.enabled" && c.State == PostureState.Risk);
    }

    [Theory]
    [InlineData(null, PostureState.Attention)] // Windows default 0x91 allows removable drives
    [InlineData(0x91, PostureState.Attention)]
    [InlineData(0x95, PostureState.Ok)]
    [InlineData(0xFF, PostureState.Ok)]
    public void AutoRun(int? value, PostureState expected)
    {
        var check = WindowsRules.Usb(new UsbSnapshot(value, false, false), None).Single(c => c.Id == "autorun.removable");
        Assert.Equal(expected, check.State);
    }

    [Fact]
    public void WorstIgnoresUnknown()
    {
        PostureCheck[] checks =
        [
            new("a", PostureArea.Network, PostureState.Ok, "", ""),
            new("b", PostureArea.Network, PostureState.Unknown, "", ""),
            new("c", PostureArea.Network, PostureState.Attention, "", ""),
        ];
        Assert.Equal(PostureState.Attention, PostureSummary.Worst(checks));
        Assert.Equal(["c"], PostureSummary.NeedingAttention(checks).Select(c => c.Id));
    }

    [Fact]
    public void FixCatalogue()
    {
        Assert.True(Fixes.IsKnown("asr.usb"));
        Assert.True(Fixes.IsKnown(Fixes.Llmnr));
        Assert.False(Fixes.IsKnown("asr.nope"));
        Assert.False(Fixes.IsKnown("defender.realTime"));
        Assert.Equal(Fixes.AsrRules.Count, Fixes.AsrRules.Select(r => r.Id).Distinct().Count());
        Assert.All(Fixes.AsrRules, r => Assert.True(Guid.TryParse(r.Id, out _)));
    }

    [Fact]
    public void WireNamesRoundTrip()
    {
        foreach (PostureState state in Enum.GetValues<PostureState>())
        {
            Assert.Equal(state, PostureWire.ParseState(PostureWire.Of(state)));
        }

        foreach (PostureArea area in Enum.GetValues<PostureArea>())
        {
            Assert.Equal(area, PostureWire.ParseArea(PostureWire.Of(area)));
        }
    }
}

public sealed class NetworkRuleTests
{
    private static readonly IReadOnlySet<string> None = new HashSet<string>();

    private static NetworkSnapshot Snapshot(
        IReadOnlyList<FirewallProfile>? firewall = null,
        IReadOnlyList<Listener>? listeners = null,
        IReadOnlyList<HostsEntry>? hosts = null,
        bool? rdp = false,
        bool? nla = true,
        int? llmnr = 0,
        bool? smb1 = false) =>
        new(firewall ?? [new("Domain", true, false), new("Private", true, false), new("Public", true, false)],
            [new("Home", "Public", "Wi-Fi")], smb1, listeners ?? [], rdp, nla, llmnr, 0, ["192.168.1.1"], hosts ?? [], false, "192.168.1.1");

    [Fact]
    public void CleanNetworkHasNoAttention()
    {
        Assert.Empty(PostureSummary.NeedingAttention(NetworkRules.Evaluate(Snapshot(), None)));
    }

    [Fact]
    public void FirewallOffIsRisk()
    {
        var checks = NetworkRules.Evaluate(Snapshot(firewall: [new("Public", false, false)]), None).ToList();
        Assert.Equal(PostureState.Risk, checks.Single(c => c.Id == "network.firewall.public").State);
    }

    [Fact]
    public void RdpWithoutNlaIsRisk()
    {
        Assert.Equal(PostureState.Risk, NetworkRules.Evaluate(Snapshot(rdp: true, nla: false), None).Single(c => c.Id == "network.rdp").State);
        Assert.Equal(PostureState.Attention, NetworkRules.Evaluate(Snapshot(rdp: true, nla: true), None).Single(c => c.Id == "network.rdp").State);
    }

    [Fact]
    public void Smb1AndLlmnr()
    {
        var checks = NetworkRules.Evaluate(Snapshot(smb1: true, llmnr: null), None).ToList();
        Assert.Equal(PostureState.Risk, checks.Single(c => c.Id == "network.smb1").State);
        PostureCheck llmnr = checks.Single(c => c.Id == "network.llmnr");
        Assert.Equal(PostureState.Attention, llmnr.State);
        Assert.Equal(Fixes.Llmnr, llmnr.FixId);
    }

    [Fact]
    public void ExposedPortsIgnoreLoopback()
    {
        var checks = NetworkRules.Evaluate(Snapshot(listeners:
        [
            new("tcp", "0.0.0.0", 3389, "svchost.exe"),
            new("tcp", "127.0.0.1", 5985, "x.exe"),
            new("tcp", "0.0.0.0", 7680, "svchost.exe"),
        ]), None).ToList();
        Assert.Contains(checks, c => c.Id == "network.port.3389" && c.State == PostureState.Attention);
        Assert.DoesNotContain(checks, c => c.Id == "network.port.5985");
        Assert.Contains(checks, c => c.Id == "network.listeners" && c.State == PostureState.Info);
    }

    [Fact]
    public void HostsParsingSkipsCommentsAndBadLines()
    {
        IReadOnlyList<HostsEntry> entries = NetworkRules.ParseHosts(
            "# comment\r\n127.0.0.1 localhost\r\n\r\n10.0.0.5  www.paypal.com paypal.com # evil\nnot-an-ip host\n0.0.0.0\tads.example\n");
        Assert.Equal(4, entries.Count);
        Assert.Contains(entries, e => e.Host == "paypal.com" && e.Address == "10.0.0.5");
    }

    [Fact]
    public void HostsRedirectOfProtectedDomainIsRisk()
    {
        PostureCheck redirect = NetworkRules.HostsChecks([new("10.0.0.5", "www.paypal.com")]).Single();
        Assert.Equal(PostureState.Risk, redirect.State);
        Assert.Contains("redirects", redirect.Title, StringComparison.Ordinal);

        PostureCheck block = NetworkRules.HostsChecks([new("0.0.0.0", "update.microsoft.com")]).Single();
        Assert.Equal(PostureState.Risk, block.State);
        Assert.Contains("blocks", block.Title, StringComparison.Ordinal);

        Assert.Equal(PostureState.Info, NetworkRules.HostsChecks([new("0.0.0.0", "ads.example")]).Single().State);
        Assert.Equal(PostureState.Ok, NetworkRules.HostsChecks([new("127.0.0.1", "localhost")]).Single().State);
        // A look-alike that only ends with the same letters is not protected.
        Assert.Equal(PostureState.Info, NetworkRules.HostsChecks([new("10.0.0.5", "notpaypal.com")]).Single().State);
    }

    [Theory]
    [InlineData("Open", "None", PostureState.Risk)]
    [InlineData("WPA2PSK", "TKIP", PostureState.Risk)]
    [InlineData("Open", "WEP", PostureState.Risk)]
    [InlineData("WPA2PSK", "CCMP", PostureState.Ok)]
    [InlineData("WPA3SAE", "CCMP", PostureState.Ok)]
    public void Wifi(string auth, string enc, PostureState expected)
    {
        Assert.Equal(expected, NetworkRules.Wifi(new WifiSnapshot("Home", auth, enc)).State);
    }
}

public sealed class StartupAndBaselineTests
{
    private static StartupEntry Run(string name, string command) =>
        new(StartupKinds.RunKey, "machine", @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", name, command);

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" --tray", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Program Files\\App\\app.exe --tray", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Tools\\run.cmd", "C:\\Tools\\run.cmd")]
    [InlineData("rundll32.exe shell32.dll,Control_RunDLL", "rundll32.exe")]
    [InlineData("", null)]
    public void ImageOfCommand(string command, string? expected)
    {
        Assert.Equal(expected, StartupRules.ImageOf(command));
    }

    [Theory]
    [InlineData("\"C:\\Users\\a\\AppData\\Local\\Temp\\x.exe\"", true)]
    [InlineData("mshta.exe http://example.test/a.hta", true)]
    [InlineData("powershell.exe -w hidden -enc AAAA", true)]
    [InlineData("\"C:\\Program Files\\OneDrive\\OneDrive.exe\" /background", false)]
    [InlineData("powershell.exe -File C:\\Scripts\\backup.ps1", false)]
    public void Suspicion(string command, bool suspicious)
    {
        Assert.Equal(suspicious, StartupRules.Suspicion(Run("x", command)) is not null);
    }

    [Fact]
    public void WmiSubscriptionIsAlwaysFlagged()
    {
        var entry = new StartupEntry(StartupKinds.WmiSubscription, "machine", @"root\subscription", "Updater", "cmd.exe /c x");
        Assert.Contains(StartupRules.Evaluate([entry]), c => c.State == PostureState.Attention);
    }

    [Fact]
    public void FirstComparisonOnlyRecords()
    {
        var now = new PostureObservation([new("Home", "192.168.1.1", "aa-bb-cc-dd-ee-ff")], ["1.1.1.1"], [Run("App", "app.exe")]);
        (IReadOnlyList<PostureChange> changes, PostureBaseline baseline) = BaselineComparer.Compare(null, now);
        Assert.Empty(changes);
        Assert.Equal("AA-BB-CC-DD-EE-FF", baseline.Gateways["Home|192.168.1.1"]);
        Assert.Single(baseline.Startup);
    }

    [Fact]
    public void DetectsGatewayDnsAndStartupChanges()
    {
        var first = new PostureObservation([new("Home", "192.168.1.1", "AA-BB-CC-DD-EE-FF")], ["1.1.1.1"], [Run("App", "app.exe")]);
        PostureBaseline baseline = BaselineComparer.Compare(null, first).Updated;

        var second = new PostureObservation(
            [new("Home", "192.168.1.1", "11-22-33-44-55-66"), new("Cafe", "10.0.0.1", "77-77-77-77-77-77")],
            ["1.1.1.1", "203.0.113.9"],
            [Run("App", "app.exe --changed"), Run("Evil", "\"C:\\Users\\Public\\e.exe\"")]);
        (IReadOnlyList<PostureChange> changes, PostureBaseline updated) = BaselineComparer.Compare(baseline, second);

        Assert.Single(changes, c => c.Kind == PostureChangeKinds.Gateway); // the new cafÃ© network is not a change
        Assert.Single(changes, c => c.Kind == PostureChangeKinds.Dns);
        Assert.Equal(2, changes.Count(c => c.Kind == PostureChangeKinds.Startup));
        Assert.Contains(changes, c => c.Path == "C:\\Users\\Public\\e.exe");
        Assert.Equal(2, updated.Gateways.Count);

        // Leaving a network does not forget its gateway.
        var third = new PostureObservation([], ["1.1.1.1", "203.0.113.9"], second.Startup);
        (changes, updated) = BaselineComparer.Compare(updated, third);
        Assert.Empty(changes);
        Assert.Equal(2, updated.Gateways.Count);
    }

    [Fact]
    public void RemovedDnsServerIsNotAChange()
    {
        PostureBaseline baseline = BaselineComparer.Compare(null, new PostureObservation([], ["1.1.1.1", "8.8.8.8"], [])).Updated;
        Assert.Empty(BaselineComparer.Compare(baseline, new PostureObservation([], ["1.1.1.1"], [])).Changes);
    }
}

public sealed class AndroidRuleTests
{
    [Fact]
    public void RiskyPhone()
    {
        var checks = AndroidRules.Evaluate(new AndroidSnapshot(true, true, false, ["com.example.store"], false)).ToList();
        Assert.Equal(PostureState.Risk, checks.Single(c => c.Id == "android.screenLock").State);
        Assert.Equal(PostureState.Risk, checks.Single(c => c.Id == "android.usbDebugging").State);
        Assert.Equal(PostureState.Attention, checks.Single(c => c.Id == "android.installers").State);
        Assert.DoesNotContain(checks, c => c.Id == "android.developerOptions"); // covered by USB debugging
        Assert.All(checks, c => Assert.Null(c.FixId)); // Android settings are changed by the user only
    }

    [Fact]
    public void SafePhone()
    {
        var checks = AndroidRules.Evaluate(new AndroidSnapshot(false, false, true, [], null)).ToList();
        Assert.Empty(PostureSummary.NeedingAttention(checks));
        Assert.Contains(checks, c => c.Id == "android.playProtect");
    }
}
