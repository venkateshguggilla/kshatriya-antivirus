namespace Kshatriya.Posture;

/// <summary>An attack surface reduction rule Kshatriya recommends (ADR 0022). GUIDs are Microsoft's.</summary>
public sealed record AsrRule(string Key, string Id, string Name, string Why, bool NeedsCloud);

/// <summary>Defender ASR rule states as <c>MSFT_MpPreference</c> reports them.</summary>
public static class AsrState
{
    public const int Off = 0;
    public const int Block = 1;
    public const int Audit = 2;
    public const int Warn = 6;
}

/// <summary>The hardening fixes the service can apply and undo (ADR 0022).</summary>
public static class Fixes
{
    public const string UacCredentialPrompt = "uac.credentialPrompt";
    public const string AlwaysInstallElevated = "msi.alwaysInstallElevated";
    public const string AutoRunRemovable = "autorun.removable";
    public const string Llmnr = "network.llmnr";

    /// <summary>Prefix of the ASR fixes: <c>asr.&lt;key&gt;</c>.</summary>
    public const string AsrPrefix = "asr.";

    /// <summary>The ASR rules offered, in display order.</summary>
    public static IReadOnlyList<AsrRule> AsrRules { get; } =
    [
        new("usb", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block unsigned programs on USB drives",
            "Stops untrusted or unsigned programs from running from USB drives and memory cards.", false),
        new("lsass", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block password theft from Windows (LSASS)",
            "Stops programs from reading saved sign-in secrets out of Windows' security process.", false),
        new("officeChild", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office from starting other programs",
            "Stops malicious documents from launching programs through Word, Excel or PowerPoint.", false),
        new("officeExecutable", "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office from creating programs",
            "Stops Office documents from dropping executable files onto the disk.", false),
        new("wmiPersistence", "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block hidden startup through WMI",
            "Stops malware from hiding a startup trigger in WMI event subscriptions.", false),
        new("emailExecutable", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block programs from email",
            "Stops programs and scripts opened from email or webmail from running.", false),
        new("scriptDownloads", "d3e037e1-3eb8-44c8-a917-57927947596d", "Block scripts launching downloads",
            "Stops JavaScript or VBScript from starting programs they downloaded.", false),
        new("vulnerableDrivers", "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block vulnerable signed drivers",
            "Stops known vulnerable drivers being installed to take over Windows.", false),
        new("obfuscatedScripts", "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block disguised scripts",
            "Stops scripts that hide what they do. Needs cloud-delivered protection.", true),
        new("ransomware", "c1db55ab-c21a-4637-bb3f-a12568109d35", "Advanced ransomware protection",
            "Blocks files that look like ransomware by reputation. Needs cloud-delivered protection.", true),
    ];

    public static AsrRule? FindAsr(string fixId) =>
        fixId.StartsWith(AsrPrefix, StringComparison.Ordinal)
            ? AsrRules.FirstOrDefault(r => string.Equals(AsrPrefix + r.Key, fixId, StringComparison.Ordinal))
            : null;

    /// <summary>True for every fix id the service knows.</summary>
    public static bool IsKnown(string fixId) =>
        fixId is UacCredentialPrompt or AlwaysInstallElevated or AutoRunRemovable or Llmnr || FindAsr(fixId) is not null;

    /// <summary>What applying the fix does, for confirmation prompts.</summary>
    public static string Describe(string fixId) => fixId switch
    {
        UacCredentialPrompt => "Administrators will have to type their password (on the secure desktop) for every install or change that needs administrator rights.",
        AlwaysInstallElevated => "Windows Installer packages will no longer install with full system rights automatically.",
        AutoRunRemovable => "AutoRun will be turned off for USB drives and memory cards. Windows Explorer picks this up after you sign in again.",
        Llmnr => "Windows will stop answering LLMNR name queries on the local network, which attackers use to capture passwords.",
        _ when FindAsr(fixId) is { } rule => $"Defender will {rule.Name.ToLowerInvariant()}. Audit mode first records what would be blocked without blocking it.",
        _ => "Unknown fix.",
    };
}
