namespace Kshatriya.Posture;

/// <summary>What the service read about Microsoft Defender. Null values could not be read.</summary>
public sealed record DefenderSnapshot(
    bool Available,
    bool? RealTime,
    bool? TamperProtection,
    bool? CloudProtection,
    DateTimeOffset? SignaturesUpdatedUtc,
    IReadOnlyDictionary<string, int> AsrRules,
    string? Problem = null);

/// <summary>UAC and Windows Installer settings. Null values are absent (Windows uses its default).</summary>
public sealed record InstallSnapshot(
    int? EnableLua,
    int? ConsentPromptBehaviorAdmin,
    int? PromptOnSecureDesktop,
    int? AlwaysInstallElevatedMachine,
    int? AlwaysInstallElevatedUser,
    bool? AdministratorProtection);

/// <summary>USB-related settings. <see cref="NoDriveTypeAutoRun"/> is the machine policy value, null when absent.</summary>
public sealed record UsbSnapshot(int? NoDriveTypeAutoRun, bool? LockEnabled, bool? LockPasswordSet);

/// <summary>Turns Defender, install and USB snapshots into checks (ADR 0022).</summary>
public static class WindowsRules
{
    /// <summary>Windows' value of <c>NoDriveTypeAutoRun</c> when no policy is set.</summary>
    public const int AutoRunDefault = 0x91;

    /// <summary>The bit that turns AutoRun off for removable drives.</summary>
    public const int AutoRunRemovableBit = 0x04;

    /// <summary>Defender checks; <paramref name="applied"/> holds the fix ids Kshatriya applied and can undo.</summary>
    public static IEnumerable<PostureCheck> Defender(DefenderSnapshot snapshot, DateTimeOffset nowUtc, IReadOnlySet<string> applied)
    {
        const PostureArea area = PostureArea.Defender;
        if (!snapshot.Available)
        {
            yield return new("defender.available", area, PostureState.Info, "Microsoft Defender status not available",
                snapshot.Problem ?? "Another antivirus may be active. Kshatriya works alongside Defender; check Windows Security.");
            yield break;
        }

        yield return snapshot.RealTime switch
        {
            true => new("defender.realTime", area, PostureState.Ok, "Real-time protection is on", "Defender scans files as they are opened."),
            false => new("defender.realTime", area, PostureState.Risk, "Real-time protection is off",
                "Turn it on in Windows Security > Virus & threat protection. Kshatriya never turns Defender off."),
            null => new("defender.realTime", area, PostureState.Unknown, "Real-time protection", "Could not be read."),
        };

        yield return snapshot.TamperProtection switch
        {
            true => new("defender.tamper", area, PostureState.Ok, "Tamper protection is on", "Malware cannot quietly switch Defender off."),
            false => new("defender.tamper", area, PostureState.Attention, "Tamper protection is off",
                "Turn it on in Windows Security > Virus & threat protection settings, so malware cannot switch Defender off."),
            null => new("defender.tamper", area, PostureState.Unknown, "Tamper protection", "Could not be read."),
        };

        yield return snapshot.CloudProtection switch
        {
            true => new("defender.cloud", area, PostureState.Ok, "Cloud-delivered protection is on", "New threats are recognised within minutes."),
            false => new("defender.cloud", area, PostureState.Attention, "Cloud-delivered protection is off",
                "Turn it on in Windows Security. Two of the recommended rules below need it."),
            null => new("defender.cloud", area, PostureState.Unknown, "Cloud-delivered protection", "Could not be read."),
        };

        if (snapshot.SignaturesUpdatedUtc is { } updated)
        {
            double days = (nowUtc - updated).TotalDays;
            string when = days < 1 ? "today" : $"{(int)days} day(s) ago";
            yield return days switch
            {
                > 7 => new("defender.signatures", area, PostureState.Risk, "Defender signatures are out of date", $"Last updated {when}. Run Windows Update."),
                > 3 => new("defender.signatures", area, PostureState.Attention, "Defender signatures are getting old", $"Last updated {when}. Run Windows Update."),
                _ => new("defender.signatures", area, PostureState.Ok, "Defender signatures are current", $"Last updated {when}."),
            };
        }
        else
        {
            yield return new("defender.signatures", area, PostureState.Unknown, "Defender signatures", "Could not be read.");
        }

        foreach (AsrRule rule in Fixes.AsrRules)
        {
            yield return Asr(rule, snapshot, applied);
        }
    }

    private static PostureCheck Asr(AsrRule rule, DefenderSnapshot snapshot, IReadOnlySet<string> applied)
    {
        string fix = Fixes.AsrPrefix + rule.Key;
        bool mine = applied.Contains(fix);
        int state = snapshot.AsrRules.TryGetValue(rule.Id, out int s) ? s : AsrState.Off;
        PostureArea area = rule.Key == "usb" ? PostureArea.Usb : PostureArea.Defender;
        string id = "asr." + rule.Key;
        return state switch
        {
            AsrState.Block or AsrState.Warn => new(id, area, PostureState.Ok, rule.Name + ": on", rule.Why, fix, mine),
            AsrState.Audit => new(id, area, PostureState.Info, rule.Name + ": audit only",
                rule.Why + " It is recording what it would block; switch it to block when nothing you need shows up.", fix, mine),
            _ => new(id, area, rule.NeedsCloud && snapshot.CloudProtection == false ? PostureState.Info : PostureState.Attention,
                rule.Name + ": off", rule.Why, fix, mine),
        };
    }

    public static IEnumerable<PostureCheck> Installs(InstallSnapshot snapshot, IReadOnlySet<string> applied)
    {
        const PostureArea area = PostureArea.Installs;
        if (snapshot.EnableLua == 0)
        {
            yield return new("uac.enabled", area, PostureState.Risk, "User Account Control is off",
                "Every program runs with full rights and installs without asking. Turn UAC on in Control Panel > User Accounts (needs a restart).");
        }

        bool prompted = applied.Contains(Fixes.UacCredentialPrompt);
        int consent = snapshot.ConsentPromptBehaviorAdmin ?? 5;
        yield return consent switch
        {
            1 or 3 => new("uac.adminPrompt", area, PostureState.Ok, "Installs need an administrator password",
                "Administrators type their password before anything installs or changes system settings." +
                (consent == 3 ? " Showing the prompt on the secure desktop would be safer." : string.Empty), Fixes.UacCredentialPrompt, prompted),
            0 => new("uac.adminPrompt", area, PostureState.Risk, "Administrators are never asked",
                "Programs started by an administrator get full rights silently, including installers.", Fixes.UacCredentialPrompt, prompted),
            _ => new("uac.adminPrompt", area, PostureState.Attention, "Installs need only a click",
                "An administrator approves installs with Yes, no password. Require the password so nobody can install apps on this account unnoticed.",
                Fixes.UacCredentialPrompt, prompted),
        };

        if (snapshot.PromptOnSecureDesktop == 0)
        {
            yield return new("uac.secureDesktop", area, PostureState.Attention, "UAC prompts are not on the secure desktop",
                "Other programs could interfere with the prompt.", Fixes.UacCredentialPrompt, prompted);
        }

        bool machine = snapshot.AlwaysInstallElevatedMachine == 1;
        bool user = snapshot.AlwaysInstallElevatedUser == 1;
        bool fixedByUs = applied.Contains(Fixes.AlwaysInstallElevated);
        yield return (machine, user) switch
        {
            (true, true) => new("msi.alwaysInstallElevated", area, PostureState.Risk, "Any installer package gets full system rights",
                "'AlwaysInstallElevated' is on: any .msi file installs as SYSTEM without a prompt. Attackers use this to take over the PC.",
                Fixes.AlwaysInstallElevated, fixedByUs),
            (true, false) => new("msi.alwaysInstallElevated", area, PostureState.Attention, "'AlwaysInstallElevated' is half set",
                "The machine policy is on. If a user policy is ever set too, any .msi installs as SYSTEM.", Fixes.AlwaysInstallElevated, fixedByUs),
            _ => new("msi.alwaysInstallElevated", area, PostureState.Ok, "Installer packages ask before taking full rights",
                "'AlwaysInstallElevated' is off.", Fixes.AlwaysInstallElevated, fixedByUs),
        };

        yield return snapshot.AdministratorProtection switch
        {
            true => new("uac.adminProtection", area, PostureState.Ok, "Administrator protection is on",
                "Windows asks for Windows Hello before every elevation and uses a separate administrator token."),
            false => new("uac.adminProtection", area, PostureState.Info, "Administrator protection is available",
                "Windows 11 can require Windows Hello for every elevation. Turn it on in Local Security Policy > Security Options > 'User Account Control: Configure type of Admin Approval Mode' (needs a restart; not compatible with Hyper-V hosts)."),
            null => new("uac.adminProtection", area, PostureState.Info, "Installers that only write to your own folders",
                "Windows asks for a password only when an installer needs administrator rights. Some installers write only to your own profile and are never asked."),
        };
    }

    public static IEnumerable<PostureCheck> Usb(UsbSnapshot snapshot, IReadOnlySet<string> applied)
    {
        const PostureArea area = PostureArea.Usb;
        int value = snapshot.NoDriveTypeAutoRun ?? AutoRunDefault;
        bool mine = applied.Contains(Fixes.AutoRunRemovable);
        yield return (value & AutoRunRemovableBit) != 0
            ? new("autorun.removable", area, PostureState.Ok, "AutoRun is off for USB drives", "Nothing starts by itself when a drive is connected.", Fixes.AutoRunRemovable, mine)
            : new("autorun.removable", area, PostureState.Attention, "AutoRun is allowed for USB drives",
                "Turn it off so nothing on a connected drive can start by itself.", Fixes.AutoRunRemovable, mine);

        yield return (snapshot.LockEnabled, snapshot.LockPasswordSet) switch
        {
            (true, _) => new("usb.lock", area, PostureState.Ok, "USB drive lock is on",
                "New USB drives stay locked until the Kshatriya password is entered. Convenience lock: a drive is usable for a moment before it locks."),
            (false, false) => new("usb.lock", area, PostureState.Info, "USB drive lock is off",
                "Set a Kshatriya password, then turn the lock on to keep new USB drives locked until the password is entered."),
            (false, _) => new("usb.lock", area, PostureState.Info, "USB drive lock is off",
                "Turn it on to keep new USB drives locked until the Kshatriya password is entered."),
            _ => new("usb.lock", area, PostureState.Unknown, "USB drive lock", "Could not be read."),
        };
    }
}
