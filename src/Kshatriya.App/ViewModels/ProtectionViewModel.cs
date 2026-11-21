using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Posture;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;

/// <summary>One protection layer: what it does, its state and how that state reads.</summary>
public sealed record ProtectionRow(string Glyph, string Label, string Detail, string State, Tone Tone);

/// <summary>One security check result with the actions it offers (ADR 0022).</summary>
public sealed record SecurityCheckRow(
    string Id,
    string Area,
    string Title,
    string Detail,
    string State,
    Tone Tone,
    string? Fix,
    bool CanFix,
    bool CanUndo,
    bool CanBlock)
{
    public bool HasActions => CanFix || CanUndo || CanBlock;
}

/// <summary>A USB drive the lock knows about (ADR 0023).</summary>
public sealed record LockedDriveRow(string Id, string Name, string Detail, string State, Tone Tone, bool CanUnlock);

/// <summary>
/// What runs in the background (ADR 0021): Kshatriya's layers as the service reports them, the security check
/// with consented fixes (ADR 0022), the USB drive lock (ADR 0023), and Windows Security's state, which
/// Kshatriya only reads and never changes (ADR 0002).
/// </summary>
public sealed class ProtectionViewModel(IServiceGateway gateway, IAppHost host, IDialogs? dialogs = null)
    : PageViewModel("Protection", "What runs in the background, and a check of Windows' own protections. Changes that weaken protection need an administrator and are written to the audit log.", Glyphs.Shield)
{
    /// <summary>Where an administrator changes real-time monitoring and schedules (ADR 0005).</summary>
    public const string SettingsFile = @"%ProgramData%\Kshatriya\config\service.json";

    private IReadOnlyList<SecurityCheckRow> _allChecks = [];
    private bool _showAllChecks;
    private string _checkSummary = "Checking…";
    private DeviceLockReplyDto? _lock;

    public ObservableCollection<ProtectionRow> Layers { get; } = [];

    public ObservableCollection<ProtectionRow> Windows { get; } = [];

    /// <summary>Checks shown: those needing attention and fixes Kshatriya applied, or all of them.</summary>
    public ObservableCollection<SecurityCheckRow> Checks { get; } = [];

    public ObservableCollection<LockedDriveRow> Drives { get; } = [];

    public string ChangeHint { get; } =
        $"Real-time monitoring and scheduled scans are set in {SettingsFile}, which only administrators can change.";

    public Func<AntivirusHealth> AntivirusSource { get; set; } = SecurityCenter.GetAntivirusHealth;

    public Func<int?> FolderAccessSource { get; set; } = SecurityCenter.GetControlledFolderAccess;

    /// <summary>Reads the connected Wi-Fi network's security (needs the user's location consent; null when not readable).</summary>
    public Func<WifiSnapshot?> WifiSource { get; set; } = WifiReader.Read;

    public RelayCommand OpenWindowsSecurityCommand => new(_ => host.OpenWindowsSecurity());

    public RelayCommand SetUpBrowserExtensionCommand => new(_ => host.OpenBrowserExtension());

    public string CheckSummary
    {
        get => _checkSummary;
        private set => Set(ref _checkSummary, value);
    }

    public bool ShowAllChecks
    {
        get => _showAllChecks;
        set
        {
            if (Set(ref _showAllChecks, value))
            {
                ApplyCheckFilter();
            }
        }
    }

    public string ShowAllLabel => $"Show all {_allChecks.Count} checks";

    public string FixHint => host.IsElevated
        ? "Each fix makes a Windows protection stricter, is written to the audit log and can be undone."
        : "Fixes change Windows settings, so Kshatriya asks to restart as administrator first. Each fix can be undone.";

    public string LockState => _lock switch
    {
        null => "Unknown",
        { State: "on" } => "On",
        { State: "off" } => "Off",
        _ => "Unavailable",
    };

    public string LockDetail => _lock switch
    {
        null => "The service did not report the USB drive lock.",
        { State: "on" } => "New USB drives stay locked until the Kshatriya password is entered. A drive is usable for a moment before it locks, so keep the USB fixes above on too.",
        { PasswordSet: false } => "Set a Kshatriya password, then turn the lock on to keep new USB drives locked until the password is entered.",
        { State: "off" } => "Turn it on to keep new USB drives locked until the Kshatriya password is entered.",
        var l => l.State,
    };

    public bool LockEnabled => _lock?.Enabled ?? false;

    public string LockButtonLabel => LockEnabled ? "Turn off…" : "Turn on…";

    public string PasswordButtonLabel => _lock?.PasswordSet == true ? "Change password…" : "Set password…";

    public AsyncCommand RunCheckCommand => new(_ => RunAsync(RefreshChecksAsync), onError: ShowError);

    public AsyncCommand FixCommand => new(p => RunAsync(() => HardenAsync(p as SecurityCheckRow, undo: false, block: false)), p => p is SecurityCheckRow { CanFix: true }, ShowError);

    public AsyncCommand BlockCommand => new(p => RunAsync(() => HardenAsync(p as SecurityCheckRow, undo: false, block: true)), p => p is SecurityCheckRow { CanBlock: true }, ShowError);

    public AsyncCommand UndoCommand => new(p => RunAsync(() => HardenAsync(p as SecurityCheckRow, undo: true, block: false)), p => p is SecurityCheckRow { CanUndo: true }, ShowError);

    public AsyncCommand ToggleLockCommand => new(_ => RunAsync(ToggleLockAsync), onError: ShowError);

    public AsyncCommand SetPasswordCommand => new(_ => RunAsync(SetPasswordAsync), onError: ShowError);

    public AsyncCommand UnlockCommand => new(p => RunAsync(() => UnlockAsync(p as LockedDriveRow)), p => p is LockedDriveRow { CanUnlock: true }, ShowError);

    protected override async Task RefreshCoreAsync()
    {
        // Windows Security Center and WMI can take a moment: read them off the UI thread.
        AntivirusHealth antivirus = await Task.Run(AntivirusSource);
        int? folderAccess = await Task.Run(FolderAccessSource);
        Windows.Clear();
        Windows.Add(new ProtectionRow(Glyphs.Shield, "Windows antivirus",
            $"{SecurityCenter.Describe(antivirus)} Kshatriya adds to it and does not replace it.",
            antivirus switch { AntivirusHealth.Good => "On", AntivirusHealth.Unknown => "Unknown", _ => "Needs attention" },
            antivirus switch { AntivirusHealth.Good => Tone.Success, AntivirusHealth.Unknown => Tone.Neutral, _ => Tone.Critical }));
        Windows.Add(new ProtectionRow(Glyphs.Folder, "Controlled folder access",
            SecurityCenter.DescribeControlledFolderAccess(folderAccess),
            folderAccess switch { 1 => "On", 2 => "Audit", null => "Unknown", _ => "Off" },
            folderAccess == 1 ? Tone.Success : Tone.Neutral));

        try
        {
            var (_, status) = await gateway.GetStatusAsync(CancellationToken.None);
            BuildLayers(status);
            ShowInfo(null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Layers.Clear();
            ShowError(ex);
            return;
        }

        await RefreshChecksAsync();
        await RefreshLockAsync();
    }

    private async Task RefreshChecksAsync()
    {
        CheckSummary = "Checking…";
        PostureReplyDto reply = await gateway.GetPostureAsync(CancellationToken.None);
        var checks = reply.Checks.Select(c => new PostureCheck(c.Id, PostureWire.ParseArea(c.Area), PostureWire.ParseState(c.State), c.Title, c.Detail, c.Fix, c.FixApplied)).ToList();

        // Wi-Fi security is read here, as the user: Windows only answers with the user's location consent.
        if (await Task.Run(WifiSource) is { } wifi)
        {
            checks.Add(NetworkRules.Wifi(wifi));
        }

        _allChecks = [.. checks
            .OrderByDescending(c => c.State == PostureState.Unknown ? -1 : (int)c.State)
            .ThenBy(c => c.Area)
            .Select(ToRow)];
        int attention = checks.Count(c => c.State is PostureState.Attention or PostureState.Risk);
        int risks = checks.Count(c => c.State == PostureState.Risk);
        CheckSummary = attention == 0
            ? $"All {checks.Count} checks are fine. Kshatriya alerts you when a startup program, your router or your DNS servers change."
            : $"{attention} of {checks.Count} checks need your attention" + (risks > 0 ? $", {risks} of them a risk." : ".");
        OnPropertyChanged(nameof(ShowAllLabel));
        ApplyCheckFilter();
    }

    internal static SecurityCheckRow ToRow(PostureCheck check)
    {
        bool asr = check.FixId?.StartsWith(Fixes.AsrPrefix, StringComparison.Ordinal) == true;
        bool needsFix = check.State is PostureState.Attention or PostureState.Risk;
        bool audit = asr && check.State == PostureState.Info && check.Title.EndsWith("audit only", StringComparison.Ordinal);
        return new SecurityCheckRow(
            check.Id,
            PostureWire.Heading(check.Area),
            check.Title,
            check.Detail,
            check.State switch
            {
                PostureState.Ok => "Fine",
                PostureState.Info => "Info",
                PostureState.Attention => "Check",
                PostureState.Risk => "Risk",
                _ => "Unknown",
            },
            check.State switch
            {
                PostureState.Ok => Tone.Success,
                PostureState.Attention => Tone.Caution,
                PostureState.Risk => Tone.Critical,
                _ => Tone.Neutral,
            },
            check.FixId,
            CanFix: check.FixId is not null && needsFix,
            CanUndo: check.FixApplied,
            CanBlock: audit);
    }

    private void ApplyCheckFilter()
    {
        Checks.Clear();
        foreach (SecurityCheckRow row in _allChecks.Where(r => _showAllChecks || r.Tone is Tone.Caution or Tone.Critical || r.CanUndo || r.CanBlock))
        {
            Checks.Add(row);
        }
    }

    private bool EnsureElevated(string what)
    {
        if (host.IsElevated)
        {
            return true;
        }

        if (dialogs?.Confirm("Administrator needed", $"{what} changes a Windows setting, so it needs an administrator. Restart Kshatriya as administrator now?") == true)
        {
            host.RestartElevated();
        }

        return false;
    }

    private async Task HardenAsync(SecurityCheckRow? row, bool undo, bool block)
    {
        if (row?.Fix is not { } fix || !EnsureElevated(undo ? "Undoing a fix" : "Fixing this"))
        {
            return;
        }

        string question = undo
            ? $"Restore the setting Kshatriya changed for '{row.Title}' to what it was before?"
            : block
                ? $"Switch '{row.Title.Replace(": audit only", string.Empty, StringComparison.Ordinal)}' from audit to block? If a program you need stops working, you can undo it here."
                : Fixes.Describe(fix) + " You can undo this here later.";
        if (dialogs is not null && !dialogs.Confirm(undo ? "Undo fix" : "Apply fix", question))
        {
            return;
        }

        OperationReplyDto reply = await gateway.HardenAsync(fix, undo, block, CancellationToken.None);
        await RefreshChecksAsync();
        if (reply.Succeeded)
        {
            ShowInfo(reply.Message);
        }
        else
        {
            ShowError(reply.Message ?? reply.Code);
        }
    }

    private async Task RefreshLockAsync()
    {
        try
        {
            _lock = await gateway.GetDeviceLockAsync(CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _lock = null;
        }

        Drives.Clear();
        foreach (LockedDriveDto d in _lock?.Drives ?? [])
        {
            Drives.Add(ToRow(d));
        }

        OnPropertyChanged(nameof(LockState));
        OnPropertyChanged(nameof(LockDetail));
        OnPropertyChanged(nameof(LockEnabled));
        OnPropertyChanged(nameof(LockButtonLabel));
        OnPropertyChanged(nameof(PasswordButtonLabel));
    }

    internal static LockedDriveRow ToRow(LockedDriveDto d)
    {
        string size = d.SizeBytes is long b ? $"{b / 1_000_000_000.0:F1} GB. " : string.Empty;
        return d.State switch
        {
            "locked" => new(d.Id, d.Name, size + "Locked: enter the Kshatriya password to use it.", "Locked", Tone.Caution, true),
            "approved" => new(d.Id, d.Name, size + "Unlocked until it is unplugged.", "Unlocked", Tone.Success, false),
            "locking" => new(d.Id, d.Name, size + (d.Message ?? "Another program has the drive open; still trying to lock it."), "Locking…", Tone.Caution, false),
            "couldNotLock" => new(d.Id, d.Name, size + (d.Message ?? "Could not be locked."), "Not locked", Tone.Critical, false),
            _ => new(d.Id, d.Name, size + (d.Message ?? "Connected before the lock started; not locked."), "Not locked", Tone.Neutral, false),
        };
    }

    private async Task ToggleLockAsync()
    {
        bool enable = !LockEnabled;
        if (enable && _lock?.PasswordSet != true)
        {
            ShowError("Set a Kshatriya password first.");
            return;
        }

        if (!EnsureElevated(enable ? "Turning on the USB drive lock" : "Turning off the USB drive lock"))
        {
            return;
        }

        string question = enable
            ? "New USB drives will stay disabled until someone enters the Kshatriya password. Drives connected now are not affected. Turn the lock on?"
            : "New USB drives will work without the password, and locked drives are enabled now. Turn the lock off?";
        if (dialogs is not null && !dialogs.Confirm("USB drive lock", question))
        {
            return;
        }

        OperationReplyDto reply = await gateway.ConfigureDeviceLockAsync(enable, CancellationToken.None);
        await RefreshLockAsync();
        await RefreshChecksAsync();
        if (reply.Succeeded)
        {
            ShowInfo(reply.Message);
        }
        else
        {
            ShowError(reply.Message ?? reply.Code);
        }
    }

    private async Task SetPasswordAsync()
    {
        bool first = _lock?.PasswordSet != true;
        if (first && !EnsureElevated("Setting the first Kshatriya password"))
        {
            return;
        }

        string? password = dialogs?.AskPassword("Kshatriya password",
            "Choose a password of at least 8 characters. It unlocks USB drives when the USB drive lock is on. If you forget it, an administrator can set a new one.",
            confirm: true);
        if (password is null)
        {
            return;
        }

        string? current = null;
        if (!first && !host.IsElevated)
        {
            current = dialogs?.AskPassword("Current password", "Enter the current Kshatriya password.", confirm: false);
            if (current is null)
            {
                return;
            }
        }

        OperationReplyDto reply = await gateway.SetPasswordAsync(password, current, CancellationToken.None);
        await RefreshLockAsync();
        if (reply.Succeeded)
        {
            ShowInfo(reply.Message);
        }
        else
        {
            ShowError(reply.Message ?? reply.Code);
        }
    }

    private async Task UnlockAsync(LockedDriveRow? row)
    {
        if (row is null)
        {
            return;
        }

        string? password = dialogs?.AskPassword($"Unlock {row.Name}", "Enter the Kshatriya password to use this USB drive.", confirm: false);
        if (password is null)
        {
            return;
        }

        OperationReplyDto reply = await gateway.UnlockDeviceAsync(row.Id, password, CancellationToken.None);
        await RefreshLockAsync();
        if (reply.Succeeded)
        {
            ShowInfo(reply.Message);
        }
        else
        {
            ShowError(reply.Message ?? reply.Code);
        }
    }

    private void BuildLayers(StatusReplyDto status)
    {
        RealTimeStatusDto rt = status.RealTime;
        Layers.Clear();
        Layers.Add(new ProtectionRow(Glyphs.Processing, "Real-time file monitoring",
            rt.Enabled
                ? $"{string.Join(", ", rt.Paths)}: scans new and changed files soon after they are written. It cannot block a file before it opens."
                : "New files are scanned only when you run a scan.",
            rt.Enabled ? "On" : "Off", rt.Enabled ? Tone.Success : Tone.Caution));
        Layers.Add(Layer(Glyphs.Search, "Programs as they start", "Checks each started program's file. Never stops a running program.", rt.Enabled ? rt.Processes : "off"));
        Layers.Add(Layer(Glyphs.Usb, "External drives", "USB sticks, USB disks and memory cards are scanned when connected.", rt.Enabled ? rt.RemovableMedia : "off"));
        Layers.Add(Layer(Glyphs.Warning, "Ransomware behaviour", "Warns about mass file changes (suspicious only, never an automatic action). Decoy files are opt-in.", rt.Enabled ? rt.Behaviour : "off"));
        Layers.Add(Layer(Glyphs.Sync, "Network protection", "Blocks connections to listed addresses.", status.Network.State));
        Layers.Add(new ProtectionRow(Glyphs.Calendar, "Scheduled scans",
            status.Schedules.Count == 0
                ? "None configured."
                : string.Join("; ", status.Schedules.Select(s => $"{s.Name}: next {HomeViewModel.Local(s.NextRunUtc)}" + (s.LastRunUtc is null ? ", never run" : $", last {HomeViewModel.Local(s.LastRunUtc)} ({s.LastOutcome})"))),
            status.Schedules.Count == 0 ? "None" : $"{status.Schedules.Count} active",
            status.Schedules.Count == 0 ? Tone.Neutral : Tone.Success));
    }

    /// <summary>A layer whose service state is a word like "off", "on", "unavailable: …" or a description.</summary>
    internal static ProtectionRow Layer(string glyph, string label, string detail, string serviceState)
    {
        string s = serviceState.Trim();
        if (s.Length == 0 || s.Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            return new ProtectionRow(glyph, label, detail, "Off", Tone.Neutral);
        }

        if (s.StartsWith("unavailable", StringComparison.OrdinalIgnoreCase))
        {
            return new ProtectionRow(glyph, label, $"{detail} {Capitalize(s)}.", "Unavailable", Tone.Caution);
        }

        return new ProtectionRow(glyph, label, s.Equals("on", StringComparison.OrdinalIgnoreCase) ? detail : $"{detail} State: {s}.", "On", Tone.Success);
    }

    private static string Capitalize(string s) => char.ToUpperInvariant(s[0]) + s[1..];
}
