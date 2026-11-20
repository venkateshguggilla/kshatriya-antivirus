using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
public sealed class HomeViewModel(IServiceGateway gateway, IAppHost host) : PageViewModel("Home", "Protection status at a glance", Glyphs.Home)
{
    private string _serviceState = "Checking…";
    private string _connectedAs = string.Empty;
    private bool _isConnected;
    private bool _isAdmin;
    private string _engines = string.Empty;
    private string _workers = string.Empty;
    private string _quarantine = string.Empty;
    private string _auditState = string.Empty;
    private string _content = string.Empty;
    private string _realTime = string.Empty;
    private AntivirusHealth _antivirus = AntivirusHealth.Unknown;

    public string ServiceState { get => _serviceState; private set => Set(ref _serviceState, value); }

    public string ConnectedAs { get => _connectedAs; private set => Set(ref _connectedAs, value); }

    public bool IsConnected { get => _isConnected; private set => Set(ref _isConnected, value); }

    public bool IsAdmin { get => _isAdmin; private set => Set(ref _isAdmin, value); }

    public string Engines { get => _engines; private set => Set(ref _engines, value); }

    public string Workers { get => _workers; private set => Set(ref _workers, value); }

    public string Quarantine { get => _quarantine; private set => Set(ref _quarantine, value); }

    public string AuditState { get => _auditState; private set => Set(ref _auditState, value); }

    public string Content { get => _content; private set => Set(ref _content, value); }

    public string RealTime { get => _realTime; private set => Set(ref _realTime, value); }

    public AntivirusHealth Antivirus
    {
        get => _antivirus;
        private set
        {
            if (Set(ref _antivirus, value))
            {
                OnPropertyChanged(nameof(AntivirusText));
                OnPropertyChanged(nameof(AntivirusNeedsAttention));
            }
        }
    }

    public string AntivirusText => SecurityCenter.Describe(Antivirus);

    private string _folderAccess = string.Empty;

    public string FolderAccessText { get => _folderAccess; private set => Set(ref _folderAccess, value); }

    /// <summary>Optional source of Defender's Controlled folder access value (tests replace it).</summary>
    public Func<int?> FolderAccessSource { get; set; } = SecurityCenter.GetControlledFolderAccess;

    public bool AntivirusNeedsAttention => Antivirus is AntivirusHealth.Poor or AntivirusHealth.Snoozed;

    public ObservableCollection<string> Schedules { get; } = [];

    public bool CanRestartElevated => !host.IsElevated;

    public RelayCommand RestartElevatedCommand => new(_ => host.RestartElevated(), _ => !host.IsElevated);

    /// <summary>Optional source of Windows antivirus health (tests replace it).</summary>
    public Func<AntivirusHealth> AntivirusSource { get; set; } = SecurityCenter.GetAntivirusHealth;

    /// <summary>
    /// True while the service is (probably) still starting, for example during its delayed start after
    /// Windows starts. The app sets it for the installed service; tests replace it.
    /// </summary>
    public Func<bool> ServiceStartingSource { get; set; } = () => false;

    /// <summary>
    /// Checks again while the service is not reachable, so the page updates by itself once the service is
    /// up (the shell calls this every few seconds while the window is shown).
    /// </summary>
    public Task RetryIfDisconnectedAsync() =>
        IsConnected || IsBusy ? Task.CompletedTask : RefreshCommand.ExecuteAsync(null);

    protected override async Task RefreshCoreAsync()
    {
        Antivirus = AntivirusSource();
        FolderAccessText = SecurityCenter.DescribeControlledFolderAccess(FolderAccessSource());
        try
        {
            var (hello, status) = await gateway.GetStatusAsync(CancellationToken.None);
            IsConnected = true;
            IsAdmin = hello.IsAdmin;
            ServiceState = $"{hello.Service} is running ({status.Mode}) since {Local(status.StartedUtc)}.";
            ConnectedAs = $"Connected as {hello.User}" + (hello.IsAdmin ? " (administrator)."
                : status.Mode == "development" ? " (development service: all actions allowed for its owner)."
                : ". Restore, exclusions and history need an administrator.");
            Engines = string.Join(Environment.NewLine, status.Engines.Select(e => $"{e.Id} {e.Version}  [{e.ContentVersion}]"));
            Workers = $"{status.Workers.Running} of {status.Workers.Configured} sandboxed workers running; {status.Workers.Crashed} crashed, {status.Workers.TimedOut} stopped at the time limit. Active scans: {status.ActiveScans}.";
            Quarantine = $"{status.QuarantineItems} item(s) in quarantine. {status.Exclusions} exclusion(s).";
            RealTimeStatusDto rt = status.RealTime;
            RealTime = rt.Enabled
                ? $"Real-time monitoring is on for {string.Join(", ", rt.Paths)}. Programs: {rt.Processes}. Removable drives: {rt.RemovableMedia}. Ransomware behaviour: {rt.Behaviour} ({rt.BehaviourAlerts} alert(s)). It scans files after they are written; it cannot block them."
                : "Real-time monitoring is off (it can be enabled in the service settings).";
            RealTime += $" Network protection: {status.Network.State}.";
            ContentStatusDto c = status.Content;
            Content = c.Sequence == 0
                ? "Content: built-in signatures only (no signed update installed)." + (c.Problem is null ? string.Empty : $" {c.Problem}")
                : $"Content: update {c.Sequence} ({c.Channel}), " + (c.Expired ? $"EXPIRED on {Local(c.ExpiresUtc)}; install a newer update." : $"valid until {Local(c.ExpiresUtc)}.");
            AuditState = status.AuditChainValid ? "Audit log: intact." : "Audit log: INTEGRITY CHECK FAILED. Review the History page.";
            Schedules.Clear();
            foreach (ScheduleStatusDto s in status.Schedules)
            {
                Schedules.Add($"{s.Name}: next {Local(s.NextRunUtc)}; " + (s.LastRunUtc is null ? "never run" : $"last {Local(s.LastRunUtc)} ({s.LastOutcome})"));
            }

            if (Schedules.Count == 0)
            {
                Schedules.Add("No scheduled scans are configured.");
            }

            BuildStatus(status);
            ShowInfo(null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            IsConnected = false;
            ServiceState = $"Not connected to the {gateway.EndpointDescription}.";
            ConnectedAs = string.Empty;
            BuildDisconnected();
            ShowError(ex);
        }
    }

    private string _verdict = "Checking protection…";
    private string _verdictDetail = string.Empty;
    private Tone _verdictTone = Tone.Neutral;

    /// <summary>One-line answer to "am I protected?".</summary>
    public string Verdict { get => _verdict; private set => Set(ref _verdict, value); }

    public string VerdictDetail { get => _verdictDetail; private set => Set(ref _verdictDetail, value); }

    public Tone VerdictTone { get => _verdictTone; private set => Set(ref _verdictTone, value); }

    /// <summary>The checks behind the verdict, one row each.</summary>
    public ObservableCollection<StatusRow> Rows { get; } = [];

    private StatusSnapshot _status = StatusSnapshot.Checking;

    /// <summary>The evaluated status the verdict comes from (ADR 0021): one level, one headline, its causes.</summary>
    public StatusSnapshot Status { get => _status; private set => Set(ref _status, value); }

    /// <summary>"Needs your attention": the causes behind a verdict other than protected, most serious first.</summary>
    public ObservableCollection<AttentionRow> Attention { get; } = [];

    /// <summary>Ids of status items the user dismissed (none yet: dismissing arrives with the redesigned Home page).</summary>
    public IReadOnlySet<string> Dismissed { get; set; } = new HashSet<string>();

    private void ShowStatus(StatusSnapshot snapshot, bool starting = false)
    {
        Status = snapshot;
        (Verdict, VerdictDetail, VerdictTone) = (snapshot.Headline, snapshot.Detail, ToneOf(snapshot.Level, starting));
        Attention.Clear();
        foreach (StatusItem item in snapshot.Items)
        {
            Attention.Add(new AttentionRow(item.Title, item.Detail, item.Level == ProtectionLevel.ActionNeeded ? Tone.Critical : Tone.Caution));
        }
    }

    internal static Tone ToneOf(ProtectionLevel level, bool starting = false) => level switch
    {
        ProtectionLevel.Protected => Tone.Success,
        ProtectionLevel.AttentionRecommended => Tone.Caution,
        ProtectionLevel.ActionNeeded => Tone.Critical,
        ProtectionLevel.NotRunning => starting ? Tone.Caution : Tone.Critical,
        _ => Tone.Neutral,
    };

    internal static WindowsAntivirusState StateOf(AntivirusHealth health) => health switch
    {
        AntivirusHealth.Good => WindowsAntivirusState.Good,
        AntivirusHealth.Unknown => WindowsAntivirusState.Unknown,
        _ => WindowsAntivirusState.NeedsAttention,
    };

    /// <summary>Raised by the Quick scan button; the shell opens the Scan page and starts a quick scan.</summary>
    public event Action? QuickScanRequested;

    public RelayCommand QuickScanCommand => new(_ => QuickScanRequested?.Invoke(), _ => IsConnected);

    private void BuildStatus(StatusReplyDto status)
    {
        RealTimeStatusDto rt = status.RealTime;
        ContentStatusDto c = status.Content;
        Tone antivirus = Antivirus switch
        {
            AntivirusHealth.Good => Tone.Success,
            AntivirusHealth.Unknown => Tone.Neutral,
            _ => Tone.Critical,
        };

        Rows.Clear();
        Rows.Add(new StatusRow(Glyphs.Shield, "Kshatriya service", $"Running since {Local(status.StartedUtc)}", Tone.Success));
        Rows.Add(new StatusRow(Glyphs.Processing, "Real-time monitoring",
            rt.Enabled ? $"On for {string.Join(", ", rt.Paths)}; scans files after they are written" : "Off; turn it on in the service settings",
            rt.Enabled ? Tone.Success : Tone.Caution));
        Rows.Add(new StatusRow(Glyphs.Usb, "External drives",
            rt.Enabled && rt.RemovableMedia != "off" ? "Scanned automatically when connected" : "The app scans USB drives when connected (tray menu)",
            Tone.Success));
        Rows.Add(new StatusRow(Glyphs.Shield, "Windows antivirus", SecurityCenter.Describe(Antivirus), antivirus));
        Rows.Add(new StatusRow(Glyphs.Folder, "Ransomware folder protection", FolderAccessText, Tone.Neutral));
        Rows.Add(new StatusRow(Glyphs.Lock, "Quarantine", status.QuarantineItems == 1 ? "1 item" : $"{status.QuarantineItems} items", Tone.Neutral));
        Rows.Add(new StatusRow(Glyphs.History, "Audit log", status.AuditChainValid ? "Intact" : "Integrity check failed: review History", status.AuditChainValid ? Tone.Success : Tone.Critical));
        Rows.Add(new StatusRow(Glyphs.Document, "Signatures",
            c.Sequence == 0 ? "Built-in only (no signed update installed)" : c.Expired ? $"Update {c.Sequence} expired on {Local(c.ExpiresUtc)}" : $"Update {c.Sequence}, valid until {Local(c.ExpiresUtc)}",
            c.Expired ? Tone.Caution : Tone.Neutral));
        Rows.Add(new StatusRow(Glyphs.Calendar, "Scheduled scans",
            status.Schedules.Count == 0 ? "None configured" : string.Join("; ", status.Schedules.Select(s => $"{s.Name}, next {Local(s.NextRunUtc)}")),
            Tone.Neutral));

        // Findings are not inputs yet: their review (quarantine or keep) arrives with the unified History page
        // (ADR 0021, slice 4); until then they are shown on the History page's Detections tab.
        ShowStatus(DesktopStatusEvaluator.Evaluate(new DesktopStatusInputs
        {
            ServiceReachable = true,
            ServiceDescription = gateway.EndpointDescription,
            WindowsAntivirus = StateOf(Antivirus),
            RealTimeEnabled = rt.Enabled,
            AuditChainValid = status.AuditChainValid,
            ContentSequence = c.Sequence,
            ContentExpired = c.Expired,
            ContentExpiresUtc = DateTimeOffset.TryParse(c.ExpiresUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset expires) ? expires : null,
            LastScanAccessDenied = LastScanAccessDenied,
            Dismissed = Dismissed,
            Now = Clock(),
        }));
        OnPropertyChanged(nameof(QuickScanCommand));
    }

    /// <summary>The current time (tests replace it).</summary>
    public Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary>Items the last user scan could not read for lack of rights (set by the scan session).</summary>
    public int LastScanAccessDenied { get; set; }

    private void BuildDisconnected()
    {
        bool starting = ServiceStartingSource();
        Rows.Clear();
        Rows.Add(new StatusRow(Glyphs.Shield, "Kshatriya service", starting ? "Starting" : "Not reachable", starting ? Tone.Caution : Tone.Critical));
        Rows.Add(new StatusRow(Glyphs.Shield, "Windows antivirus", SecurityCenter.Describe(Antivirus), Antivirus == AntivirusHealth.Good ? Tone.Success : Tone.Caution));
        ShowStatus(DesktopStatusEvaluator.Evaluate(new DesktopStatusInputs
        {
            ServiceReachable = false,
            ServiceStarting = starting,
            ServiceDescription = gateway.EndpointDescription,
            WindowsAntivirus = StateOf(Antivirus),
            Now = Clock(),
        }), starting);
        OnPropertyChanged(nameof(QuickScanCommand));
    }

    internal static string Local(string? isoUtc) =>
        DateTimeOffset.TryParse(isoUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset t)
            ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : "-";
}

/// <summary>One check on the dashboard.</summary>
public sealed record StatusRow(string Glyph, string Label, string Value, Tone Tone);

/// <summary>One cause in "Needs your attention".</summary>
public sealed record AttentionRow(string Title, string Detail, Tone Tone);
