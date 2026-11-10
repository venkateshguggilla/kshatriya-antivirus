using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;

/// <summary>Dialogs the view models need; implemented with WPF dialogs in the app and with fakes in tests.</summary>
public interface IDialogs
{
    IReadOnlyList<string> PickFolders();

    string? PickRestoreLocation(string suggestedFileName);

    bool Confirm(string title, string message);
}

/// <summary>Process-level actions (restart elevated).</summary>
public interface IAppHost
{
    bool IsElevated { get; }

    void RestartElevated();
}

/// <summary>A page in the navigation list.</summary>
public abstract class PageViewModel : ObservableObject
{
    private string? _message;
    private bool _isError;
    private bool _isBusy;

    protected PageViewModel(string title, string description, string glyph = Glyphs.Info)
    {
        Title = title;
        Description = description;
        Glyph = glyph;
        RefreshCommand = new AsyncCommand(_ => RunAsync(RefreshCoreAsync), onError: ShowError);
    }

    public string Title { get; }

    public string Description { get; }

    /// <summary>Icon for the navigation list (a Segoe Fluent Icons / MDL2 Assets glyph).</summary>
    public string Glyph { get; }

    public AsyncCommand RefreshCommand { get; }

    public string? Message
    {
        get => _message;
        protected set => Set(ref _message, value);
    }

    public bool IsError
    {
        get => _isError;
        protected set => Set(ref _isError, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        protected set => Set(ref _isBusy, value);
    }

    protected abstract Task RefreshCoreAsync();

    protected async Task RunAsync(Func<Task> action)
    {
        IsBusy = true;
        try
        {
            await action();
        }
        finally
        {
            IsBusy = false;
        }
    }

    protected void ShowError(Exception ex)
    {
        IsError = true;
        Message = ErrorText.Describe(ex);
    }

    protected void ShowInfo(string? text)
    {
        IsError = false;
        Message = text;
    }
}

public sealed class DashboardViewModel(IServiceGateway gateway, IAppHost host) : PageViewModel("Dashboard", "Protection status at a glance", Glyphs.Home)
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
            _ => Tone.Caution,
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

        if (!status.AuditChainValid)
        {
            (Verdict, VerdictDetail, VerdictTone) = ("The audit log may have been tampered with", "Its integrity check failed. Review the History page.", Tone.Critical);
        }
        else if (!rt.Enabled || antivirus == Tone.Caution || c.Expired)
        {
            (Verdict, VerdictDetail, VerdictTone) = ("Attention needed", "Some protection is off or out of date. The items marked below explain what to do.", Tone.Caution);
        }
        else
        {
            (Verdict, VerdictDetail, VerdictTone) = ("All checks passed", $"Kshatriya is running alongside {(Antivirus == AntivirusHealth.Good ? "Microsoft Defender" : "your antivirus")}. Real-time monitoring is on.", Tone.Success);
        }

        OnPropertyChanged(nameof(QuickScanCommand));
    }

    private void BuildDisconnected()
    {
        bool starting = ServiceStartingSource();
        Rows.Clear();
        Rows.Add(new StatusRow(Glyphs.Shield, "Kshatriya service", starting ? "Starting" : "Not reachable", starting ? Tone.Caution : Tone.Critical));
        Rows.Add(new StatusRow(Glyphs.Shield, "Windows antivirus", SecurityCenter.Describe(Antivirus), Antivirus == AntivirusHealth.Good ? Tone.Success : Tone.Caution));
        (Verdict, VerdictDetail, VerdictTone) = starting
            ? ("Kshatriya is starting", "The service starts a minute or two after Windows does. This page updates by itself when it is ready; Microsoft Defender keeps protecting you meanwhile.", Tone.Caution)
            : ("Kshatriya is not running", $"The {gateway.EndpointDescription} is not reachable. Scans and real-time monitoring need it; Microsoft Defender keeps protecting you. This page checks again every few seconds.", Tone.Critical);
        OnPropertyChanged(nameof(QuickScanCommand));
    }

    internal static string Local(string? isoUtc) =>
        DateTimeOffset.TryParse(isoUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset t)
            ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : "-";
}

/// <summary>One check on the dashboard.</summary>
public sealed record StatusRow(string Glyph, string Label, string Value, Tone Tone);

/// <summary>One line in the scan results.</summary>
public sealed record ResultRow(string Status, string Path, string Detail, string Action)
{
    public Tone Tone => Status switch
    {
        "Detected" => Tone.Critical,
        "Suspicious" or "Not scanned" => Tone.Caution,
        _ => Tone.Neutral,
    };
}

/// <summary>The scan types offered on the Scan page.</summary>
public enum ScanChoice
{
    Quick,
    Full,
    External,
    Drive,
    Custom,
}

/// <summary>A drive offered for a drive scan.</summary>
public sealed record DriveChoice(string Root, string Label, bool IsExternal = false)
{
    public override string ToString() => Label;
}

public sealed class ScanViewModel : PageViewModel, IDisposable
{
    /// <summary>Result rows shown at most; a full scan can list thousands of files that could not be opened.</summary>
    internal const int MaxRows = 2000;

    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private readonly Func<IReadOnlyList<DriveChoice>> _drives;
    private CancellationTokenSource? _cancel;
    private bool _quarantine;
    private bool _isScanning;
    private string _progress = string.Empty;
    private string _summary = string.Empty;
    private DriveChoice? _selectedDrive;

    public ScanViewModel(IServiceGateway gateway, IDialogs dialogs, Func<IReadOnlyList<DriveChoice>>? drives = null)
        : base("Scan", "Quick, full, external-drive and custom scans with your own access rights", Glyphs.Search)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        _drives = drives ?? LocalDrives;
        AddFoldersCommand = new RelayCommand(_ => AddTargets(_dialogs.PickFolders()), _ => !IsScanning);
        AddKnownFolderCommand = new RelayCommand(p => AddTargets([KnownFolder(p as string)]), _ => !IsScanning);
        RemoveTargetCommand = new RelayCommand(p => Targets.Remove((string)p!), p => !IsScanning && p is string);
        StartCommand = new AsyncCommand(_ => RunScanAsync("Custom scan", (progress, token) => _gateway.ScanAsync([.. Targets], Quarantine, progress, token)), _ => !IsScanning && Targets.Count > 0, ShowError);
        QuickScanCommand = new AsyncCommand(_ => RunScanAsync("Quick scan", (progress, token) => _gateway.ScanKindAsync(ScanKinds.Quick, Quarantine, progress, token)), _ => !IsScanning, ShowError);
        FullScanCommand = new AsyncCommand(_ => RunScanAsync("Full scan", (progress, token) => _gateway.ScanKindAsync(ScanKinds.Full, Quarantine, progress, token)), _ => !IsScanning, ShowError);
        ExternalScanCommand = new AsyncCommand(
            _ => RunScanAsync("External drive scan", (progress, token) => _gateway.ScanKindAsync(ScanKinds.External, Quarantine, progress, token)),
            _ => !IsScanning && Drives.Any(d => d.IsExternal),
            ShowError);
        DriveScanCommand = new AsyncCommand(
            _ => RunScanAsync($"Scan of {SelectedDrive!.Root}", (progress, token) => _gateway.ScanAsync([SelectedDrive!.Root], Quarantine, progress, token)),
            _ => !IsScanning && SelectedDrive is not null,
            ShowError);
        CancelCommand = new RelayCommand(_ => _cancel?.Cancel(), _ => IsScanning);
        LoadDrives();
    }

    public ObservableCollection<DriveChoice> Drives { get; } = [];

    public DriveChoice? SelectedDrive { get => _selectedDrive; set => Set(ref _selectedDrive, value); }

    public AsyncCommand QuickScanCommand { get; }

    public AsyncCommand FullScanCommand { get; }

    /// <summary>Scans every connected external drive (USB drives and disks, memory cards).</summary>
    public AsyncCommand ExternalScanCommand { get; }

    /// <summary>Selects <paramref name="root"/> (after re-reading the drive list) and scans it, unless a scan is running.</summary>
    public Task ScanDriveAsync(string root)
    {
        LoadDrives();
        if (IsScanning || Drives.FirstOrDefault(d => string.Equals(d.Root, root, StringComparison.OrdinalIgnoreCase)) is not { } drive)
        {
            return Task.CompletedTask;
        }

        SelectedDrive = drive;
        return DriveScanCommand.ExecuteAsync(null);
    }

    public AsyncCommand DriveScanCommand { get; }

    public ObservableCollection<string> Targets { get; } = [];

    public ObservableCollection<ResultRow> Results { get; } = [];

    /// <summary>Quarantine confirmed, high-confidence detections (off by default; the user opts in).</summary>
    public bool Quarantine { get => _quarantine; set => Set(ref _quarantine, value); }

    public bool IsScanning { get => _isScanning; private set => Set(ref _isScanning, value); }

    public string Progress { get => _progress; private set => Set(ref _progress, value); }

    public string Summary { get => _summary; private set => Set(ref _summary, value); }

    public RelayCommand AddFoldersCommand { get; }

    public RelayCommand AddKnownFolderCommand { get; }

    public RelayCommand RemoveTargetCommand { get; }

    public AsyncCommand StartCommand { get; }

    public RelayCommand CancelCommand { get; }

    public void AddTargets(IEnumerable<string> paths)
    {
        foreach (string path in paths.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            string full = Path.GetFullPath(path);
            if (!Targets.Contains(full, StringComparer.OrdinalIgnoreCase))
            {
                Targets.Add(full);
            }
        }
    }

    public void Dispose() => _cancel?.Dispose();

    /// <summary>Refreshing the page re-reads the drive list (for example after a USB drive was attached).</summary>
    protected override Task RefreshCoreAsync()
    {
        LoadDrives();
        return Task.CompletedTask;
    }

    /// <summary>Ready fixed and removable drives, labelled internal or external (USB, memory card) with name and size.</summary>
    internal static IReadOnlyList<DriveChoice> LocalDrives() =>
        [.. Kshatriya.Scanning.Targets.Drives.Local().Select(d => new DriveChoice(d.Root, d.Label, d.IsExternal))];

    private void LoadDrives()
    {
        string? selected = SelectedDrive?.Root;
        Drives.Clear();
        foreach (DriveChoice drive in _drives())
        {
            Drives.Add(drive);
        }

        SelectedDrive = Drives.FirstOrDefault(d => d.Root == selected) ?? Drives.FirstOrDefault();
    }

    private static string KnownFolder(string? name) => name switch
    {
        "Downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        "Desktop" => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "Documents" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private async Task RunScanAsync(string label, Func<IProgress<ScanProgressDto>, CancellationToken, Task<ScanReport>> start)
    {
        _cancel = new CancellationTokenSource();
        IsScanning = true;
        Results.Clear();
        Summary = string.Empty;
        ShowInfo(null);
        Progress = $"{label}: starting…";
        try
        {
            var progress = new Progress<ScanProgressDto>(p =>
                Progress = $"{label}: {p.ItemsCompleted:N0} item(s) checked, {p.Detected:N0} finding(s), {p.BytesScanned / (1024.0 * 1024):N1} MiB read");
            ScanReport report = await start(progress, _cancel.Token);
            ShowReport(report, label);
        }
        catch (OperationCanceledException)
        {
            Progress = string.Empty;
            ShowInfo($"{label} was cancelled. Results are incomplete.");
        }
        finally
        {
            IsScanning = false;
            _cancel.Dispose();
            _cancel = null;
        }
    }

    internal void ShowReport(ScanReport report, string label = "Scan")
    {
        // Findings first; at most MaxRows rows, so a full scan's long list of unreadable files stays usable.
        foreach (ScanItemResult item in report.Items.OrderBy(i => i.Status switch
                 {
                     ScanStatus.Detected => 0,
                     ScanStatus.Suspicious => 1,
                     ScanStatus.NotScanned => 2,
                     _ => 3,
                 }).ThenBy(i => i.Path, StringComparer.OrdinalIgnoreCase).Take(MaxRows))
        {
            string status = item.Status switch
            {
                ScanStatus.Detected => "Detected",
                ScanStatus.Suspicious => "Suspicious",
                ScanStatus.NotScanned => "Not scanned",
                ScanStatus.Skipped => "Skipped",
                _ => "Clean",
            };
            string detail = item.Detections.Count > 0
                ? string.Join("; ", item.Detections.Select(d => $"{d.Name} ({WireNames.Of(d.Category)}, {WireNames.Of(d.Confidence)})" + (d.Location is null ? string.Empty : $" in {d.Location}")))
                : WireNames.Of(item.Reason) + (item.Message is null ? string.Empty : $": {item.Message}");
            string action = item.Action switch
            {
                null => item.Status == ScanStatus.Detected ? "Reported only" : string.Empty,
                { Succeeded: true } => "Quarantined",
                { } a => $"Not quarantined: {WireNames.Of(a.Failure)}",
            };
            Results.Add(new ResultRow(status, item.Path, detail, action));
        }

        ScanSummary s = report.Summary;
        Progress = string.Empty;
        string result = s.Detected > 0
            ? $"{s.Detected} item(s) detected, {s.Quarantined} quarantined, {s.QuarantineFailed} could not be quarantined. {s.FilesScanned:N0} file(s) scanned."
            : s.Suspicious > 0
                ? $"{s.Suspicious} item(s) look suspicious but are not confirmed malware. Nothing was changed. {s.FilesScanned:N0} file(s) scanned."
                : s.NotScanned > 0
                    ? $"Nothing detected, but {s.NotScanned} item(s) could not be scanned. {s.FilesScanned:N0} file(s) scanned."
                    : $"Nothing detected. {s.FilesScanned:N0} file(s) scanned.";
        string capped = report.Items.Count > MaxRows ? $" Showing the first {MaxRows:N0} of {report.Items.Count:N0} listed items, findings first." : string.Empty;
        SummaryTone = s.Detected > 0 ? Tone.Critical : s.Suspicious > 0 || s.NotScanned > 0 ? Tone.Caution : Tone.Success;
        SummaryTitle = s.Detected > 0 ? "Threats found" : s.Suspicious > 0 ? "Suspicious files found" : s.NotScanned > 0 ? "Scan incomplete" : "No threats found";
        Summary = $"{label} finished. {result}{capped}";
    }

    private Tone _summaryTone = Tone.Neutral;
    private string _summaryTitle = string.Empty;
    private ScanChoice _choice = ScanChoice.Quick;

    /// <summary>Tone of the last result: critical (threats), caution (suspicious or incomplete) or success.</summary>
    public Tone SummaryTone { get => _summaryTone; private set => Set(ref _summaryTone, value); }

    public string SummaryTitle { get => _summaryTitle; private set => Set(ref _summaryTitle, value); }

    /// <summary>The scan type chosen on the page; <see cref="ScanNowCommand"/> runs it.</summary>
    public ScanChoice Choice
    {
        get => _choice;
        set
        {
            if (Set(ref _choice, value))
            {
                foreach (string name in new[] { nameof(IsQuick), nameof(IsFull), nameof(IsExternal), nameof(IsDrive), nameof(IsCustom) })
                {
                    OnPropertyChanged(name);
                }
            }
        }
    }

    // Radio-button bindings for each choice.
    public bool IsQuick { get => Choice == ScanChoice.Quick; set => Pick(value, ScanChoice.Quick); }

    public bool IsFull { get => Choice == ScanChoice.Full; set => Pick(value, ScanChoice.Full); }

    public bool IsExternal { get => Choice == ScanChoice.External; set => Pick(value, ScanChoice.External); }

    public bool IsDrive { get => Choice == ScanChoice.Drive; set => Pick(value, ScanChoice.Drive); }

    public bool IsCustom { get => Choice == ScanChoice.Custom; set => Pick(value, ScanChoice.Custom); }

    /// <summary>Runs the chosen scan type.</summary>
    public AsyncCommand ScanNowCommand => _scanNow ??= new AsyncCommand(_ => Selected.ExecuteAsync(null), _ => Selected.CanExecute(null));

    private AsyncCommand? _scanNow;

    private AsyncCommand Selected => Choice switch
    {
        ScanChoice.Full => FullScanCommand,
        ScanChoice.External => ExternalScanCommand,
        ScanChoice.Drive => DriveScanCommand,
        ScanChoice.Custom => StartCommand,
        _ => QuickScanCommand,
    };

    private void Pick(bool selected, ScanChoice choice)
    {
        if (selected)
        {
            Choice = choice;
        }
    }
}

/// <summary>One quarantined item.</summary>
public sealed record QuarantineRow(string Id, string QuarantinedLocal, string OriginalPath, string Detections, string User, long SizeBytes);

public sealed class QuarantineViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private QuarantineRow? _selected;

    public QuarantineViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Quarantine", "Files Kshatriya moved into its encrypted vault", Glyphs.Lock)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        RestoreCommand = new AsyncCommand(_ => RestoreAsync(toOtherLocation: false), _ => Selected is not null, ShowError);
        RestoreToCommand = new AsyncCommand(_ => RestoreAsync(toOtherLocation: true), _ => Selected is not null, ShowError);
        DeleteCommand = new AsyncCommand(_ => DeleteAsync(), _ => Selected is not null, ShowError);
    }

    public ObservableCollection<QuarantineRow> Items { get; } = [];

    public QuarantineRow? Selected { get => _selected; set => Set(ref _selected, value); }

    public AsyncCommand RestoreCommand { get; }

    public AsyncCommand RestoreToCommand { get; }

    public AsyncCommand DeleteCommand { get; }

    protected override async Task RefreshCoreAsync()
    {
        QuarantineListReplyDto list = await _gateway.ListQuarantineAsync(CancellationToken.None);
        Items.Clear();
        foreach (QuarantineItemDto i in list.Items)
        {
            Items.Add(new QuarantineRow(i.Id, DashboardViewModel.Local(i.QuarantinedUtc), i.OriginalPath, i.Detections.Count == 0 ? "Added manually" : string.Join(", ", i.Detections), i.User, i.SizeBytes));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }

    private async Task RestoreAsync(bool toOtherLocation)
    {
        QuarantineRow row = Selected!;
        string? target = null;
        if (toOtherLocation)
        {
            target = _dialogs.PickRestoreLocation(Path.GetFileName(row.OriginalPath));
            if (target is null)
            {
                return;
            }
        }

        if (!_dialogs.Confirm(
                "Restore file?",
                $"Restore {Path.GetFileName(row.OriginalPath)} to {target ?? row.OriginalPath}?\n\nKshatriya quarantined it because of: {row.Detections}. Restore only if you are sure it is safe. It will be marked as downloaded from the internet and will be detected again by the next scan unless you exclude it."))
        {
            return;
        }

        OperationReplyDto reply = await _gateway.RestoreAsync(row.Id, target, CancellationToken.None);
        await RefreshCoreAsync();
        if (reply.Succeeded)
        {
            ShowInfo($"Restored to {reply.Path}.");
        }
        else
        {
            IsError = true;
            Message = $"Not restored ({reply.Code}): {reply.Message}";
        }
    }

    private async Task DeleteAsync()
    {
        QuarantineRow row = Selected!;
        if (!_dialogs.Confirm("Delete permanently?", $"Permanently delete the quarantined copy of {row.OriginalPath}? This cannot be undone."))
        {
            return;
        }

        OperationReplyDto reply = await _gateway.DeleteQuarantinedAsync(row.Id, CancellationToken.None);
        await RefreshCoreAsync();
        if (reply.Succeeded)
        {
            ShowInfo("Deleted permanently.");
        }
        else
        {
            IsError = true;
            Message = reply.Message;
        }
    }
}

/// <summary>One exclusion.</summary>
public sealed record ExclusionRow(string Kind, string Value);

public sealed class ExclusionsViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private ExclusionRow? _selected;
    private string _newValue = string.Empty;

    public ExclusionsViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Exclusions", "Folders, files and hashes Kshatriya does not scan", Glyphs.Filter)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        AddFolderCommand = new AsyncCommand(_ => AddFoldersAsync(), onError: ShowError);
        AddValueCommand = new AsyncCommand(_ => ChangeAsync(add: true, NewValue.Trim()), _ => !string.IsNullOrWhiteSpace(NewValue), ShowError);
        RemoveCommand = new AsyncCommand(_ => ChangeAsync(add: false, Selected!.Value), _ => Selected is not null, ShowError);
    }

    public ObservableCollection<ExclusionRow> Items { get; } = [];

    public ExclusionRow? Selected { get => _selected; set => Set(ref _selected, value); }

    public string NewValue { get => _newValue; set => Set(ref _newValue, value); }

    public AsyncCommand AddFolderCommand { get; }

    public AsyncCommand AddValueCommand { get; }

    public AsyncCommand RemoveCommand { get; }

    protected override async Task RefreshCoreAsync() => Show(await _gateway.GetExclusionsAsync(CancellationToken.None));

    private async Task AddFoldersAsync()
    {
        foreach (string folder in _dialogs.PickFolders())
        {
            await ChangeAsync(add: true, folder);
        }
    }

    private async Task ChangeAsync(bool add, string value)
    {
        if (add && !_dialogs.Confirm("Add exclusion?", $"Kshatriya will stop scanning {value}. Excluded items are still listed as skipped in every report. This does not change Microsoft Defender."))
        {
            return;
        }

        Show(await _gateway.ChangeExclusionAsync(add, value, CancellationToken.None));
        NewValue = string.Empty;
        ShowInfo(add ? $"Excluded {value}." : $"Removed the exclusion for {value}.");
    }

    private void Show(ExclusionsReplyDto reply)
    {
        Items.Clear();
        foreach (string p in reply.Paths)
        {
            Items.Add(new ExclusionRow("Path", p));
        }

        foreach (string h in reply.Sha256)
        {
            Items.Add(new ExclusionRow("SHA-256", h));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }
}

/// <summary>One finding in the detections history.</summary>
public sealed record DetectionRow(string TimeLocal, string Status, string Path, string Names, string Source, string Action)
{
    public Tone Tone => Status == "Detected" ? Tone.Critical : Tone.Caution;
}

public sealed class DetectionsViewModel(IServiceGateway gateway) : PageViewModel("Detections", "Recent findings from scans and real-time monitoring", Glyphs.Warning)
{
    public ObservableCollection<DetectionRow> Items { get; } = [];

    protected override async Task RefreshCoreAsync()
    {
        DetectionsReplyDto reply = await gateway.GetDetectionsAsync(200, CancellationToken.None);
        Items.Clear();
        foreach (DetectionRecordDto d in reply.Items)
        {
            Items.Add(new DetectionRow(DashboardViewModel.Local(d.TimeUtc), d.Status == "detected" ? "Detected" : "Suspicious", d.Path, string.Join(", ", d.Names), d.Source, d.Action));
        }

        ShowInfo(null); // an empty list shows the page's empty state
    }
}

/// <summary>One audit record.</summary>
public sealed record AuditRow(long Seq, string TimeLocal, string User, string Action, string Outcome, string Target, string Detail);

public sealed class HistoryViewModel(IServiceGateway gateway) : PageViewModel("History", "Audit log of quarantine, restore and exclusion changes", Glyphs.History)
{
    private string _chainState = string.Empty;

    public ObservableCollection<AuditRow> Records { get; } = [];

    public string ChainState { get => _chainState; private set => Set(ref _chainState, value); }

    private Tone _chainTone = Tone.Neutral;

    /// <summary>Success when the hash chain verified, critical when it did not.</summary>
    public Tone ChainTone { get => _chainTone; private set => Set(ref _chainTone, value); }

    protected override async Task RefreshCoreAsync()
    {
        AuditReplyDto reply = await gateway.GetAuditAsync(500, CancellationToken.None);
        Records.Clear();
        foreach (AuditRecordDto r in reply.Records)
        {
            Records.Add(new AuditRow(r.Seq, DashboardViewModel.Local(r.TimeUtc), r.User, r.Action, r.Outcome, r.Target, r.Detail ?? string.Empty));
        }

        ChainTone = reply.ChainValid ? Tone.Success : Tone.Critical;
        ChainState = reply.ChainValid
            ? $"Integrity check passed: the hash chain of {Records.Count} shown record(s) and the full log is intact."
            : $"Integrity check FAILED: {reply.Problem} The log may have been edited.";
        ShowInfo(null);
    }
}

public sealed class AboutViewModel(IServiceGateway gateway) : PageViewModel("About", "Version, status and limitations", Glyphs.Info)
{
    public string Version { get; } = $"Kshatriya Antivirus {AppInfo.Version}";

    public string Endpoint => $"Talking to the {gateway.EndpointDescription}.";

    public string Status { get; } =
        "Prototype. Kshatriya is an early-stage, defensive security project. It is not a replacement for Microsoft Defender or any commercial antivirus and makes no claim of equivalent protection. Keep Microsoft Defender turned on.";

    public string Limitations { get; } =
        "Scans run on demand, on a schedule, and (when enabled) shortly after files are written or programs start. This user-mode monitoring cannot block a file or program before it runs; there is no real-time protection yet in that sense. Quarantine removes only confirmed, high-confidence detections and only when you ask for it. Running programs are not stopped.";

    protected override Task RefreshCoreAsync() => Task.CompletedTask;
}
