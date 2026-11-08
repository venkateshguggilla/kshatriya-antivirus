using System.Collections.ObjectModel;
using System.Globalization;
using Sentinel.App.Infrastructure;
using Sentinel.App.Services;
using Sentinel.Core;
using Sentinel.Protocol;

namespace Sentinel.App.ViewModels;

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

    protected PageViewModel(string title, string description)
    {
        Title = title;
        Description = description;
        RefreshCommand = new AsyncCommand(_ => RunAsync(RefreshCoreAsync), onError: ShowError);
    }

    public string Title { get; }

    public string Description { get; }

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

public sealed class DashboardViewModel(IServiceGateway gateway, IAppHost host) : PageViewModel("Dashboard", "Protection status at a glance")
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

    public bool AntivirusNeedsAttention => Antivirus is AntivirusHealth.Poor or AntivirusHealth.Snoozed;

    public ObservableCollection<string> Schedules { get; } = [];

    public bool CanRestartElevated => !host.IsElevated;

    public RelayCommand RestartElevatedCommand => new(_ => host.RestartElevated(), _ => !host.IsElevated);

    /// <summary>Optional source of Windows antivirus health (tests replace it).</summary>
    public Func<AntivirusHealth> AntivirusSource { get; set; } = SecurityCenter.GetAntivirusHealth;

    protected override async Task RefreshCoreAsync()
    {
        Antivirus = AntivirusSource();
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
                ? $"Real-time monitoring is on for {string.Join(", ", rt.Paths)}. Programs: {rt.Processes}. Removable drives: {rt.RemovableMedia}. It scans files after they are written; it cannot block them."
                : "Real-time monitoring is off (it can be enabled in the service settings).";
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

            ShowInfo(null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            IsConnected = false;
            ServiceState = $"Not connected to the {gateway.EndpointDescription}.";
            ConnectedAs = string.Empty;
            ShowError(ex);
        }
    }

    internal static string Local(string? isoUtc) =>
        DateTimeOffset.TryParse(isoUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset t)
            ? t.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : "-";
}

/// <summary>One line in the scan results.</summary>
public sealed record ResultRow(string Status, string Path, string Detail, string Action);

public sealed class ScanViewModel : PageViewModel, IDisposable
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private CancellationTokenSource? _cancel;
    private bool _quarantine;
    private bool _isScanning;
    private string _progress = string.Empty;
    private string _summary = string.Empty;

    public ScanViewModel(IServiceGateway gateway, IDialogs dialogs)
        : base("Scan", "Scan files and folders with your own access rights")
    {
        _gateway = gateway;
        _dialogs = dialogs;
        AddFoldersCommand = new RelayCommand(_ => AddTargets(_dialogs.PickFolders()), _ => !IsScanning);
        AddKnownFolderCommand = new RelayCommand(p => AddTargets([KnownFolder(p as string)]), _ => !IsScanning);
        RemoveTargetCommand = new RelayCommand(p => Targets.Remove((string)p!), p => !IsScanning && p is string);
        StartCommand = new AsyncCommand(_ => ScanAsync(), _ => !IsScanning && Targets.Count > 0, ShowError);
        CancelCommand = new RelayCommand(_ => _cancel?.Cancel(), _ => IsScanning);
    }

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

    protected override Task RefreshCoreAsync() => Task.CompletedTask;

    private static string KnownFolder(string? name) => name switch
    {
        "Downloads" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        "Desktop" => Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        "Documents" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private async Task ScanAsync()
    {
        _cancel = new CancellationTokenSource();
        IsScanning = true;
        Results.Clear();
        Summary = string.Empty;
        ShowInfo(null);
        Progress = "Starting…";
        try
        {
            var progress = new Progress<ScanProgressDto>(p =>
                Progress = $"{p.ItemsCompleted:N0} item(s) checked, {p.Detected:N0} finding(s), {p.BytesScanned / (1024.0 * 1024):N1} MiB read");
            ScanReport report = await _gateway.ScanAsync([.. Targets], Quarantine, progress, _cancel.Token);
            ShowReport(report);
        }
        catch (OperationCanceledException)
        {
            Progress = string.Empty;
            ShowInfo("The scan was cancelled. Results are incomplete.");
        }
        finally
        {
            IsScanning = false;
            _cancel.Dispose();
            _cancel = null;
        }
    }

    internal void ShowReport(ScanReport report)
    {
        foreach (ScanItemResult item in report.Items.OrderBy(i => i.Status switch
                 {
                     ScanStatus.Detected => 0,
                     ScanStatus.Suspicious => 1,
                     ScanStatus.NotScanned => 2,
                     _ => 3,
                 }).ThenBy(i => i.Path, StringComparer.OrdinalIgnoreCase))
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
        Summary = s.Detected > 0
            ? $"{s.Detected} item(s) detected, {s.Quarantined} quarantined, {s.QuarantineFailed} could not be quarantined. {s.FilesScanned:N0} file(s) scanned."
            : s.Suspicious > 0
                ? $"{s.Suspicious} item(s) look suspicious but are not confirmed malware. Nothing was changed. {s.FilesScanned:N0} file(s) scanned."
                : s.NotScanned > 0
                    ? $"Nothing detected, but {s.NotScanned} item(s) could not be scanned. {s.FilesScanned:N0} file(s) scanned."
                    : $"Nothing detected. {s.FilesScanned:N0} file(s) scanned.";
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
        : base("Quarantine", "Files Sentinel moved into its encrypted vault")
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

        ShowInfo(Items.Count == 0 ? "The quarantine is empty." : null);
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
                $"Restore {Path.GetFileName(row.OriginalPath)} to {target ?? row.OriginalPath}?\n\nSentinel quarantined it because of: {row.Detections}. Restore only if you are sure it is safe. It will be marked as downloaded from the internet and will be detected again by the next scan unless you exclude it."))
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
        : base("Exclusions", "Folders, files and hashes Sentinel does not scan")
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
        if (add && !_dialogs.Confirm("Add exclusion?", $"Sentinel will stop scanning {value}. Excluded items are still listed as skipped in every report. This does not change Microsoft Defender."))
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

        ShowInfo(Items.Count == 0 ? "No exclusions." : null);
    }
}

/// <summary>One finding in the detections history.</summary>
public sealed record DetectionRow(string TimeLocal, string Status, string Path, string Names, string Source, string Action);

public sealed class DetectionsViewModel(IServiceGateway gateway) : PageViewModel("Detections", "Recent findings from scans and real-time monitoring")
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

        ShowInfo(Items.Count == 0 ? "No recent detections. (The history is kept in memory by the service and starts empty after a restart.)" : null);
    }
}

/// <summary>One audit record.</summary>
public sealed record AuditRow(long Seq, string TimeLocal, string User, string Action, string Outcome, string Target, string Detail);

public sealed class HistoryViewModel(IServiceGateway gateway) : PageViewModel("History", "Audit log of quarantine, restore and exclusion changes")
{
    private string _chainState = string.Empty;

    public ObservableCollection<AuditRow> Records { get; } = [];

    public string ChainState { get => _chainState; private set => Set(ref _chainState, value); }

    protected override async Task RefreshCoreAsync()
    {
        AuditReplyDto reply = await gateway.GetAuditAsync(500, CancellationToken.None);
        Records.Clear();
        foreach (AuditRecordDto r in reply.Records)
        {
            Records.Add(new AuditRow(r.Seq, DashboardViewModel.Local(r.TimeUtc), r.User, r.Action, r.Outcome, r.Target, r.Detail ?? string.Empty));
        }

        ChainState = reply.ChainValid
            ? $"Integrity check passed: the hash chain of {Records.Count} shown record(s) and the full log is intact."
            : $"Integrity check FAILED: {reply.Problem} The log may have been edited.";
        ShowInfo(null);
    }
}

public sealed class AboutViewModel(IServiceGateway gateway) : PageViewModel("About", "Version, status and limitations")
{
    public string Version { get; } = $"Sentinel {AppInfo.Version}";

    public string Endpoint => $"Talking to the {gateway.EndpointDescription}.";

    public string Status { get; } =
        "Prototype. Sentinel is an early-stage, defensive security project. It is not a replacement for Microsoft Defender or any commercial antivirus and makes no claim of equivalent protection. Keep Microsoft Defender turned on.";

    public string Limitations { get; } =
        "Scans run on demand, on a schedule, and (when enabled) shortly after files are written or programs start. This user-mode monitoring cannot block a file or program before it runs; there is no real-time protection yet in that sense. Quarantine removes only confirmed, high-confidence detections and only when you ask for it. Running programs are not stopped.";

    protected override Task RefreshCoreAsync() => Task.CompletedTask;
}
