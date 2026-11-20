using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
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

/// <summary>One finding in the scan results, as a card: what, where, why and what happened.</summary>
public sealed record FindingCard(string Name, string Path, string Why, string Badge, Tone Tone, string Outcome, bool Quarantined);

/// <summary>Items not scanned for one reason.</summary>
public sealed record NotScannedGroup(string Reason, int Count, string Hint)
{
    public string Title => Count == 1 ? $"1 item: {Reason}" : $"{Count:N0} items: {Reason}";
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
    private bool _quarantine;
    private bool _isScanning;
    private string _progress = string.Empty;
    private string _summary = string.Empty;
    private DriveChoice? _selectedDrive;

    public ScanViewModel(IServiceGateway gateway, IDialogs dialogs, Func<IReadOnlyList<DriveChoice>>? drives = null)
        : base("Scan", "Quick, full, external-drive and custom scans with your own access rights", Glyphs.Search)
    {
        Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ScanSession.IsRunning))
            {
                IsScanning = Session.IsRunning;
            }
        };
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
        CancelCommand = new RelayCommand(_ => Session.Cancel(), _ => IsScanning);
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

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            Set(ref _isScanning, value);
            HasActivity = value;
        }
    }

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

    public void Dispose() => Session.Dispose();

    /// <summary>The current scan, shared with the shell and the notification area.</summary>
    public ScanSession Session { get; } = new();

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
        if (Session.IsRunning)
        {
            return;
        }

        ClearResults();
        ShowInfo(null);
        Progress = $"{label}: starting…";
        void Update(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(ScanSession.StatusLine) && Session.IsRunning)
            {
                Progress = $"{label}: {Session.ItemsChecked:N0} item(s) checked, {Session.Findings:N0} finding(s), {Session.MiBRead:N1} MiB read";
            }
        }

        Session.PropertyChanged += Update;
        try
        {
            ScanReport? report = await Session.RunAsync(label, start);
            if (report is not null)
            {
                ShowReport(report, label);
            }
            else
            {
                Progress = string.Empty;
                ShowInfo($"{label} was cancelled. Results are incomplete.");
            }
        }
        finally
        {
            Session.PropertyChanged -= Update;
        }
    }

    /// <summary>Finding cards shown at most (the full list stays in the table and the saved report).</summary>
    internal const int MaxCards = 200;

    /// <summary>Suspicious items: heuristics, never acted on automatically; the user decides.</summary>
    public ObservableCollection<FindingCard> NeedsDecision { get; } = [];

    /// <summary>Confirmed detections, quarantined or reported.</summary>
    public ObservableCollection<FindingCard> Threats { get; } = [];

    /// <summary>Items that were not scanned, grouped by reason with what the user can do about it.</summary>
    public ObservableCollection<NotScannedGroup> NotScanned { get; } = [];

    private int _notScannedTotal;

    public int NotScannedTotal { get => _notScannedTotal; private set => Set(ref _notScannedTotal, value); }

    /// <summary>Items the last completed scan could not read for lack of rights (a Home recommendation).</summary>
    public int LastAccessDenied { get; private set; }

    internal static int CountAccessDenied(ScanReport report) =>
        report.Items.Count(i => i.Status == ScanStatus.NotScanned && i.Reason == ScanReason.AccessDenied);

    private void ClearResults()
    {
        Results.Clear();
        NeedsDecision.Clear();
        Threats.Clear();
        NotScanned.Clear();
        NotScannedTotal = 0;
        Summary = string.Empty;
    }

    private static FindingCard Card(ScanItemResult item)
    {
        Detection? first = item.Detections.FirstOrDefault(d => d.Category != DetectionCategory.Suspicious) ?? (item.Detections.Count > 0 ? item.Detections[0] : null);
        string name = first?.Name ?? Path.GetFileName(item.Path);
        string badge = first is null ? "Finding" : $"{Category(first.Category)} · {WireNames.Of(first.Confidence)} confidence";
        string why = string.Join("; ", item.Detections.Select(d => d.Name + (d.Location is null ? string.Empty : $" in {d.Location}")));
        string outcome = item.Action switch
        {
            null => item.Status == ScanStatus.Detected ? "Reported only. Quarantine it from History if you did not expect it." : "Flagged by a heuristic, not a confirmed detection. Nothing was changed.",
            { Succeeded: true } => "Moved to quarantine with a verified copy. An administrator can restore it.",
            { } a => $"Could not be quarantined ({WireNames.Of(a.Failure)}).",
        };
        Tone tone = item.Status == ScanStatus.Detected ? Tone.Critical : Tone.Caution;
        return new FindingCard(name, item.Path, why, badge, tone, outcome, item.Action is { Succeeded: true });
    }

    private static string Category(DetectionCategory category) => category switch
    {
        DetectionCategory.Malware => "Malware",
        DetectionCategory.PotentiallyUnwanted => "Potentially unwanted",
        DetectionCategory.TestFile => "Test file",
        DetectionCategory.Suspicious => "Suspicious",
        _ => "Finding",
    };

    /// <summary>What the user can do about items not scanned for a reason (empty: nothing to do).</summary>
    internal static string Hint(ScanReason reason) => reason switch
    {
        ScanReason.AccessDenied => "Your account may not read them. Restart Kshatriya as administrator and scan again to include them.",
        ScanReason.Locked => "Another program had them open. Scan again later.",
        ScanReason.CloudPlaceholder => "Cloud-only files are not downloaded just to scan them. They are scanned once they are on this PC.",
        ScanReason.TooLarge => "Larger than the scan size limit.",
        ScanReason.Timeout => "Took longer than the per-file time limit.",
        ScanReason.ArchiveEncrypted => "Password-protected archives cannot be looked into.",
        ScanReason.Excluded => "Excluded in Settings.",
        ScanReason.ReparsePoint or ScanReason.LoopDetected => "Links are not followed, so nothing is scanned twice or outside the chosen folders.",
        _ => string.Empty,
    };

    internal void ShowReport(ScanReport report, string label = "Scan")
    {
        ClearResults();
        foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.Detected).Take(MaxCards))
        {
            Threats.Add(Card(item));
        }

        foreach (ScanItemResult item in report.Items.Where(i => i.Status == ScanStatus.Suspicious).Take(MaxCards))
        {
            NeedsDecision.Add(Card(item));
        }

        foreach (IGrouping<ScanReason, ScanItemResult> group in report.Items.Where(i => i.Status == ScanStatus.NotScanned)
                     .GroupBy(i => i.Reason).OrderByDescending(g => g.Count()))
        {
            NotScanned.Add(new NotScannedGroup(WireNames.Of(group.Key), group.Count(), Hint(group.Key)));
        }

        NotScannedTotal = NotScanned.Sum(g => g.Count);
        LastAccessDenied = CountAccessDenied(report);

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
