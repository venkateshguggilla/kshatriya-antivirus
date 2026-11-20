using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;

namespace Kshatriya.App.ViewModels;

/// <summary>The History filters (ADR 0021): one record, shown by what the user has to do.</summary>
public enum HistoryFilter
{
    All,
    NeedsDecision,
    Quarantined,
    Kept,
    ActionsLog,
}

/// <summary>What a History entry is.</summary>
public enum HistoryKind
{
    /// <summary>A detection or suspicious item reported by a scan, real-time monitoring or behaviour detection.</summary>
    Finding,

    /// <summary>A file in the quarantine vault.</summary>
    Quarantined,

    /// <summary>An audit record (quarantine, restore, exclusion changes); administrators only.</summary>
    Action,
}

/// <summary>One entry in History, with what is needed for its row and its detail pane.</summary>
public sealed record HistoryEntry
{
    public required HistoryKind Kind { get; init; }

    public required string Title { get; init; }

    public required string Subtitle { get; init; }

    public required DateTimeOffset Time { get; init; }

    public required Tone Tone { get; init; }

    public string Path { get; init; } = string.Empty;

    /// <summary>Why it was reported (detection names), or the audit detail.</summary>
    public string Why { get; init; } = string.Empty;

    public string Source { get; init; } = string.Empty;

    /// <summary>A finding the user still has to decide on (not quarantined and not kept).</summary>
    public bool NeedsDecision { get; init; }

    /// <summary>A confirmed detection (not a suspicious heuristic).</summary>
    public bool Confirmed { get; init; }

    public bool Kept { get; init; }

    /// <summary>For findings, the key the "kept" choice is stored under.</summary>
    public string ReviewKey { get; init; } = string.Empty;

    public QuarantineRow? QuarantineItem { get; init; }

    public string TimeLocal => Time == DateTimeOffset.MinValue ? "-" : Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
}

/// <summary>
/// History (ADR 0021, slice 4): findings, the quarantine vault and the actions log in one filterable list with
/// a detail pane. Findings can be quarantined (as the user, reversible) or kept (an acknowledgement in the app,
/// never an exclusion). Suspicious findings are never acted on without the user.
/// </summary>
public sealed class HistoryViewModel : PageViewModel
{
    private readonly IServiceGateway _gateway;
    private readonly IDialogs _dialogs;
    private readonly IAppHost _host;
    private readonly IReviewStore _reviews;
    private readonly List<HistoryEntry> _all = [];
    private HistoryFilter _filter;
    private HistoryEntry? _selected;
    private string _search = string.Empty;
    private string _auditState = string.Empty;
    private Tone _auditTone = Tone.Neutral;
    private int _needsDecision;

    public HistoryViewModel(IServiceGateway gateway, IDialogs dialogs, IAppHost host, IReviewStore reviews)
        : base("History", "Findings, quarantine and actions, newest first", Glyphs.History)
    {
        _gateway = gateway;
        _dialogs = dialogs;
        _host = host;
        _reviews = reviews;
        Vault = new QuarantineViewModel(gateway, dialogs) { IsEmbedded = true };
        QuarantineCommand = new AsyncCommand(_ => RunAsync(QuarantineSelectedAsync), _ => Selected is { Kind: HistoryKind.Finding, NeedsDecision: true } || Selected is { Kind: HistoryKind.Finding, Kept: true }, ShowError);
        KeepCommand = new RelayCommand(_ => SetKept(true), _ => Selected is { Kind: HistoryKind.Finding, NeedsDecision: true });
        UnkeepCommand = new RelayCommand(_ => SetKept(false), _ => Selected is { Kind: HistoryKind.Finding, Kept: true });
        RestoreCommand = new AsyncCommand(_ => VaultActionAsync(Vault.RestoreCommand), _ => Selected?.QuarantineItem is not null, ShowError);
        RestoreToCommand = new AsyncCommand(_ => VaultActionAsync(Vault.RestoreToCommand), _ => Selected?.QuarantineItem is not null, ShowError);
        DeleteCommand = new AsyncCommand(_ => VaultActionAsync(Vault.DeleteCommand), _ => Selected?.QuarantineItem is not null, ShowError);
        OpenFolderCommand = new RelayCommand(_ => _host.ShowInFolder(Selected!.Path), _ => Selected is { Kind: HistoryKind.Finding, Path.Length: > 0 });
    }

    /// <summary>The quarantine operations (restore, delete), shared with the vault's own logic and tests.</summary>
    public QuarantineViewModel Vault { get; }

    /// <summary>The entries shown with the current filter and search.</summary>
    public ObservableCollection<HistoryEntry> Entries { get; } = [];

    public HistoryFilter Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
            {
                foreach (string name in new[] { nameof(IsAll), nameof(IsNeedsDecision), nameof(IsQuarantined), nameof(IsKept), nameof(IsActionsLog) })
                {
                    OnPropertyChanged(name);
                }

                Apply();
            }
        }
    }

    // Filter buttons (toggle buttons bound two-way).
    public bool IsAll { get => Filter == HistoryFilter.All; set => Pick(value, HistoryFilter.All); }

    public bool IsNeedsDecision { get => Filter == HistoryFilter.NeedsDecision; set => Pick(value, HistoryFilter.NeedsDecision); }

    public bool IsQuarantined { get => Filter == HistoryFilter.Quarantined; set => Pick(value, HistoryFilter.Quarantined); }

    public bool IsKept { get => Filter == HistoryFilter.Kept; set => Pick(value, HistoryFilter.Kept); }

    public bool IsActionsLog { get => Filter == HistoryFilter.ActionsLog; set => Pick(value, HistoryFilter.ActionsLog); }

    /// <summary>Matches name, path or source, ignoring case.</summary>
    public string Search
    {
        get => _search;
        set
        {
            if (Set(ref _search, value ?? string.Empty))
            {
                Apply();
            }
        }
    }

    public HistoryEntry? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    /// <summary>Findings waiting for the user's decision (the navigation badge).</summary>
    public int NeedsDecisionCount
    {
        get => _needsDecision;
        private set
        {
            if (Set(ref _needsDecision, value))
            {
                BadgeCount = value;
            }
        }
    }

    public int QuarantinedCount => _all.Count(e => e.Kind == HistoryKind.Quarantined);

    public int KeptCount => _all.Count(e => e.Kept);

    /// <summary>The audit log's integrity, or why it cannot be shown (administrators only).</summary>
    public string AuditState { get => _auditState; private set => Set(ref _auditState, value); }

    public Tone AuditTone { get => _auditTone; private set => Set(ref _auditTone, value); }

    public AsyncCommand QuarantineCommand { get; }

    public RelayCommand KeepCommand { get; }

    public RelayCommand UnkeepCommand { get; }

    public AsyncCommand RestoreCommand { get; }

    public AsyncCommand RestoreToCommand { get; }

    public AsyncCommand DeleteCommand { get; }

    public RelayCommand OpenFolderCommand { get; }

    /// <summary>Unresolved findings for Home's status: confirmed detections and suspicious items.</summary>
    public static (int Confirmed, int Suspicious) CountUnresolved(IEnumerable<HistoryEntry> entries)
    {
        int confirmed = 0, suspicious = 0;
        foreach (HistoryEntry e in entries.Where(e => e.NeedsDecision))
        {
            if (e.Confirmed)
            {
                confirmed++;
            }
            else
            {
                suspicious++;
            }
        }

        return (confirmed, suspicious);
    }

    /// <summary>
    /// Builds the findings and vault entries. A finding counts as resolved when the service quarantined it or
    /// its file is in the vault from the same time or later; kept findings no longer need a decision.
    /// </summary>
    public static List<HistoryEntry> Build(IEnumerable<DetectionRecordDto> detections, IEnumerable<QuarantineItemDto> vault, IReviewStore reviews)
    {
        ArgumentNullException.ThrowIfNull(reviews);
        List<QuarantineItemDto> vaultItems = [.. vault];
        var entries = new List<HistoryEntry>();
        foreach (DetectionRecordDto d in detections)
        {
            DateTimeOffset time = Parse(d.TimeUtc);
            bool confirmed = d.Status == "detected";
            bool quarantined = d.Action.StartsWith("quarantined", StringComparison.Ordinal)
                || vaultItems.Any(q => string.Equals(q.OriginalPath, d.Path, StringComparison.OrdinalIgnoreCase) && Parse(q.QuarantinedUtc) >= time);
            if (quarantined && vaultItems.Any(q => string.Equals(q.OriginalPath, d.Path, StringComparison.OrdinalIgnoreCase)))
            {
                continue; // the vault entry below tells the same story
            }

            string key = IReviewStore.KeyOf(d.Path, d.Names);
            bool kept = !quarantined && reviews.IsKept(key);
            string state = quarantined ? "quarantined" : kept ? "kept by you" : "waiting for you";
            entries.Add(new HistoryEntry
            {
                Kind = HistoryKind.Finding,
                Title = System.IO.Path.GetFileName(d.Path) is { Length: > 0 } name ? name : d.Path,
                Subtitle = $"{(confirmed ? "Detected" : "Suspicious")} · {d.Source} · {state}",
                Time = time,
                Tone = quarantined || kept ? Tone.Neutral : confirmed ? Tone.Critical : Tone.Caution,
                Path = d.Path,
                Why = string.Join(", ", d.Names),
                Source = d.Source,
                NeedsDecision = !quarantined && !kept,
                Confirmed = confirmed,
                Kept = kept,
                ReviewKey = key,
            });
        }

        foreach (QuarantineItemDto q in vaultItems)
        {
            string why = q.Detections.Count == 0 ? "Added manually" : string.Join(", ", q.Detections);
            entries.Add(new HistoryEntry
            {
                Kind = HistoryKind.Quarantined,
                Title = System.IO.Path.GetFileName(q.OriginalPath),
                Subtitle = $"Quarantined · {why}",
                Time = Parse(q.QuarantinedUtc),
                Tone = Tone.Success,
                Path = q.OriginalPath,
                Why = why,
                Source = q.Origin,
                QuarantineItem = new QuarantineRow(q.Id, HomeViewModel.Local(q.QuarantinedUtc), q.OriginalPath, why, q.User, q.SizeBytes),
            });
        }

        return entries;
    }

    protected override async Task RefreshCoreAsync()
    {
        DetectionsReplyDto detections = await _gateway.GetDetectionsAsync(500, CancellationToken.None);
        QuarantineListReplyDto vault = await _gateway.ListQuarantineAsync(CancellationToken.None);
        _all.Clear();
        _all.AddRange(Build(detections.Items, vault.Items, _reviews));
        try
        {
            AuditReplyDto audit = await _gateway.GetAuditAsync(500, CancellationToken.None);
            foreach (AuditRecordDto r in audit.Records)
            {
                _all.Add(new HistoryEntry
                {
                    Kind = HistoryKind.Action,
                    Title = $"{r.Action}: {r.Outcome}",
                    Subtitle = $"{r.User} · {r.Target}",
                    Time = Parse(r.TimeUtc),
                    Tone = Tone.Neutral,
                    Path = r.Target,
                    Why = r.Detail ?? string.Empty,
                    Source = r.User,
                });
            }

            (AuditState, AuditTone) = audit.ChainValid
                ? ("Integrity check passed: the actions log's hash chain is intact.", Tone.Success)
                : ($"Integrity check FAILED: {audit.Problem} The log may have been edited.", Tone.Critical);
        }
        catch (ServiceException ex) when (ex.Code == ErrorCodes.AccessDenied)
        {
            (AuditState, AuditTone) = ("The actions log is shown to administrators only. Use Restart as administrator on Home.", Tone.Neutral);
        }

        NeedsDecisionCount = _all.Count(e => e.NeedsDecision);
        OnPropertyChanged(nameof(QuarantinedCount));
        OnPropertyChanged(nameof(KeptCount));
        Apply();
        ShowInfo(null);
    }

    private void Apply()
    {
        HistoryEntry? previous = Selected;
        IEnumerable<HistoryEntry> shown = Filter switch
        {
            HistoryFilter.NeedsDecision => _all.Where(e => e.NeedsDecision),
            HistoryFilter.Quarantined => _all.Where(e => e.Kind == HistoryKind.Quarantined),
            HistoryFilter.Kept => _all.Where(e => e.Kept),
            HistoryFilter.ActionsLog => _all.Where(e => e.Kind == HistoryKind.Action),
            _ => _all.Where(e => e.Kind != HistoryKind.Action),
        };
        if (Search.Length > 0)
        {
            shown = shown.Where(e => e.Title.Contains(Search, StringComparison.OrdinalIgnoreCase)
                || e.Path.Contains(Search, StringComparison.OrdinalIgnoreCase)
                || e.Source.Contains(Search, StringComparison.OrdinalIgnoreCase));
        }

        Entries.Clear();
        foreach (HistoryEntry e in shown.OrderByDescending(e => e.Time))
        {
            Entries.Add(e);
        }

        Selected = previous is null ? Entries.FirstOrDefault() : Entries.FirstOrDefault(e => e.Path == previous.Path && e.Kind == previous.Kind) ?? Entries.FirstOrDefault();
    }

    private async Task QuarantineSelectedAsync()
    {
        HistoryEntry entry = Selected!;
        if (!_dialogs.Confirm(
                "Quarantine file?",
                $"Move {entry.Title} into Kshatriya's quarantine?\n\n{entry.Path}\n\nKshatriya keeps a verified copy, and an administrator can restore it. The file is opened with your own access rights."))
        {
            return;
        }

        OperationReplyDto reply = await _gateway.QuarantineFileAsync(entry.Path, CancellationToken.None);
        if (reply.Succeeded)
        {
            _reviews.Unkeep(entry.ReviewKey);
        }

        await RefreshCoreAsync();
        if (reply.Succeeded)
        {
            ShowInfo($"{entry.Title} was moved to quarantine.");
        }
        else
        {
            IsError = true;
            Message = $"Not quarantined ({reply.Code}): {reply.Message}";
        }
    }

    private void SetKept(bool keep)
    {
        HistoryEntry entry = Selected!;
        if (keep)
        {
            _reviews.Keep(entry.ReviewKey);
        }
        else
        {
            _reviews.Unkeep(entry.ReviewKey);
        }

        int index = _all.IndexOf(entry);
        HistoryEntry updated = entry with
        {
            Kept = keep,
            NeedsDecision = !keep,
            Tone = keep ? Tone.Neutral : entry.Confirmed ? Tone.Critical : Tone.Caution,
            Subtitle = entry.Subtitle[..entry.Subtitle.LastIndexOf('·')] + (keep ? "· kept by you" : "· waiting for you"),
        };
        if (index >= 0)
        {
            _all[index] = updated;
        }

        NeedsDecisionCount = _all.Count(e => e.NeedsDecision);
        OnPropertyChanged(nameof(KeptCount));
        Selected = updated;
        Apply();
        ShowInfo(keep
            ? $"{entry.Title} is kept. It no longer counts on Home, but every scan still reports it. This is not an exclusion."
            : $"{entry.Title} is waiting for your decision again.");
    }

    private async Task VaultActionAsync(AsyncCommand command)
    {
        Vault.Selected = Selected!.QuarantineItem;
        string? before = Vault.Message;
        await command.ExecuteAsync(null);
        if (Vault.Message is { } message && !ReferenceEquals(message, before))
        {
            IsError = Vault.IsError;
            Message = message;
        }

        string? keepMessage = Message;
        bool keepError = IsError;
        await RunAsync(RefreshCoreAsync);
        (Message, IsError) = (keepMessage, keepError);
    }

    private static DateTimeOffset Parse(string? isoUtc) =>
        DateTimeOffset.TryParse(isoUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset t) ? t : DateTimeOffset.MinValue;

    private void Pick(bool selected, HistoryFilter filter)
    {
        if (selected)
        {
            Filter = filter;
        }
    }
}
