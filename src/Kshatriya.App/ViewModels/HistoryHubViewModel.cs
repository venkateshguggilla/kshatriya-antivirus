using System.Collections.ObjectModel;

namespace Kshatriya.App.ViewModels;

/// <summary>
/// One place for what happened (ADR 0021): findings, quarantine and the actions log as tabs. A later slice
/// merges them into one filterable list; the tabs keep each part's own commands meanwhile.
/// </summary>
public sealed class HistoryHubViewModel : PageViewModel
{
    private PageViewModel _selected;

    public HistoryHubViewModel(DetectionsViewModel detections, QuarantineViewModel quarantine, AuditLogViewModel auditLog)
        : base("History", "Findings, quarantine and the actions log", Glyphs.History)
    {
        Detections = detections;
        Quarantine = quarantine;
        AuditLog = auditLog;
        Tabs = [detections, quarantine, auditLog];
        _selected = detections;
    }

    public DetectionsViewModel Detections { get; }

    public QuarantineViewModel Quarantine { get; }

    public AuditLogViewModel AuditLog { get; }

    public ObservableCollection<PageViewModel> Tabs { get; }

    /// <summary>The tab shown; selecting one refreshes it.</summary>
    public PageViewModel Selected
    {
        get => _selected;
        set
        {
            if (value is not null && Set(ref _selected, value))
            {
                value.RefreshCommand.Execute(null);
            }
        }
    }

    protected override Task RefreshCoreAsync() => Selected.RefreshCommand.ExecuteAsync(null);
}
