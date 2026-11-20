using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Presentation;

namespace Kshatriya.App.ViewModels;

/// <summary>
/// Navigation shell (ADR 0021): five task pages and two footer pages; the current page is refreshed on
/// selection.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private PageViewModel _current;

    public MainViewModel(IServiceGateway gateway, IDialogs dialogs, IAppHost host, IAppSettings? settings = null, IReviewStore? reviews = null)
    {
        reviews ??= new InMemoryReviewStore();
        Home = new HomeViewModel(gateway, host) { Reviews = reviews };
        Scan = new ScanViewModel(gateway, dialogs);
        ScanViewModel scan = Scan;
        Home.QuickScanRequested += () =>
        {
            Current = scan;
            scan.Choice = ScanChoice.Quick;
            scan.QuickScanCommand.Execute(null);
        };
        Protection = new ProtectionViewModel(gateway, host, dialogs);
        History = new HistoryViewModel(gateway, dialogs, host, reviews);
        Updates = new UpdatesViewModel(gateway, dialogs);
        Settings = new SettingsViewModel(settings ?? new InMemorySettings(), host, new ExclusionsViewModel(gateway, dialogs) { IsEmbedded = true });
        About = new AboutViewModel(gateway);
        Scan.Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(ScanSession.IsRunning) or nameof(ScanSession.StatusLine))
            {
                OnPropertyChanged(nameof(ShowScanStrip));
            }
        };
        Scan.Session.Finished += s =>
        {
            if (s.Report is { } report)
            {
                Home.LastScanAccessDenied = ScanViewModel.CountAccessDenied(report);
            }
        };
        OpenScanCommand = new RelayCommand(_ => Current = Scan);
        Home.ActionRequested += id => Perform(id, host);
        Pages = [Home, Scan, Protection, History, Updates];
        FooterPages = [Settings, About];
        _current = Home;
        Title = $"Kshatriya Antivirus {AppInfo.Version} (prototype)" + (host.IsElevated ? " - Administrator" : string.Empty);
    }

    public string Title { get; }

    /// <summary>The task pages at the top of the navigation.</summary>
    public ObservableCollection<PageViewModel> Pages { get; }

    /// <summary>Settings and Help and about, at the bottom of the navigation.</summary>
    public ObservableCollection<PageViewModel> FooterPages { get; }

    /// <summary>Every page reachable from the navigation.</summary>
    public IEnumerable<PageViewModel> AllPages => Pages.Concat(FooterPages);

    public HomeViewModel Home { get; }

    public ScanViewModel Scan { get; }

    public ProtectionViewModel Protection { get; }

    public HistoryViewModel History { get; }

    public UpdatesViewModel Updates { get; }

    public SettingsViewModel Settings { get; }

    public AboutViewModel About { get; }

    public ExclusionsViewModel Exclusions => Settings.Exclusions;

    /// <summary>A scan is running and another page is shown: the shell shows a strip with its progress.</summary>
    public bool ShowScanStrip => Scan.Session.IsRunning && !ReferenceEquals(Current, Scan);

    /// <summary>Opens the Scan page (the strip's View button).</summary>
    public RelayCommand OpenScanCommand { get; }

    /// <summary>Performs a status item's action (ADR 0021): open the page that resolves it, or ask the host.</summary>
    internal void Perform(string actionId, IAppHost host)
    {
        switch (actionId)
        {
            case StatusActions.ReviewFindings:
                History.Filter = HistoryFilter.NeedsDecision;
                Current = History;
                break;
            case StatusActions.OpenHistory:
                History.Filter = HistoryFilter.ActionsLog;
                Current = History;
                break;
            case StatusActions.CheckUpdates:
                Current = Updates;
                break;
            case StatusActions.ProtectionSettings:
                Current = Protection;
                break;
            case StatusActions.OpenWindowsSecurity:
                host.OpenWindowsSecurity();
                break;
            case StatusActions.RestartElevated:
                host.RestartElevated();
                break;
            case StatusActions.QuickScan:
                Home.QuickScanCommand.Execute(null);
                break;
        }
    }

    /// <summary>Opens History on all findings (for example from a notification about a background finding).</summary>
    public void ShowDetections()
    {
        History.Filter = HistoryFilter.All;
        if (ReferenceEquals(Current, History))
        {
            History.RefreshCommand.Execute(null);
        }

        Current = History;
    }

    /// <summary>
    /// The page shown. A navigation list that does not contain the current page reports null; that is
    /// ignored, so selecting a footer page does not bounce back.
    /// </summary>
    public PageViewModel Current
    {
        get => _current;
        set
        {
            if (value is not null && Set(ref _current, value))
            {
                OnPropertyChanged(nameof(ShowScanStrip));
                value.RefreshCommand.Execute(null);
            }
        }
    }
}
