using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;

namespace Kshatriya.App.ViewModels;

/// <summary>
/// Navigation shell (ADR 0021): five task pages and two footer pages; the current page is refreshed on
/// selection.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private PageViewModel _current;

    public MainViewModel(IServiceGateway gateway, IDialogs dialogs, IAppHost host, IAppSettings? settings = null)
    {
        Home = new HomeViewModel(gateway, host);
        Scan = new ScanViewModel(gateway, dialogs);
        ScanViewModel scan = Scan;
        Home.QuickScanRequested += () =>
        {
            Current = scan;
            scan.Choice = ScanChoice.Quick;
            scan.QuickScanCommand.Execute(null);
        };
        Protection = new ProtectionViewModel(gateway, host);
        History = new HistoryHubViewModel(
            new DetectionsViewModel(gateway) { IsEmbedded = true },
            new QuarantineViewModel(gateway, dialogs) { IsEmbedded = true },
            new AuditLogViewModel(gateway) { IsEmbedded = true });
        Updates = new UpdatesViewModel(gateway, dialogs);
        Settings = new SettingsViewModel(settings ?? new InMemorySettings(), host, new ExclusionsViewModel(gateway, dialogs) { IsEmbedded = true });
        About = new AboutViewModel(gateway);
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

    public HistoryHubViewModel History { get; }

    public UpdatesViewModel Updates { get; }

    public SettingsViewModel Settings { get; }

    public AboutViewModel About { get; }

    public DetectionsViewModel Detections => History.Detections;

    public QuarantineViewModel Quarantine => History.Quarantine;

    public ExclusionsViewModel Exclusions => Settings.Exclusions;

    /// <summary>Opens History on its findings tab (for example from a notification).</summary>
    public void ShowDetections()
    {
        History.Selected = History.Detections;
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
                value.RefreshCommand.Execute(null);
            }
        }
    }
}
