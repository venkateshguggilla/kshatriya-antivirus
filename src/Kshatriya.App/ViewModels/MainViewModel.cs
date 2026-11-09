using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;

namespace Kshatriya.App.ViewModels;

/// <summary>Navigation shell: a list of pages, the current page refreshed on selection.</summary>
public sealed class MainViewModel : ObservableObject
{
    private PageViewModel _current;

    public MainViewModel(IServiceGateway gateway, IDialogs dialogs, IAppHost host)
    {
        Dashboard = new DashboardViewModel(gateway, host);
        Scan = new ScanViewModel(gateway, dialogs);
        Detections = new DetectionsViewModel(gateway);
        Quarantine = new QuarantineViewModel(gateway, dialogs);
        Exclusions = new ExclusionsViewModel(gateway, dialogs);
        History = new HistoryViewModel(gateway);
        About = new AboutViewModel(gateway);
        Pages = [Dashboard, Scan, Detections, Quarantine, Exclusions, History, About];
        _current = Dashboard;
        Title = $"Kshatriya Antivirus {AppInfo.Version} (prototype)" + (host.IsElevated ? " - Administrator" : string.Empty);
    }

    public string Title { get; }

    public ObservableCollection<PageViewModel> Pages { get; }

    public DashboardViewModel Dashboard { get; }

    public ScanViewModel Scan { get; }

    public DetectionsViewModel Detections { get; }

    public QuarantineViewModel Quarantine { get; }

    public ExclusionsViewModel Exclusions { get; }

    public HistoryViewModel History { get; }

    public AboutViewModel About { get; }

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
