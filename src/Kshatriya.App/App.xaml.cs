using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Kshatriya.App.Services;
using Kshatriya.App.ViewModels;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;

namespace Kshatriya.App;

public sealed partial class App : Application, IAppHost, IDisposable
{
    private const string InstanceName = @"Local\Kshatriya.App.Instance";
    private const string ShowSignalName = @"Local\Kshatriya.App.Show";
    private static readonly TimeSpan s_pollInterval = TimeSpan.FromSeconds(15);

    private string[] _args = [];
    private Mutex? _instance;
    private EventWaitHandle? _showSignal;
    private RegisteredWaitHandle? _showWait;
    private TrayIcon? _tray;
    private MainViewModel? _main;
    private DetectionWatcher? _watcher;
    private AppPreferences? _preferences;
    private DispatcherTimer? _timer;
    private bool _polling;
    private bool _exiting;

    public bool IsElevated { get; } = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public void RestartElevated()
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" };
        foreach (string arg in _args.Where(a => !a.Equals("--background", StringComparison.OrdinalIgnoreCase)))
        {
            start.ArgumentList.Add(arg);
        }

        // Let the elevated copy become the single instance.
        ReleaseInstance();
        try
        {
            Process.Start(start);
            ExitApp();
        }
        catch (Win32Exception)
        {
            // The user declined the elevation prompt; keep running as is.
            ClaimInstance();
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _args = e.Args;
        if (ScanArguments(e.Args) is { Count: > 0 } scanPaths)
        {
            StartContextScan(scanPaths, e.Args.Contains("--dev", StringComparer.OrdinalIgnoreCase));
            return;
        }

        if (!ClaimInstance())
        {
            // Already running in this session (for example in the tray): bring that window up instead.
            using (var signal = EventWaitHandle.OpenExisting(ShowSignalName))
            {
                signal.Set();
            }

            Shutdown();
            return;
        }

        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        bool dev = e.Args.Contains("--dev", StringComparer.OrdinalIgnoreCase);
        bool background = e.Args.Contains("--background", StringComparer.OrdinalIgnoreCase);
        IServiceGateway gateway = dev
            ? new ServiceGateway(ServiceEndpoint.Development(), "development service")
            : new ServiceGateway(ServiceEndpoint.Production, "installed Kshatriya service");

        _main = new MainViewModel(gateway, new WpfDialogs(), this);
        var window = new MainWindow { DataContext = _main };
        window.Closing += (_, args) =>
        {
            // Closing the window keeps the app in the notification area; Exit is in the tray menu.
            if (!_exiting)
            {
                args.Cancel = true;
                window.Hide();
            }
        };
        MainWindow = window;

        _preferences = new AppPreferences();
        _watcher = new DetectionWatcher(gateway);
        _tray = new TrayIcon(_preferences.Notifications, () => ShowMainWindow(detections: false), _preferences.SetNotifications, ExitApp);
        _tray.NotificationClicked += () => ShowMainWindow(detections: true);
        _timer = new DispatcherTimer { Interval = s_pollInterval };
        _timer.Tick += async (_, _) => await PollAsync();
        _timer.Start();
        _ = PollAsync(); // sets the starting point, so older findings are not announced

        if (!background)
        {
            ShowMainWindow(detections: false);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Dispose();
        base.OnExit(e);
    }

    /// <summary>Removes the tray icon and releases the single-instance objects (called on exit).</summary>
    public void Dispose()
    {
        _timer?.Stop();
        _tray?.Dispose();
        _tray = null;
        _showWait?.Unregister(null);
        _showWait = null;
        _showSignal?.Dispose();
        _showSignal = null;
        ReleaseInstance();
    }

    /// <summary>Paths after <c>--scan</c> (Explorer's "Scan with Kshatriya Antivirus" passes one per item).</summary>
    internal static IReadOnlyList<string> ScanArguments(IReadOnlyList<string> args)
    {
        var paths = new List<string>();
        for (int i = 0; i < args.Count - 1; i++)
        {
            if (args[i].Equals("--scan", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(args[i + 1]))
            {
                paths.Add(args[++i]);
            }
        }

        return paths;
    }

    /// <summary>
    /// A separate window for a right-click scan: it opens on the Scan page, starts at once, and exits when
    /// closed. It does not take over the notification-area instance.
    /// </summary>
    private void StartContextScan(IReadOnlyList<string> paths, bool dev)
    {
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        IServiceGateway gateway = dev
            ? new ServiceGateway(ServiceEndpoint.Development(), "development service")
            : new ServiceGateway(ServiceEndpoint.Production, "installed Kshatriya service");
        _main = new MainViewModel(gateway, new WpfDialogs(), this);
        var window = new MainWindow { DataContext = _main };
        MainWindow = window;
        _main.Current = _main.Scan;
        _main.Scan.AddTargets(paths);
        window.Show();
        _main.Scan.StartCommand.Execute(null);
    }

    private bool ClaimInstance()
    {
        _instance = new Mutex(initiallyOwned: true, InstanceName, out bool created);
        if (!created)
        {
            _instance.Dispose();
            _instance = null;
            return false;
        }

        if (_showSignal is null)
        {
            _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
            _showWait = ThreadPool.RegisterWaitForSingleObject(_showSignal, (_, _) => Dispatcher.BeginInvoke(() => ShowMainWindow(detections: false)), null, Timeout.Infinite, executeOnlyOnce: false);
        }

        return true;
    }

    private void ReleaseInstance()
    {
        if (_instance is not null)
        {
            _instance.ReleaseMutex();
            _instance.Dispose();
            _instance = null;
        }
    }

    private void ShowMainWindow(bool detections)
    {
        if (MainWindow is not { } window || _main is null)
        {
            return;
        }

        window.Show();
        if (window.WindowState == WindowState.Minimized)
        {
            window.WindowState = WindowState.Normal;
        }

        window.Activate();
        if (detections)
        {
            _main.Current = _main.Detections;
        }
        else if (_main.Current == _main.Dashboard)
        {
            _main.Dashboard.RefreshCommand.Execute(null);
        }
    }

    private void ExitApp()
    {
        _exiting = true;
        Shutdown();
    }

    private async Task PollAsync()
    {
        if (_polling || _watcher is null || _tray is null || _preferences is null)
        {
            return;
        }

        _polling = true;
        try
        {
            IReadOnlyList<DetectionRecordDto> fresh = await _watcher.PollAsync(CancellationToken.None);
            _tray.SetStatus(_watcher.ServiceReachable ? "Kshatriya Antivirus" : "Kshatriya Antivirus: service not reachable");
            if (fresh.Count > 0 && _preferences.Notifications)
            {
                FindingNotice notice = DetectionWatcher.Describe(fresh);
                _tray.Notify(notice.Title, notice.Message, notice.IsThreat);
            }
        }
        finally
        {
            _polling = false;
        }
    }
}

/// <summary>Standard Windows dialogs.</summary>
internal sealed class WpfDialogs : IDialogs
{
    public IReadOnlyList<string> PickFolders()
    {
        var dialog = new OpenFolderDialog { Multiselect = true, Title = "Choose folders" };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FolderNames : [];
    }

    public string? PickRestoreLocation(string suggestedFileName)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Restore to",
            FileName = suggestedFileName,
            OverwritePrompt = false,
            CheckFileExists = false,
        };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public bool Confirm(string title, string message) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
}
