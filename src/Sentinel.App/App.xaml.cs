using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using Microsoft.Win32;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Runtime.Ipc;

namespace Sentinel.App;

public partial class App : Application, IAppHost
{
    private string[] _args = [];

    public bool IsElevated { get; } = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public void RestartElevated()
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" };
        foreach (string arg in _args)
        {
            start.ArgumentList.Add(arg);
        }

        try
        {
            Process.Start(start);
            Shutdown();
        }
        catch (Win32Exception)
        {
            // The user declined the elevation prompt; keep running as is.
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        _args = e.Args;
        bool dev = e.Args.Contains("--dev", StringComparer.OrdinalIgnoreCase);
        IServiceGateway gateway = dev
            ? new ServiceGateway(ServiceEndpoint.Development(), "development service")
            : new ServiceGateway(ServiceEndpoint.Production, "installed Sentinel service");

        var main = new MainViewModel(gateway, new WpfDialogs(), this);
        var window = new MainWindow { DataContext = main };
        MainWindow = window;
        window.Show();
        main.Dashboard.RefreshCommand.Execute(null);
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
