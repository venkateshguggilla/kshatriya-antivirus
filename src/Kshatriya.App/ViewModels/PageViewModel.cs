using System.Collections.ObjectModel;
using System.Globalization;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Core;
using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;
/// <summary>Dialogs the view models need; implemented with WPF dialogs in the app and with fakes in tests.</summary>
public interface IDialogs
{
    IReadOnlyList<string> PickFolders();

    string? PickRestoreLocation(string suggestedFileName);

    bool Confirm(string title, string message);

    /// <summary>Asks for a signed content update package (.kstu); null when cancelled.</summary>
    string? PickUpdatePackage();
}

/// <summary>Process-level actions: restart elevated, open Windows Security, open the browser extension folder.</summary>
public interface IAppHost
{
    bool IsElevated { get; }

    void RestartElevated();

    /// <summary>Opens the Windows Security app (read-only companion status; Kshatriya never changes it).</summary>
    void OpenWindowsSecurity();

    /// <summary>Opens the folder to load in the browser's "Load unpacked" dialog (ADR 0018).</summary>
    void OpenBrowserExtension();

    /// <summary>Shows a file in File Explorer (selects it in its folder). Nothing is opened or run.</summary>
    void ShowInFolder(string path);
}

/// <summary>The user's app preferences shown on the Settings page (and in the notification-area menu).</summary>
public interface IAppSettings
{
    bool Notifications { get; }

    bool ScanExternalDrives { get; }

    void SetNotifications(bool enabled);

    void SetScanExternalDrives(bool enabled);
}

/// <summary>Preferences kept in memory only (tests, and the separate scan windows that have no tray).</summary>
public sealed class InMemorySettings : IAppSettings
{
    public bool Notifications { get; private set; } = true;

    public bool ScanExternalDrives { get; private set; } = true;

    public void SetNotifications(bool enabled) => Notifications = enabled;

    public void SetScanExternalDrives(bool enabled) => ScanExternalDrives = enabled;
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

    private int _badgeCount;

    /// <summary>A count shown next to the page in the navigation (items waiting for the user); 0 hides it.</summary>
    public int BadgeCount
    {
        get => _badgeCount;
        protected set => Set(ref _badgeCount, value);
    }

    /// <summary>Shown inside another page (a History tab, Exclusions in Settings): its header is a section heading.</summary>
    public bool IsEmbedded { get; init; }

    private bool _hasActivity;

    /// <summary>Something is running on this page (a scan): the navigation shows a dot next to it.</summary>
    public bool HasActivity
    {
        get => _hasActivity;
        protected set => Set(ref _hasActivity, value);
    }

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
