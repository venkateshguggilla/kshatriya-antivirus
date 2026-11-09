using System.Windows;
using System.Windows.Threading;

namespace Kshatriya.App.Tests;

/// <summary>
/// One STA thread with a running dispatcher that owns the single WPF <see cref="Application"/> of the test
/// process, with the app's resources merged as App.xaml declares them. UI tests run their work on it, so they
/// can share the application without cross-thread access.
/// </summary>
internal static class UiThread
{
    /// <summary>The dictionaries App.xaml merges, in the same order.</summary>
    public static readonly string[] AppResources =
    [
        "pack://application:,,,/PresentationFramework.Fluent;component/Themes/Fluent.xaml",
        "pack://application:,,,/Kshatriya.App;component/Views/Theme.xaml",
        "pack://application:,,,/Kshatriya.App;component/Views/Pages.xaml",
    ];

    private static readonly Lazy<Dispatcher> s_dispatcher = new(Start);

    /// <summary>Runs <paramref name="action"/> on the UI thread and rethrows its failure here.</summary>
    public static void Run(Action action)
    {
        ExceptionDispatchInfoHolder? failure = null;
        s_dispatcher.Value.Invoke(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = new ExceptionDispatchInfoHolder(ex);
            }
        });
        failure?.Throw();
    }

    private static Dispatcher Start()
    {
        Dispatcher? dispatcher = null;
        using var ready = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

            // A plain Application: App's own startup (single instance, tray icon) must not run in a test.
            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            foreach (string source in AppResources)
            {
                app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri(source) });
            }

            ready.Set();
            Dispatcher.Run();
        })
        {
            IsBackground = true,
            Name = "UI tests",
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Wait();
        return dispatcher!;
    }

    private sealed class ExceptionDispatchInfoHolder(Exception exception)
    {
        public void Throw() => System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception).Throw();
    }
}
