using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Kshatriya.App.ViewModels;

namespace Kshatriya.App.Tests;

/// <summary>Loads the real XAML on the UI thread and renders every page, so markup and binding errors fail tests.</summary>
public class XamlTests
{
    [Fact]
    public void Every_page_renders_with_its_template() => UiThread.Run(RenderAllPages);

    [Fact]
    public void A_narrow_window_switches_to_icon_navigation() => UiThread.Run(() =>
    {
        var window = new MainWindow { DataContext = new MainViewModel(new FakeGateway(), new FakeDialogs(), new FakeHost()), ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -20000, Width = 1180, Height = 700 };
        window.Show();
        try
        {
            Assert.False(window.IsCompact);
            window.Width = 700;
            window.UpdateLayout();
            Assert.True(window.IsCompact);
        }
        finally
        {
            window.Hide();
        }
    });

    private static void RenderAllPages()
    {
        var gateway = new FakeGateway();
        var main = new MainViewModel(gateway, new FakeDialogs(), new FakeHost());
        var window = new MainWindow { DataContext = main, ShowInTaskbar = false, WindowStartupLocation = WindowStartupLocation.Manual, Left = -10000 };
        window.Show();
        try
        {
            foreach (PageViewModel page in main.Pages)
            {
                main.Current = page;
                window.UpdateLayout();
                ContentPresenter presenter = FindPresenter(window)!;
                Assert.NotNull(presenter);
                Assert.True(VisualTreeHelper.GetChildrenCount(presenter) > 0, $"{page.Title} has no template.");
                Assert.IsNotType<TextBlock>(VisualTreeHelper.GetChild(presenter, 0));
            }
        }
        finally
        {
            // Hidden, not closed: closing the last window of a test Application would shut it down.
            window.Hide();
        }
    }

    private static ContentPresenter? FindPresenter(DependencyObject root)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, i);
            if (child is ContentPresenter { Content: PageViewModel } presenter && presenter.TemplatedParent is not ListBoxItem)
            {
                return presenter;
            }

            if (FindPresenter(child) is { } found)
            {
                return found;
            }
        }

        return null;
    }
}
