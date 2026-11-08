using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Tests;

/// <summary>Loads the real XAML on an STA thread and renders every page, so markup and binding errors fail tests.</summary>
public class XamlTests
{
    [Fact]
    public void Every_page_renders_with_its_template()
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                RenderAllPages();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.Null(failure);
    }

    private static void RenderAllPages()
    {
        var app = Application.Current ?? new App();
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("pack://application:,,,/PresentationFramework.Fluent;component/Themes/Fluent.xaml") });
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("pack://application:,,,/Sentinel.App;component/Views/Pages.xaml") });

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
            window.Close();
        }
    }

    private static ContentPresenter? FindPresenter(DependencyObject root)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(root, i);
            if (child is ContentPresenter { Content: PageViewModel } presenter)
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
