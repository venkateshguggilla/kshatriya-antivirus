using System.Windows;

namespace Kshatriya.App;

public partial class MainWindow : Window
{
    /// <summary>Below this width the navigation shows icons only and pages use tighter margins.</summary>
    public const double CompactWidth = 900;

    public static readonly DependencyProperty IsCompactProperty =
        DependencyProperty.Register(nameof(IsCompact), typeof(bool), typeof(MainWindow), new PropertyMetadata(false, OnCompactChanged));

    public MainWindow()
    {
        InitializeComponent();
        SizeChanged += (_, e) => IsCompact = e.NewSize.Width < CompactWidth;
    }

    /// <summary>True on narrow windows: icon-only navigation (titles stay available as tooltips and names).</summary>
    public bool IsCompact
    {
        get => (bool)GetValue(IsCompactProperty);
        set => SetValue(IsCompactProperty, value);
    }

    private static void OnCompactChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var window = (MainWindow)d;
        bool compact = (bool)e.NewValue;
        window.Nav.Width = compact ? 76 : (double)window.FindResource("NavWidth");
        window.Wordmark.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        window.Footnote.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        window.PageHost.Margin = (Thickness)window.FindResource(compact ? "PagePaddingCompact" : "PagePadding");
    }
}
