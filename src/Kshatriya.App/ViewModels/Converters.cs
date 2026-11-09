using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Kshatriya.App.ViewModels;

/// <summary>Value converters referenced from XAML.</summary>
public static class Converters
{
    public static IValueConverter NotEmptyToVisibility { get; } = new NotEmptyToVisibilityConverter();

    private sealed class NotEmptyToVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is string s && s.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
