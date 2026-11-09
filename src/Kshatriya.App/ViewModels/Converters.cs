using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace Kshatriya.App.ViewModels;

/// <summary>Value converters referenced from XAML.</summary>
public static class Converters
{
    public static IValueConverter NotEmptyToVisibility { get; } = new NotEmptyToVisibilityConverter();

    /// <summary>Visible when a count is zero: empty states.</summary>
    public static IValueConverter ZeroToVisible { get; } = new CountConverter(visibleWhenZero: true);

    /// <summary>Visible when a count is above zero: lists that have content.</summary>
    public static IValueConverter NonZeroToVisible { get; } = new CountConverter(visibleWhenZero: false);

    /// <summary>Collapsed when true.</summary>
    public static IValueConverter FalseToVisible { get; } = new FalseToVisibleConverter();

    /// <summary>Boolean negation (for example IsEnabled = not scanning).</summary>
    public static IValueConverter Not { get; } = new NotConverter();

    private sealed class NotConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
    }

    private sealed class CountConverter(bool visibleWhenZero) : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            (value is int count && count == 0) == visibleWhenZero ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    private sealed class FalseToVisibleConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is true ? Visibility.Collapsed : Visibility.Visible;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }

    private sealed class NotEmptyToVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is string s && s.Length > 0 ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotSupportedException();
    }
}
