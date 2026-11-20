using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Kshatriya.App;

/// <summary>
/// A small password prompt (ADR 0023): one box, or two when choosing a new password. Built in code so it
/// takes the app's Fluent theme. The password is returned to the caller and never stored by the app.
/// </summary>
internal sealed class PasswordDialog : Window
{
    private readonly PasswordBox _first = new() { MaxLength = 256, Margin = new Thickness(0, 12, 0, 0) };
    private readonly PasswordBox? _second;
    private readonly TextBlock _problem = new() { Foreground = SystemColors.HotTrackBrush, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), Visibility = Visibility.Collapsed };
    private readonly bool _confirm;

    private PasswordDialog(string title, string message, bool confirm)
    {
        _confirm = confirm;
        Title = title;
        Width = 420;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        AutomationLabel(_first, confirm ? "New password" : "Password");
        panel.Children.Add(_first);
        if (confirm)
        {
            _second = new PasswordBox { MaxLength = 256, Margin = new Thickness(0, 8, 0, 0) };
            AutomationLabel(_second, "Type the password again");
            panel.Children.Add(new TextBlock { Text = "Type it again", Margin = new Thickness(0, 8, 0, 0) });
            panel.Children.Add(_second);
        }

        panel.Children.Add(_problem);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        var ok = new Button { Content = "OK", IsDefault = true, MinWidth = 90 };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90, Margin = new Thickness(8, 0, 0, 0) };
        ok.Click += (_, _) => Accept();
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) => Keyboard.Focus(_first);
    }

    /// <summary>The password, or null when cancelled.</summary>
    public string? Password { get; private set; }

    /// <summary>Shows the dialog; without a visible owner it is centred on screen and kept on top (USB unlock).</summary>
    public static string? Ask(Window? owner, string title, string message, bool confirm)
    {
        var dialog = new PasswordDialog(title, message, confirm);
        if (owner is { IsVisible: true })
        {
            dialog.Owner = owner;
        }
        else
        {
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            dialog.Topmost = true;
        }

        return dialog.ShowDialog() == true ? dialog.Password : null;
    }

    private void Accept()
    {
        string first = _first.Password;
        if (first.Length == 0)
        {
            ShowProblem("Enter the password.");
            return;
        }

        if (_confirm)
        {
            if (first.Length < 8)
            {
                ShowProblem("Use at least 8 characters.");
                return;
            }

            if (first != _second!.Password)
            {
                ShowProblem("The two passwords are different.");
                return;
            }
        }

        Password = first;
        DialogResult = true;
    }

    private void ShowProblem(string problem)
    {
        _problem.Text = problem;
        _problem.Visibility = Visibility.Visible;
    }

    private static void AutomationLabel(PasswordBox box, string name) =>
        System.Windows.Automation.AutomationProperties.SetName(box, name);
}
