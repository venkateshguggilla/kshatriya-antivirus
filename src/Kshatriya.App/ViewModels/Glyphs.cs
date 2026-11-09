namespace Kshatriya.App.ViewModels;

/// <summary>
/// Icon glyphs shared by Segoe Fluent Icons (Windows 11) and Segoe MDL2 Assets (Windows 10), so the same code
/// points render on both. Icons always accompany text or carry an accessible name; they never carry meaning alone.
/// </summary>
public static class Glyphs
{
    public const string Home = "";
    public const string Search = "";
    public const string Warning = "";
    public const string Lock = "";
    public const string Filter = "";
    public const string History = "";
    public const string Info = "";
    public const string Shield = "";
    public const string Completed = "";
    public const string Error = "";
    public const string Drive = "";
    public const string Usb = "";
    public const string Folder = "";
    public const string Sync = "";
    public const string Calendar = "";
    public const string Document = "";
    public const string Processing = "";
}

/// <summary>Meaning of a status, mapped to the theme's success, caution and critical colours in XAML.</summary>
public enum Tone
{
    Neutral,
    Success,
    Caution,
    Critical,
}
