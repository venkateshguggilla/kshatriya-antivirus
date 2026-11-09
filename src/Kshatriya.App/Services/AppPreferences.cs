using System.Text.Json;

namespace Kshatriya.App.Services;

/// <summary>Per-user app preferences, kept in %LocalAppData%\Kshatriya\app-settings.json.</summary>
public sealed class AppPreferences
{
    private readonly string _path;

    public AppPreferences(string? path = null)
    {
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Kshatriya", "app-settings.json");
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(_path));
            Notifications = Read(document, "notifications", Notifications);
            ScanExternalDrives = Read(document, "scanExternalDrives", ScanExternalDrives);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // Missing or unreadable: defaults (both on).
        }
    }

    /// <summary>Show desktop notifications for new background findings (default on).</summary>
    public bool Notifications { get; private set; } = true;

    /// <summary>Scan USB drives, external disks and memory cards as soon as they are connected (default on).</summary>
    public bool ScanExternalDrives { get; private set; } = true;

    public void SetNotifications(bool enabled)
    {
        Notifications = enabled;
        Save();
    }

    public void SetScanExternalDrives(bool enabled)
    {
        ScanExternalDrives = enabled;
        Save();
    }

    private static bool Read(JsonDocument document, string name, bool fallback) =>
        document.RootElement.ValueKind == JsonValueKind.Object && document.RootElement.TryGetProperty(name, out JsonElement value)
            ? value.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => fallback }
            : fallback;

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(new Dictionary<string, bool>
            {
                ["notifications"] = Notifications,
                ["scanExternalDrives"] = ScanExternalDrives,
            }));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Not persisted; the choice still applies until the app exits.
        }
    }
}
