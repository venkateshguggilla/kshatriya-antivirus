using System.Collections.ObjectModel;
using Kshatriya.App.Infrastructure;
using Kshatriya.App.Services;
using Kshatriya.Protocol;

namespace Kshatriya.App.ViewModels;

/// <summary>One protection layer: what it does, its state and how that state reads.</summary>
public sealed record ProtectionRow(string Glyph, string Label, string Detail, string State, Tone Tone);

/// <summary>
/// What runs in the background (ADR 0021): Kshatriya's layers as the service reports them, and Windows
/// Security's state, which Kshatriya only reads and never changes (ADR 0002).
/// </summary>
public sealed class ProtectionViewModel(IServiceGateway gateway, IAppHost host)
    : PageViewModel("Protection", "What runs in the background. Changes that weaken protection need an administrator and are written to the audit log.", Glyphs.Shield)
{
    /// <summary>Where an administrator changes real-time monitoring and schedules (ADR 0005).</summary>
    public const string SettingsFile = @"%ProgramData%\Kshatriya\config\service.json";

    public ObservableCollection<ProtectionRow> Layers { get; } = [];

    public ObservableCollection<ProtectionRow> Windows { get; } = [];

    public string ChangeHint { get; } =
        $"Real-time monitoring and scheduled scans are set in {SettingsFile}, which only administrators can change.";

    public Func<AntivirusHealth> AntivirusSource { get; set; } = SecurityCenter.GetAntivirusHealth;

    public Func<int?> FolderAccessSource { get; set; } = SecurityCenter.GetControlledFolderAccess;

    public RelayCommand OpenWindowsSecurityCommand => new(_ => host.OpenWindowsSecurity());

    public RelayCommand SetUpBrowserExtensionCommand => new(_ => host.OpenBrowserExtension());

    protected override async Task RefreshCoreAsync()
    {
        // Windows Security Center and WMI can take a moment: read them off the UI thread.
        AntivirusHealth antivirus = await Task.Run(AntivirusSource);
        int? folderAccess = await Task.Run(FolderAccessSource);
        Windows.Clear();
        Windows.Add(new ProtectionRow(Glyphs.Shield, "Windows antivirus",
            $"{SecurityCenter.Describe(antivirus)} Kshatriya adds to it and does not replace it.",
            antivirus switch { AntivirusHealth.Good => "On", AntivirusHealth.Unknown => "Unknown", _ => "Needs attention" },
            antivirus switch { AntivirusHealth.Good => Tone.Success, AntivirusHealth.Unknown => Tone.Neutral, _ => Tone.Critical }));
        Windows.Add(new ProtectionRow(Glyphs.Folder, "Controlled folder access",
            SecurityCenter.DescribeControlledFolderAccess(folderAccess),
            folderAccess switch { 1 => "On", 2 => "Audit", null => "Unknown", _ => "Off" },
            folderAccess == 1 ? Tone.Success : Tone.Neutral));

        try
        {
            var (_, status) = await gateway.GetStatusAsync(CancellationToken.None);
            BuildLayers(status);
            ShowInfo(null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Layers.Clear();
            ShowError(ex);
        }
    }

    private void BuildLayers(StatusReplyDto status)
    {
        RealTimeStatusDto rt = status.RealTime;
        Layers.Clear();
        Layers.Add(new ProtectionRow(Glyphs.Processing, "Real-time file monitoring",
            rt.Enabled
                ? $"{string.Join(", ", rt.Paths)}: scans new and changed files soon after they are written. It cannot block a file before it opens."
                : "New files are scanned only when you run a scan.",
            rt.Enabled ? "On" : "Off", rt.Enabled ? Tone.Success : Tone.Caution));
        Layers.Add(Layer(Glyphs.Search, "Programs as they start", "Checks each started program's file. Never stops a running program.", rt.Enabled ? rt.Processes : "off"));
        Layers.Add(Layer(Glyphs.Usb, "External drives", "USB sticks, USB disks and memory cards are scanned when connected.", rt.Enabled ? rt.RemovableMedia : "off"));
        Layers.Add(Layer(Glyphs.Warning, "Ransomware behaviour", "Warns about mass file changes (suspicious only, never an automatic action). Decoy files are opt-in.", rt.Enabled ? rt.Behaviour : "off"));
        Layers.Add(Layer(Glyphs.Sync, "Network protection", "Blocks connections to listed addresses.", status.Network.State));
        Layers.Add(new ProtectionRow(Glyphs.Calendar, "Scheduled scans",
            status.Schedules.Count == 0
                ? "None configured."
                : string.Join("; ", status.Schedules.Select(s => $"{s.Name}: next {HomeViewModel.Local(s.NextRunUtc)}" + (s.LastRunUtc is null ? ", never run" : $", last {HomeViewModel.Local(s.LastRunUtc)} ({s.LastOutcome})"))),
            status.Schedules.Count == 0 ? "None" : $"{status.Schedules.Count} active",
            status.Schedules.Count == 0 ? Tone.Neutral : Tone.Success));
    }

    /// <summary>A layer whose service state is a word like "off", "on", "unavailable: …" or a description.</summary>
    internal static ProtectionRow Layer(string glyph, string label, string detail, string serviceState)
    {
        string s = serviceState.Trim();
        if (s.Length == 0 || s.Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            return new ProtectionRow(glyph, label, detail, "Off", Tone.Neutral);
        }

        if (s.StartsWith("unavailable", StringComparison.OrdinalIgnoreCase))
        {
            return new ProtectionRow(glyph, label, $"{detail} {Capitalize(s)}.", "Unavailable", Tone.Caution);
        }

        return new ProtectionRow(glyph, label, s.Equals("on", StringComparison.OrdinalIgnoreCase) ? detail : $"{detail} State: {s}.", "On", Tone.Success);
    }

    private static string Capitalize(string s) => char.ToUpperInvariant(s[0]) + s[1..];
}
