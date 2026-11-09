using Kshatriya.Scanning.Targets;

namespace Kshatriya.App.Services;

/// <summary>
/// Notices external drives (USB drives and disks, memory cards) that were plugged in since the last check.
/// The first check only records what is already connected.
/// </summary>
public sealed class ExternalDriveWatcher
{
    private HashSet<string>? _known;

    /// <summary>The external drives in <paramref name="current"/> that were not connected at the last check.</summary>
    public IReadOnlyList<DriveDescription> Update(IReadOnlyList<DriveDescription> current)
    {
        ArgumentNullException.ThrowIfNull(current);
        var external = current.Where(d => d.IsExternal).ToList();
        var roots = external.Select(d => d.Root).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (_known is null)
        {
            _known = roots;
            return [];
        }

        List<DriveDescription> attached = [.. external.Where(d => !_known.Contains(d.Root))];
        _known = roots; // a drive that is removed and plugged in again is announced again
        return attached;
    }

    /// <summary>
    /// What to tell the user about a newly attached drive: real-time protection is scanning it, the app is
    /// scanning it now (the result follows in another notification), or a scan is offered.
    /// </summary>
    public static FindingNotice Describe(DriveDescription drive, ConnectAction action)
    {
        ArgumentNullException.ThrowIfNull(drive);
        return action switch
        {
            ConnectAction.ServiceScans => new FindingNotice("External drive connected", $"{drive.Label}. Real-time protection is scanning it and will tell you if it finds anything.", IsThreat: false),
            ConnectAction.AppScans => new FindingNotice("Scanning external drive", $"{drive.Label}. You will be told the result when the scan finishes.", IsThreat: false),
            _ => new FindingNotice("External drive connected", $"{drive.Label}. Click here to scan it with Kshatriya Antivirus.", IsThreat: false),
        };
    }
}

/// <summary>What happens when an external drive is connected.</summary>
public enum ConnectAction
{
    /// <summary>Real-time protection in the service scans new external drives.</summary>
    ServiceScans,

    /// <summary>The app scans it now ("Scan USB drives when connected" is on).</summary>
    AppScans,

    /// <summary>Automatic scanning is off: offer a scan.</summary>
    Offer,
}
