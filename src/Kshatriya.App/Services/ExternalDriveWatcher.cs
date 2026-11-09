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
    /// What to tell the user about a newly attached drive. When real-time protection scans new external
    /// drives itself, the notification says so; otherwise it offers a scan.
    /// </summary>
    public static FindingNotice Describe(DriveDescription drive, bool scannedAutomatically)
    {
        ArgumentNullException.ThrowIfNull(drive);
        return scannedAutomatically
            ? new FindingNotice("External drive connected", $"{drive.Label}. Kshatriya Antivirus is scanning it now and will tell you if it finds anything.", IsThreat: false)
            : new FindingNotice("External drive connected", $"{drive.Label}. Click here to scan it with Kshatriya Antivirus.", IsThreat: false);
    }
}
