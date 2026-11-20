namespace Kshatriya.Presentation;

/// <summary>Windows antivirus health as the desktop app reads it from Windows Security Center (read-only).</summary>
public enum WindowsAntivirusState
{
    /// <summary>On and up to date.</summary>
    Good,

    /// <summary>Off, snoozed, not monitored or out of date.</summary>
    NeedsAttention,

    /// <summary>Could not be read; says nothing either way.</summary>
    Unknown,
}

/// <summary>Everything the desktop status depends on, gathered by the app (ADR 0021, section 1).</summary>
public sealed record DesktopStatusInputs
{
    /// <summary>Whether the service answered.</summary>
    public required bool ServiceReachable { get; init; }

    /// <summary>The service is unreachable but probably still in its delayed start.</summary>
    public bool ServiceStarting { get; init; }

    /// <summary>"installed service" or "development service", for the not-running wording.</summary>
    public string ServiceDescription { get; init; } = "Kshatriya service";

    public WindowsAntivirusState WindowsAntivirus { get; init; } = WindowsAntivirusState.Unknown;

    public bool RealTimeEnabled { get; init; }

    public bool AuditChainValid { get; init; } = true;

    /// <summary>Installed signed content update, 0 for built-in signatures only.</summary>
    public long ContentSequence { get; init; }

    public bool ContentExpired { get; init; }

    public DateTimeOffset? ContentExpiresUtc { get; init; }

    /// <summary>Confirmed detections (malware, PUA, test) that are neither quarantined nor kept by the user.</summary>
    public int UnresolvedConfirmedFindings { get; init; }

    /// <summary>Suspicious (heuristic) findings that the user has not reviewed.</summary>
    public int UnresolvedSuspiciousFindings { get; init; }

    /// <summary>Items the last user scan could not read for lack of rights.</summary>
    public int LastScanAccessDenied { get; init; }

    /// <summary>Ids of items the user dismissed.</summary>
    public IReadOnlySet<string> Dismissed { get; init; } = new HashSet<string>();

    public required DateTimeOffset Now { get; init; }
}

/// <summary>
/// Turns <see cref="DesktopStatusInputs"/> into one <see cref="StatusSnapshot"/>. Pure: the same inputs
/// always give the same snapshot. The rules are the table in ADR 0021, section 1.
/// </summary>
public static class DesktopStatusEvaluator
{
    /// <summary>Signatures expiring within this many days are worth a (dismissible) reminder.</summary>
    public static readonly TimeSpan ExpiryWarning = TimeSpan.FromDays(7);

    public const string ConfirmedFindingsId = "findings.confirmed";
    public const string SuspiciousFindingsId = "findings.suspicious";
    public const string WindowsAntivirusId = "windows-antivirus";
    public const string AuditLogId = "audit-log";
    public const string SignaturesExpiredId = "signatures.expired";
    public const string SignaturesExpiringId = "signatures.expiring";
    public const string RealTimeOffId = "real-time.off";
    public const string AccessDeniedId = "scan.access-denied";

    public static StatusSnapshot Evaluate(DesktopStatusInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        if (!inputs.ServiceReachable)
        {
            return NotRunning(inputs);
        }

        List<StatusItem> all = [.. Items(inputs)];
        List<StatusItem> active = [.. all.Where(i => !(i.Dismissible && inputs.Dismissed.Contains(i.Id)))];
        List<StatusItem> muted = [.. all.Except(active)];
        if (active.Count == 0)
        {
            string companion = inputs.WindowsAntivirus == WindowsAntivirusState.Good ? "Microsoft Defender" : "your antivirus";
            string detail = $"Kshatriya is running alongside {companion}." + (inputs.RealTimeEnabled ? " Real-time monitoring is on." : string.Empty);
            return new StatusSnapshot(ProtectionLevel.Protected, "All checks passed", detail, StatusActions.QuickScan, [], muted);
        }

        ProtectionLevel level = active.Max(i => i.Level);
        StatusItem first = active[0];
        string headline = active.Count == 1
            ? first.Title
            : level == ProtectionLevel.ActionNeeded ? $"{active.Count} problems need your action" : $"{active.Count} things to review";
        string text = active.Count == 1
            ? first.Detail
            : level == ProtectionLevel.ActionNeeded
                ? "Start with the first item below. Microsoft Defender keeps protecting you meanwhile."
                : "Protection is running. The items below explain what to do.";
        return new StatusSnapshot(level, headline, text, first.ActionId, active, muted);
    }

    // Most serious first; within a level, in the order of the ADR table.
    private static IEnumerable<StatusItem> Items(DesktopStatusInputs i)
    {
        if (i.UnresolvedConfirmedFindings > 0)
        {
            int n = i.UnresolvedConfirmedFindings;
            yield return new StatusItem(ConfirmedFindingsId, StatusArea.Findings, ProtectionLevel.ActionNeeded,
                n == 1 ? "1 threat needs your decision" : $"{n} threats need your decision",
                "A detected file has not been quarantined. Review it and quarantine it if you did not expect it.",
                StatusActions.ReviewFindings, Dismissible: false);
        }

        if (!i.AuditChainValid)
        {
            yield return new StatusItem(AuditLogId, StatusArea.AuditLog, ProtectionLevel.ActionNeeded,
                "The audit log may have been tampered with",
                "Its integrity check failed. Review the History page.",
                StatusActions.OpenHistory, Dismissible: false);
        }

        if (i.WindowsAntivirus == WindowsAntivirusState.NeedsAttention)
        {
            yield return new StatusItem(WindowsAntivirusId, StatusArea.WindowsAntivirus, ProtectionLevel.ActionNeeded,
                "Windows antivirus is off or out of date",
                "Kshatriya adds to Microsoft Defender and does not replace it. Turn it back on in Windows Security.",
                StatusActions.OpenWindowsSecurity, Dismissible: false);
        }

        if (i.UnresolvedSuspiciousFindings > 0)
        {
            int n = i.UnresolvedSuspiciousFindings;
            yield return new StatusItem(SuspiciousFindingsId, StatusArea.Findings, ProtectionLevel.AttentionRecommended,
                n == 1 ? "1 suspicious item to review" : $"{n} suspicious items to review",
                "Flagged by a heuristic, not a confirmed detection. Kshatriya never acts on these by itself.",
                StatusActions.ReviewFindings, Dismissible: false);
        }

        if (i.ContentExpired)
        {
            yield return new StatusItem(SignaturesExpiredId, StatusArea.Signatures, ProtectionLevel.AttentionRecommended,
                "Signatures have expired",
                "Install a newer signed update so new threats are recognised.",
                StatusActions.CheckUpdates, Dismissible: false);
        }
        else if (i.ContentSequence > 0 && i.ContentExpiresUtc is { } expires && expires - i.Now <= ExpiryWarning)
        {
            int days = Math.Max(0, (int)Math.Ceiling((expires - i.Now).TotalDays));
            yield return new StatusItem(SignaturesExpiringId, StatusArea.Signatures, ProtectionLevel.AttentionRecommended,
                days <= 1 ? "Signatures expire within a day" : $"Signatures expire in {days} days",
                $"Update {i.ContentSequence} is valid until {expires.ToLocalTime():d}. Install a newer signed update before then.",
                StatusActions.CheckUpdates, Dismissible: true);
        }

        if (!i.RealTimeEnabled)
        {
            yield return new StatusItem(RealTimeOffId, StatusArea.RealTime, ProtectionLevel.AttentionRecommended,
                "Real-time monitoring is off",
                "New files are scanned only when you run a scan. An administrator can turn it on in the service settings.",
                StatusActions.ProtectionSettings, Dismissible: true);
        }

        if (i.LastScanAccessDenied > 0)
        {
            int n = i.LastScanAccessDenied;
            yield return new StatusItem(AccessDeniedId, StatusArea.Scans, ProtectionLevel.AttentionRecommended,
                n == 1 ? "1 file could not be scanned" : $"{n} files could not be scanned",
                "Your account is not allowed to read them. Restart Kshatriya as administrator and scan again to include them.",
                StatusActions.RestartElevated, Dismissible: true);
        }
    }

    private static StatusSnapshot NotRunning(DesktopStatusInputs i) => i.ServiceStarting
        ? new StatusSnapshot(ProtectionLevel.NotRunning, "Kshatriya is starting",
            "The service starts a minute or two after Windows does. This page updates by itself when it is ready; Microsoft Defender keeps protecting you meanwhile.",
            null, [], [])
        : new StatusSnapshot(ProtectionLevel.NotRunning, "Kshatriya is not running",
            $"The {i.ServiceDescription} is not reachable. Scans and real-time monitoring need it; Microsoft Defender keeps protecting you. This page checks again every few seconds.",
            null, [], []);
}
