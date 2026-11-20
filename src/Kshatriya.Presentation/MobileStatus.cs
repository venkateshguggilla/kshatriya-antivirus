namespace Kshatriya.Presentation;

/// <summary>Everything the Android status depends on (ADR 0021, sections 1 and 5).</summary>
public sealed record MobileStatusInputs
{
    /// <summary>Confirmed detections (an app or file matched a signature or a signing certificate), not kept.</summary>
    public int UnresolvedConfirmedFindings { get; init; }

    /// <summary>Suspicious findings (for example a package name alone), not kept.</summary>
    public int UnresolvedSuspiciousFindings { get; init; }

    /// <summary>Installed signed content update, 0 for built-in signatures only.</summary>
    public long ContentSequence { get; init; }

    public bool ContentExpired { get; init; }

    public DateTimeOffset? ContentExpiresUtc { get; init; }

    /// <summary>When installed apps were last all checked; null when never.</summary>
    public DateTimeOffset? LastAppScanUtc { get; init; }

    /// <summary>Whether Android lets Kshatriya post notifications (Android 13 and later ask).</summary>
    public bool NotificationsAllowed { get; init; } = true;

    public IReadOnlySet<string> Dismissed { get; init; } = new HashSet<string>();

    public required DateTimeOffset Now { get; init; }
}

/// <summary>Turns <see cref="MobileStatusInputs"/> into one <see cref="StatusSnapshot"/>. Pure, like the desktop evaluator.</summary>
public static class MobileStatusEvaluator
{
    public const string ConfirmedFindingsId = "findings.confirmed";
    public const string SuspiciousFindingsId = "findings.suspicious";
    public const string SignaturesExpiredId = "signatures.expired";
    public const string SignaturesExpiringId = "signatures.expiring";
    public const string NeverScannedId = "apps.never-scanned";
    public const string NotificationsOffId = "notifications.off";

    public static StatusSnapshot Evaluate(MobileStatusInputs inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        List<StatusItem> all = [.. Items(inputs)];
        List<StatusItem> active = [.. all.Where(i => !(i.Dismissible && inputs.Dismissed.Contains(i.Id)))];
        List<StatusItem> muted = [.. all.Except(active)];
        if (active.Count == 0)
        {
            return new StatusSnapshot(ProtectionLevel.Protected, "No threats found",
                "Kshatriya works alongside Google Play Protect. New and updated apps are checked about every 15 minutes.",
                StatusActions.ScanApps, [], muted);
        }

        ProtectionLevel level = active.Max(i => i.Level);
        StatusItem first = active[0];
        string headline = active.Count == 1
            ? first.Title
            : level == ProtectionLevel.ActionNeeded ? $"{active.Count} things need your attention" : $"{active.Count} things to review";
        return new StatusSnapshot(level, headline, active.Count == 1 ? first.Detail : "Start with the first item below.", first.ActionId, active, muted);
    }

    private static IEnumerable<StatusItem> Items(MobileStatusInputs i)
    {
        if (i.UnresolvedConfirmedFindings > 0)
        {
            int n = i.UnresolvedConfirmedFindings;
            yield return new StatusItem(ConfirmedFindingsId, StatusArea.Findings, ProtectionLevel.ActionNeeded,
                n == 1 ? "1 threat found" : $"{n} threats found",
                "Review it. Kshatriya never removes anything itself; Android's app page lets you uninstall an app.",
                StatusActions.ReviewFindings, Dismissible: false);
        }

        if (i.UnresolvedSuspiciousFindings > 0)
        {
            int n = i.UnresolvedSuspiciousFindings;
            yield return new StatusItem(SuspiciousFindingsId, StatusArea.Findings, ProtectionLevel.AttentionRecommended,
                n == 1 ? "1 item to review" : $"{n} items to review",
                "Weak evidence, such as a package name alone. Keep it if you installed it on purpose.",
                StatusActions.ReviewFindings, Dismissible: false);
        }

        if (i.LastAppScanUtc is null)
        {
            yield return new StatusItem(NeverScannedId, StatusArea.Scans, ProtectionLevel.AttentionRecommended,
                "Apps have not been checked yet",
                "Check your installed apps once; after that, new and updated apps are checked automatically.",
                StatusActions.ScanApps, Dismissible: false);
        }

        if (i.ContentExpired)
        {
            yield return new StatusItem(SignaturesExpiredId, StatusArea.Signatures, ProtectionLevel.AttentionRecommended,
                "Signatures have expired",
                "Check for updates, or import a newer signed update.",
                StatusActions.CheckUpdates, Dismissible: false);
        }
        else if (i.ContentSequence > 0 && i.ContentExpiresUtc is { } expires && expires - i.Now <= DesktopStatusEvaluator.ExpiryWarning)
        {
            int days = Math.Max(0, (int)Math.Ceiling((expires - i.Now).TotalDays));
            yield return new StatusItem(SignaturesExpiringId, StatusArea.Signatures, ProtectionLevel.AttentionRecommended,
                days <= 1 ? "Signatures expire within a day" : $"Signatures expire in {days} days",
                "Check for updates before then.",
                StatusActions.CheckUpdates, Dismissible: true);
        }

        if (!i.NotificationsAllowed)
        {
            yield return new StatusItem(NotificationsOffId, StatusArea.Findings, ProtectionLevel.AttentionRecommended,
                "Notifications are off",
                "You will not hear about risky new apps until you open Kshatriya. You can allow notifications in Android settings.",
                StatusActions.AllowNotifications, Dismissible: true);
        }
    }
}
