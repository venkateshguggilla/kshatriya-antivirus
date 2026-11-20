namespace Kshatriya.Presentation;

/// <summary>
/// The overall answer to "am I protected?" (ADR 0021). Every level is shown with its own icon shape
/// and text, never by colour alone.
/// </summary>
public enum ProtectionLevel
{
    /// <summary>Status not known yet (the first check is running).</summary>
    Checking,

    /// <summary>Nothing needs the user.</summary>
    Protected,

    /// <summary>Something is worth the user's attention, but protection is running.</summary>
    AttentionRecommended,

    /// <summary>Something needs the user's action now.</summary>
    ActionNeeded,

    /// <summary>Kshatriya itself is not running (or is still starting).</summary>
    NotRunning,
}

/// <summary>What a status item is about.</summary>
public enum StatusArea
{
    Service,
    Findings,
    WindowsAntivirus,
    AuditLog,
    Signatures,
    RealTime,
    Scans,
}

/// <summary>
/// Wire-stable identifiers of the actions a status item can offer. Each app maps them to a command;
/// an app that cannot perform an action simply shows the item without a button.
/// </summary>
public static class StatusActions
{
    public const string QuickScan = "quick-scan";
    public const string ReviewFindings = "review-findings";
    public const string OpenHistory = "open-history";
    public const string CheckUpdates = "check-updates";
    public const string OpenWindowsSecurity = "open-windows-security";
    public const string ProtectionSettings = "protection-settings";
    public const string RestartElevated = "restart-elevated";
}

/// <summary>One cause behind the overall level, in plain language, with at most one action.</summary>
/// <param name="Id">Stable id, used to remember that the user dismissed the item.</param>
/// <param name="Area">What the item is about.</param>
/// <param name="Level">How serious it is (<see cref="ProtectionLevel.AttentionRecommended"/> or <see cref="ProtectionLevel.ActionNeeded"/>).</param>
/// <param name="Title">One line, for example "Signatures have expired".</param>
/// <param name="Detail">What it means and what to do.</param>
/// <param name="ActionId">One of <see cref="StatusActions"/>, or null.</param>
/// <param name="Dismissible">Whether the user may mute it. Dismissing never hides the fact, only stops it counting.</param>
public sealed record StatusItem(string Id, StatusArea Area, ProtectionLevel Level, string Title, string Detail, string? ActionId, bool Dismissible);

/// <summary>The evaluated status: one level and headline, the active items (most serious first) and muted ones.</summary>
public sealed record StatusSnapshot(
    ProtectionLevel Level,
    string Headline,
    string Detail,
    string? PrimaryActionId,
    IReadOnlyList<StatusItem> Items,
    IReadOnlyList<StatusItem> Muted)
{
    /// <summary>Shown before the first check completes.</summary>
    public static StatusSnapshot Checking { get; } =
        new(ProtectionLevel.Checking, "Checking protection…", string.Empty, null, [], []);
}
