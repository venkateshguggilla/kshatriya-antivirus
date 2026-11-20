namespace Kshatriya.Posture;

/// <summary>How a check came out. Ordered from good to bad; <see cref="Unknown"/> means it could not be read.</summary>
public enum PostureState
{
    Ok,
    Info,
    Attention,
    Risk,
    Unknown,
}

/// <summary>The groups shown in the Security check.</summary>
public enum PostureArea
{
    Defender,
    Installs,
    Usb,
    Network,
    Startup,
    Device,
}

/// <summary>
/// One check result (ADR 0022). <see cref="FixId"/> names a hardening fix that would resolve it, when there is
/// one; <see cref="FixApplied"/> is true when that fix was applied by Kshatriya and can be undone.
/// </summary>
public sealed record PostureCheck(
    string Id,
    PostureArea Area,
    PostureState State,
    string Title,
    string Detail,
    string? FixId = null,
    bool FixApplied = false);

/// <summary>Wire names for the public formats. Enum member names are never serialized directly.</summary>
public static class PostureWire
{
    public static string Of(PostureState state) => state switch
    {
        PostureState.Ok => "ok",
        PostureState.Info => "info",
        PostureState.Attention => "attention",
        PostureState.Risk => "risk",
        _ => "unknown",
    };

    public static string Of(PostureArea area) => area switch
    {
        PostureArea.Defender => "defender",
        PostureArea.Installs => "installs",
        PostureArea.Usb => "usb",
        PostureArea.Network => "network",
        PostureArea.Startup => "startup",
        _ => "device",
    };

    public static PostureState ParseState(string? value) => value switch
    {
        "ok" => PostureState.Ok,
        "info" => PostureState.Info,
        "attention" => PostureState.Attention,
        "risk" => PostureState.Risk,
        _ => PostureState.Unknown,
    };

    public static PostureArea ParseArea(string? value) => value switch
    {
        "defender" => PostureArea.Defender,
        "installs" => PostureArea.Installs,
        "usb" => PostureArea.Usb,
        "network" => PostureArea.Network,
        "startup" => PostureArea.Startup,
        _ => PostureArea.Device,
    };

    /// <summary>A heading for an area, for the apps and the CLI.</summary>
    public static string Heading(PostureArea area) => area switch
    {
        PostureArea.Defender => "Microsoft Defender",
        PostureArea.Installs => "App installs",
        PostureArea.Usb => "USB drives",
        PostureArea.Network => "Network",
        PostureArea.Startup => "Startup programs",
        _ => "Device",
    };
}

/// <summary>Helpers for summarising a set of results.</summary>
public static class PostureSummary
{
    /// <summary>The worst state among the results, ignoring <see cref="PostureState.Unknown"/>.</summary>
    public static PostureState Worst(IEnumerable<PostureCheck> checks)
    {
        PostureState worst = PostureState.Ok;
        foreach (PostureCheck check in checks)
        {
            if (check.State != PostureState.Unknown && check.State > worst)
            {
                worst = check.State;
            }
        }

        return worst;
    }

    /// <summary>Results that need the user: attention and risk, worst first, in a stable order.</summary>
    public static IReadOnlyList<PostureCheck> NeedingAttention(IEnumerable<PostureCheck> checks) =>
        [.. checks
            .Where(c => c.State is PostureState.Attention or PostureState.Risk)
            .OrderByDescending(c => c.State)
            .ThenBy(c => c.Area)
            .ThenBy(c => c.Id, StringComparer.Ordinal)];
}
