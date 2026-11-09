using System.Globalization;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;

namespace Kshatriya.App.Services;

/// <summary>What a desktop notification about new findings says.</summary>
public sealed record FindingNotice(string Title, string Message, bool IsThreat);

/// <summary>
/// Polls the service's recent findings and returns the ones that are new since the last poll and came from
/// background protection (real-time monitoring, behaviour alerts, scheduled scans). Scans the user started
/// themselves already show their results and are not repeated. The first successful poll only sets the
/// starting point, so findings from before the app started are not announced.
/// </summary>
public sealed class DetectionWatcher(IServiceGateway gateway)
{
    private const int MessageLimit = 240;
    private DateTimeOffset? _since;

    /// <summary>False after a poll could not reach the service.</summary>
    public bool ServiceReachable { get; private set; } = true;

    public async Task<IReadOnlyList<DetectionRecordDto>> PollAsync(CancellationToken cancellationToken)
    {
        DetectionsReplyDto reply;
        try
        {
            reply = await gateway.GetDetectionsAsync(200, cancellationToken);
            ServiceReachable = true;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException or ServiceException or ServiceAuthenticationException or ProtocolException)
        {
            ServiceReachable = false;
            return [];
        }

        var timed = reply.Items
            .Select(item => (Item: item, Time: ParseTime(item.TimeUtc)))
            .Where(x => x.Time is not null)
            .Select(x => (x.Item, Time: x.Time!.Value))
            .ToList();
        DateTimeOffset newest = timed.Count == 0 ? DateTimeOffset.MinValue : timed.Max(x => x.Time);
        if (_since is not DateTimeOffset since)
        {
            _since = newest;
            return [];
        }

        List<DetectionRecordDto> fresh = [.. timed.Where(x => x.Time > since && IsBackground(x.Item.Source)).OrderBy(x => x.Time).Select(x => x.Item)];
        if (newest > since)
        {
            _since = newest;
        }

        return fresh;
    }

    /// <summary>Findings from scans the user started are shown on screen already.</summary>
    public static bool IsBackground(string source) => !string.Equals(source, "scan", StringComparison.Ordinal);

    /// <summary>One notification for a batch of new findings.</summary>
    public static FindingNotice Describe(IReadOnlyList<DetectionRecordDto> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (findings.Count == 0)
        {
            throw new ArgumentException("At least one finding is needed.", nameof(findings));
        }

        bool threat = findings.Any(f => f.Status == "detected");
        DetectionRecordDto latest = findings[^1];
        if (findings.Count == 1)
        {
            string title = latest.Source == "behaviour" ? "Possible ransomware activity"
                : threat ? "Threat found" : "Suspicious file found";
            return new FindingNotice(title, Clip($"{FileName(latest.Path)}: {string.Join(", ", latest.Names)}. {ActionText(latest)}"), threat);
        }

        return new FindingNotice(
            $"{findings.Count} new findings",
            Clip($"Latest: {FileName(latest.Path)}: {string.Join(", ", latest.Names)}. Open Kshatriya Antivirus to review them."),
            threat);
    }

    private static string ActionText(DetectionRecordDto finding) => finding.Action switch
    {
        "reported" => "Reported only; nothing was changed.",
        var a when a.StartsWith("quarantined", StringComparison.Ordinal) => "Moved to quarantine; it can be restored.",
        var a when a.StartsWith("alert only", StringComparison.Ordinal) => "Alert only; no automatic action was taken.",
        var a => $"Action: {a}.",
    };

    private static string FileName(string path)
    {
        string name = Path.GetFileName(path.TrimEnd('\\'));
        return name.Length == 0 ? path : name;
    }

    private static string Clip(string text) => text.Length <= MessageLimit ? text : text[..(MessageLimit - 1)] + "…";

    private static DateTimeOffset? ParseTime(string value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset time) ? time : null;
}
