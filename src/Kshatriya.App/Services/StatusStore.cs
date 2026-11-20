using Kshatriya.Presentation;
using Kshatriya.Protocol;

namespace Kshatriya.App.Services;

/// <summary>
/// The one place the app asks the service how things are (ADR 0021, section 3): status, recent findings and
/// the quarantine list, fetched together. Home, the navigation badge, the notification-area icon and finding
/// notifications all read the same snapshot instead of polling on their own.
/// </summary>
public sealed class StatusStore(IServiceGateway gateway)
{
    private Task? _inFlight;

    public bool Connected { get; private set; }

    public HelloReplyDto? Hello { get; private set; }

    public StatusReplyDto? Status { get; private set; }

    public IReadOnlyList<DetectionRecordDto> Detections { get; private set; } = [];

    public IReadOnlyList<QuarantineItemDto> Vault { get; private set; } = [];

    /// <summary>Why the last refresh could not reach the service (null when it could).</summary>
    public Exception? Error { get; private set; }

    /// <summary>Raised after each refresh, connected or not.</summary>
    public event Action<StatusStore>? Refreshed;

    /// <summary>Fetches everything once. Concurrent callers share the refresh that is already running.</summary>
    public Task RefreshAsync()
    {
        if (_inFlight is { IsCompleted: false } running)
        {
            return running;
        }

        _inFlight = RefreshCoreAsync();
        return _inFlight;
    }

    private async Task RefreshCoreAsync()
    {
        try
        {
            (Hello, Status) = await gateway.GetStatusAsync(CancellationToken.None);
            Connected = true;
            Error = null;
            try
            {
                Detections = (await gateway.GetDetectionsAsync(500, CancellationToken.None)).Items;
                Vault = (await gateway.ListQuarantineAsync(CancellationToken.None)).Items;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Status is known; findings are not this time. Keep the last lists rather than showing none.
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Connected = false;
            Error = ex;
        }
        finally
        {
            Refreshed?.Invoke(this);
        }
    }
}

/// <summary>A critical notification caused by a change of state between two refreshes.</summary>
public sealed record StatusAlert(NotificationCategory Category, string Title, string Message);

/// <summary>Turns state changes into critical alerts: the service stopping, the audit log failing its check.</summary>
public sealed class StatusAlerts
{
    private bool? _connected;
    private bool? _auditValid;

    /// <summary>Compares with the previous refresh. The first refresh only sets the starting point.</summary>
    public IReadOnlyList<StatusAlert> Observe(bool connected, bool? auditValid, bool starting, bool exiting)
    {
        var alerts = new List<StatusAlert>();
        if (_connected == true && !connected && !starting && !exiting)
        {
            alerts.Add(new StatusAlert(NotificationCategory.ServiceStopped,
                "Kshatriya service stopped",
                "Scans and real-time monitoring are paused until it runs again. Microsoft Defender keeps protecting you."));
        }

        if (_auditValid == true && auditValid == false)
        {
            alerts.Add(new StatusAlert(NotificationCategory.AuditFailure,
                "Audit log check failed",
                "The actions log may have been edited. Open History to review it."));
        }

        _connected = connected;
        if (auditValid is not null)
        {
            _auditValid = auditValid;
        }

        return alerts;
    }
}
