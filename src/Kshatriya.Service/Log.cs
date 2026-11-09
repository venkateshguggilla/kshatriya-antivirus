using Microsoft.Extensions.Logging;

namespace Kshatriya.Service;

/// <summary>
/// Every service log and audit event, source-generated. Event IDs are stable so that event-log
/// filters and monitoring rules keep working across versions.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(1000, LogLevel.Information, "Kshatriya service {Version} started ({Mode}); engines: {Engines}.")]
    public static partial void Started(ILogger logger, string version, string mode, string engines);

    [LoggerMessage(1001, LogLevel.Warning, "{Warning}")]
    public static partial void EngineWarning(ILogger logger, string warning);

    [LoggerMessage(1002, LogLevel.Information, "No settings file at {File}; using defaults.")]
    public static partial void DefaultSettings(ILogger logger, string file);

    [LoggerMessage(1003, LogLevel.Critical, "Kshatriya service failed to start: {Reason}")]
    public static partial void StartFailed(ILogger logger, Exception exception, string reason);

    [LoggerMessage(2000, LogLevel.Information, "Client connected: {User} (pid {Pid}, administrator {IsAdmin}, client '{Client}').")]
    public static partial void ClientConnected(ILogger logger, string user, uint pid, bool isAdmin, string client);

    [LoggerMessage(2001, LogLevel.Information, "Client connection ended: {Reason}")]
    public static partial void ConnectionEnded(ILogger logger, string reason);

    [LoggerMessage(2002, LogLevel.Error, "Unexpected error while serving a client.")]
    public static partial void ClientError(ILogger logger, Exception exception);

    [LoggerMessage(2003, LogLevel.Information, "Client sent message 0x{Type:X2} during a scan; the scan was cancelled.")]
    public static partial void UnexpectedDuringScan(ILogger logger, byte type);

    [LoggerMessage(3000, LogLevel.Information, "Scan requested by {User}: {Count} path(s).")]
    public static partial void ScanRequested(ILogger logger, string user, int count);

    [LoggerMessage(3001, LogLevel.Information, "Scan for {User} finished: {Files} file(s), {Detected} detected, {Suspicious} suspicious, {NotScanned} not scanned.")]
    public static partial void ScanFinished(ILogger logger, string user, long files, long detected, long suspicious, long notScanned);

    [LoggerMessage(3002, LogLevel.Information, "Scan for {User} was cancelled.")]
    public static partial void ScanCancelled(ILogger logger, string user);

    [LoggerMessage(3003, LogLevel.Warning, "{Status} in {Path} (requested by {Requester}): {Names}. Action: {Action}.")]
    public static partial void Finding(ILogger logger, string status, string path, string requester, string names, string action);

    [LoggerMessage(4000, LogLevel.Information, "Scheduled scan '{Name}' starting ({Count} path(s)).")]
    public static partial void ScheduleStarting(ILogger logger, string name, int count);

    [LoggerMessage(4001, LogLevel.Information, "Scheduled scan '{Name}' finished: {Outcome}. Report: {File}")]
    public static partial void ScheduleFinished(ILogger logger, string name, string outcome, string file);

    [LoggerMessage(4002, LogLevel.Warning, "Scheduled scan '{Name}' postponed: the service is busy.")]
    public static partial void SchedulePostponed(ILogger logger, string name);

    [LoggerMessage(4003, LogLevel.Error, "Scheduled scan '{Name}' failed.")]
    public static partial void ScheduleFailed(ILogger logger, Exception exception, string name);

    [LoggerMessage(5000, LogLevel.Warning, "{User} quarantined {Path} (id {Id}).")]
    public static partial void Quarantined(ILogger logger, string user, string path, string id);

    [LoggerMessage(5001, LogLevel.Warning, "Quarantine of {Path} for {User} failed: {Failure}. The file was left in place.")]
    public static partial void QuarantineFailed(ILogger logger, string path, string user, string failure);

    [LoggerMessage(5002, LogLevel.Warning, "{User} restored quarantined item {Id} to {Path}: {Outcome}.")]
    public static partial void Restored(ILogger logger, string user, string id, string path, string outcome);

    [LoggerMessage(5003, LogLevel.Information, "{User} deleted quarantined item {Id}: {Deleted}.")]
    public static partial void QuarantineDeleted(ILogger logger, string user, string id, bool deleted);

    [LoggerMessage(5004, LogLevel.Warning, "Denied {Action} for {User}: {Reason}")]
    public static partial void Denied(ILogger logger, string action, string user, string reason);

    [LoggerMessage(7000, LogLevel.Warning, "{Problem}")]
    public static partial void RealTimeProblem(ILogger logger, string problem);

    [LoggerMessage(8000, LogLevel.Critical, "Possible ransomware activity ({Name}) at {Path}: {Detail} No automatic action was taken.")]
    public static partial void BehaviourAlert(ILogger logger, string name, string path, string detail);

    [LoggerMessage(7001, LogLevel.Information, "Removable drive {Drive} attached; scanning it.")]
    public static partial void RemovableDrive(ILogger logger, string drive);

    [LoggerMessage(7002, LogLevel.Warning, "Real-time protection has been scanning {Folders} in full for {Seconds:F0} s ({Items} item(s) so far). New files and started programs are still scanned meanwhile.")]
    public static partial void RealTimeLongFolderScan(ILogger logger, string folders, double seconds, long items);

    [LoggerMessage(7003, LogLevel.Warning, "Real-time scan of {Paths} file event(s) took {Seconds:F0} s ({Files} file(s) scanned).")]
    public static partial void RealTimeSlowBatch(ILogger logger, double seconds, long files, int paths);

    [LoggerMessage(6000, LogLevel.Information,"Content package {Sequence} (channel {Channel}, key {KeyId}) is now active.")]
    public static partial void ContentActivated(ILogger logger, long sequence, string channel, string keyId);

    [LoggerMessage(6001, LogLevel.Error, "{Problem}")]
    public static partial void ContentProblem(ILogger logger, string problem);

    [LoggerMessage(6002, LogLevel.Warning, "Content import by {User} refused: {Code}: {Reason}")]
    public static partial void ContentRefused(ILogger logger, string user, string code, string reason);

    [LoggerMessage(5005, LogLevel.Warning, "{User} {Operation} exclusion '{Value}': {Outcome}.")]
    public static partial void ExclusionChanged(ILogger logger, string user, string operation, string value, string outcome);
}
