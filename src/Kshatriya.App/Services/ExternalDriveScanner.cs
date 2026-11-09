using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Scanning.Targets;

namespace Kshatriya.App.Services;

/// <summary>
/// Scans external drives as they are connected, one at a time, through the service (with the user's own
/// access rights) and describes the outcome. Report only: nothing is quarantined automatically.
/// </summary>
public sealed class ExternalDriveScanner(IServiceGateway gateway) : IDisposable
{
    private readonly SemaphoreSlim _oneAtATime = new(1, 1);

    public async Task<FindingNotice> ScanAsync(DriveDescription drive, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(drive);
        await _oneAtATime.WaitAsync(cancellationToken);
        try
        {
            ScanReport report = await gateway.ScanAsync([drive.Root], quarantine: false, new Progress<ScanProgressDto>(), cancellationToken);
            return Describe(drive, report);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException or ServiceException or ServiceAuthenticationException or ProtocolException)
        {
            return new FindingNotice("External drive not scanned", $"{drive.Label}: {ErrorText.Describe(ex)}", IsThreat: false);
        }
        finally
        {
            _oneAtATime.Release();
        }
    }

    /// <summary>One notification for the result of scanning a drive.</summary>
    public static FindingNotice Describe(DriveDescription drive, ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(drive);
        ArgumentNullException.ThrowIfNull(report);
        ScanSummary s = report.Summary;
        if (s.Detected > 0)
        {
            return new FindingNotice("Threat found on external drive", $"{drive.Label}: {s.Detected} threat(s) found{(s.Suspicious > 0 ? $", {s.Suspicious} suspicious" : string.Empty)}. Nothing was changed. Click to review.", IsThreat: true);
        }

        if (s.Suspicious > 0)
        {
            return new FindingNotice("Suspicious files on external drive", $"{drive.Label}: {s.Suspicious} file(s) look suspicious. Nothing was changed. Click to review.", IsThreat: false);
        }

        string incomplete = s.NotScanned > 0 ? $" {s.NotScanned} item(s) could not be scanned." : string.Empty;
        return new FindingNotice("External drive scanned", $"{drive.Label}: nothing found in {s.FilesScanned:N0} file(s).{incomplete}", IsThreat: false);
    }

    public void Dispose() => _oneAtATime.Dispose();
}
