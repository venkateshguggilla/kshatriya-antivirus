using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Ipc;

namespace Kshatriya.App.Services;

/// <summary>Everything the app asks of the Kshatriya service. The app itself never opens or changes scanned files.</summary>
public interface IServiceGateway
{
    /// <summary>Human-readable description of the endpoint ("installed service" or "development service").</summary>
    string EndpointDescription { get; }

    Task<(HelloReplyDto Hello, StatusReplyDto Status)> GetStatusAsync(CancellationToken cancellationToken);

    Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken);

    /// <summary>A quick or full scan (<see cref="ScanKinds"/>); the service determines the targets.</summary>
    Task<ScanReport> ScanKindAsync(string kind, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken);

    Task<QuarantineListReplyDto> ListQuarantineAsync(CancellationToken cancellationToken);

    Task<OperationReplyDto> RestoreAsync(string id, string? targetPath, CancellationToken cancellationToken);

    Task<OperationReplyDto> DeleteQuarantinedAsync(string id, CancellationToken cancellationToken);

    Task<ExclusionsReplyDto> GetExclusionsAsync(CancellationToken cancellationToken);

    Task<ExclusionsReplyDto> ChangeExclusionAsync(bool add, string value, CancellationToken cancellationToken);

    Task<AuditReplyDto> GetAuditAsync(int max, CancellationToken cancellationToken);

    Task<DetectionsReplyDto> GetDetectionsAsync(int max, CancellationToken cancellationToken);

    /// <summary>Moves a file into quarantine at the user's request; the service opens it as the caller (reversible).</summary>
    Task<OperationReplyDto> QuarantineFileAsync(string path, CancellationToken cancellationToken);

    /// <summary>Asks the service to verify and install a signed content package; it reads the file as the caller.</summary>
    Task<ContentImportReplyDto> ImportContentAsync(string packagePath, CancellationToken cancellationToken);

    /// <summary>Runs the read-only security check (ADR 0022).</summary>
    Task<PostureReplyDto> GetPostureAsync(CancellationToken cancellationToken);

    /// <summary>Applies or undoes a hardening fix; needs an elevated administrator.</summary>
    Task<OperationReplyDto> HardenAsync(string fix, bool undo, bool block, CancellationToken cancellationToken);

    /// <summary>The USB drive lock and the drives it knows (ADR 0023).</summary>
    Task<DeviceLockReplyDto> GetDeviceLockAsync(CancellationToken cancellationToken);

    Task<OperationReplyDto> UnlockDeviceAsync(string id, string password, CancellationToken cancellationToken);

    Task<OperationReplyDto> ConfigureDeviceLockAsync(bool enabled, CancellationToken cancellationToken);

    Task<OperationReplyDto> SetPasswordAsync(string newPassword, string? currentPassword, CancellationToken cancellationToken);
}

/// <summary>Talks to the service over its authenticated pipe; one connection per operation.</summary>
public sealed class ServiceGateway(ServiceEndpoint endpoint, string description) : IServiceGateway
{
    private static readonly TimeSpan s_connectTimeout = TimeSpan.FromSeconds(3);

    public string EndpointDescription => description;

    public async Task<(HelloReplyDto Hello, StatusReplyDto Status)> GetStatusAsync(CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ConnectAsync(cancellationToken);
        return (client.Hello, await client.GetStatusAsync(cancellationToken));
    }

    public async Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ConnectAsync(cancellationToken);
        return await client.ScanAsync(paths, includeClean: false, quarantine, progress, cancellationToken);
    }

    public async Task<ScanReport> ScanKindAsync(string kind, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ConnectAsync(cancellationToken);
        return await client.ScanKindAsync(kind, includeClean: false, quarantine, progress, cancellationToken);
    }

    public Task<QuarantineListReplyDto> ListQuarantineAsync(CancellationToken cancellationToken) =>
        WithClient(c => c.ListQuarantineAsync(cancellationToken), cancellationToken);

    public Task<OperationReplyDto> RestoreAsync(string id, string? targetPath, CancellationToken cancellationToken) =>
        WithClient(c => c.RestoreAsync(id, targetPath, cancellationToken), cancellationToken);

    public Task<OperationReplyDto> DeleteQuarantinedAsync(string id, CancellationToken cancellationToken) =>
        WithClient(c => c.DeleteQuarantinedAsync(id, cancellationToken), cancellationToken);

    public Task<ExclusionsReplyDto> GetExclusionsAsync(CancellationToken cancellationToken) =>
        WithClient(c => c.GetExclusionsAsync(cancellationToken), cancellationToken);

    public Task<ExclusionsReplyDto> ChangeExclusionAsync(bool add, string value, CancellationToken cancellationToken) =>
        WithClient(c => c.ChangeExclusionAsync(add, value, cancellationToken), cancellationToken);

    public Task<AuditReplyDto> GetAuditAsync(int max, CancellationToken cancellationToken) =>
        WithClient(c => c.GetAuditAsync(max, cancellationToken), cancellationToken);

    public Task<DetectionsReplyDto> GetDetectionsAsync(int max, CancellationToken cancellationToken) =>
        WithClient(c => c.GetDetectionsAsync(max, cancellationToken), cancellationToken);

    public Task<OperationReplyDto> QuarantineFileAsync(string path, CancellationToken cancellationToken) =>
        WithClient(c => c.QuarantineFileAsync(path, cancellationToken), cancellationToken);

    public Task<ContentImportReplyDto> ImportContentAsync(string packagePath, CancellationToken cancellationToken) =>
        WithClient(c => c.ImportContentAsync(packagePath, cancellationToken), cancellationToken);

    public Task<PostureReplyDto> GetPostureAsync(CancellationToken cancellationToken) =>
        WithClient(c => c.GetPostureAsync(cancellationToken), cancellationToken);

    public Task<OperationReplyDto> HardenAsync(string fix, bool undo, bool block, CancellationToken cancellationToken) =>
        WithClient(c => c.HardenAsync(fix, undo, block, cancellationToken), cancellationToken);

    public Task<DeviceLockReplyDto> GetDeviceLockAsync(CancellationToken cancellationToken) =>
        WithClient(c => c.GetDeviceLockAsync(cancellationToken), cancellationToken);

    public Task<OperationReplyDto> UnlockDeviceAsync(string id, string password, CancellationToken cancellationToken) =>
        WithClient(c => c.UnlockDeviceAsync(id, password, cancellationToken), cancellationToken);

    public Task<OperationReplyDto> ConfigureDeviceLockAsync(bool enabled, CancellationToken cancellationToken) =>
        WithClient(c => c.ConfigureDeviceLockAsync(enabled, cancellationToken), cancellationToken);

    public Task<OperationReplyDto> SetPasswordAsync(string newPassword, string? currentPassword, CancellationToken cancellationToken) =>
        WithClient(c => c.SetPasswordAsync(newPassword, currentPassword, cancellationToken), cancellationToken);

    private Task<ServiceClient> ConnectAsync(CancellationToken cancellationToken) =>
        ServiceClient.ConnectAsync(endpoint, $"kshatriya-app/{AppInfo.Version}", s_connectTimeout, cancellationToken);

    private async Task<T> WithClient<T>(Func<ServiceClient, Task<T>> call, CancellationToken cancellationToken)
    {
        await using ServiceClient client = await ConnectAsync(cancellationToken);
        return await call(client);
    }
}

/// <summary>Turns exceptions from the gateway into calm, actionable messages.</summary>
public static class ErrorText
{
    public static string Describe(Exception ex) => ex switch
    {
        ServiceException { Code: ErrorCodes.AccessDenied } s => s.Message + " Use \"Restart as administrator\" on the Home page (Technical details).",
        ServiceException s => s.Message,
        ServiceAuthenticationException a => "The service could not be verified, so nothing was sent: " + a.Message,
        TimeoutException or IOException => "The Kshatriya service is not reachable. Is it installed and running?",
        ProtocolException p => "The service sent an unexpected reply: " + p.Message,
        OperationCanceledException => "Cancelled.",
        _ => ex.Message,
    };
}

public static class AppInfo
{
    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().FirstOrDefault()?.InformationalVersion.Split('+')[0] ?? "0.0.0";
}
