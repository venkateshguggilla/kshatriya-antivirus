using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;

namespace Sentinel.App.Services;

/// <summary>Everything the app asks of the Sentinel service. The app itself never opens or changes scanned files.</summary>
public interface IServiceGateway
{
    /// <summary>Human-readable description of the endpoint ("installed service" or "development service").</summary>
    string EndpointDescription { get; }

    Task<(HelloReplyDto Hello, StatusReplyDto Status)> GetStatusAsync(CancellationToken cancellationToken);

    Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool quarantine, IProgress<ScanProgressDto> progress, CancellationToken cancellationToken);

    Task<QuarantineListReplyDto> ListQuarantineAsync(CancellationToken cancellationToken);

    Task<OperationReplyDto> RestoreAsync(string id, string? targetPath, CancellationToken cancellationToken);

    Task<OperationReplyDto> DeleteQuarantinedAsync(string id, CancellationToken cancellationToken);

    Task<ExclusionsReplyDto> GetExclusionsAsync(CancellationToken cancellationToken);

    Task<ExclusionsReplyDto> ChangeExclusionAsync(bool add, string value, CancellationToken cancellationToken);

    Task<AuditReplyDto> GetAuditAsync(int max, CancellationToken cancellationToken);
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

    private Task<ServiceClient> ConnectAsync(CancellationToken cancellationToken) =>
        ServiceClient.ConnectAsync(endpoint, $"sentinel-app/{AppInfo.Version}", s_connectTimeout, cancellationToken);

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
        ServiceException { Code: ErrorCodes.AccessDenied } s => s.Message + " Use \"Restart as administrator\" on the Dashboard.",
        ServiceException s => s.Message,
        ServiceAuthenticationException a => "The service could not be verified, so nothing was sent: " + a.Message,
        TimeoutException or IOException => "The Sentinel service is not reachable. Is it installed and running?",
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
