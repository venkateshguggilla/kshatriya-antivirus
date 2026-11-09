using Microsoft.Extensions.Logging.Abstractions;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Service;
using Kshatriya.Tests.Shared;

namespace Kshatriya.Service.Tests;

/// <summary>
/// A real <see cref="ServiceCore"/> (sandboxed workers included) serving a unique development pipe,
/// with its data directory and a custom signature database in a temporary folder.
/// </summary>
internal sealed class RunningService : IAsyncDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _run;

    private RunningService(TempDirectory temp, ServiceCore core, string pipeName, byte[] knownBad)
    {
        Temp = temp;
        Core = core;
        PipeName = pipeName;
        KnownBad = knownBad;
        Endpoint = new ServiceEndpoint(pipeName, ServerIdentityCheck.CurrentUser, "KshatriyaServiceTests");
        _run = Task.Run(() => core.RunAsync(_stop.Token));
    }

    public TempDirectory Temp { get; }

    public ServiceCore Core { get; }

    public string PipeName { get; }

    public ServiceEndpoint Endpoint { get; }

    /// <summary>Benign bytes that the service's custom signature database flags as a test detection.</summary>
    public byte[] KnownBad { get; }

    public static async Task<RunningService> StartAsync(ServiceSettings? settings = null, TimeProvider? time = null, bool requireAdministrator = false, Kshatriya.Service.RealTime.IProcessStartSource? processes = null, Func<IEnumerable<string>>? removableDrives = null, Microsoft.Extensions.Logging.ILogger? logger = null)
    {
        var temp = new TempDirectory();
        byte[] knownBad = TestData.BenignBytes(77, 4096);
        string hashdb = temp.File(@"config\custom.hashdb", System.Text.Encoding.UTF8.GetBytes(TestData.HashDb((TestData.Sha256Hex(knownBad), "Service.Test.Sample", "test"))));
        FileLockdown.ToCurrentUser(hashdb);
        settings = (settings ?? new ServiceSettings()) with { SignatureFiles = [hashdb], Workers = 2 };

        string pipe = $"Kshatriya.Tests.{Guid.NewGuid():N}";
        ServiceCore core = await ServiceCore.StartAsync(
            new ServiceCoreOptions
            {
                Paths = new ServicePaths(Path.Combine(temp.Path, "data"), Production: false),
                Pipe = new PipeServerOptions(pipe, Production: false, Listeners: 3),
                SettingsOverride = settings,
                Time = time ?? TimeProvider.System,
                TimeZone = TimeZoneInfo.Utc,
                RequireAdministrator = requireAdministrator,
                ProcessStartSource = processes,
                RemovableDrives = removableDrives,
            },
            logger ?? NullLogger.Instance,
            CancellationToken.None);

        var service = new RunningService(temp, core, pipe, knownBad);
        await service.WaitUntilListeningAsync();
        return service;
    }

    public Task<ServiceClient> ConnectAsync() => ServiceClient.ConnectAsync(Endpoint, "tests", TimeSpan.FromSeconds(10));

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        try
        {
            await _run.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (OperationCanceledException)
        {
        }

        Core.Dispose();
        _stop.Dispose();
        Temp.Dispose();
    }

    private async Task WaitUntilListeningAsync()
    {
        for (int i = 0; i < 100; i++)
        {
            if (_run.IsFaulted)
            {
                await _run;
            }

            if (File.Exists($@"\\.\pipe\{PipeName}"))
            {
                return;
            }

            await Task.Delay(50);
        }

        throw new TimeoutException("Service pipe did not appear.");
    }
}

internal static class FileLockdown
{
    /// <summary>Gives a file a protected ACL: owner and full control for the current user only.</summary>
    public static string ToCurrentUser(string path)
    {
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var security = new System.Security.AccessControl.FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(me);
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(me, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
        return path;
    }
}
