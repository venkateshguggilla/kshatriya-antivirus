using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Sentinel.Runtime.Sandbox;

namespace Sentinel.Runtime.Ipc;

/// <summary>How a client decides that the process serving a pipe really is the Sentinel service.</summary>
public enum ServerIdentityCheck
{
    /// <summary>
    /// Production: the pipe server's process ID must equal the process ID the Service Control Manager
    /// reports for the installed Sentinel service. A local process that squats the pipe name cannot be
    /// that process, and only administrators can install or reconfigure the service.
    /// </summary>
    InstalledService,

    /// <summary>Development: the pipe server must run as the same user as the client.</summary>
    CurrentUser,
}

/// <summary>A named-pipe endpoint plus the rule used to authenticate its server.</summary>
public sealed record ServiceEndpoint(string PipeName, ServerIdentityCheck Check, string ServiceName)
{
    public const string ProductionPipeName = "Sentinel.Service.v1";
    public const string DefaultServiceName = "SentinelService";

    public static ServiceEndpoint Production { get; } = new(ProductionPipeName, ServerIdentityCheck.InstalledService, DefaultServiceName);

    /// <summary>Per-user development endpoint (service started with <c>--dev</c> as the current user).</summary>
    public static ServiceEndpoint Development()
    {
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? "unknown";
        return new ServiceEndpoint($"{ProductionPipeName}.dev.{sid}", ServerIdentityCheck.CurrentUser, DefaultServiceName);
    }

    /// <summary>Throws <see cref="ServiceAuthenticationException"/> unless the connected server passes the check.</summary>
    public void VerifyServer(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!PipeNative.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverPid))
        {
            throw new ServiceAuthenticationException($"Could not identify the pipe server: {TokenInfo.LastError()}");
        }

        switch (Check)
        {
            case ServerIdentityCheck.CurrentUser:
                SecurityIdentifier? me = WindowsIdentity.GetCurrent().User;
                SecurityIdentifier? server = TokenInfo.ProcessUser((int)serverPid);
                if (server is null || me is null || server != me)
                {
                    throw new ServiceAuthenticationException("The development pipe is served by a process of another user; refusing to connect.");
                }

                break;
            case ServerIdentityCheck.InstalledService:
                uint? servicePid = PipeNative.QueryServiceProcessId(ServiceName);
                if (servicePid is null)
                {
                    throw new ServiceAuthenticationException($"The '{ServiceName}' service is not installed or not running.");
                }

                if (servicePid != serverPid)
                {
                    throw new ServiceAuthenticationException("The service pipe is not served by the installed Sentinel service; refusing to connect.");
                }

                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(pipe));
        }
    }
}

/// <summary>Raised when the process behind the service pipe is not the expected one.</summary>
public sealed class ServiceAuthenticationException : Exception
{
    public ServiceAuthenticationException()
    {
    }

    public ServiceAuthenticationException(string message)
        : base(message)
    {
    }

    public ServiceAuthenticationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Named-pipe and Service Control Manager calls used for peer authentication.</summary>
public static partial class PipeNative
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceRunning = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    /// <summary>The process ID of a running service, or null if it is not installed, not running, or not queryable.</summary>
    public static unsafe uint? QueryServiceProcessId(string serviceName)
    {
        ArgumentException.ThrowIfNullOrEmpty(serviceName);
        IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
        if (manager == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            IntPtr service = OpenService(manager, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                ServiceStatusProcess status;
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, &status, (uint)sizeof(ServiceStatusProcess), out _)
                    || status.CurrentState != ServiceRunning || status.ProcessId == 0)
                {
                    return null;
                }

                return status.ProcessId;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryServiceStatusEx(IntPtr service, int infoLevel, void* buffer, uint bufferSize, out uint bytesNeeded);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);
}
