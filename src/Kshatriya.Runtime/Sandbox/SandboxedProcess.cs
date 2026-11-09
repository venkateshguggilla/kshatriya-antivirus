using System.Collections;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Runtime.Sandbox;

/// <summary>How a worker process is confined.</summary>
public sealed record SandboxOptions
{
    /// <summary>Per-process committed memory cap enforced by the Job Object.</summary>
    public long MemoryLimitBytes { get; init; } = 1536L * 1024 * 1024;
}

/// <summary>Raised when a sandboxed process cannot be created.</summary>
public sealed class SandboxException : Exception
{
    public SandboxException()
    {
    }

    public SandboxException(string message)
        : base(message)
    {
    }

    public SandboxException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// A child process confined for parsing untrusted content. It is created from a restricted copy of the
/// caller's token (all privileges except SeChangeNotify removed, Administrators deny-only) lowered to
/// <b>low</b> integrity, inside a Job Object that kills it when the parent goes away, forbids child
/// processes, caps memory and blocks UI/clipboard access, with process mitigations (no extension points,
/// no remote or low-label images, no non-system fonts, heap termination, ASLR). Only its standard
/// handles are inherited; they are the only channel to the parent. It runs on a private window station
/// and desktop (<see cref="WorkerDesktop"/>) whenever the broker may create one.
/// </summary>
/// <remarks>
/// Low integrity blocks writes to almost every file, registry key and process of the user, but does not
/// by default prevent reads. Workers are designed never to open files (content arrives over the pipe); a
/// stronger read barrier (AppContainer) is tracked in the threat model as future hardening.
/// </remarks>
public sealed class SandboxedProcess : IDisposable
{
    private const string LowIntegritySid = "S-1-16-4096";
    private const string AdministratorsSid = "S-1-5-32-544";
    private const int ErrorTailChars = 4096;

    /// <summary>Environment variables that could load code into the worker; never passed on.</summary>
    private static readonly string[] s_strippedVariables =
    [
        "DOTNET_STARTUP_HOOKS",
        "DOTNET_ADDITIONAL_DEPS",
        "DOTNET_SHARED_STORE",
        "CORECLR_ENABLE_PROFILING",
        "CORECLR_PROFILER",
        "CORECLR_PROFILER_PATH",
        "CORECLR_PROFILER_PATH_64",
        "COR_ENABLE_PROFILING",
        "COR_PROFILER",
        "COR_PROFILER_PATH",
    ];

    private readonly SafeKernelHandle _job;
    private readonly SafeKernelHandle _process;
    private readonly NamedPipeServerStream _stdin;
    private readonly NamedPipeServerStream _stdout;
    private readonly NamedPipeServerStream _stderr;
    private readonly StringBuilder _errorTail = new();
    private readonly Lock _errorGate = new();
    private int _disposed;

    private SandboxedProcess(SafeKernelHandle job, SafeKernelHandle process, int processId, NamedPipeServerStream stdin, NamedPipeServerStream stdout, NamedPipeServerStream stderr)
    {
        _job = job;
        _process = process;
        ProcessId = processId;
        _stdin = stdin;
        _stdout = stdout;
        _stderr = stderr;
        _ = Task.Run(DrainErrorsAsync);
    }

    public int ProcessId { get; }

    /// <summary>
    /// Gives the child read-only access to a file-mapping section: the handle is duplicated into the child
    /// with FILE_MAP_READ as its only right (it cannot map for writing, change the section or reach the file).
    /// Returns the handle value as seen by the child, which closes it when done.
    /// </summary>
    public long ShareReadOnlySection(SafeHandle section)
    {
        ArgumentNullException.ThrowIfNull(section);
        bool added = false;
        try
        {
            section.DangerousAddRef(ref added);
            Check(SandboxNative.DuplicateHandle(SandboxNative.GetCurrentProcess(), section.DangerousGetHandle(), _process, out IntPtr target, SandboxNative.FileMapRead, false, 0), "DuplicateHandle");
            return target;
        }
        finally
        {
            if (added)
            {
                section.DangerousRelease();
            }
        }
    }

    /// <summary>Writes to the child's standard input.</summary>
    public Stream Input => _stdin;

    /// <summary>Reads from the child's standard output.</summary>
    public Stream Output => _stdout;

    /// <summary>The last few kilobytes the child wrote to standard error (for crash diagnostics).</summary>
    public string ErrorTail
    {
        get
        {
            lock (_errorGate)
            {
                return _errorTail.ToString();
            }
        }
    }

    public bool HasExited => SandboxNative.WaitForSingleObject(_process, 0) == SandboxNative.WaitObject0;

    public uint? ExitCode =>
        SandboxNative.GetExitCodeProcess(_process, out uint code) && code != SandboxNative.StillActive ? code : null;

    /// <summary>Starts <paramref name="executablePath"/> confined. Always runs as the process identity, never as an impersonated caller.</summary>
    public static SandboxedProcess Start(string executablePath, string arguments, SandboxOptions options)
    {
        ArgumentException.ThrowIfNullOrEmpty(executablePath);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(options);
        string fullPath = Path.GetFullPath(executablePath);
        if (!File.Exists(fullPath))
        {
            throw new SandboxException($"Worker executable not found: {fullPath}");
        }

        // Thread impersonation (service scans run as the caller) must not leak into process creation.
        return WindowsIdentity.RunImpersonated(SafeAccessTokenHandle.InvalidHandle, () => StartCore(fullPath, arguments, options));
    }

    /// <summary>Kills the process (and anything in its job). Safe to call repeatedly.</summary>
    public void Kill()
    {
        if (!_job.IsClosed)
        {
            SandboxNative.TerminateJobObject(_job, 0xC000013A);
        }
    }

    public bool WaitForExit(TimeSpan timeout) =>
        SandboxNative.WaitForSingleObject(_process, (uint)Math.Clamp(timeout.TotalMilliseconds, 0, uint.MaxValue - 1)) == SandboxNative.WaitObject0;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Kill();
        _stdin.Dispose();
        _stdout.Dispose();
        _stderr.Dispose();
        _process.Dispose();
        _job.Dispose();
    }

    private static unsafe SandboxedProcess StartCore(string fullPath, string arguments, SandboxOptions options)
    {
        using ChildPipe stdinPipe = ChildPipe.Create(PipeDirection.Out);
        using ChildPipe stdoutPipe = ChildPipe.Create(PipeDirection.In);
        using ChildPipe stderrPipe = ChildPipe.Create(PipeDirection.In);
        NamedPipeServerStream stdin = stdinPipe.Server, stdout = stdoutPipe.Server, stderr = stderrPipe.Server;
        SafeKernelHandle? job = null;
        SafeKernelHandle? process = null;
        try
        {
            using SafeKernelHandle token = CreateWorkerToken();
            job = CreateJob(options);

            IntPtr* handles = stackalloc IntPtr[3];
            handles[0] = stdinPipe.Child.DangerousGetHandle();
            handles[1] = stdoutPipe.Child.DangerousGetHandle();
            handles[2] = stderrPipe.Child.DangerousGetHandle();

            ulong mitigations = SandboxNative.MitigationHeapTerminateAlwaysOn
                | SandboxNative.MitigationBottomUpAslrAlwaysOn
                | SandboxNative.MitigationHighEntropyAslrAlwaysOn
                | SandboxNative.MitigationExtensionPointDisableAlwaysOn
                | SandboxNative.MitigationFontDisableAlwaysOn
                | SandboxNative.MitigationImageLoadNoRemoteAlwaysOn
                | SandboxNative.MitigationImageLoadNoLowLabelAlwaysOn;
            uint childPolicy = SandboxNative.ProcessCreationChildProcessRestricted;

            nint listSize = 0;
            SandboxNative.InitializeProcThreadAttributeList(IntPtr.Zero, 3, 0, ref listSize);
            IntPtr attributeList = (IntPtr)NativeMemory.Alloc((nuint)listSize);
            bool listInitialized = false;
            try
            {
                Check(SandboxNative.InitializeProcThreadAttributeList(attributeList, 3, 0, ref listSize), "InitializeProcThreadAttributeList");
                listInitialized = true;
                Check(SandboxNative.UpdateProcThreadAttribute(attributeList, 0, SandboxNative.ProcThreadAttributeHandleList, handles, 3 * IntPtr.Size, IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute(handles)");
                Check(SandboxNative.UpdateProcThreadAttribute(attributeList, 0, SandboxNative.ProcThreadAttributeMitigationPolicy, &mitigations, sizeof(ulong), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute(mitigations)");
                Check(SandboxNative.UpdateProcThreadAttribute(attributeList, 0, SandboxNative.ProcThreadAttributeChildProcessPolicy, &childPolicy, sizeof(uint), IntPtr.Zero, IntPtr.Zero), "UpdateProcThreadAttribute(child policy)");

                var startup = new SandboxNative.StartupInfoEx
                {
                    StartupInfo = new SandboxNative.StartupInfo
                    {
                        Cb = (uint)sizeof(SandboxNative.StartupInfoEx),
                        Flags = SandboxNative.StartfUseStdHandles,
                        StdInput = handles[0],
                        StdOutput = handles[1],
                        StdError = handles[2],
                    },
                    AttributeList = attributeList,
                };

                // DETACHED_PROCESS: the worker gets no console, so no conhost.exe has to be created for it.
                // The child-process policy forbids that, and the worker would fail to initialise (0xC0000142).
                char[] commandLine = $"\"{fullPath}\" {arguments}\0".ToCharArray();
                char[] environment = BuildEnvironmentBlock();
                // A private desktop the restricted, low-integrity token can connect to (see WorkerDesktop).
                string? desktopPath = WorkerDesktop.Path;
                char[] desktop = ((desktopPath ?? string.Empty) + "\0").ToCharArray();
                SandboxNative.ProcessInformation info;
                fixed (char* commandLinePtr = commandLine)
                fixed (char* environmentPtr = environment)
                fixed (char* desktopPtr = desktop)
                {
                    startup.StartupInfo.Desktop = desktopPath is null ? IntPtr.Zero : (IntPtr)desktopPtr;
                    Check(
                        SandboxNative.CreateProcessAsUser(
                            token,
                            fullPath,
                            commandLinePtr,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            inheritHandles: true,
                            SandboxNative.CreateSuspended | SandboxNative.DetachedProcess | SandboxNative.ExtendedStartupInfoPresent | SandboxNative.CreateUnicodeEnvironment,
                            environmentPtr,
                            Path.GetDirectoryName(fullPath)!,
                            ref startup,
                            out info),
                        "CreateProcessAsUser");
                }

                process = new SafeKernelHandle(info.Process);
                using var thread = new SafeKernelHandle(info.Thread);
                if (!SandboxNative.AssignProcessToJobObject(job, process))
                {
                    int error = Marshal.GetLastPInvokeError();
                    SandboxNative.TerminateProcess(process, 1);
                    throw new SandboxException($"Could not place the worker in its job object: {new Win32Exception(error).Message}");
                }

                if (SandboxNative.ResumeThread(thread) == uint.MaxValue)
                {
                    int error = Marshal.GetLastPInvokeError();
                    SandboxNative.TerminateJobObject(job, 1);
                    throw new SandboxException($"Could not start the worker: {new Win32Exception(error).Message}");
                }

                // The child now holds its ends; the server ends move to the new instance.
                return new SandboxedProcess(job, process, (int)info.ProcessId, stdinPipe.TakeServer(), stdoutPipe.TakeServer(), stderrPipe.TakeServer());
            }
            finally
            {
                if (listInitialized)
                {
                    SandboxNative.DeleteProcThreadAttributeList(attributeList);
                }

                NativeMemory.Free((void*)attributeList);
            }
        }
        catch
        {
            if (job is not null && !job.IsInvalid)
            {
                SandboxNative.TerminateJobObject(job, 1);
            }

            process?.Dispose();
            job?.Dispose();
            throw;
        }
    }

    /// <summary>
    /// One channel to the child. The parent's end is an overlapped named-pipe server (true asynchronous I/O,
    /// so many workers do not tie up thread-pool threads the way synchronous anonymous pipes do). The pipe has
    /// a random name, a single instance and an ACL for the parent's own account; the parent opens the child's
    /// end itself (synchronous, inheritable) before the child exists, so nothing else can connect.
    /// </summary>
    private sealed class ChildPipe : IDisposable
    {
        private NamedPipeServerStream? _server;

        private ChildPipe(NamedPipeServerStream server, SafeFileHandle child)
        {
            _server = server;
            Child = child;
        }

        public NamedPipeServerStream Server => _server ?? throw new ObjectDisposedException(nameof(ChildPipe));

        public SafeFileHandle Child { get; }

        public static ChildPipe Create(PipeDirection serverDirection)
        {
            string name = $"Kshatriya.Worker.{Environment.ProcessId}.{Guid.NewGuid():N}";
            var security = new PipeSecurity();
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
            NamedPipeServerStream server = NamedPipeServerStreamAcl.Create(
                name,
                serverDirection,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
                inBufferSize: 0,
                outBufferSize: 0,
                security);
            try
            {
                FileAccess childAccess = serverDirection == PipeDirection.Out ? FileAccess.Read : FileAccess.Write;
                SafeFileHandle child = File.OpenHandle($@"\\.\pipe\{name}", FileMode.Open, childAccess, FileShare.None, FileOptions.None);
                if (!SandboxNative.SetHandleInformation(child, SandboxNative.HandleFlagInherit, SandboxNative.HandleFlagInherit))
                {
                    int error = Marshal.GetLastPInvokeError();
                    child.Dispose();
                    throw new SandboxException($"Could not make the worker pipe inheritable: {new Win32Exception(error).Message}");
                }

                server.WaitForConnection();
                return new ChildPipe(server, child);
            }
            catch
            {
                server.Dispose();
                throw;
            }
        }

        /// <summary>Transfers ownership of the server end to the caller.</summary>
        public NamedPipeServerStream TakeServer()
        {
            NamedPipeServerStream server = Server;
            _server = null;
            return server;
        }

        public void Dispose()
        {
            Child.Dispose();
            _server?.Dispose();
        }
    }

    private static unsafe SafeKernelHandle CreateWorkerToken()
    {
        Check(
            SandboxNative.OpenProcessToken(
                SandboxNative.GetCurrentProcess(),
                SandboxNative.TokenDuplicate | SandboxNative.TokenQuery | SandboxNative.TokenAssignPrimary | SandboxNative.TokenAdjustDefault,
                out SafeKernelHandle processToken),
            "OpenProcessToken");

        using (processToken)
        {
            IntPtr admins = ToSid(AdministratorsSid);
            IntPtr low = ToSid(LowIntegritySid);
            byte* user = stackalloc byte[256];
            Check(SandboxNative.GetTokenInformation(processToken, SandboxNative.TokenUser, user, 256, out _), "GetTokenInformation(TokenUser)");
            try
            {
                // Deny-only SIDs can only deny. Making the account's own SID deny-only means files that are
                // private to the account (its profile, SYSTEM-only data) cannot be read by the worker; it keeps
                // only what broad groups such as Users or Everyone may read (its own binaries, system DLLs).
                SandboxNative.SidAndAttributes* disable = stackalloc SandboxNative.SidAndAttributes[2];
                disable[0] = new SandboxNative.SidAndAttributes { Sid = admins };
                disable[1] = new SandboxNative.SidAndAttributes { Sid = ((SandboxNative.SidAndAttributes*)user)->Sid };
                Check(
                    SandboxNative.CreateRestrictedToken(processToken, SandboxNative.DisableMaxPrivilege, 2, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out SafeKernelHandle restricted),
                    "CreateRestrictedToken");

                var label = new SandboxNative.SidAndAttributes { Sid = low, Attributes = SandboxNative.SeGroupIntegrity };
                uint size = (uint)sizeof(SandboxNative.SidAndAttributes) + SandboxNative.GetLengthSid(low);
                if (!SandboxNative.SetTokenInformation(restricted, SandboxNative.TokenIntegrityLevel, &label, size))
                {
                    int error = Marshal.GetLastPInvokeError();
                    restricted.Dispose();
                    throw new SandboxException($"Could not lower the worker token to low integrity: {new Win32Exception(error).Message}");
                }

                return restricted;
            }
            finally
            {
                SandboxNative.LocalFree(admins);
                SandboxNative.LocalFree(low);
            }
        }
    }

    private static unsafe SafeKernelHandle CreateJob(SandboxOptions options)
    {
        SafeKernelHandle job = SandboxNative.CreateJobObject(IntPtr.Zero, IntPtr.Zero);
        if (job.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new SandboxException($"CreateJobObject failed: {new Win32Exception(error).Message}");
        }

        var limits = new SandboxNative.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new SandboxNative.JobObjectBasicLimitInformation
            {
                LimitFlags = SandboxNative.JobObjectLimitKillOnJobClose
                    | SandboxNative.JobObjectLimitActiveProcess
                    | SandboxNative.JobObjectLimitDieOnUnhandledException
                    | SandboxNative.JobObjectLimitProcessMemory,
                ActiveProcessLimit = 1,
            },
            ProcessMemoryLimit = (nuint)options.MemoryLimitBytes,
        };

        uint ui = SandboxNative.JobObjectUiLimitAll;
        if (!SandboxNative.SetInformationJobObject(job, SandboxNative.JobInfoExtendedLimitInformation, &limits, (uint)sizeof(SandboxNative.JobObjectExtendedLimitInformation))
            || !SandboxNative.SetInformationJobObject(job, SandboxNative.JobInfoBasicUiRestrictions, &ui, sizeof(uint)))
        {
            int error = Marshal.GetLastPInvokeError();
            job.Dispose();
            throw new SandboxException($"Could not configure the worker job object: {new Win32Exception(error).Message}");
        }

        return job;
    }

    private static char[] BuildEnvironmentBlock()
    {
        var variables = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            string name = (string)entry.Key;
            if (!s_strippedVariables.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                variables[name] = (string?)entry.Value ?? string.Empty;
            }
        }

        // No diagnostics IPC endpoint inside the sandbox.
        variables["DOTNET_EnableDiagnostics"] = "0";

        var block = new StringBuilder();
        foreach ((string name, string value) in variables)
        {
            block.Append(name).Append('=').Append(value).Append('\0');
        }

        block.Append('\0');
        return block.ToString().ToCharArray();
    }

    private static IntPtr ToSid(string sid)
    {
        Check(SandboxNative.ConvertStringSidToSid(sid, out IntPtr value), "ConvertStringSidToSid");
        return value;
    }

    private static void Check(bool ok, string operation)
    {
        if (!ok)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new SandboxException($"{operation} failed: {new Win32Exception(error).Message}");
        }
    }

    private async Task DrainErrorsAsync()
    {
        try
        {
            using var reader = new StreamReader(_stderr, Encoding.UTF8);
            char[] buffer = new char[1024];
            int read;
            while ((read = await reader.ReadAsync(buffer)) > 0)
            {
                lock (_errorGate)
                {
                    _errorTail.Append(buffer, 0, read);
                    if (_errorTail.Length > ErrorTailChars)
                    {
                        _errorTail.Remove(0, _errorTail.Length - ErrorTailChars);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // The worker went away; nothing more to collect.
        }
    }
}
