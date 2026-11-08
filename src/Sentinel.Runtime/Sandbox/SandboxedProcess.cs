using System.Collections;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Runtime.Sandbox;

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
/// handles are inherited; they are the only channel to the parent.
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
    private readonly AnonymousPipeServerStream _stdin;
    private readonly AnonymousPipeServerStream _stdout;
    private readonly AnonymousPipeServerStream _stderr;
    private readonly StringBuilder _errorTail = new();
    private readonly Lock _errorGate = new();
    private int _disposed;

    private SandboxedProcess(SafeKernelHandle job, SafeKernelHandle process, int processId, AnonymousPipeServerStream stdin, AnonymousPipeServerStream stdout, AnonymousPipeServerStream stderr)
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
        var stdin = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.Inheritable);
        var stdout = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        var stderr = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        SafeKernelHandle? job = null;
        SafeKernelHandle? process = null;
        try
        {
            using SafeKernelHandle token = CreateWorkerToken();
            job = CreateJob(options);

            IntPtr* handles = stackalloc IntPtr[3];
            handles[0] = stdin.ClientSafePipeHandle.DangerousGetHandle();
            handles[1] = stdout.ClientSafePipeHandle.DangerousGetHandle();
            handles[2] = stderr.ClientSafePipeHandle.DangerousGetHandle();

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
                SandboxNative.ProcessInformation info;
                fixed (char* commandLinePtr = commandLine)
                fixed (char* environmentPtr = environment)
                {
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

                stdin.DisposeLocalCopyOfClientHandle();
                stdout.DisposeLocalCopyOfClientHandle();
                stderr.DisposeLocalCopyOfClientHandle();
                return new SandboxedProcess(job, process, (int)info.ProcessId, stdin, stdout, stderr);
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
            stdin.Dispose();
            stdout.Dispose();
            stderr.Dispose();
            throw;
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
            try
            {
                var disable = new SandboxNative.SidAndAttributes { Sid = admins };
                Check(
                    SandboxNative.CreateRestrictedToken(processToken, SandboxNative.DisableMaxPrivilege, 1, &disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out SafeKernelHandle restricted),
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
