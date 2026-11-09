using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Sentinel.Runtime.Sandbox;

/// <summary>
/// A private window station and desktop for sandboxed workers, created once per broker process and kept
/// for its lifetime.
/// </summary>
/// <remarks>
/// Every process that loads user32 (the .NET runtime does) connects to a window station and desktop
/// during DLL initialisation. Workers otherwise inherit the broker's: for a LocalSystem service that is
/// the session-0 "Service-0x0-3e7$" station, whose DACL grants only SYSTEM and Administrators. The worker
/// token makes both deny-only, so initialisation fails with STATUS_DLL_INIT_FAILED (0xC0000142).
/// <para>
/// The private station and desktop are labelled low integrity so the low-integrity worker can use them,
/// and grant access to the broker's account and to Everyone (the worker token's account and Administrators
/// SIDs are deny-only, so a broad group is the one it still matches). They hold nothing but workers, which
/// keeps workers off the broker's desktop: the Job Object's UI limits apply in addition.
/// </para>
/// <para>
/// Only administrators and SYSTEM may create a named window station. A standard user (development
/// mode) gets <see langword="null"/> and workers inherit the interactive station, which works there
/// because its DACL grants the logon SID that the worker token keeps.
/// </para>
/// </remarks>
internal static unsafe class WorkerDesktop
{
    private const string DesktopName = "Worker";
    private static readonly Lock s_gate = new();
    private static bool s_initialized;
    private static string? s_path;

    /// <summary>
    /// The "station\desktop" path to put in STARTUPINFO.lpDesktop, or <see langword="null"/> to inherit
    /// the broker's (only when the broker may not create window stations).
    /// </summary>
    public static string? Path
    {
        get
        {
            lock (s_gate)
            {
                if (!s_initialized)
                {
                    s_path = Create();
                    s_initialized = true;
                }

                return s_path;
            }
        }
    }

    private const int ErrorAccessDenied = 5;

    private static string? Create()
    {
        string station = $"SentinelWorker-{Environment.ProcessId}-{Guid.NewGuid():N}";
        string self = WindowsIdentity.GetCurrent().User!.Value;
        // Protected DACL: SYSTEM, the broker's account and Everyone. The low mandatory label is applied
        // after creation (a creation descriptor carrying a SACL is refused without SeSecurityPrivilege).
        string sddl = $"D:P(A;;GA;;;SY)(A;;GA;;;{self})(A;;GA;;;WD)";
        if (!SandboxNative.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out IntPtr descriptor, IntPtr.Zero))
        {
            throw Fail("ConvertStringSecurityDescriptorToSecurityDescriptor");
        }

        try
        {
            var attributes = new SandboxNative.SecurityAttributes
            {
                Length = (uint)sizeof(SandboxNative.SecurityAttributes),
                SecurityDescriptor = descriptor,
            };

            // The handles are deliberately never closed: the objects must outlive every worker.
            // WRITE_OWNER is needed to set the integrity label below.
            IntPtr winsta = SandboxNative.CreateWindowStation(station, SandboxNative.CreateWindowStationFlagsNone, SandboxNative.WinstaAllAccess | SandboxNative.ReadControl | SandboxNative.WriteOwner, &attributes);
            if (winsta == IntPtr.Zero)
            {
                if (Marshal.GetLastPInvokeError() == ErrorAccessDenied)
                {
                    return null;
                }

                throw Fail("CreateWindowStation");
            }

            if (!SetLowLabel(winsta, out int labelError))
            {
                SandboxNative.CloseWindowStation(winsta);
                throw new SandboxException($"Could not label the worker window station: {new Win32Exception(labelError).Message}");
            }

            // CreateDesktop always creates in the process's current window station, so switch briefly.
            IntPtr original = SandboxNative.GetProcessWindowStation();
            if (original == IntPtr.Zero || !SandboxNative.SetProcessWindowStation(winsta))
            {
                SandboxException error = Fail("SetProcessWindowStation");
                SandboxNative.CloseWindowStation(winsta);
                throw error;
            }

            IntPtr desktop;
            int desktopError;
            try
            {
                desktop = SandboxNative.CreateDesktop(DesktopName, IntPtr.Zero, IntPtr.Zero, 0, SandboxNative.GenericAll, &attributes);
                desktopError = Marshal.GetLastPInvokeError();
            }
            finally
            {
                SandboxNative.SetProcessWindowStation(original);
            }

            if (desktop == IntPtr.Zero)
            {
                SandboxNative.CloseWindowStation(winsta);
                throw new SandboxException($"CreateDesktop failed: {new Win32Exception(desktopError).Message}");
            }

            if (!SetLowLabel(desktop, out labelError))
            {
                SandboxNative.CloseDesktop(desktop);
                SandboxNative.CloseWindowStation(winsta);
                throw new SandboxException($"Could not label the worker desktop: {new Win32Exception(labelError).Message}");
            }

            return $@"{station}\{DesktopName}";
        }
        finally
        {
            SandboxNative.LocalFree(descriptor);
        }
    }

    /// <summary>Sets a low mandatory label (no write up) so the low-integrity worker may use the object.</summary>
    private static bool SetLowLabel(IntPtr handle, out int error)
    {
        error = 0;
        if (!SandboxNative.ConvertStringSecurityDescriptorToSecurityDescriptor("S:(ML;;NW;;;LW)", 1, out IntPtr descriptor, IntPtr.Zero))
        {
            error = Marshal.GetLastPInvokeError();
            return false;
        }

        try
        {
            if (!SandboxNative.GetSecurityDescriptorSacl(descriptor, out _, out IntPtr sacl, out _))
            {
                error = Marshal.GetLastPInvokeError();
                return false;
            }

            error = (int)SandboxNative.SetSecurityInfo(handle, SandboxNative.SeWindowObject, SandboxNative.LabelSecurityInformation, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
            return error == 0;
        }
        finally
        {
            SandboxNative.LocalFree(descriptor);
        }
    }

    private static SandboxException Fail(string operation) =>
        new($"Could not create the worker desktop ({operation}): {new Win32Exception(Marshal.GetLastPInvokeError()).Message}");
}
