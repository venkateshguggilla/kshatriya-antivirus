using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Sentinel.Runtime.Sandbox;

/// <summary>Reads security properties of process tokens.</summary>
public static class TokenInfo
{
    /// <summary>The current process's mandatory integrity level: untrusted, low, medium, high, system or unknown.</summary>
    public static string CurrentIntegrityLevel()
    {
        if (!SandboxNative.OpenProcessToken(SandboxNative.GetCurrentProcess(), SandboxNative.TokenQuery, out SafeKernelHandle token))
        {
            return "unknown";
        }

        using (token)
        {
            return IntegrityLevelOf(token);
        }
    }

    /// <summary>The user SID of another process, or null if it cannot be queried.</summary>
    public static SecurityIdentifier? ProcessUser(int processId)
    {
        using SafeKernelHandle process = SandboxNative.OpenProcess(SandboxNative.ProcessQueryLimitedInformation, false, (uint)processId);
        if (process.IsInvalid || !SandboxNative.OpenProcessToken(process.DangerousGetHandle(), SandboxNative.TokenQuery, out SafeKernelHandle token))
        {
            return null;
        }

        using (token)
        {
            return UserOf(token);
        }
    }

    internal static unsafe string IntegrityLevelOf(SafeKernelHandle token)
    {
        byte* buffer = stackalloc byte[256];
        if (!SandboxNative.GetTokenInformation(token, SandboxNative.TokenIntegrityLevel, buffer, 256, out _))
        {
            return "unknown";
        }

        IntPtr sidPointer = ((SandboxNative.SidAndAttributes*)buffer)->Sid;
        string sid = new SecurityIdentifier(sidPointer).Value;
        return Name(sid);
    }

    internal static string Name(string integritySid) => integritySid switch
    {
        "S-1-16-0" => "untrusted",
        "S-1-16-4096" => "low",
        "S-1-16-8192" => "medium",
        "S-1-16-8448" => "medium",
        "S-1-16-12288" => "high",
        "S-1-16-16384" => "system",
        _ => "unknown",
    };

    private static unsafe SecurityIdentifier? UserOf(SafeKernelHandle token)
    {
        byte* buffer = stackalloc byte[256];
        if (!SandboxNative.GetTokenInformation(token, SandboxNative.TokenUser, buffer, 256, out _))
        {
            return null;
        }

        return new SecurityIdentifier(((SandboxNative.SidAndAttributes*)buffer)->Sid);
    }

    /// <summary>Last Win32 error as a message (diagnostics).</summary>
    internal static string LastError() => new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()).Message;
}
