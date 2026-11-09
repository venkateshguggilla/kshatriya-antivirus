using System.Security.AccessControl;
using System.Security.Principal;

namespace Kshatriya.Response;

/// <summary>Who performed (or requested) an action. Always taken from a Windows token, never from a client message.</summary>
public sealed record Actor(string Sid, string Name)
{
    public static Actor FromIdentity(WindowsIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return new Actor(identity.User?.Value ?? "unknown", identity.Name);
    }

    public static Actor Current()
    {
        using WindowsIdentity me = WindowsIdentity.GetCurrent();
        return FromIdentity(me);
    }

    public static Actor System(string label) => new(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value, label);
}

/// <summary>
/// Runs vault and audit operations with the right identity. The service reverts to its own (SYSTEM)
/// identity for its protected vault while the rest of an operation runs impersonating the client.
/// </summary>
public interface IPrivilegeScope
{
    T Run<T>(Func<T> action);
}

/// <summary>Runs actions as the current thread identity (local, single-user use).</summary>
public sealed class CurrentIdentityScope : IPrivilegeScope
{
    public static CurrentIdentityScope Instance { get; } = new();

    public T Run<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        return action();
    }
}

/// <summary>Temporarily stops impersonating and runs actions as the process identity (the service account).</summary>
public sealed class ProcessIdentityScope : IPrivilegeScope
{
    public static ProcessIdentityScope Instance { get; } = new();

    public T Run<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        return WindowsIdentity.RunImpersonated(Microsoft.Win32.SafeHandles.SafeAccessTokenHandle.InvalidHandle, action);
    }
}

/// <summary>Who may read the vault and audit directories.</summary>
public enum StorageAccess
{
    /// <summary>SYSTEM and Administrators only (the installed service).</summary>
    Machine,

    /// <summary>The current user (and SYSTEM) only (the CLI's local vault and development services).</summary>
    CurrentUser,
}

internal static class ProtectedDirectory
{
    /// <summary>Creates <paramref name="path"/> and gives it an explicit, non-inherited ACL.</summary>
    public static void Ensure(string path, StorageAccess access)
    {
        Directory.CreateDirectory(path);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (access == StorageAccess.Machine)
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.SetOwner(admins);
            security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        else
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            security.SetOwner(me.User!);
            security.AddAccessRule(new FileSystemAccessRule(me.User!, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }

        new DirectoryInfo(path).SetAccessControl(security);
    }
}
