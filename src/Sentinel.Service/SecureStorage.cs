using System.Security.AccessControl;
using System.Security.Principal;

namespace Sentinel.Service;

/// <summary>Where the service keeps its configuration, reports and state.</summary>
public sealed record ServicePaths(string Root, bool Production)
{
    public string ConfigFile => Path.Combine(Root, "config", "service.json");

    public string ReportsDirectory => Path.Combine(Root, "reports");

    public string StateDirectory => Path.Combine(Root, "state");

    public string ExclusionsFile => Path.Combine(Root, "config", "exclusions.json");

    /// <summary>Encrypted quarantine vault (SYSTEM and Administrators only, not readable by Users).</summary>
    public string QuarantineDirectory => Path.Combine(Root, "quarantine");

    /// <summary>Hash-chained audit log (SYSTEM and Administrators only).</summary>
    public string AuditDirectory => Path.Combine(Root, "audit");

    /// <summary>Signed content packages and the anti-rollback state.</summary>
    public string ContentDirectory => Path.Combine(Root, "content");

    /// <summary>%ProgramData%\Sentinel, writable only by SYSTEM and Administrators.</summary>
    public static ServicePaths ForProduction() =>
        new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel"), Production: true);

    /// <summary>%LOCALAPPDATA%\Sentinel\dev for a development service running as the current user.</summary>
    public static ServicePaths ForDevelopment() =>
        new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sentinel", "dev"), Production: false);
}

/// <summary>
/// Protects the service's files. In production the data directory gets an explicit, non-inherited
/// ACL (SYSTEM and Administrators full control, Users read) and Administrators as owner. Files that
/// change what a SYSTEM scan does (settings, signature and rule files) are refused unless only
/// SYSTEM, Administrators or TrustedInstaller own them and can write them.
/// </summary>
public static class SecureStorage
{
    private static readonly SecurityIdentifier s_system = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier s_admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier s_users = new(WellKnownSidType.BuiltinUsersSid, null);
    private static readonly SecurityIdentifier s_trustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier s_creatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    /// <summary>Creates the data directories; in production also (re)applies the protected ACL.</summary>
    public static void EnsureDirectories(ServicePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        foreach (string dir in new[] { paths.Root, Path.GetDirectoryName(paths.ConfigFile)!, paths.ReportsDirectory, paths.StateDirectory })
        {
            Directory.CreateDirectory(dir);
        }

        if (!paths.Production)
        {
            return;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(s_admins);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(s_system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(s_admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(s_users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(paths.Root).SetAccessControl(security);
    }

    /// <summary>
    /// Writes a file the service itself owns (for example exclusions) with an explicit, non-inherited ACL:
    /// SYSTEM and Administrators (production) or SYSTEM and the current user (development), so that it
    /// passes <see cref="CheckTrustedFile"/> regardless of the folder's inherited permissions. The file is
    /// written to a temporary name, protected, then moved into place.
    /// </summary>
    public static void WriteProtectedFile(string path, string contents, bool production)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(contents);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + ".tmp";
        File.WriteAllText(temp, contents);

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(s_system, FileSystemRights.FullControl, AccessControlType.Allow));
        if (production)
        {
            security.SetOwner(s_admins);
            security.AddAccessRule(new FileSystemAccessRule(s_admins, FileSystemRights.FullControl, AccessControlType.Allow));
        }
        else
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            security.SetOwner(me.User!);
            security.AddAccessRule(new FileSystemAccessRule(me.User!, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        new FileInfo(temp).SetAccessControl(security);
        File.Move(temp, path, overwrite: true);
    }

    /// <summary>
    /// Returns null if the file may be trusted to configure a privileged scan, or the reason it may not.
    /// In development mode the current user may also own and write the file.
    /// </summary>
    public static string? CheckTrustedFile(string path, bool production)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var info = new FileInfo(path);
        if (!info.Exists)
        {
            return $"'{path}' does not exist.";
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return $"'{path}' is a link; configuration files must be regular files.";
        }

        FileSecurity security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        HashSet<SecurityIdentifier> trusted = [s_system, s_admins, s_trustedInstaller];
        if (!production && WindowsIdentity.GetCurrent().User is SecurityIdentifier me)
        {
            trusted.Add(me);
        }

        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !trusted.Contains(owner))
        {
            return $"'{path}' is not owned by SYSTEM or Administrators.";
        }

        foreach (FileSystemAccessRule rule in security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow
                && (rule.FileSystemRights & WriteRights) != 0
                && rule.IdentityReference is SecurityIdentifier sid
                && !trusted.Contains(sid)
                && sid != s_creatorOwner)
            {
                return $"'{path}' can be modified by {Describe(sid)}; only SYSTEM and Administrators may be able to change it.";
            }
        }

        return null;
    }

    private static string Describe(SecurityIdentifier sid)
    {
        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (IdentityNotMappedException)
        {
            return sid.Value;
        }
    }
}
