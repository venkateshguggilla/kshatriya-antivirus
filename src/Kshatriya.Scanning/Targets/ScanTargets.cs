using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Kshatriya.Scanning.Targets;

/// <summary>Kinds of scan offered to users, like other antivirus products.</summary>
public enum ScanKind
{
    /// <summary>The paths the user chose (files, folders or a drive).</summary>
    Custom,

    /// <summary>Places malware usually starts from or lands in; minutes, not hours.</summary>
    Quick,

    /// <summary>Every fixed drive.</summary>
    Full,

    /// <summary>Every connected external drive (USB, memory card, FireWire, removable media).</summary>
    External,
}

/// <summary>Wire names for <see cref="ScanKind"/>.</summary>
public static class ScanKindNames
{
    public const string Custom = "custom";
    public const string Quick = "quick";
    public const string Full = "full";
    public const string External = "external";

    public static string Of(ScanKind kind) => kind switch
    {
        ScanKind.Quick => Quick,
        ScanKind.Full => Full,
        ScanKind.External => External,
        _ => Custom,
    };

    /// <summary>Null and "custom" are <see cref="ScanKind.Custom"/>; anything unknown is null.</summary>
    public static ScanKind? Parse(string? value) => value switch
    {
        null or Custom => ScanKind.Custom,
        Quick => ScanKind.Quick,
        Full => ScanKind.Full,
        External => ScanKind.External,
        _ => null,
    };
}

/// <summary>Whose locations a quick scan covers.</summary>
/// <param name="UserSid">The user a scan runs for; null for a machine-wide (scheduled) scan.</param>
/// <param name="UserProfile">That user's profile folder; null for a machine-wide scan.</param>
/// <param name="IncludeAdminLocations">Also cover locations only administrators can read (Windows Temp).</param>
public sealed record QuickScanScope(string? UserSid, string? UserProfile, bool IncludeAdminLocations)
{
    /// <summary>All user profiles and administrator-only locations (scheduled scans run as the service).</summary>
    public static QuickScanScope Machine { get; } = new(null, null, IncludeAdminLocations: true);
}

/// <summary>What a quick scan looks at, gathered from the system (kept apart from the selection logic for tests).</summary>
/// <param name="Folders">Folders to scan in full (downloads, desktop, temp, startup folders).</param>
/// <param name="CommandLines">Startup commands (Run keys, Winlogon) and service image paths.</param>
/// <param name="ProcessImages">Executables of running processes.</param>
/// <param name="ProfilesRoot">Folder holding all user profiles (usually C:\Users).</param>
/// <param name="AllowedProfile">The only profile whose contents may be scanned; null allows every profile.</param>
public sealed record QuickScanInputs(
    IReadOnlyList<string> Folders,
    IReadOnlyList<string> CommandLines,
    IReadOnlyList<string> ProcessImages,
    string? ProfilesRoot,
    string? AllowedProfile);

/// <summary>Builds the target list for quick and full scans.</summary>
public static partial class ScanTargets
{
    private static readonly string[] s_profileSubfolders =
    [
        "Downloads",
        "Desktop",
        @"AppData\Local\Temp",
        @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    ];

    private static readonly string[] s_runKeys =
    [
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    /// <summary>Roots of all ready fixed drives (a full scan).</summary>
    public static IReadOnlyList<string> FullSystem() => FullSystem(DriveInfo.GetDrives().Select(d => (d.Name, d.DriveType, SafeIsReady(d))));

    /// <summary>Roots of the ready fixed drives among <paramref name="drives"/>.</summary>
    public static IReadOnlyList<string> FullSystem(IEnumerable<(string Root, DriveType Type, bool IsReady)> drives) =>
        [.. drives.Where(d => d.Type == DriveType.Fixed && d.IsReady && PathPolicy.IsLocalAbsolutePath(d.Root)).Select(d => d.Root).Order(StringComparer.OrdinalIgnoreCase)];

    /// <summary>Quick-scan targets for <paramref name="scope"/>, gathered from this machine.</summary>
    public static IReadOnlyList<string> Quick(QuickScanScope scope) => Quick(Gather(scope), File.Exists, Directory.Exists);

    /// <summary>
    /// Selects the quick-scan targets: existing folders and the files named by startup commands and running
    /// processes, without duplicates, only fully qualified local paths, and never inside another user's
    /// profile when the scan runs for one user.
    /// </summary>
    public static IReadOnlyList<string> Quick(QuickScanInputs inputs, Func<string, bool> fileExists, Func<string, bool> directoryExists)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        var targets = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string path, bool directory)
        {
            string full;
            try
            {
                full = Path.GetFullPath(path);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return;
            }

            if (PathPolicy.IsLocalAbsolutePath(full) && Allowed(full, inputs) && (directory ? directoryExists(full) : fileExists(full)) && seen.Add(full))
            {
                targets.Add(full);
            }
        }

        foreach (string folder in inputs.Folders)
        {
            Add(folder, directory: true);
        }

        foreach (string commandLine in inputs.CommandLines)
        {
            foreach (string file in FilesFromCommandLine(commandLine, fileExists))
            {
                Add(file, directory: false);
            }
        }

        foreach (string image in inputs.ProcessImages)
        {
            Add(image, directory: false);
        }

        return targets;
    }

    /// <summary>
    /// The files a startup command or service image path runs: the executable, plus the DLL for
    /// rundll32/regsvr32. Handles quotes, environment variables, unquoted paths with spaces, missing
    /// ".exe", <c>\SystemRoot\</c> and <c>\??\</c> prefixes and bare names found in System32.
    /// </summary>
    public static IReadOnlyList<string> FilesFromCommandLine(string commandLine, Func<string, bool> fileExists)
    {
        ArgumentNullException.ThrowIfNull(fileExists);
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return [];
        }

        string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string line = Environment.ExpandEnvironmentVariables(commandLine.Trim());
        line = line.StartsWith(@"\??\", StringComparison.Ordinal) ? line[4..]
            : line.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase) ? Path.Combine(systemRoot, line[@"\SystemRoot\".Length..])
            : line.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) ? Path.Combine(systemRoot, line)
            : line;

        (string? executable, string arguments) = SplitExecutable(line, fileExists, systemRoot);
        if (executable is null)
        {
            return [];
        }

        var files = new List<string> { executable };
        string name = Path.GetFileName(executable);
        if (name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase))
        {
            // rundll32 "C:\x\y.dll",Entry  /  regsvr32 /s C:\x\y.dll
            string argument = string.Join(' ', arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries).Where(a => !a.StartsWith('/') && !a.StartsWith('-')));
            string dll = argument.Trim().Trim('"');
            int comma = dll.IndexOf(',', StringComparison.Ordinal);
            dll = (comma >= 0 ? dll[..comma] : dll).Trim().Trim('"');
            if (dll.Length > 0 && Resolve(dll, fileExists, systemRoot) is { } resolved)
            {
                files.Add(resolved);
            }
        }

        return files;
    }

    private static (string? Executable, string Arguments) SplitExecutable(string line, Func<string, bool> fileExists, string systemRoot)
    {
        if (line.StartsWith('"'))
        {
            int end = line.IndexOf('"', 1);
            string quoted = end > 0 ? line[1..end] : line[1..];
            return (Resolve(quoted, fileExists, systemRoot), end > 0 ? line[(end + 1)..] : string.Empty);
        }

        // Unquoted: try ever longer prefixes ("C:\Program", "C:\Program Files\App\app.exe", ...).
        string[] parts = line.Split(' ');
        for (int i = 1; i <= parts.Length; i++)
        {
            string candidate = string.Join(' ', parts[..i]);
            if (Resolve(candidate, fileExists, systemRoot) is { } found)
            {
                return (found, string.Join(' ', parts[i..]));
            }
        }

        return (null, string.Empty);
    }

    private static string? Resolve(string candidate, Func<string, bool> fileExists, string systemRoot)
    {
        candidate = candidate.Trim().TrimEnd(',');
        if (candidate.Length == 0 || candidate.AsSpan().IndexOfAny('*', '?', '"') >= 0)
        {
            return null;
        }

        string[] tries = Path.IsPathFullyQualified(candidate)
            ? [candidate, candidate + ".exe"]
            : candidate.Contains('\\', StringComparison.Ordinal)
                ? []
                : [Path.Combine(systemRoot, "System32", candidate), Path.Combine(systemRoot, "System32", candidate + ".exe"), Path.Combine(systemRoot, candidate)];
        return tries.FirstOrDefault(t => PathPolicy.IsLocalAbsolutePath(t) && fileExists(t));
    }

    private static bool Allowed(string path, QuickScanInputs inputs)
    {
        if (inputs.AllowedProfile is null || inputs.ProfilesRoot is null)
        {
            return true;
        }

        string root = inputs.ProfilesRoot.TrimEnd('\\') + "\\";
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string own = inputs.AllowedProfile.TrimEnd('\\');
        string shared = Path.Combine(inputs.ProfilesRoot, "Public");
        return path.Equals(own, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(own + "\\", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(shared + "\\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads startup entries, services, running processes and well-known folders from this machine.</summary>
    public static QuickScanInputs Gather(QuickScanScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        string? profilesRoot = ProfilesDirectory();
        var profiles = new List<string>();
        if (scope.UserProfile is not null)
        {
            profiles.Add(scope.UserProfile);
        }
        else if (profilesRoot is not null)
        {
            profiles.AddRange(SafeDirectories(profilesRoot));
        }

        var folders = new List<string>();
        foreach (string profile in profiles)
        {
            folders.AddRange(s_profileSubfolders.Select(sub => Path.Combine(profile, sub)));
        }

        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        folders.Add(Path.Combine(programData, @"Microsoft\Windows\Start Menu\Programs\StartUp"));
        if (scope.IncludeAdminLocations)
        {
            folders.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
        }

        var commands = new List<string>();
        foreach (string key in s_runKeys)
        {
            commands.AddRange(Values(Registry.LocalMachine, key));
        }

        commands.AddRange(Values(Registry.LocalMachine, @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "Userinit")
            .SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)));
        foreach (string sid in scope.UserSid is not null ? [scope.UserSid] : LoadedUserSids())
        {
            foreach (string key in s_runKeys)
            {
                commands.AddRange(Values(Registry.Users, $@"{sid}\{key}"));
            }
        }

        commands.AddRange(ServiceImagePaths());
        return new QuickScanInputs(folders, commands, ProcessImages(), profilesRoot, scope.UserProfile);
    }

    /// <summary>The profile folder of a user, from the system's profile list; null if unknown.</summary>
    public static string? ProfileOf(string sid)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
            return key?.GetValue("ProfileImagePath") is string path ? Environment.ExpandEnvironmentVariables(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static string? ProfilesDirectory()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            return key?.GetValue("ProfilesDirectory") is string path ? Environment.ExpandEnvironmentVariables(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static IEnumerable<string> LoadedUserSids()
    {
        try
        {
            return [.. Registry.Users.GetSubKeyNames().Where(n => n.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !n.EndsWith("_Classes", StringComparison.Ordinal))];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return [];
        }
    }

    private static IEnumerable<string> Values(RegistryKey hive, string path, params string[] names)
    {
        try
        {
            using RegistryKey? key = hive.OpenSubKey(path);
            if (key is null)
            {
                return [];
            }

            IEnumerable<string> selected = names.Length > 0 ? names : key.GetValueNames();
            return [.. selected.Select(n => key.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string).OfType<string>()];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return [];
        }
    }

    private static List<string> ServiceImagePaths()
    {
        var paths = new List<string>();
        try
        {
            using RegistryKey? services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            foreach (string name in services?.GetSubKeyNames() ?? [])
            {
                using RegistryKey? service = services!.OpenSubKey(name);
                // Win32 services only (own or shared process); drivers are outside the scope of a quick scan.
                if (service?.GetValue("Type") is int type && (type & 0x30) != 0 && service.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string image)
                {
                    paths.Add(image);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            // Partial list: what was read is still scanned.
        }

        return paths;
    }

    private static List<string> ProcessImages()
    {
        var images = new List<string>();
        foreach (Process process in Process.GetProcesses())
        {
            using (process)
            {
                if (ImagePath((uint)process.Id) is string path)
                {
                    images.Add(path);
                }
            }
        }

        return images;
    }

    private static IEnumerable<string> SafeDirectories(string root)
    {
        try
        {
            return [.. new DirectoryInfo(root).EnumerateDirectories().Where(d => (d.Attributes & FileAttributes.ReparsePoint) == 0).Select(d => d.FullName)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return [];
        }
    }

    private static bool SafeIsReady(DriveInfo drive)
    {
        try
        {
            return drive.IsReady;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static unsafe string? ImagePath(uint pid)
    {
        IntPtr process = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            char* buffer = stackalloc char[1024];
            int size = 1024;
            return QueryFullProcessImageNameW(process, 0, buffer, ref size) ? new string(buffer, 0, size) : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial IntPtr OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* name, ref int size);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(IntPtr handle);
}
