namespace Kshatriya.Posture;

/// <summary>Kinds of automatic start points (ATT&amp;CK T1547.001, T1053.005, T1543.003, T1546.003).</summary>
public static class StartupKinds
{
    public const string RunKey = "run";
    public const string RunOnceKey = "runOnce";
    public const string StartupFolder = "startupFolder";
    public const string Service = "service";
    public const string ScheduledTask = "task";
    public const string WmiSubscription = "wmi";
}

/// <summary>
/// One thing set to start automatically. <see cref="Scope"/> is "machine" or the owning user's SID.
/// <see cref="Location"/> is the key, folder or task path; <see cref="Command"/> what it runs.
/// </summary>
public sealed record StartupEntry(string Kind, string Scope, string Location, string Name, string Command)
{
    public string Key => $"{Kind}|{Scope}|{Location}|{Name}";

    /// <summary>The program the entry starts, when it can be told from the command.</summary>
    public string? ImagePath => StartupRules.ImageOf(Command);
}

/// <summary>Turns the startup inventory into checks (ADR 0022).</summary>
public static class StartupRules
{
    private static readonly string[] s_riskyFolders =
    [
        @"\appdata\local\temp\", @"\windows\temp\", @"\downloads\", @"\users\public\", @"\$recycle.bin\", @"\programdata\temp\",
    ];

    private static readonly string[] s_scriptHosts =
    [
        "mshta", "wscript", "cscript", "regsvr32", "rundll32", "certutil", "bitsadmin",
    ];

    public static IEnumerable<PostureCheck> Evaluate(IReadOnlyList<StartupEntry> entries)
    {
        const PostureArea area = PostureArea.Startup;
        int flagged = 0;
        foreach (StartupEntry entry in entries.OrderBy(e => e.Key, StringComparer.Ordinal))
        {
            string? reason = Suspicion(entry);
            if (reason is null)
            {
                continue;
            }

            flagged++;
            yield return new($"startup.{entry.Kind}.{Hash(entry.Key)}", area, PostureState.Attention,
                $"Check startup entry '{entry.Name}'", $"{reason} It runs: {Shorten(entry.Command)} ({Describe(entry)}).");
        }

        int services = entries.Count(e => e.Kind == StartupKinds.Service);
        int others = entries.Count - services;
        yield return new("startup.summary", area, flagged == 0 ? PostureState.Ok : PostureState.Info,
            $"{others} program(s) and {services} service(s) start automatically",
            flagged == 0
                ? "None of them start from temporary or download folders or through script hosts. Kshatriya alerts you when a new one appears."
                : "Kshatriya alerts you when a new one appears.");
    }

    /// <summary>Why an entry looks risky, or null. Heuristic: reported as attention, never acted on.</summary>
    public static string? Suspicion(StartupEntry entry)
    {
        if (entry.Kind == StartupKinds.WmiSubscription)
        {
            return "WMI event subscriptions that run commands are rarely used by normal software and are a known way for malware to hide.";
        }

        string command = entry.Command.ToLowerInvariant();
        if (s_riskyFolders.Any(f => command.Contains(f, StringComparison.Ordinal)))
        {
            return "It starts from a temporary, download or shared folder.";
        }

        string? image = ImageOf(entry.Command);
        string program = Path.GetFileNameWithoutExtension(image ?? string.Empty).ToLowerInvariant();
        if (s_scriptHosts.Contains(program))
        {
            return $"It starts through {program}, which malware often uses to run hidden code.";
        }

        if (program is "powershell" or "pwsh" &&
            (command.Contains(" -enc", StringComparison.Ordinal) || command.Contains(" -e ", StringComparison.Ordinal) ||
             command.Contains("downloadstring", StringComparison.Ordinal) || command.Contains("-w hidden", StringComparison.Ordinal) ||
             command.Contains("-windowstyle hidden", StringComparison.Ordinal)))
        {
            return "It runs a hidden or encoded PowerShell command.";
        }

        return null;
    }

    /// <summary>The program path at the start of a command line: a quoted path or the text up to ".exe".</summary>
    public static string? ImageOf(string command)
    {
        string c = Environment.ExpandEnvironmentVariables(command.Trim());
        if (c.Length == 0)
        {
            return null;
        }

        if (c[0] == '"')
        {
            int end = c.IndexOf('"', 1);
            return end > 1 ? c[1..end] : null;
        }

        int exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe > 0 && (exe + 4 == c.Length || c[exe + 4] == ' '))
        {
            return c[..(exe + 4)];
        }

        int space = c.IndexOf(' ', StringComparison.Ordinal);
        return space > 0 ? c[..space] : c;
    }

    public static string Describe(StartupEntry entry) => entry.Kind switch
    {
        StartupKinds.RunKey => "Run key " + entry.Location,
        StartupKinds.RunOnceKey => "RunOnce key " + entry.Location,
        StartupKinds.StartupFolder => "startup folder",
        StartupKinds.Service => "service",
        StartupKinds.ScheduledTask => "scheduled task " + entry.Location,
        StartupKinds.WmiSubscription => "WMI subscription",
        _ => entry.Kind,
    };

    private static string Shorten(string command) => command.Length <= 160 ? command : command[..157] + "...";

    /// <summary>A short stable id fragment for an entry key (FNV-1a, hex).</summary>
    internal static string Hash(string key)
    {
        uint hash = 2166136261;
        foreach (char c in key)
        {
            hash = (hash ^ c) * 16777619;
        }

        return hash.ToString("x8", System.Globalization.CultureInfo.InvariantCulture);
    }
}
