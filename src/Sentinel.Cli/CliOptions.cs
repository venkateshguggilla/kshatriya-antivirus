using System.Globalization;
using Sentinel.Scanning;

namespace Sentinel.Cli;

public enum CliCommand
{
    Help,
    Version,
    Scan,
    Status,
    Quarantine,
    Exclusions,
    Audit,
}

/// <summary>Parsed command line. Hand-written parser: tiny surface, no third-party dependency.</summary>
public sealed record CliOptions
{
    public CliCommand Command { get; init; } = CliCommand.Help;

    public IReadOnlyList<string> Targets { get; init; } = [];

    public bool ReadStdin { get; init; }

    public string StdinName { get; init; } = "<stdin>";

    public bool Json { get; init; }

    public string? OutputPath { get; init; }

    public bool IncludeClean { get; init; }

    public bool Quiet { get; init; }

    public IReadOnlyList<string> SignatureFiles { get; init; } = [];

    public IReadOnlyList<string> RuleFiles { get; init; } = [];

    public bool NoHeuristics { get; init; }

    public bool HeuristicsIncludeSigned { get; init; }

    public int? ArchiveDepth { get; init; }

    public long? MaxFileSizeBytes { get; init; }

    public TimeSpan? Timeout { get; init; }

    public int? Parallelism { get; init; }

    /// <summary>Analyse content in this process instead of sandboxed workers (development and benchmarking only).</summary>
    public bool NoSandbox { get; init; }

    /// <summary>Send the scan to the Sentinel service instead of scanning in this process.</summary>
    public bool UseService { get; init; }

    /// <summary>Talk to a development service (started with --dev) instead of the installed one.</summary>
    public bool DevService { get; init; }

    /// <summary>Quarantine high-confidence detections found by the scan.</summary>
    public bool Quarantine { get; init; }

    /// <summary>Paths excluded from this scan only (local scans).</summary>
    public IReadOnlyList<string> Excludes { get; init; } = [];

    /// <summary>Sub-command of quarantine/exclusions: list, add, restore, delete, remove.</summary>
    public string? Action { get; init; }

    /// <summary>Argument of the sub-command (path, id or exclusion value).</summary>
    public string? Argument { get; init; }

    /// <summary>Restore destination (quarantine restore --to).</summary>
    public string? RestoreTo { get; init; }

    /// <summary>Number of audit records to show.</summary>
    public int AuditLast { get; init; } = 50;

    public const string HelpText = """
        Sentinel scanner (milestone 4 prototype)

        Usage:
          sentinel scan <path>... [options]
          sentinel scan --stdin [--name <label>] [options]
          sentinel scan --service [--dev] <path>... [--quarantine] [--json] [--output <file>] [--include-clean] [--quiet]
          sentinel status [--dev]
          sentinel quarantine list | add <file> | restore <id> [--to <path>] | delete <id>   [--service [--dev]]
          sentinel exclusions list | add <path|sha256:...> | remove <path|sha256:...>   --service [--dev]
          sentinel audit [--last <n>] [--service [--dev]]
          sentinel version
          sentinel help

        Options:
          --quarantine           Move confirmed high-confidence detections (malware, test files) into the
                                 encrypted quarantine. Suspicious and PUA findings are only reported.
          --exclude <path>       Do not scan this file or folder in this scan (repeatable; local scans only)
          --json                 Write the report as JSON (schema: docs/schemas/scan-report.v3.schema.json)
          --output <file>        Write the report to a file instead of standard output
          --include-clean        List clean items in the report (counts are always included)
          --signatures <file>    Load an additional hash database (repeatable)
          --rules <file>         Load additional YARA rules (repeatable; includes are disabled)
          --no-heuristics        Disable static PE heuristics
          --heuristics-include-signed  Also score validly signed files (for false-positive evaluation)
          --archive-depth <n>    Nested archive depth to inspect, 0-10 (default 3; 0 disables)
          --max-file-size <MiB>  Skip files larger than this (default 256)
          --timeout <seconds>    Per-item time limit (default 60)
          --parallelism <n>      Items scanned concurrently (default: CPU count, max 16)
          --quiet                Print only the summary in text mode
          --stdin                Scan data piped to standard input
          --name <label>         Display name for --stdin content
          --no-sandbox           Parse files in this process instead of sandboxed worker processes
                                 (development and benchmarking only; less safe)
          --service              Ask the Sentinel service to scan, with your own access rights
          --dev                  With --service or status: use a development service (Sentinel.Service --dev)

        Quarantine and exclusions:
          Without --service, quarantine uses your own vault in %LOCALAPPDATA%\Sentinel\local.
          With --service, restoring files, managing exclusions and reading the audit log require an
          elevated administrator. Restore never overwrites an existing file and marks the restored
          file as downloaded from the internet. Exclusions apply to Sentinel only, never to Defender.

        Exit codes:
          0 clean   1 detections   5 suspicious only   2 incomplete   3 usage error   4 fatal error
          (precedence: 1, then 5, then 2)

        Scans are read-only unless --quarantine is given. Quarantine acts only on files you can delete.
        """;

    public static CliOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count == 0)
        {
            return new CliOptions { Command = CliCommand.Help };
        }

        switch (args[0])
        {
            case "help" or "--help" or "-h" or "/?":
                return new CliOptions { Command = CliCommand.Help };
            case "version" or "--version":
                return new CliOptions { Command = CliCommand.Version };
            case "scan":
                break;
            case "status":
                return ParseStatus(args);
            case "quarantine":
                return ParseManagement(args, CliCommand.Quarantine, ["list", "add", "restore", "delete"]);
            case "exclusions":
                return ParseManagement(args, CliCommand.Exclusions, ["list", "add", "remove"]);
            case "audit":
                return ParseManagement(args, CliCommand.Audit, []);
            default:
                throw new CliUsageException($"Unknown command '{args[0]}'.");
        }

        var targets = new List<string>();
        var excludes = new List<string>();
        var signatures = new List<string>();
        var rules = new List<string>();
        var options = new CliOptions { Command = CliCommand.Scan };

        for (int i = 1; i < args.Count; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "--json":
                    options = options with { Json = true };
                    break;
                case "--include-clean":
                    options = options with { IncludeClean = true };
                    break;
                case "--quiet":
                    options = options with { Quiet = true };
                    break;
                case "--stdin":
                    options = options with { ReadStdin = true };
                    break;
                case "--name":
                    options = options with { StdinName = Next(args, ref i, arg) };
                    break;
                case "--output":
                    options = options with { OutputPath = Next(args, ref i, arg) };
                    break;
                case "--signatures":
                    signatures.Add(Next(args, ref i, arg));
                    break;
                case "--rules":
                    rules.Add(Next(args, ref i, arg));
                    break;
                case "--no-heuristics":
                    options = options with { NoHeuristics = true };
                    break;
                case "--heuristics-include-signed":
                    options = options with { HeuristicsIncludeSigned = true };
                    break;
                case "--archive-depth":
                    options = options with { ArchiveDepth = (int)ParseRange(Next(args, ref i, arg), arg, min: 0, max: 10) };
                    break;
                case "--max-file-size":
                    long mib = ParsePositive(Next(args, ref i, arg), arg, max: 1024 * 1024);
                    options = options with { MaxFileSizeBytes = mib * 1024 * 1024 };
                    break;
                case "--timeout":
                    options = options with { Timeout = TimeSpan.FromSeconds(ParsePositive(Next(args, ref i, arg), arg, max: 86_400)) };
                    break;
                case "--parallelism":
                    options = options with { Parallelism = (int)ParsePositive(Next(args, ref i, arg), arg, max: 64) };
                    break;
                case "--no-sandbox":
                    options = options with { NoSandbox = true };
                    break;
                case "--service":
                    options = options with { UseService = true };
                    break;
                case "--dev":
                    options = options with { DevService = true };
                    break;
                case "--quarantine":
                    options = options with { Quarantine = true };
                    break;
                case "--exclude":
                    string excluded = Path.GetFullPath(Next(args, ref i, arg));
                    excludes.Add(ExclusionSet.ValidatePath(excluded) is { } problem ? throw new CliUsageException(problem) : excluded);
                    break;
                case "--":
                    targets.AddRange(args.Skip(i + 1));
                    i = args.Count;
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new CliUsageException($"Unknown option '{arg}'.");
                    }

                    targets.Add(arg);
                    break;
            }
        }

        if (options.ReadStdin && targets.Count > 0)
        {
            throw new CliUsageException("Use either --stdin or paths, not both.");
        }

        if (!options.ReadStdin && targets.Count == 0)
        {
            throw new CliUsageException("No scan targets given.");
        }

        if (options.DevService && !options.UseService)
        {
            throw new CliUsageException("--dev is only valid together with --service.");
        }

        if (options.Quarantine && options.ReadStdin)
        {
            throw new CliUsageException("--quarantine cannot be used with --stdin (there is no file to move).");
        }

        if (excludes.Count > 0 && options.UseService)
        {
            throw new CliUsageException("--exclude applies to local scans only; the service uses its own exclusions ('sentinel exclusions').");
        }

        if (options.UseService)
        {
            // The service decides engines, limits and isolation from its own protected configuration.
            bool local = options.ReadStdin || signatures.Count > 0 || rules.Count > 0 || options.NoHeuristics || options.HeuristicsIncludeSigned
                || options.ArchiveDepth is not null || options.MaxFileSizeBytes is not null || options.Timeout is not null
                || options.Parallelism is not null || options.NoSandbox;
            if (local)
            {
                throw new CliUsageException("With --service only --json, --output, --include-clean, --quiet and --dev can be used; the service applies its own engines and limits.");
            }
        }
        else if (!options.NoSandbox && options.MaxFileSizeBytes > 1024L * 1024 * 1024)
        {
            throw new CliUsageException("Sandboxed scanning supports files up to 1024 MiB; use a smaller --max-file-size.");
        }

        return options with { Targets = targets, SignatureFiles = signatures, RuleFiles = rules, Excludes = excludes };
    }

    private static CliOptions ParseManagement(IReadOnlyList<string> args, CliCommand command, string[] actions)
    {
        var options = new CliOptions { Command = command };
        var positional = new List<string>();
        for (int i = 1; i < args.Count; i++)
        {
            string arg = args[i];
            switch (arg)
            {
                case "--service":
                    options = options with { UseService = true };
                    break;
                case "--dev":
                    options = options with { DevService = true };
                    break;
                case "--to" when command == CliCommand.Quarantine:
                    options = options with { RestoreTo = Next(args, ref i, arg) };
                    break;
                case "--last" when command == CliCommand.Audit:
                    options = options with { AuditLast = (int)ParseRange(Next(args, ref i, arg), arg, 1, 1000) };
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new CliUsageException($"Unknown option '{arg}' for {args[0]}.");
                    }

                    positional.Add(arg);
                    break;
            }
        }

        if (options.DevService && !options.UseService)
        {
            throw new CliUsageException("--dev is only valid together with --service.");
        }

        if (command == CliCommand.Audit)
        {
            return positional.Count == 0 ? options : throw new CliUsageException("audit takes no arguments.");
        }

        if (positional.Count == 0 || !actions.Contains(positional[0]))
        {
            throw new CliUsageException($"Use: {args[0]} {string.Join(" | ", actions)}.");
        }

        string action = positional[0];
        bool needsArgument = action != "list";
        if (positional.Count != (needsArgument ? 2 : 1))
        {
            throw new CliUsageException(needsArgument ? $"{args[0]} {action} needs exactly one argument." : $"{args[0]} list takes no arguments.");
        }

        if (options.RestoreTo is not null && action != "restore")
        {
            throw new CliUsageException("--to is only valid with quarantine restore.");
        }

        if (command == CliCommand.Exclusions && !options.UseService)
        {
            throw new CliUsageException("Persistent exclusions are managed by the service: add --service. For a single local scan use 'scan --exclude <path>'.");
        }

        string? argument = needsArgument ? positional[1] : null;
        if (argument is not null && (action == "add" && command == CliCommand.Quarantine))
        {
            argument = Path.GetFullPath(argument);
        }

        return options with
        {
            Action = action,
            Argument = argument,
            RestoreTo = options.RestoreTo is null ? null : Path.GetFullPath(options.RestoreTo),
        };
    }

    private static CliOptions ParseStatus(IReadOnlyList<string> args)
    {
        var options = new CliOptions { Command = CliCommand.Status };
        for (int i = 1; i < args.Count; i++)
        {
            options = args[i] switch
            {
                "--dev" => options with { DevService = true },
                _ => throw new CliUsageException($"Unknown option '{args[i]}' for status."),
            };
        }

        return options;
    }

    private static string Next(IReadOnlyList<string> args, ref int i, string option)
    {
        if (i + 1 >= args.Count)
        {
            throw new CliUsageException($"Option '{option}' requires a value.");
        }

        return args[++i];
    }

    private static long ParsePositive(string value, string option, long max) => ParseRange(value, option, 1, max);

    private static long ParseRange(string value, string option, long min, long max)
    {
        if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long result) || result < min || result > max)
        {
            throw new CliUsageException($"Option '{option}' expects an integer between {min} and {max}.");
        }

        return result;
    }
}

public sealed class CliUsageException : Exception
{
    public CliUsageException()
    {
    }

    public CliUsageException(string message)
        : base(message)
    {
    }

    public CliUsageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
