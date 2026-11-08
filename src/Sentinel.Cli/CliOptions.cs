using System.Globalization;

namespace Sentinel.Cli;

public enum CliCommand
{
    Help,
    Version,
    Scan,
    Status,
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

    public const string HelpText = """
        Sentinel scanner (milestone 3, read-only prototype)

        Usage:
          sentinel scan <path>... [options]
          sentinel scan --stdin [--name <label>] [options]
          sentinel scan --service [--dev] <path>... [--json] [--output <file>] [--include-clean] [--quiet]
          sentinel status [--dev]
          sentinel version
          sentinel help

        Options:
          --json                 Write the report as JSON (schema: docs/schemas/scan-report.v2.schema.json)
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

        Exit codes:
          0 clean   1 detections   5 suspicious only   2 incomplete   3 usage error   4 fatal error
          (precedence: 1, then 5, then 2)

        This tool never modifies, moves or deletes files.
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
            default:
                throw new CliUsageException($"Unknown command '{args[0]}'.");
        }

        var targets = new List<string>();
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

        return options with { Targets = targets, SignatureFiles = signatures, RuleFiles = rules };
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
