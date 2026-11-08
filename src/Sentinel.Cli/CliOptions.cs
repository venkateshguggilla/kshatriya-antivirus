using System.Globalization;

namespace Sentinel.Cli;

public enum CliCommand
{
    Help,
    Version,
    Scan,
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

    public const string HelpText = """
        Sentinel scanner (milestone 2, read-only prototype)

        Usage:
          sentinel scan <path>... [options]
          sentinel scan --stdin [--name <label>] [options]
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

        return options with { Targets = targets, SignatureFiles = signatures, RuleFiles = rules };
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
