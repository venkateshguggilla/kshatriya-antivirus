using System.Globalization;
using System.Reflection;
using System.Text;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Response;
using Sentinel.Runtime;
using Sentinel.Runtime.Ipc;
using Sentinel.Runtime.Workers;
using Sentinel.Scanning;
using Sentinel.Scanning.Trust;

namespace Sentinel.Cli;

/// <summary>Testable entry point: all I/O goes through the supplied streams and writers.</summary>
public static class CliApp
{
    public static string ToolVersion { get; } =
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    /// <summary>Overrides the service endpoint (tests). Null uses the installed or development service.</summary>
    public static ServiceEndpoint? EndpointOverride { get; set; }

    public static async Task<int> RunAsync(
        IReadOnlyList<string> args,
        Stream stdin,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stdin);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        CliOptions options;
        try
        {
            options = CliOptions.Parse(args);
        }
        catch (CliUsageException ex)
        {
            await stderr.WriteLineAsync($"error: {ex.Message}");
            await stderr.WriteLineAsync("Run 'sentinel help' for usage.");
            return ExitCodes.Usage;
        }

        switch (options.Command)
        {
            case CliCommand.Help:
                await stdout.WriteAsync(CliOptions.HelpText);
                return ExitCodes.Clean;
            case CliCommand.Version:
                await stdout.WriteLineAsync($"sentinel {ToolVersion}");
                return ExitCodes.Clean;
            case CliCommand.Status:
                return await StatusAsync(options, stdout, stderr, cancellationToken);
            case CliCommand.Quarantine or CliCommand.Exclusions or CliCommand.Audit or CliCommand.Update:
                return await ManageAsync(options, stdout, stderr, cancellationToken);
        }

        return options.UseService
            ? await ServiceScanAsync(options, stdout, stderr, cancellationToken)
            : await LocalScanAsync(options, stdin, stdout, stderr, cancellationToken);
    }

    private static async Task<int> LocalScanAsync(CliOptions options, Stream stdin, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        var limits = new ScanLimits();
        limits = limits with
        {
            MaxFileSizeBytes = options.MaxFileSizeBytes ?? limits.MaxFileSizeBytes,
            PerItemTimeout = options.Timeout ?? limits.PerItemTimeout,
            MaxDegreeOfParallelism = options.Parallelism ?? limits.MaxDegreeOfParallelism,
            Archives = options.ArchiveDepth is int depth ? limits.Archives with { MaxDepth = depth } : limits.Archives,
        };

        EngineConfiguration engines;
        try
        {
            engines = EngineConfiguration.FromFiles(options.SignatureFiles, options.RuleFiles) with
            {
                Heuristics = !options.NoHeuristics,
                HeuristicsIncludeSigned = options.HeuristicsIncludeSigned,
                MaxScanBytes = limits.MaxFileSizeBytes,
                Archives = limits.Archives,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await stderr.WriteLineAsync($"error: could not load signatures or rules: {ex.Message}");
            return ExitCodes.Fatal;
        }

        IContentAnalyzer analyzer;
        IDisposable lifetime;
        IReadOnlyList<string> warnings;
        try
        {
            if (options.NoSandbox)
            {
                (InProcessAnalyzer local, EngineSet set) = EngineSetup.BuildInProcess(engines);
                (analyzer, lifetime, warnings) = (local, set, set.Warnings);
            }
            else
            {
                WorkerPoolAnalyzer pool = await WorkerPoolAnalyzer.StartAsync(
                    new WorkerPoolOptions { Engines = engines, WorkerCount = limits.MaxDegreeOfParallelism },
                    cancellationToken);
                (analyzer, lifetime, warnings) = (pool, pool, pool.Warnings);
            }
        }
        catch (EngineSetupException ex)
        {
            await stderr.WriteLineAsync($"error: could not load signatures or rules: {ex.Message}");
            return ExitCodes.Fatal;
        }
        catch (WorkerStartException ex) when (ex.IsConfigurationError)
        {
            await stderr.WriteLineAsync($"error: could not load signatures or rules: {ex.Message}");
            return ExitCodes.Fatal;
        }
        catch (WorkerStartException ex)
        {
            await stderr.WriteLineAsync($"error: could not start sandboxed scan workers: {ex.Message}");
            await stderr.WriteLineAsync("Scanning without isolation is possible with --no-sandbox (less safe; for development only).");
            return ExitCodes.Fatal;
        }

        using (lifetime)
        {
            foreach (string warning in warnings)
            {
                await stderr.WriteLineAsync($"warning: {warning}");
            }

            IItemResponder? responder = null;
            if (options.Quarantine)
            {
                try
                {
                    responder = new QuarantineResponder(ManagementCommands.OpenLocal(), Actor.Current());
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or VaultIntegrityException)
                {
                    await stderr.WriteLineAsync($"error: could not open the quarantine vault: {ex.Message}");
                    return ExitCodes.Fatal;
                }
            }

            var runner = new ScanRunner(analyzer, new ScanOptions
            {
                Limits = limits,
                IncludeCleanItems = options.IncludeClean,
                TrustProvider = new AuthenticodeTrustProvider(),
                Exclusions = options.Excludes.Count > 0 ? new ExclusionSet(options.Excludes) : null,
                Responder = responder,
            });

            ScanReport report;
            try
            {
                report = options.ReadStdin
                    ? await ScanStdinAsync(runner, stdin, options.StdinName, cancellationToken)
                    : await runner.ScanPathsAsync(options.Targets, progress: null, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                await stderr.WriteLineAsync("Scan cancelled. Results are incomplete.");
                return ExitCodes.Incomplete;
            }

            return await WriteReportAsync(report, options, stdout, stderr, cancellationToken);
        }
    }

    private static async Task<int> ServiceScanAsync(CliOptions options, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        // The service accepts only absolute paths; resolve relative ones against this process's directory.
        string[] targets = [.. options.Targets.Select(Path.GetFullPath)];
        ScanReport report;
        try
        {
            await using ServiceClient client = await ConnectAsync(options, cancellationToken);
            report = await client.ScanAsync(targets, options.IncludeClean, options.Quarantine, progress: null, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            await stderr.WriteLineAsync("Scan cancelled. Results are incomplete.");
            return ExitCodes.Incomplete;
        }
        catch (Exception ex) when (IsServiceFailure(ex))
        {
            await stderr.WriteLineAsync($"error: {ex.Message}");
            return ExitCodes.Fatal;
        }

        return await WriteReportAsync(report, options, stdout, stderr, cancellationToken);
    }

    private static async Task<int> StatusAsync(CliOptions options, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        try
        {
            await using ServiceClient client = await ConnectAsync(options, cancellationToken);
            StatusReplyDto status = await client.GetStatusAsync(cancellationToken);
            await stdout.WriteAsync(FormatStatus(client.Hello, status));
            return ExitCodes.Clean;
        }
        catch (Exception ex) when (IsServiceFailure(ex))
        {
            await stderr.WriteLineAsync($"error: {ex.Message}");
            return ExitCodes.Fatal;
        }
    }

    private static async Task<int> ManageAsync(CliOptions options, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        try
        {
            return options.Command switch
            {
                CliCommand.Quarantine => await ManagementCommands.QuarantineAsync(options, () => ConnectAsync(options, cancellationToken), stdout, stderr, cancellationToken),
                CliCommand.Exclusions => await ManagementCommands.ExclusionsAsync(options, () => ConnectAsync(options, cancellationToken), stdout, cancellationToken),
                CliCommand.Update => await ManagementCommands.UpdateAsync(options, () => ConnectAsync(options, cancellationToken), stdout, stderr, cancellationToken),
                _ => await ManagementCommands.AuditAsync(options, () => ConnectAsync(options, cancellationToken), stdout, stderr, cancellationToken),
            };
        }
        catch (Exception ex) when (IsServiceFailure(ex) || ex is VaultIntegrityException)
        {
            await stderr.WriteLineAsync($"error: {ex.Message}");
            return ExitCodes.Fatal;
        }
    }

    private static Task<ServiceClient> ConnectAsync(CliOptions options, CancellationToken cancellationToken)
    {
        ServiceEndpoint endpoint = EndpointOverride ?? (options.DevService ? ServiceEndpoint.Development() : ServiceEndpoint.Production);
        return ServiceClient.ConnectAsync(endpoint, $"sentinel-cli/{ToolVersion}", TimeSpan.FromSeconds(5), cancellationToken);
    }

    private static bool IsServiceFailure(Exception ex) =>
        ex is ServiceException or ServiceAuthenticationException or ProtocolException or IOException or TimeoutException or UnauthorizedAccessException;

    internal static string FormatStatus(HelloReplyDto hello, StatusReplyDto status)
    {
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"{hello.Service} ({status.Mode}), running since {status.StartedUtc}").AppendLine();
        sb.Append(CultureInfo.InvariantCulture, $"Connected as: {hello.User} (administrator: {(hello.IsAdmin ? "yes" : "no")})").AppendLine();
        sb.Append("Engines: ").AppendJoin(", ", status.Engines.Select(e => $"{e.Id} {e.Version} [{e.ContentVersion}]")).AppendLine();
        WorkerStatsDto w = status.Workers;
        sb.Append(CultureInfo.InvariantCulture, $"Sandboxed workers: {w.Configured} configured, {w.Running} running, {w.Started} started, {w.Crashed} crashed, {w.TimedOut} stopped at time limit").AppendLine();
        sb.Append(CultureInfo.InvariantCulture, $"Verdict cache: {status.Cache.Entries} entries, {status.Cache.Hits} hits, {status.Cache.Misses} misses").AppendLine();
        sb.Append(CultureInfo.InvariantCulture, $"Active scans: {status.ActiveScans}").AppendLine();
        ContentStatusDto content = status.Content;
        sb.Append("Content: ").Append(content.Sequence == 0
            ? "built-in only (no signed update installed)"
            : $"update {content.Sequence} ({content.Channel}), " + (content.Expired ? $"EXPIRED {content.ExpiresUtc}" : $"valid until {content.ExpiresUtc}"))
          .AppendLine(content.Problem is null ? string.Empty : $"; {content.Problem}");
        sb.Append(CultureInfo.InvariantCulture, $"Quarantine: {status.QuarantineItems} item(s). Exclusions: {status.Exclusions}. Audit log: {(status.AuditChainValid ? "intact" : "INTEGRITY CHECK FAILED")}").AppendLine();
        if (status.Schedules.Count == 0)
        {
            sb.AppendLine("Scheduled scans: none configured");
        }
        else
        {
            sb.AppendLine("Scheduled scans:");
            foreach (ScheduleStatusDto s in status.Schedules)
            {
                string last = s.LastRunUtc is null ? "never run" : $"last {s.LastRunUtc} ({s.LastOutcome})";
                sb.Append(CultureInfo.InvariantCulture, $"  {s.Name}  next {s.NextRunUtc}  {last}").AppendLine();
            }
        }

        return sb.ToString();
    }

    private static async Task<int> WriteReportAsync(ScanReport report, CliOptions options, TextWriter stdout, TextWriter stderr, CancellationToken cancellationToken)
    {
        string output = options.Json
            ? JsonReportWriter.Write(report, ToolVersion)
            : TextReportWriter.Write(report, options.Quiet);

        if (options.OutputPath is not null)
        {
            try
            {
                await File.WriteAllTextAsync(options.OutputPath, output, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                await stderr.WriteLineAsync($"error: could not write report: {ex.Message}");
                return ExitCodes.Fatal;
            }
        }
        else
        {
            await stdout.WriteAsync(output);
        }

        return report.HasDetections ? ExitCodes.Detections
            : report.HasSuspicious ? ExitCodes.Suspicious
            : report.IsComplete ? ExitCodes.Clean
            : ExitCodes.Incomplete;
    }

    private static async Task<ScanReport> ScanStdinAsync(ScanRunner runner, Stream stdin, string name, CancellationToken ct)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        ScanItemResult item = await runner.ScanStreamAsync(stdin, name, ct);
        bool scanned = item.Status is ScanStatus.Clean or ScanStatus.Detected or ScanStatus.Suspicious;
        return new ScanReport
        {
            Targets = [name],
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            Engines = runner.Engines,
            Summary = new ScanSummary
            {
                ItemsSeen = 1,
                FilesScanned = scanned ? 1 : 0,
                Detected = item.Status == ScanStatus.Detected ? 1 : 0,
                Suspicious = item.Status == ScanStatus.Suspicious ? 1 : 0,
                Partial = item.IsIncomplete && item.Status != ScanStatus.NotScanned ? 1 : 0,
                Skipped = item.Status == ScanStatus.Skipped ? 1 : 0,
                NotScanned = item.Status == ScanStatus.NotScanned ? 1 : 0,
                BytesScanned = scanned ? item.SizeBytes ?? 0 : 0,
            },
            Items = [item],
            CleanItemsIncluded = true,
        };
    }
}
