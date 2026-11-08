using System.Reflection;
using System.Text;
using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Engines.Hash;
using Sentinel.Engines.Pe;
using Sentinel.Engines.Yara;
using Sentinel.Scanning;
using Sentinel.Scanning.Trust;

namespace Sentinel.Cli;

/// <summary>Testable entry point: all I/O goes through the supplied streams and writers.</summary>
public static class CliApp
{
    public static string ToolVersion { get; } =
        typeof(CliApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

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
        }

        var engines = new List<IDetectionEngine>();
        YaraEngine? yara = null;
        try
        {
            engines.Add(HashEngine.CreateDefault(options.SignatureFiles.Select(HashSignatureDatabase.LoadFile)));

            if (YaraEngine.IsAvailable(out string? yaraUnavailable))
            {
                var sources = new List<YaraSource> { YaraEngine.BuiltInRules() };
                sources.AddRange(options.RuleFiles.Select(f => new YaraSource(File.ReadAllText(f, Encoding.UTF8), Path.GetFileName(f))));
                yara = YaraEngine.Create(sources, new YaraEngineOptions { MaxScanBytes = options.MaxFileSizeBytes ?? new ScanLimits().MaxFileSizeBytes });
                engines.Add(yara);
            }
            else if (options.RuleFiles.Count > 0)
            {
                await stderr.WriteLineAsync($"error: --rules requires the YARA engine, which is unavailable: {yaraUnavailable}");
                return ExitCodes.Fatal;
            }
            else
            {
                await stderr.WriteLineAsync($"warning: YARA engine unavailable ({yaraUnavailable}). Scanning without YARA rules.");
            }

            if (!options.NoHeuristics)
            {
                engines.Add(new PeHeuristicEngine(new PeHeuristicOptions { SkipValidlySigned = !options.HeuristicsIncludeSigned }));
            }
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            yara?.Dispose();
            await stderr.WriteLineAsync($"error: could not load signatures or rules: {ex.Message}");
            return ExitCodes.Fatal;
        }
        catch (YaraCompileException ex)
        {
            await stderr.WriteLineAsync($"error: {ex.Message}");
            return ExitCodes.Fatal;
        }

        using var yaraLifetime = yara;
        var limits = new ScanLimits();
        limits = limits with
        {
            MaxFileSizeBytes = options.MaxFileSizeBytes ?? limits.MaxFileSizeBytes,
            PerItemTimeout = options.Timeout ?? limits.PerItemTimeout,
            MaxDegreeOfParallelism = options.Parallelism ?? limits.MaxDegreeOfParallelism,
            Archives = options.ArchiveDepth is int depth ? limits.Archives with { MaxDepth = depth } : limits.Archives,
        };

        var runner = new ScanRunner(engines, new ScanOptions
        {
            Limits = limits,
            IncludeCleanItems = options.IncludeClean,
            TrustProvider = new AuthenticodeTrustProvider(),
        });

        ScanReport report;
        try
        {
            report = options.ReadStdin
                ? await ScanStdinAsync(runner, engines.Select(e => e.Descriptor.ToInfo()).ToArray(), stdin, options.StdinName, cancellationToken)
                : await runner.ScanPathsAsync(options.Targets, progress: null, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await stderr.WriteLineAsync("Scan cancelled. Results are incomplete.");
            return ExitCodes.Incomplete;
        }

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

    private static async Task<ScanReport> ScanStdinAsync(ScanRunner runner, IReadOnlyList<EngineInfo> engines, Stream stdin, string name, CancellationToken ct)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        ScanItemResult item = await runner.ScanStreamAsync(stdin, name, ct);
        bool scanned = item.Status is ScanStatus.Clean or ScanStatus.Detected or ScanStatus.Suspicious;
        return new ScanReport
        {
            Targets = [name],
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            Engines = engines,
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
