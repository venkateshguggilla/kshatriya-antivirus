using System.Reflection;
using System.Text;
using Sentinel.Core;
using Sentinel.Engines.Hash;
using Sentinel.Scanning;

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

        HashEngine engine;
        try
        {
            engine = HashEngine.CreateDefault(options.SignatureFiles.Select(HashSignatureDatabase.LoadFile));
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            await stderr.WriteLineAsync($"error: could not load signatures: {ex.Message}");
            return ExitCodes.Fatal;
        }

        var limits = new ScanLimits();
        limits = limits with
        {
            MaxFileSizeBytes = options.MaxFileSizeBytes ?? limits.MaxFileSizeBytes,
            PerItemTimeout = options.Timeout ?? limits.PerItemTimeout,
            MaxDegreeOfParallelism = options.Parallelism ?? limits.MaxDegreeOfParallelism,
        };

        var runner = new ScanRunner([engine], new ScanOptions { Limits = limits, IncludeCleanItems = options.IncludeClean });

        ScanReport report;
        try
        {
            report = options.ReadStdin
                ? await ScanStdinAsync(runner, [engine.Descriptor.ToInfo()], stdin, options.StdinName, cancellationToken)
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
            : report.IsComplete ? ExitCodes.Clean
            : ExitCodes.Incomplete;
    }

    private static async Task<ScanReport> ScanStdinAsync(ScanRunner runner, IReadOnlyList<EngineInfo> engines, Stream stdin, string name, CancellationToken ct)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        ScanItemResult item = await runner.ScanStreamAsync(stdin, name, ct);
        bool scanned = item.Status is ScanStatus.Clean or ScanStatus.Detected;
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
                Skipped = item.Status == ScanStatus.Skipped ? 1 : 0,
                NotScanned = item.Status == ScanStatus.NotScanned ? 1 : 0,
                BytesScanned = scanned ? item.SizeBytes ?? 0 : 0,
            },
            Items = [item],
            CleanItemsIncluded = true,
        };
    }
}
