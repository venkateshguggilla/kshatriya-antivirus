using System.Globalization;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime;
using Sentinel.Runtime.Workers;

namespace Sentinel.Service;

/// <summary>How a <see cref="ServiceCore"/> is started.</summary>
public sealed record ServiceCoreOptions
{
    public required ServicePaths Paths { get; init; }

    public required PipeServerOptions Pipe { get; init; }

    /// <summary>Settings to use instead of reading the config file (tests).</summary>
    public ServiceSettings? SettingsOverride { get; init; }

    public string WorkerPath { get; init; } = WorkerPoolOptions.DefaultWorkerPath;

    public TimeProvider Time { get; init; } = TimeProvider.System;

    public TimeZoneInfo TimeZone { get; init; } = TimeZoneInfo.Local;
}

/// <summary>
/// The service's moving parts: settings, sandboxed worker pool, scan coordinator, pipe server and
/// scheduler. Hosted by the Windows service (or a console in development); tests drive it directly.
/// </summary>
public sealed class ServiceCore : IDisposable
{
    private readonly ServiceCoreOptions _options;
    private readonly ILogger _logger;
    private readonly DateTimeOffset _started;
    private ScheduleState? _scheduleState;

    private ServiceCore(ServiceCoreOptions options, ServiceSettings settings, ScanCoordinator coordinator, ILogger logger)
    {
        _options = options;
        Settings = settings;
        Coordinator = coordinator;
        _logger = logger;
        _started = options.Time.GetUtcNow();
    }

    public static string Version { get; } =
        typeof(ServiceCore).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public ServiceSettings Settings { get; }

    public ScanCoordinator Coordinator { get; }

    /// <summary>Loads settings, verifies trusted files, prepares directories and starts the worker pool.</summary>
    public static async Task<ServiceCore> StartAsync(ServiceCoreOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        SecureStorage.EnsureDirectories(options.Paths);
        ServiceSettings settings = options.SettingsOverride ?? LoadSettings(options.Paths, logger);

        foreach (string file in settings.SignatureFiles.Concat(settings.RuleFiles))
        {
            string? problem = SecureStorage.CheckTrustedFile(file, options.Paths.Production);
            if (problem is not null)
            {
                throw new InvalidOperationException($"Refusing to load signatures or rules: {problem}");
            }
        }

        EngineConfiguration engines = EngineConfiguration.FromFiles(settings.SignatureFiles, settings.RuleFiles) with
        {
            Heuristics = settings.Heuristics,
            HeuristicsIncludeSigned = settings.HeuristicsIncludeSigned,
            MaxScanBytes = settings.MaxFileSizeBytes,
        };

        WorkerPoolAnalyzer pool = await WorkerPoolAnalyzer.StartAsync(
            new WorkerPoolOptions { Engines = engines, WorkerCount = settings.Workers, WorkerPath = options.WorkerPath },
            cancellationToken);
        foreach (string warning in pool.Warnings)
        {
            Log.EngineWarning(logger, warning);
        }

        Log.Started(
            logger,
            Version,
            options.Paths.Production ? "production" : "development",
            string.Join(", ", pool.Engines.Select(e => $"{e.Id} {e.Version} [{e.ContentVersion}]")));
        return new ServiceCore(options, settings, new ScanCoordinator(pool, settings), logger);
    }

    /// <summary>Serves the pipe and runs the scheduler until cancelled.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _scheduleState = new ScheduleState(_options.Paths.StateDirectory);
        var scheduler = new Scheduler(this, _scheduleState, new ReportStore(_options.Paths.ReportsDirectory, Settings.ReportRetention), _options.Time, _options.TimeZone, _logger);
        var server = new PipeServer(_options.Pipe, this, _logger);
        try
        {
            await Task.WhenAll(server.RunAsync(cancellationToken), scheduler.RunAsync(cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    public StatusReplyDto GetStatus()
    {
        var stats = Coordinator.Pool.Stats;
        DateTimeOffset now = _options.Time.GetUtcNow();
        return new StatusReplyDto
        {
            Version = Version,
            Mode = _options.Paths.Production ? "service" : "development",
            StartedUtc = Iso(_started),
            Engines = [.. Coordinator.Pool.Engines.Select(e => e.ToDto())],
            Workers = new WorkerStatsDto { Configured = stats.Configured, Running = stats.Running, Started = stats.Started, Crashed = stats.Crashed, TimedOut = stats.TimedOut },
            Cache = new CacheStatsDto { Entries = Coordinator.Cache.Count, Hits = Coordinator.Cache.Hits, Misses = Coordinator.Cache.Misses },
            Schedules = [.. Settings.ScheduledScans.Select(s =>
            {
                var last = _scheduleState?.Get(s.Name);
                return new ScheduleStatusDto
                {
                    Name = s.Name,
                    NextRunUtc = Iso(ScheduleCalculator.Next(s, now, _options.TimeZone)),
                    LastRunUtc = last is { Outcome: not "pending" } l ? Iso(l.LastRun) : null,
                    LastOutcome = last?.Outcome,
                };
            })],
            ActiveScans = Coordinator.ActiveScans,
        };
    }

    /// <summary>Writes one audit entry per detection or suspicious item.</summary>
    public void RecordDetections(ScanReport report, string requestedBy)
    {
        ArgumentNullException.ThrowIfNull(report);
        foreach (ScanItemResult item in report.Items.Where(i => i.Status is ScanStatus.Detected or ScanStatus.Suspicious))
        {
            Log.Finding(
                _logger,
                WireNames.Of(item.Status),
                item.Path,
                requestedBy,
                string.Join(", ", item.Detections.Select(d => d.Location is null ? d.Name : $"{d.Name} at {d.Location}")));
        }
    }

    public void Dispose() => Coordinator.Dispose();

    private static ServiceSettings LoadSettings(ServicePaths paths, ILogger logger)
    {
        if (!File.Exists(paths.ConfigFile))
        {
            Log.DefaultSettings(logger, paths.ConfigFile);
            return new ServiceSettings();
        }

        string? problem = SecureStorage.CheckTrustedFile(paths.ConfigFile, paths.Production);
        if (problem is not null)
        {
            throw new InvalidOperationException($"Refusing to use the settings file: {problem}");
        }

        return ServiceSettings.Parse(File.ReadAllText(paths.ConfigFile));
    }

    private static string Iso(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
}
