using System.Globalization;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Response;
using Sentinel.Runtime;
using Sentinel.Runtime.Workers;
using Sentinel.Updates;

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

    /// <summary>
    /// Require an elevated administrator for restore, exclusions, the audit log and other users'
    /// quarantine items. Null (default) requires it in production only; a development service serves
    /// only its own user.
    /// </summary>
    public bool? RequireAdministrator { get; init; }
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
    private readonly SemaphoreSlim _contentGate = new(1, 1);
    private readonly ContentStore _contentStore;
    private readonly IReadOnlyList<ContentKey> _contentKeys;
    private ScheduleState? _scheduleState;

    private ServiceCore(ServiceCoreOptions options, ServiceSettings settings, ScanCoordinator coordinator, ExclusionStore exclusions, QuarantineManager quarantine, ILogger logger, ContentStore contentStore, IReadOnlyList<ContentKey> contentKeys, VerifiedContent? content, string? contentProblem)
    {
        _options = options;
        _contentStore = contentStore;
        _contentKeys = contentKeys;
        ActiveContent = content;
        ContentProblem = contentProblem;
        Settings = settings;
        Coordinator = coordinator;
        Exclusions = exclusions;
        Quarantine = quarantine;
        _logger = logger;
        _started = options.Time.GetUtcNow();
    }

    public static string Version { get; } =
        typeof(ServiceCore).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    public ServiceSettings Settings { get; }

    public ScanCoordinator Coordinator { get; }

    public ExclusionStore Exclusions { get; }

    public QuarantineManager Quarantine { get; }

    /// <summary>True for the installed service; false for a development service that serves only its own user.</summary>
    public bool IsProduction => _options.Paths.Production;

    /// <summary>The verified content package in use, or null when only built-in content is loaded.</summary>
    public VerifiedContent? ActiveContent { get; private set; }

    /// <summary>Why installed content could not be loaded, if it could not.</summary>
    public string? ContentProblem { get; private set; }

    /// <summary>Whether management operations require an elevated administrator.</summary>
    public bool RequireAdministrator => _options.RequireAdministrator ?? _options.Paths.Production;

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

        ExclusionStore exclusions = ExclusionStore.Load(options.Paths.ExclusionsFile, options.Paths.Production);
        StorageAccess access = options.Paths.Production ? StorageAccess.Machine : StorageAccess.CurrentUser;
        var quarantine = new QuarantineManager(
            QuarantineVault.Open(options.Paths.QuarantineDirectory, access),
            AuditLog.Open(options.Paths.AuditDirectory, access, options.Time),
            ProcessIdentityScope.Instance,
            time: options.Time);

        IReadOnlyList<ContentKey> keys = [.. ContentTrust.ProductionKeys, .. settings.ContentKeys.Select(ContentKey.Parse)];
        var contentStore = new ContentStore(options.Paths.ContentDirectory, options.Paths.Production);
        VerifiedContent? content = null;
        string? contentProblem = null;
        try
        {
            content = contentStore.LoadActive(keys, options.Time.GetUtcNow());
        }
        catch (Exception ex) when (ex is ContentVerificationException or IOException or FormatException or System.Text.Json.JsonException)
        {
            // Fail safe: keep protecting with built-in and configured content, and say so loudly.
            contentProblem = $"Installed content was not loaded: {ex.Message}";
            Log.ContentProblem(logger, contentProblem);
        }

        WorkerPoolAnalyzer pool;
        try
        {
            pool = await StartPoolAsync(options, settings, content, cancellationToken);
        }
        catch (WorkerStartException ex) when (ex.IsConfigurationError && content is not null)
        {
            contentProblem = $"Installed content {content.Manifest.Sequence} could not be loaded by the engines: {ex.Message}";
            Log.ContentProblem(logger, contentProblem);
            content = null;
            pool = await StartPoolAsync(options, settings, null, cancellationToken);
        }
        foreach (string warning in pool.Warnings)
        {
            Log.EngineWarning(logger, warning);
        }

        Log.Started(
            logger,
            Version,
            options.Paths.Production ? "production" : "development",
            string.Join(", ", pool.Engines.Select(e => $"{e.Id} {e.Version} [{e.ContentVersion}]")));
        return new ServiceCore(options, settings, new ScanCoordinator(pool, settings, exclusions), exclusions, quarantine, logger, contentStore, keys, content, contentProblem);
    }

    /// <summary>
    /// Verifies and activates a content package: signature, hashes, expiry, anti-rollback, then a new
    /// sandboxed worker pool must build its engines from it before it replaces the running pool. Any
    /// failure leaves the current content in use.
    /// </summary>
    public async Task<VerifiedContent> ImportContentAsync(byte[] package, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);
        await _contentGate.WaitAsync(cancellationToken);
        try
        {
            VerifiedContent content = ContentPackage.Verify(package, _contentKeys, _options.Time.GetUtcNow());
            _contentStore.CheckForward(content.Manifest);
            long sequence = content.Manifest.Sequence;
            _contentStore.Stage(sequence, package);
            WorkerPoolAnalyzer next;
            try
            {
                next = await StartPoolAsync(_options, Settings, content, cancellationToken);
            }
            catch (WorkerStartException ex) when (ex.IsConfigurationError)
            {
                _contentStore.Discard(sequence);
                throw new ContentVerificationException(ContentErrors.ContentInvalid, $"The engines rejected the package content: {ex.Message}");
            }

            try
            {
                await Coordinator.SwapPoolAsync(next, TimeSpan.FromSeconds(30), cancellationToken);
            }
            catch
            {
                next.Dispose();
                _contentStore.Discard(sequence);
                throw;
            }

            _contentStore.Activate(sequence);
            ActiveContent = content;
            ContentProblem = null;
            Coordinator.Cache.Clear();
            Log.ContentActivated(_logger, sequence, content.Manifest.Channel, content.KeyId);
            return content;
        }
        finally
        {
            _contentGate.Release();
        }
    }

    private static async Task<WorkerPoolAnalyzer> StartPoolAsync(ServiceCoreOptions options, ServiceSettings settings, VerifiedContent? content, CancellationToken cancellationToken)
    {
        EngineConfiguration engines = EngineConfiguration.FromFiles(settings.SignatureFiles, settings.RuleFiles) with
        {
            Heuristics = settings.Heuristics,
            HeuristicsIncludeSigned = settings.HeuristicsIncludeSigned,
            MaxScanBytes = settings.MaxFileSizeBytes,
        };
        if (content is not null)
        {
            string origin = $"content {content.Manifest.Sequence}";
            TextSource Source(ContentFile f) => new($"{origin}/{f.Name}", System.Text.Encoding.UTF8.GetString(content.Files[f.Name]));
            TextSource[] hashdbs = [.. content.Manifest.Files.Where(f => f.Kind == "hashdb").Select(Source)];
            TextSource[] rules = [.. content.Manifest.Files.Where(f => f.Kind == "yara").Select(Source)];
            engines = engines with
            {
                HashDatabases = [.. engines.HashDatabases, .. hashdbs],
                YaraRules = [.. engines.YaraRules, .. rules],
                YaraRequired = engines.YaraRequired || rules.Length > 0,
            };
        }

        return await WorkerPoolAnalyzer.StartAsync(
            new WorkerPoolOptions { Engines = engines, WorkerCount = settings.Workers, WorkerPath = options.WorkerPath },
            cancellationToken);
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
            QuarantineItems = Quarantine.List().Count,
            Exclusions = Exclusions.Current.Paths.Count + Exclusions.Current.Hashes.Count,
            AuditChainValid = Quarantine.Audit.Verify().Valid,
            Content = new ContentStatusDto
            {
                Sequence = ActiveContent?.Manifest.Sequence ?? 0,
                Channel = ActiveContent?.Manifest.Channel,
                ExpiresUtc = ActiveContent is { } c ? Iso(c.Manifest.ExpiresUtc) : null,
                Expired = ActiveContent is { } a && a.Manifest.ExpiresUtc <= now,
                Problem = ContentProblem,
            },
        };
    }

    /// <summary>Writes one log entry per detection or suspicious item, including any action taken.</summary>
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
                string.Join(", ", item.Detections.Select(d => d.Location is null ? d.Name : $"{d.Name} at {d.Location}")),
                item.Action switch
                {
                    null => "none (reported only)",
                    { Succeeded: true } a => $"quarantined ({a.QuarantineId})",
                    { } a => $"quarantine failed ({WireNames.Of(a.Failure)}); the file was left in place",
                });
        }
    }

    public void Dispose()
    {
        Coordinator.Dispose();
        _contentGate.Dispose();
    }

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
