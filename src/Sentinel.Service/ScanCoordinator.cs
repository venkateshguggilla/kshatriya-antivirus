using Sentinel.Core;
using Sentinel.Runtime.Workers;
using Sentinel.Scanning;
using Sentinel.Scanning.Trust;

namespace Sentinel.Service;

/// <summary>Raised when the service already runs the maximum number of scans.</summary>
public sealed class ScanCapacityException : Exception
{
    public ScanCapacityException()
    {
    }

    public ScanCapacityException(string message)
        : base(message)
    {
    }

    public ScanCapacityException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Runs scans for the service: one shared sandboxed worker pool, one verdict cache and one trust
/// provider, with a cap on concurrent scans. Callers that scan on a user's behalf invoke this while
/// impersonating that user, so every file is opened with the user's own access rights.
/// </summary>
public sealed class ScanCoordinator : IDisposable
{
    private readonly WorkerPoolAnalyzer _pool;
    private readonly ServiceSettings _settings;
    private readonly ITrustProvider _trust = new AuthenticodeTrustProvider();
    private readonly SemaphoreSlim _capacity;

    public ScanCoordinator(WorkerPoolAnalyzer pool, ServiceSettings settings)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(settings);
        _pool = pool;
        _settings = settings;
        _capacity = new SemaphoreSlim(settings.MaxConcurrentScans, settings.MaxConcurrentScans);
    }

    public VerdictCache Cache { get; } = new();

    public WorkerPoolAnalyzer Pool => _pool;

    public int ActiveScans => _settings.MaxConcurrentScans - _capacity.CurrentCount;

    /// <summary>Runs a scan. Throws <see cref="ScanCapacityException"/> immediately if the service is at capacity.</summary>
    public async Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool includeClean, bool useCache, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!await _capacity.WaitAsync(TimeSpan.Zero, cancellationToken))
        {
            throw new ScanCapacityException($"The service is already running {_settings.MaxConcurrentScans} scan(s). Try again later.");
        }

        try
        {
            var limits = new ScanLimits
            {
                MaxFileSizeBytes = _settings.MaxFileSizeBytes,
                MaxDegreeOfParallelism = _settings.Workers,
            };
            var runner = new ScanRunner(_pool, new ScanOptions
            {
                Limits = limits,
                IncludeCleanItems = includeClean,
                TrustProvider = _trust,
                Cache = useCache ? Cache : null,
            });
            return await runner.ScanPathsAsync(paths, progress, cancellationToken);
        }
        finally
        {
            _capacity.Release();
        }
    }

    public void Dispose()
    {
        _pool.Dispose();
        _capacity.Dispose();
    }
}
