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
    private WorkerPoolAnalyzer _pool;
    private readonly ServiceSettings _settings;
    private readonly ITrustProvider _trust = new AuthenticodeTrustProvider();
    private readonly SemaphoreSlim _capacity;
    private readonly ExclusionStore _exclusions;

    public ScanCoordinator(WorkerPoolAnalyzer pool, ServiceSettings settings, ExclusionStore exclusions)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(exclusions);
        _pool = pool;
        _settings = settings;
        _exclusions = exclusions;
        _capacity = new SemaphoreSlim(settings.MaxConcurrentScans, settings.MaxConcurrentScans);
    }

    public VerdictCache Cache { get; } = new();

    public WorkerPoolAnalyzer Pool => Volatile.Read(ref _pool);

    public int ActiveScans => _settings.MaxConcurrentScans - _capacity.CurrentCount;

    /// <summary>
    /// Runs a scan with the current exclusions. <paramref name="responder"/> (quarantine) is optional.
    /// Throws <see cref="ScanCapacityException"/> immediately if the service is at capacity.
    /// </summary>
    public async Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool includeClean, bool useCache, IItemResponder? responder, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
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
            var runner = new ScanRunner(Pool, new ScanOptions
            {
                Limits = limits,
                IncludeCleanItems = includeClean,
                TrustProvider = _trust,
                Cache = useCache ? Cache : null,
                Exclusions = _exclusions.Current,
                Responder = responder,
            });
            return await runner.ScanPathsAsync(paths, progress, cancellationToken);
        }
        finally
        {
            _capacity.Release();
        }
    }

    /// <summary>
    /// Replaces the worker pool (new content) between scans: waits up to <paramref name="timeout"/> until no
    /// scan is running, swaps, then disposes the old pool. Throws <see cref="ScanCapacityException"/> if scans
    /// keep running.
    /// </summary>
    public async Task SwapPoolAsync(WorkerPoolAnalyzer next, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(next);
        int acquired = 0;
        try
        {
            for (; acquired < _settings.MaxConcurrentScans; acquired++)
            {
                if (!await _capacity.WaitAsync(timeout, cancellationToken))
                {
                    throw new ScanCapacityException("Scans are still running; try the update again when they finish.");
                }
            }

            WorkerPoolAnalyzer old = Interlocked.Exchange(ref _pool, next);
            old.Dispose();
        }
        finally
        {
            if (acquired > 0)
            {
                _capacity.Release(acquired);
            }
        }
    }

    public void Dispose()
    {
        Pool.Dispose();
        _capacity.Dispose();
    }
}
