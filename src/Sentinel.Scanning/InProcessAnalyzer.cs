using Sentinel.Core;
using Sentinel.Engines;
using Sentinel.Scanning.Archives;

namespace Sentinel.Scanning;

/// <summary>
/// Runs engines and archive expansion in the current process. Used inside sandboxed workers, and
/// directly by the CLI when isolation is turned off (development and benchmarking).
/// </summary>
public sealed class InProcessAnalyzer : IContentAnalyzer
{
    private readonly IReadOnlyList<IDetectionEngine> _engines;
    private readonly ArchiveLimits _archives;

    public InProcessAnalyzer(IReadOnlyList<IDetectionEngine> engines, ArchiveLimits? archives = null, long maxScanBytes = 256L * 1024 * 1024)
    {
        ArgumentNullException.ThrowIfNull(engines);
        if (engines.Count == 0)
        {
            throw new ArgumentException("At least one engine is required.", nameof(engines));
        }

        _engines = engines;
        _archives = archives ?? new ArchiveLimits();
        Engines = [.. engines.Select(e => e.Descriptor.ToInfo())];
        ConfigurationFingerprint = AnalyzerFingerprint.Compute(Engines, _archives, maxScanBytes);
    }

    public IReadOnlyList<EngineInfo> Engines { get; }

    public string ConfigurationFingerprint { get; }

    public async Task<AnalysisResult> AnalyzeAsync(AnalysisRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var collector = new Collector();
        var subject = new ScanSubject(request.DisplayPath, request.Length, request.Sha256, request.Content, request.Trust);
        try
        {
            await AnalyzeAsync(subject, depth: 0, new ArchiveBudget(_archives), collector, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            collector.SetFailure(ScanReason.Timeout, "Per-item time limit exceeded.");
        }

        return collector.ToResult();
    }

    /// <summary>Runs every engine on the subject, then recurses into archive entries within the shared budget.</summary>
    private async Task AnalyzeAsync(ScanSubject subject, int depth, ArchiveBudget budget, Collector collector, CancellationToken cancellationToken)
    {
        foreach (IDetectionEngine engine in _engines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            subject.Content.Position = 0;
            try
            {
                IReadOnlyList<Detection> found = await engine.ScanAsync(subject, cancellationToken);
                foreach (Detection d in found)
                {
                    collector.Add(subject.Location is null ? d : d with { Location = subject.Location });
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (EngineTimeoutException ex)
            {
                collector.SetFailure(ScanReason.Timeout, $"Engine '{engine.Descriptor.Id}' timed out{At(subject)}: {ex.Message}");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A faulty engine must not take down the scan; the item is reported as incomplete.
                collector.SetFailure(ScanReason.EngineError, $"Engine '{engine.Descriptor.Id}' failed{At(subject)}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        if (depth >= budget.Limits.MaxDepth || !ZipExpander.LooksLikeZip(subject.Content))
        {
            return;
        }

        (ScanReason reason, string? message) = await ZipExpander.ExpandAsync(
            subject.Content,
            subject.Location,
            budget,
            entry => AnalyzeAsync(
                new ScanSubject(subject.DisplayPath, entry.Content.Length, entry.Sha256, entry.Content, trust: null, entry.Location),
                depth + 1,
                budget,
                collector,
                cancellationToken),
            cancellationToken);

        if (reason != ScanReason.None)
        {
            collector.SetFailure(reason, message);
        }

        subject.Content.Position = 0;
    }

    private static string At(ScanSubject subject) => subject.Location is null ? string.Empty : $" on '{subject.Location}'";

    /// <summary>Accumulates findings so that detections found before a limit or timeout are still reported.</summary>
    private sealed class Collector
    {
        private readonly List<Detection> _detections = [];
        private readonly Lock _gate = new();
        private ScanReason _reason;
        private string? _message;

        public void Add(Detection detection)
        {
            lock (_gate)
            {
                _detections.Add(detection);
            }
        }

        /// <summary>A timeout overrides other reasons; otherwise the first reason wins.</summary>
        public void SetFailure(ScanReason reason, string? message)
        {
            lock (_gate)
            {
                if (_reason == ScanReason.None || (reason == ScanReason.Timeout && _reason != ScanReason.Timeout))
                {
                    _reason = reason;
                    _message = message;
                }
            }
        }

        public AnalysisResult ToResult()
        {
            lock (_gate)
            {
                return new AnalysisResult([.. _detections], _reason, _message);
            }
        }
    }
}
