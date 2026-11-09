using System.Collections.Concurrent;
using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Runtime.Sandbox;
using Kshatriya.Scanning;
using Kshatriya.Scanning.Native;

namespace Kshatriya.Runtime.Workers;

/// <summary>Configuration of the sandboxed worker pool.</summary>
public sealed record WorkerPoolOptions
{
    public required EngineConfiguration Engines { get; init; }

    /// <summary>Worker executable. Defaults to Kshatriya.Worker.exe next to the current application.</summary>
    public string WorkerPath { get; init; } = DefaultWorkerPath;

    /// <summary>Maximum concurrent workers; each analyses one item at a time.</summary>
    public int WorkerCount { get; init; } = Math.Clamp(Environment.ProcessorCount, 1, 8);

    public SandboxOptions Sandbox { get; init; } = new();

    /// <summary>Refuse workers that do not report low (or untrusted) integrity. Only tests turn this off.</summary>
    public bool RequireLowIntegrity { get; init; } = true;

    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Margin kept between the worker's own soft deadline and the hard kill.</summary>
    public TimeSpan SoftDeadlineMargin { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>Starts workers with diagnostic probes enabled (sandbox tests only).</summary>
    public bool TestHooks { get; init; }

    public static string DefaultWorkerPath => Path.Combine(AppContext.BaseDirectory, "Kshatriya.Worker.exe");
}

/// <summary>Raised when the worker pool cannot start a usable worker.</summary>
public sealed class WorkerStartException : Exception
{
    public WorkerStartException()
    {
    }

    public WorkerStartException(string message)
        : base(message)
    {
    }

    public WorkerStartException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>True when the worker started but rejected the engine configuration (bad signatures or rules).</summary>
    public bool IsConfigurationError { get; init; }
}

/// <summary>Live counters for status reporting.</summary>
public readonly record struct WorkerPoolStats(int Configured, int Running, long Started, long Crashed, long TimedOut);

/// <summary>
/// Analyses content in sandboxed worker processes. The broker (this class) streams already-opened
/// content over the worker's standard input; the worker never opens files. A worker that crashes,
/// exceeds its memory cap, hangs past the item deadline or violates the protocol is killed and
/// replaced, and the item is reported as not (fully) scanned — the scan itself continues.
/// </summary>
public sealed class WorkerPoolAnalyzer : IContentAnalyzer, IDisposable
{
    private readonly WorkerPoolOptions _options;
    private readonly EngineConfigDto _config;
    private readonly SemaphoreSlim _slots;
    private readonly ConcurrentBag<Worker> _idle = [];
    private readonly ConcurrentDictionary<Worker, byte> _all = new();
    private readonly int _maxFrameBytes;
    private long _started;
    private long _crashed;
    private long _timedOut;
    private int _disposed;

    private WorkerPoolAnalyzer(WorkerPoolOptions options, EngineConfigDto config)
    {
        _options = options;
        _config = config;
        _slots = new SemaphoreSlim(options.WorkerCount, options.WorkerCount);
        // Frames carry only content that is not a file (standard input); files are shared as mapped sections.
        _maxFrameBytes = (int)Math.Min(FrameIO.AbsoluteMaxFrameBytes, Math.Min(options.Engines.MaxScanBytes, ScanLimits.MaxStreamBytes) + (2L << 20));
        Engines = [];
        ConfigurationFingerprint = string.Empty;
    }

    public IReadOnlyList<EngineInfo> Engines { get; private set; }

    public string ConfigurationFingerprint { get; private set; }

    /// <summary>Warnings reported by the first worker (for example YARA unavailable).</summary>
    public IReadOnlyList<string> Warnings { get; private set; } = [];

    public WorkerPoolStats Stats => new(_options.WorkerCount, _all.Count, Interlocked.Read(ref _started), Interlocked.Read(ref _crashed), Interlocked.Read(ref _timedOut));

    /// <summary>Starts the pool with one worker, verifying the sandbox and building the engines once.</summary>
    public static async Task<WorkerPoolAnalyzer> StartAsync(WorkerPoolOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.WorkerCount, 1);
        var pool = new WorkerPoolAnalyzer(options, options.Engines.ToDto());
        try
        {
            (Worker first, WorkerInitReplyDto reply) = await pool.StartWorkerAsync(cancellationToken);
            pool.Engines = [.. reply.Engines.Select(e => e.ToDomain())];
            pool.ConfigurationFingerprint = reply.Fingerprint;
            pool.Warnings = reply.Warnings;
            pool._idle.Add(first);
            return pool;
        }
        catch
        {
            pool.Dispose();
            throw;
        }
    }

    public async Task<AnalysisResult> AnalyzeAsync(AnalysisRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        bool canMap = request.File is not null && request.Length > 0;
        if (!canMap && request.Length + (1L << 20) > _maxFrameBytes)
        {
            return AnalysisResult.Failed(ScanReason.TooLarge, "Content is larger than the sandboxed worker limit for content that is not a file (1 GiB).");
        }

        try
        {
            await _slots.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded while waiting for a scan worker.");
        }

        Worker? worker = null;
        try
        {
            if (!_idle.TryTake(out worker))
            {
                try
                {
                    (worker, _) = await StartWorkerAsync(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded while starting a scan worker.");
                }
                catch (Exception ex) when (ex is WorkerStartException or SandboxException)
                {
                    return AnalysisResult.Failed(ScanReason.EngineError, $"Could not start a scan worker: {ex.Message}");
                }
            }

            (AnalysisResult result, WorkerOutcome outcome) = await worker.AnalyzeAsync(request, _options.SoftDeadlineMargin, _maxFrameBytes, cancellationToken);
            if (outcome != WorkerOutcome.Healthy)
            {
                if (outcome == WorkerOutcome.TimedOut)
                {
                    Interlocked.Increment(ref _timedOut);
                }
                else if (outcome == WorkerOutcome.Crashed)
                {
                    Interlocked.Increment(ref _crashed);
                }

                Retire(worker);
                worker = null;
            }

            return result;
        }
        finally
        {
            if (worker is not null)
            {
                _idle.Add(worker);
            }

            _slots.Release();
        }
    }

    /// <summary>Sends a diagnostic probe to a fresh worker (requires <see cref="WorkerPoolOptions.TestHooks"/>).</summary>
    public async Task<ProbeReplyDto> ProbeAsync(ProbeDto probe, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(probe);
        (Worker worker, _) = await StartWorkerAsync(CancellationToken.None);
        try
        {
            return await worker.ProbeAsync(probe, timeout);
        }
        finally
        {
            Retire(worker);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (Worker worker in _all.Keys)
        {
            worker.Dispose();
        }

        _all.Clear();
        _slots.Dispose();
    }

    private void Retire(Worker worker)
    {
        _all.TryRemove(worker, out _);
        worker.Dispose();
    }

    private async Task<(Worker Worker, WorkerInitReplyDto Reply)> StartWorkerAsync(CancellationToken cancellationToken)
    {
        string arguments = _options.TestHooks ? "--worker --test-hooks" : "--worker";
        SandboxedProcess process;
        try
        {
            process = SandboxedProcess.Start(_options.WorkerPath, arguments, _options.Sandbox);
        }
        catch (SandboxException ex)
        {
            throw new WorkerStartException($"Could not create the sandboxed worker process: {ex.Message}", ex);
        }

        var worker = new Worker(process);
        Interlocked.Increment(ref _started);
        _all[worker] = 0;
        try
        {
            WorkerInitReplyDto reply = await worker.InitializeAsync(_config, _options.StartupTimeout, cancellationToken);
            if (reply.Error is not null)
            {
                throw new WorkerStartException(reply.Error) { IsConfigurationError = true };
            }

            if (_options.RequireLowIntegrity && reply.IntegrityLevel is not ("low" or "untrusted"))
            {
                throw new WorkerStartException($"Worker reported integrity level '{reply.IntegrityLevel}'; refusing to scan without the sandbox.");
            }

            if (ConfigurationFingerprint.Length > 0 && !string.Equals(reply.Fingerprint, ConfigurationFingerprint, StringComparison.Ordinal))
            {
                throw new WorkerStartException("Worker engine configuration does not match the pool.");
            }

            return (worker, reply);
        }
        catch
        {
            Retire(worker);
            throw;
        }
    }

    private enum WorkerOutcome
    {
        Healthy,

        /// <summary>The worker may have been killed by a deadline that fired after its reply; do not reuse it.</summary>
        Recycle,
        TimedOut,
        Crashed,
    }

    /// <summary>One worker process and its request/response channel. Not thread-safe: one request at a time.</summary>
    private sealed class Worker(SandboxedProcess process) : IDisposable
    {
        private long _nextId;

        public async Task<WorkerInitReplyDto> InitializeAsync(EngineConfigDto config, TimeSpan timeout, CancellationToken cancellationToken)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);
            using CancellationTokenRegistration kill = deadline.Token.Register(process.Kill);
            try
            {
                byte[] json = ProtocolJson.Serialize(new WorkerInitDto { Protocol = ProtocolVersion.Worker, Engines = config });
                await FrameIO.WriteAsync(process.Input, MessageType.WorkerInit, json, cancellationToken: CancellationToken.None);
                Frame? frame = await FrameIO.ReadAsync(process.Output, FrameLimits.Control, CancellationToken.None);
                WorkerInitReplyDto reply = ProtocolJson.Expect<WorkerInitReplyDto>(frame, MessageType.WorkerInitReply);
                if (reply.Protocol != ProtocolVersion.Worker)
                {
                    throw new WorkerStartException($"Worker speaks protocol {reply.Protocol}; expected {ProtocolVersion.Worker}.");
                }

                return reply;
            }
            catch (Exception ex) when (ex is IOException or ProtocolException or ObjectDisposedException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string why = deadline.IsCancellationRequested ? "did not start in time" : "exited during startup";
                throw new WorkerStartException($"Scan worker {why}.{Diagnostics()}", ex);
            }
        }

        /// <summary>Returns the result and whether the worker can be reused.</summary>
        public async Task<(AnalysisResult Result, WorkerOutcome Outcome)> AnalyzeAsync(AnalysisRequest request, TimeSpan margin, int maxFrameBytes, CancellationToken cancellationToken)
        {
            long id = ++_nextId;
            TimeSpan soft = request.TimeBudget - margin;
            if (soft < TimeSpan.FromMilliseconds(100))
            {
                soft = TimeSpan.FromMilliseconds(100);
            }

            // A file on disk is shared as a read-only mapped section (any size, no copy through the pipe);
            // other content is streamed in the frame. Either way the worker never sees a path.
            long? section = null;
            if (request.File is { } file && request.Length > 0)
            {
                try
                {
                    using SafeSectionHandle mapping = FileMapping.CreateReadOnlySection(file);
                    if (RandomAccess.GetLength(file) != request.Length)
                    {
                        return (AnalysisResult.Failed(ScanReason.IoError, "The file changed size while it was being scanned."), WorkerOutcome.Healthy);
                    }

                    section = process.ShareReadOnlySection(mapping);
                }
                catch (IOException) when (request.Length + (1L << 20) <= maxFrameBytes)
                {
                    // Not mappable here (some network or virtual file systems): stream it instead.
                }
                catch (IOException ex)
                {
                    return (AnalysisResult.Failed(ScanReason.IoError, ex.Message), WorkerOutcome.Healthy);
                }
                catch (SandboxException ex)
                {
                    return (AnalysisResult.Failed(ScanReason.EngineError, $"Could not share the file with the scan worker: {ex.Message}"), WorkerOutcome.Recycle);
                }
            }

            var header = new AnalyzeDto
            {
                Id = id,
                DisplayPath = request.DisplayPath,
                Length = request.Length,
                Sha256 = request.Sha256,
                Trust = request.Trust?.ToDto(),
                BudgetMs = (long)soft.TotalMilliseconds,
                Section = section,
            };

            // Past the item deadline the worker is killed: nothing it does can hold the scan hostage.
            CancellationTokenRegistration kill = cancellationToken.Register(process.Kill);
            try
            {
                if (section is not null)
                {
                    await FrameIO.WriteAsync(process.Input, MessageType.Analyze, ProtocolJson.Serialize(header), cancellationToken: CancellationToken.None);
                }
                else
                {
                    request.Content.Position = 0;
                    await FrameIO.WriteAsync(process.Input, MessageType.Analyze, ProtocolJson.Serialize(header), request.Content, request.Length, CancellationToken.None);
                }
            }
            catch (Exception ex) when (ex is IOException or ProtocolException or ObjectDisposedException)
            {
                await kill.DisposeAsync();
                return Failure(ex, contentProblem: !process.HasExited && !cancellationToken.IsCancellationRequested, cancellationToken);
            }

            try
            {
                Frame? frame = await FrameIO.ReadAsync(process.Output, new FrameLimits(maxFrameBytes, 64 << 20), CancellationToken.None);
                AnalyzeReplyDto reply = ProtocolJson.Expect<AnalyzeReplyDto>(frame, MessageType.AnalyzeReply);
                if (reply.Id != id)
                {
                    throw new ProtocolException($"Reply id {reply.Id} does not match request {id}.");
                }

                var detections = reply.Detections.Select(d => d.ToDomain()).ToList();
                var result = new AnalysisResult(detections, DtoMapping.ParseReason(reply.Reason), reply.Message);

                // Disposing waits for a running kill callback, so after it the token state is final.
                await kill.DisposeAsync();
                return (result, cancellationToken.IsCancellationRequested ? WorkerOutcome.Recycle : WorkerOutcome.Healthy);
            }
            catch (Exception ex) when (ex is IOException or ProtocolException or ObjectDisposedException)
            {
                await kill.DisposeAsync();
                return Failure(ex, contentProblem: false, cancellationToken);
            }
        }

        public async Task<ProbeReplyDto> ProbeAsync(ProbeDto probe, TimeSpan timeout)
        {
            using var deadline = new CancellationTokenSource(timeout);
            using CancellationTokenRegistration kill = deadline.Token.Register(process.Kill);
            try
            {
                await FrameIO.WriteAsync(process.Input, MessageType.Probe, ProtocolJson.Serialize(probe));
                Frame? frame = await FrameIO.ReadAsync(process.Output, FrameLimits.Control);
                return ProtocolJson.Expect<ProbeReplyDto>(frame, MessageType.ProbeReply);
            }
            catch (Exception ex) when (ex is IOException or ProtocolException or ObjectDisposedException)
            {
                process.WaitForExit(TimeSpan.FromSeconds(5));
                return new ProbeReplyDto
                {
                    Succeeded = false,
                    Detail = deadline.IsCancellationRequested ? "worker-killed-after-timeout" : $"worker-exited:{process.ExitCode?.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) ?? "?"}",
                };
            }
        }

        public void Dispose() => process.Dispose();

        private (AnalysisResult, WorkerOutcome) Failure(Exception ex, bool contentProblem, CancellationToken cancellationToken)
        {
            process.Kill();
            if (cancellationToken.IsCancellationRequested)
            {
                return (AnalysisResult.Failed(ScanReason.Timeout, "Per-item time limit exceeded; the scan worker was stopped and its partial findings discarded."), WorkerOutcome.TimedOut);
            }

            if (contentProblem)
            {
                // The file changed while it was streamed; the worker is fine but its input is now out of sync.
                return (AnalysisResult.Failed(ScanReason.IoError, ex.Message), WorkerOutcome.Recycle);
            }

            process.WaitForExit(TimeSpan.FromSeconds(2));
            return (AnalysisResult.Failed(ScanReason.EngineError, $"The scan worker stopped unexpectedly while analysing this item.{Diagnostics()}"), WorkerOutcome.Crashed);
        }

        private string Diagnostics()
        {
            uint? code = process.ExitCode;
            string tail = process.ErrorTail.Trim();
            if (tail.Length > 300)
            {
                tail = string.Concat("…", tail.AsSpan(tail.Length - 300));
            }

            string exit = code is uint c ? $" Exit code 0x{c:X8}." : string.Empty;
            return tail.Length > 0 ? $"{exit} Worker error output: {tail}" : exit;
        }
    }
}
