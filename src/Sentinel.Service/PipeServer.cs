using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Sentinel.Protocol;
using Sentinel.Runtime.Ipc;
using Sentinel.Scanning;

namespace Sentinel.Service;

/// <summary>Pipe server configuration.</summary>
/// <param name="PipeName">Pipe name (without <c>\\.\pipe\</c>).</param>
/// <param name="Production">Production ACL (SYSTEM/Administrators full, Authenticated Users read/write) or development ACL (current user only).</param>
/// <param name="Listeners">Concurrent connections served.</param>
public sealed record PipeServerOptions(string PipeName, bool Production, int Listeners = 8);

/// <summary>
/// Accepts client connections on the service pipe. Remote (network) logons are denied by the pipe
/// ACL, non-administrators cannot create competing pipe instances, and several listeners keep the
/// name occupied so it is never free for another process to claim while the service runs.
/// </summary>
public sealed class PipeServer
{
    private readonly PipeServerOptions _options;
    private readonly ServiceCore _core;
    private readonly ILogger _logger;

    public PipeServer(PipeServerOptions options, ServiceCore core, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(core);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options;
        _core = core;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        // Claim the name with FILE_FLAG_FIRST_PIPE_INSTANCE: if another process already owns it, refuse to start.
        NamedPipeServerStream first;
        try
        {
            first = CreateInstance(firstInstance: true);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new InvalidOperationException($"The pipe '{_options.PipeName}' is already owned by another process; refusing to start.", ex);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException($"The pipe '{_options.PipeName}' is already in use; refusing to start.", ex);
        }

        var listeners = new List<Task> { ListenAsync(first, cancellationToken) };
        for (int i = 1; i < _options.Listeners; i++)
        {
            listeners.Add(ListenAsync(null, cancellationToken));
        }

        await Task.WhenAll(listeners);
    }

    private async Task ListenAsync(NamedPipeServerStream? instance, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe = instance ?? CreateInstance(firstInstance: false);
            instance = null;
            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken);
                using var session = new ClientSession(pipe, _core, _logger);
                await session.RunAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutting down.
            }
            catch (Exception ex) when (ex is IOException or ProtocolException or UnauthorizedAccessException)
            {
                Log.ConnectionEnded(_logger, ex.Message);
            }
            catch (Exception ex)
            {
                Log.ClientError(_logger, ex);
            }
            finally
            {
                await pipe.DisposeAsync();
            }
        }
    }

    private NamedPipeServerStream CreateInstance(bool firstInstance)
    {
        var security = new PipeSecurity();
        var network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
        security.AddAccessRule(new PipeAccessRule(network, PipeAccessRights.FullControl, AccessControlType.Deny));
        if (_options.Production)
        {
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

            // Read/write but not CreateNewInstance: ordinary users can talk to the service but not impersonate it.
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        }
        else
        {
            security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        PipeOptions options = PipeOptions.Asynchronous | (firstInstance ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(
            _options.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            options,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }
}

/// <summary>One client connection: handshake, then status and scan requests until the client disconnects.</summary>
internal sealed class ClientSession(NamedPipeServerStream pipe, ServiceCore core, ILogger logger) : IDisposable
{
    private static readonly FrameLimits s_requestLimits = FrameLimits.Control;
    private static readonly TimeSpan s_progressInterval = TimeSpan.FromMilliseconds(250);
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Channel<Frame> _inbox = Channel.CreateBounded<Frame>(16);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var sessionEnd = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task reader = ReadLoopAsync(sessionEnd.Token);
        try
        {
            await ServeAsync(sessionEnd.Token);
        }
        finally
        {
            await sessionEnd.CancelAsync();
            try
            {
                await reader;
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or ProtocolException or ObjectDisposedException)
            {
                // Reader stops with the session.
            }
        }
    }

    /// <summary>Single reader for the whole session, so a late cancel request never desynchronises the stream.</summary>
    private async Task ReadLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                Frame? frame = await FrameIO.ReadAsync(pipe, s_requestLimits, cancellationToken);
                if (frame is null)
                {
                    break;
                }

                await _inbox.Writer.WriteAsync(frame, cancellationToken);
            }

            _inbox.Writer.TryComplete();
        }
        catch (Exception ex)
        {
            _inbox.Writer.TryComplete(ex);
        }
    }

    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        if (!await _inbox.Reader.WaitToReadAsync(cancellationToken) || !_inbox.Reader.TryRead(out Frame? helloFrame))
        {
            return;
        }

        if (helloFrame.Type != MessageType.Hello)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, "Expected a hello message.", cancellationToken);
            return;
        }

        HelloDto hello = ProtocolJson.Deserialize<HelloDto>(helloFrame.Json);
        if (hello.Protocol != ProtocolVersion.Service)
        {
            await SendErrorAsync(ErrorCodes.VersionMismatch, $"This service speaks protocol {ProtocolVersion.Service}; the client sent {hello.Protocol}.", cancellationToken);
            return;
        }

        // The caller's identity comes from the pipe itself (impersonation), never from anything it sends.
        using WindowsIdentity? caller = GetCaller();
        if (caller is null || caller.ImpersonationLevel < TokenImpersonationLevel.Impersonation)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, "The client must allow impersonation so that scans run with its own access rights.", cancellationToken);
            return;
        }

        bool isAdmin = new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator);
        PipeNative.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint clientPid);
        Log.ClientConnected(logger, caller.Name, clientPid, isAdmin, hello.Client);

        await SendAsync(MessageType.HelloReply, new HelloReplyDto
        {
            Protocol = ProtocolVersion.Service,
            Service = $"Sentinel {ServiceCore.Version}",
            User = caller.Name,
            IsAdmin = isAdmin,
        }, cancellationToken);

        await foreach (Frame frame in _inbox.Reader.ReadAllAsync(cancellationToken))
        {
            switch (frame.Type)
            {
                case MessageType.Status:
                    await SendAsync(MessageType.StatusReply, core.GetStatus(), cancellationToken);
                    break;
                case MessageType.Scan:
                    await ScanAsync(ProtocolJson.Deserialize<ScanRequestDto>(frame.Json), caller, cancellationToken);
                    break;
                case MessageType.Cancel:
                    // No scan running; nothing to cancel.
                    break;
                default:
                    await SendErrorAsync(ErrorCodes.BadRequest, $"Unexpected message 0x{frame.Type:X2}.", cancellationToken);
                    return;
            }
        }
    }

    private async Task ScanAsync(ScanRequestDto request, WindowsIdentity caller, CancellationToken cancellationToken)
    {
        string? invalid = ScanPathPolicy.Validate(request.Paths);
        if (invalid is not null)
        {
            await SendErrorAsync(ErrorCodes.InvalidPath, invalid, cancellationToken);
            return;
        }

        Log.ScanRequested(logger, caller.Name, request.Paths.Count);
        using var scanCancel = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task watcher = WatchForCancelAsync(scanCancel);
        var progress = new ThrottledProgress(this, scanCancel.Token);
        try
        {
            // Every file is opened while impersonating the caller: the service cannot be used to read
            // anything the caller could not read themselves. Workers are started as the service identity.
            ScanReport report = await WindowsIdentity.RunImpersonatedAsync(
                caller.AccessToken,
                () => core.Coordinator.ScanAsync(request.Paths, request.IncludeClean, useCache: true, progress, scanCancel.Token));

            core.RecordDetections(report, caller.Name);

            // No progress frame may follow the result, or the client would read it as the next reply.
            await progress.StopAsync();
            await SendAsync(MessageType.ScanResult, new ScanResultDto { Report = ScanReportJson.Write(report, ServiceCore.Version) }, cancellationToken);
            Log.ScanFinished(
                logger,
                caller.Name,
                report.Summary.FilesScanned,
                report.Summary.Detected,
                report.Summary.Suspicious,
                report.Summary.NotScanned);
        }
        catch (ScanCapacityException ex)
        {
            await SendErrorAsync(ErrorCodes.Busy, ex.Message, cancellationToken);
        }
        catch (OperationCanceledException) when (scanCancel.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            Log.ScanCancelled(logger, caller.Name);
            await SendErrorAsync(ErrorCodes.Cancelled, "The scan was cancelled. Results are incomplete.", cancellationToken);
        }
        finally
        {
            await progress.StopAsync();
            await scanCancel.CancelAsync();
            await watcher;
        }
    }

    /// <summary>While a scan runs, consumes inbound frames: cancel (or the client disconnecting) stops the scan.</summary>
    private async Task WatchForCancelAsync(CancellationTokenSource scan)
    {
        try
        {
            while (await _inbox.Reader.WaitToReadAsync(scan.Token))
            {
                if (_inbox.Reader.TryRead(out Frame? frame))
                {
                    await scan.CancelAsync();
                    if (frame.Type != MessageType.Cancel)
                    {
                        Log.UnexpectedDuringScan(logger, frame.Type);
                    }

                    return;
                }
            }

            // Client disconnected.
            await scan.CancelAsync();
        }
        catch (OperationCanceledException)
        {
            // Scan finished first.
        }
        catch (Exception ex) when (ex is IOException or ProtocolException or ChannelClosedException)
        {
            await scan.CancelAsync();
        }
    }

    public void Dispose() => _writeLock.Dispose();

    private WindowsIdentity? GetCaller()
    {
        WindowsIdentity? identity = null;
        pipe.RunAsClient(() => identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Duplicate | TokenAccessLevels.Impersonate));
        return identity;
    }

    private async Task SendAsync<T>(byte type, T message, CancellationToken cancellationToken)
        where T : class
    {
        byte[] json = ProtocolJson.Serialize(message);
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            await FrameIO.WriteAsync(pipe, type, json, cancellationToken: cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private Task SendErrorAsync(string code, string message, CancellationToken cancellationToken) =>
        SendAsync(MessageType.Error, new ErrorDto { Code = code, Message = message }, cancellationToken);

    /// <summary>Forwards progress to the client at most every 250 ms, without blocking the scan.</summary>
    private sealed class ThrottledProgress(ClientSession session, CancellationToken cancellationToken) : IProgress<ScanProgress>
    {
        private readonly Lock _gate = new();
        private long _lastTicks = Environment.TickCount64;
        private Task _pending = Task.CompletedTask;
        private bool _stopped;

        public void Report(ScanProgress value)
        {
            lock (_gate)
            {
                long now = Environment.TickCount64;
                if (_stopped || !_pending.IsCompleted || now - _lastTicks < s_progressInterval.TotalMilliseconds)
                {
                    return;
                }

                _lastTicks = now;
                _pending = SendAsync(value);
            }
        }

        /// <summary>Stops further progress and waits for any frame already being written.</summary>
        public Task StopAsync()
        {
            lock (_gate)
            {
                _stopped = true;
                return _pending;
            }
        }

        private async Task SendAsync(ScanProgress value)
        {
            try
            {
                await session.SendAsync(MessageType.ScanProgress, new ScanProgressDto
                {
                    ItemsCompleted = value.ItemsCompleted,
                    Detected = value.Detected,
                    BytesScanned = value.BytesScanned,
                }, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
            {
                // Progress is best effort.
            }
        }
    }
}
