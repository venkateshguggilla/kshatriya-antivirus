using System.IO.Pipes;
using System.Security.Principal;
using Sentinel.Core;
using Sentinel.Protocol;

namespace Sentinel.Runtime.Ipc;

/// <summary>An error reported by the service.</summary>
public sealed class ServiceException : Exception
{
    public ServiceException()
    {
        Code = ErrorCodes.Internal;
    }

    public ServiceException(string message)
        : base(message)
    {
        Code = ErrorCodes.Internal;
    }

    public ServiceException(string message, Exception innerException)
        : base(message, innerException)
    {
        Code = ErrorCodes.Internal;
    }

    public ServiceException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

/// <summary>
/// Client for the Sentinel service pipe. It connects with impersonation allowed (so the service can
/// act as the caller), authenticates the server before sending anything, and speaks the framed protocol.
/// </summary>
public sealed class ServiceClient : IAsyncDisposable
{
    private static readonly FrameLimits s_replyLimits = new(256 << 20, 256 << 20);

    private readonly NamedPipeClientStream _pipe;

    private ServiceClient(NamedPipeClientStream pipe, HelloReplyDto hello)
    {
        _pipe = pipe;
        Hello = hello;
    }

    /// <summary>The service's view of this connection (identity, service version).</summary>
    public HelloReplyDto Hello { get; }

    public static async Task<ServiceClient> ConnectAsync(ServiceEndpoint endpoint, string clientName, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrEmpty(clientName);
        var pipe = new NamedPipeClientStream(".", endpoint.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation);
        try
        {
            try
            {
                await pipe.ConnectAsync(timeout, cancellationToken);
            }
            catch (TimeoutException ex)
            {
                throw new ServiceException($"The Sentinel service is not reachable (pipe '{endpoint.PipeName}'). Is it running?", ex);
            }

            endpoint.VerifyServer(pipe);

            byte[] hello = ProtocolJson.Serialize(new HelloDto { Protocol = ProtocolVersion.Service, Client = clientName });
            await FrameIO.WriteAsync(pipe, MessageType.Hello, hello, cancellationToken: cancellationToken);
            Frame? frame = await FrameIO.ReadAsync(pipe, FrameLimits.Control, cancellationToken);
            ThrowIfError(frame);
            HelloReplyDto reply = ProtocolJson.Expect<HelloReplyDto>(frame, MessageType.HelloReply);
            if (reply.Protocol != ProtocolVersion.Service)
            {
                throw new ServiceException(ErrorCodes.VersionMismatch, $"Service speaks protocol {reply.Protocol}; this client speaks {ProtocolVersion.Service}.");
            }

            return new ServiceClient(pipe, reply);
        }
        catch
        {
            await pipe.DisposeAsync();
            throw;
        }
    }

    public async Task<StatusReplyDto> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        await FrameIO.WriteAsync(_pipe, MessageType.Status, ProtocolJson.Serialize(new EmptyDto()), cancellationToken: cancellationToken);
        Frame? frame = await FrameIO.ReadAsync(_pipe, FrameLimits.Control, cancellationToken);
        ThrowIfError(frame);
        return ProtocolJson.Expect<StatusReplyDto>(frame, MessageType.StatusReply);
    }

    /// <summary>
    /// Asks the service to scan <paramref name="paths"/> as the calling user. Cancelling the token sends
    /// a cancel request; the service then stops and this method throws <see cref="OperationCanceledException"/>.
    /// </summary>
    public async Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool includeClean, IProgress<ScanProgressDto>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        byte[] request = ProtocolJson.Serialize(new ScanRequestDto { Paths = [.. paths], IncludeClean = includeClean });
        await FrameIO.WriteAsync(_pipe, MessageType.Scan, request, cancellationToken: cancellationToken);

        int cancelSent = 0;
        await using CancellationTokenRegistration onCancel = cancellationToken.Register(() =>
        {
            if (Interlocked.Exchange(ref cancelSent, 1) == 0)
            {
                _ = SendCancelAsync();
            }
        });

        while (true)
        {
            Frame? frame = await FrameIO.ReadAsync(_pipe, s_replyLimits, CancellationToken.None);
            if (frame?.Type == MessageType.ScanProgress)
            {
                progress?.Report(ProtocolJson.Deserialize<ScanProgressDto>(frame.Json));
                continue;
            }

            if (frame?.Type == MessageType.Error)
            {
                ErrorDto error = ProtocolJson.Deserialize<ErrorDto>(frame.Json);
                if (error.Code == ErrorCodes.Cancelled)
                {
                    throw new OperationCanceledException(error.Message, cancellationToken);
                }

                throw new ServiceException(error.Code, error.Message);
            }

            ScanResultDto result = ProtocolJson.Expect<ScanResultDto>(frame, MessageType.ScanResult);
            try
            {
                return ScanReportJson.Read(result.Report);
            }
            catch (FormatException ex)
            {
                throw new ProtocolException($"Service returned an invalid report: {ex.Message}", ex);
            }
        }
    }

    public ValueTask DisposeAsync() => _pipe.DisposeAsync();

    private async Task SendCancelAsync()
    {
        try
        {
            await FrameIO.WriteAsync(_pipe, MessageType.Cancel, ProtocolJson.Serialize(new EmptyDto()));
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // The connection is already gone; the scan ends with it.
        }
    }

    private static void ThrowIfError(Frame? frame)
    {
        if (frame?.Type == MessageType.Error)
        {
            ErrorDto error = ProtocolJson.Deserialize<ErrorDto>(frame.Json);
            throw new ServiceException(error.Code, error.Message);
        }
    }
}
