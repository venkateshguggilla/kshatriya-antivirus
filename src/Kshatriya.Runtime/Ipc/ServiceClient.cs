using System.IO.Pipes;
using System.Security.Principal;
using Kshatriya.Core;
using Kshatriya.Protocol;

namespace Kshatriya.Runtime.Ipc;

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
/// Client for the Kshatriya service pipe. It connects with impersonation allowed (so the service can
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
                throw new ServiceException($"The Kshatriya service is not reachable (pipe '{endpoint.PipeName}'). Is it running?", ex);
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
    public Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool includeClean, IProgress<ScanProgressDto>? progress = null, CancellationToken cancellationToken = default) =>
        ScanAsync(paths, includeClean, quarantine: false, progress, cancellationToken);

    /// <summary>
    /// Asks the service to scan as the calling user; with <paramref name="quarantine"/> high-confidence
    /// detections are quarantined (files the caller can delete only).
    /// </summary>
    public Task<ScanReport> ScanAsync(IReadOnlyList<string> paths, bool includeClean, bool quarantine, IProgress<ScanProgressDto>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return SendScanAsync([.. paths], ScanKinds.Custom, includeClean, quarantine, progress, cancellationToken);
    }

    /// <summary>
    /// Asks the service for a quick (<see cref="ScanKinds.Quick"/>) or full (<see cref="ScanKinds.Full"/>)
    /// scan; the service determines the targets and still opens every file as the calling user.
    /// </summary>
    public Task<ScanReport> ScanKindAsync(string kind, bool includeClean, bool quarantine, IProgress<ScanProgressDto>? progress = null, CancellationToken cancellationToken = default)
    {
        if (kind is not (ScanKinds.Quick or ScanKinds.Full))
        {
            throw new ArgumentException($"Unknown scan kind '{kind}'.", nameof(kind));
        }

        return SendScanAsync([], kind, includeClean, quarantine, progress, cancellationToken);
    }

    private async Task<ScanReport> SendScanAsync(List<string> paths, string kind, bool includeClean, bool quarantine, IProgress<ScanProgressDto>? progress, CancellationToken cancellationToken)
    {
        byte[] request = ProtocolJson.Serialize(new ScanRequestDto
        {
            Paths = paths,
            Kind = kind,
            IncludeClean = includeClean,
            Action = quarantine ? ScanActions.Quarantine : ScanActions.Report,
        });
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

    public Task<QuarantineListReplyDto> ListQuarantineAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<EmptyDto, QuarantineListReplyDto>(MessageType.QuarantineList, new EmptyDto(), MessageType.QuarantineListReply, cancellationToken);

    public Task<OperationReplyDto> QuarantineFileAsync(string path, CancellationToken cancellationToken = default) =>
        RequestAsync<QuarantineAddDto, OperationReplyDto>(MessageType.QuarantineAdd, new QuarantineAddDto { Path = path }, MessageType.OperationReply, cancellationToken);

    public Task<OperationReplyDto> RestoreAsync(string id, string? targetPath, CancellationToken cancellationToken = default) =>
        RequestAsync<QuarantineRestoreDto, OperationReplyDto>(MessageType.QuarantineRestore, new QuarantineRestoreDto { Id = id, TargetPath = targetPath }, MessageType.OperationReply, cancellationToken);

    public Task<OperationReplyDto> DeleteQuarantinedAsync(string id, CancellationToken cancellationToken = default) =>
        RequestAsync<QuarantineDeleteDto, OperationReplyDto>(MessageType.QuarantineDelete, new QuarantineDeleteDto { Id = id }, MessageType.OperationReply, cancellationToken);

    public Task<ExclusionsReplyDto> GetExclusionsAsync(CancellationToken cancellationToken = default) =>
        RequestAsync<EmptyDto, ExclusionsReplyDto>(MessageType.ExclusionsList, new EmptyDto(), MessageType.ExclusionsReply, cancellationToken);

    /// <summary>Adds or removes an exclusion (<paramref name="add"/>); returns the resulting list.</summary>
    public Task<ExclusionsReplyDto> ChangeExclusionAsync(bool add, string value, CancellationToken cancellationToken = default) =>
        RequestAsync<ExclusionChangeDto, ExclusionsReplyDto>(MessageType.ExclusionsChange, new ExclusionChangeDto { Operation = add ? "add" : "remove", Value = value }, MessageType.ExclusionsReply, cancellationToken);

    public Task<AuditReplyDto> GetAuditAsync(int max, CancellationToken cancellationToken = default) =>
        RequestAsync<AuditQueryDto, AuditReplyDto>(MessageType.AuditQuery, new AuditQueryDto { Max = max }, MessageType.AuditReply, cancellationToken);

    /// <summary>Recent findings visible to the caller (administrators: all; others: under their profile).</summary>
    public Task<DetectionsReplyDto> GetDetectionsAsync(int max, CancellationToken cancellationToken = default) =>
        RequestAsync<DetectionsQueryDto, DetectionsReplyDto>(MessageType.DetectionsQuery, new DetectionsQueryDto { Max = max }, MessageType.DetectionsReply, cancellationToken);

    /// <summary>Asks the service to verify and install a signed content package (administrator only).</summary>
    public Task<ContentImportReplyDto> ImportContentAsync(string packagePath, CancellationToken cancellationToken = default) =>
        RequestAsync<ContentImportDto, ContentImportReplyDto>(MessageType.ContentImport, new ContentImportDto { Path = packagePath }, MessageType.ContentImportReply, cancellationToken);

    public ValueTask DisposeAsync() => _pipe.DisposeAsync();

    private async Task<TReply> RequestAsync<TRequest, TReply>(byte type, TRequest request, byte replyType, CancellationToken cancellationToken)
        where TRequest : class
        where TReply : class
    {
        await FrameIO.WriteAsync(_pipe, type, ProtocolJson.Serialize(request), cancellationToken: cancellationToken);
        Frame? frame = await FrameIO.ReadAsync(_pipe, s_replyLimits, cancellationToken);
        ThrowIfError(frame);
        return ProtocolJson.Expect<TReply>(frame, replyType);
    }

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
