using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Kshatriya.Core;
using Kshatriya.Protocol;
using Kshatriya.Response;
using Kshatriya.Runtime.Ipc;
using Kshatriya.Scanning;

namespace Kshatriya.Service;

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

/// <summary>
/// One client connection: handshake, then requests until the client disconnects. Operations that weaken
/// protection (restore, exclusions) and reading other users' quarantine items or the audit log require an
/// elevated administrator in production; a development service serves only its own user. Refusals are audited.
/// </summary>
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
        bool canManage = isAdmin || !core.RequireAdministrator;
        Actor actor = Actor.FromIdentity(caller);
        PipeNative.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint clientPid);
        Log.ClientConnected(logger, caller.Name, clientPid, isAdmin, hello.Client);

        await SendAsync(MessageType.HelloReply, new HelloReplyDto
        {
            Protocol = ProtocolVersion.Service,
            Service = $"Kshatriya Antivirus {ServiceCore.Version}",
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
                    await ScanAsync(ProtocolJson.Deserialize<ScanRequestDto>(frame.Json), caller, actor, cancellationToken);
                    break;
                case MessageType.QuarantineList:
                    ProtocolJson.Deserialize<EmptyDto>(frame.Json);
                    await SendAsync(MessageType.QuarantineListReply, ListQuarantine(actor, canManage), cancellationToken);
                    break;
                case MessageType.QuarantineAdd:
                    await QuarantineAddAsync(ProtocolJson.Deserialize<QuarantineAddDto>(frame.Json), caller, actor, cancellationToken);
                    break;
                case MessageType.QuarantineRestore:
                    await RestoreAsync(ProtocolJson.Deserialize<QuarantineRestoreDto>(frame.Json), caller, actor, canManage, cancellationToken);
                    break;
                case MessageType.QuarantineDelete:
                    await DeleteAsync(ProtocolJson.Deserialize<QuarantineDeleteDto>(frame.Json), actor, canManage, cancellationToken);
                    break;
                case MessageType.ExclusionsList:
                    ProtocolJson.Deserialize<EmptyDto>(frame.Json);
                    await ExclusionsListAsync(actor, canManage, cancellationToken);
                    break;
                case MessageType.ExclusionsChange:
                    await ExclusionsChangeAsync(ProtocolJson.Deserialize<ExclusionChangeDto>(frame.Json), actor, canManage, cancellationToken);
                    break;
                case MessageType.DetectionsQuery:
                    await DetectionsAsync(ProtocolJson.Deserialize<DetectionsQueryDto>(frame.Json), caller, canManage, cancellationToken);
                    break;
                case MessageType.ContentImport:
                    await ContentImportAsync(ProtocolJson.Deserialize<ContentImportDto>(frame.Json), caller, actor, canManage, cancellationToken);
                    break;
                case MessageType.AuditQuery:
                    await AuditAsync(ProtocolJson.Deserialize<AuditQueryDto>(frame.Json), actor, canManage, cancellationToken);
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

    private async Task ScanAsync(ScanRequestDto request, WindowsIdentity caller, Actor actor, CancellationToken cancellationToken)
    {
        string? invalid = ScanPathPolicy.Validate(request.Paths);
        if (invalid is not null)
        {
            await SendErrorAsync(ErrorCodes.InvalidPath, invalid, cancellationToken);
            return;
        }

        IItemResponder? responder;
        switch (request.Action)
        {
            case ScanActions.Report:
                responder = null;
                break;
            case ScanActions.Quarantine:
                // Quarantine opens and removes files while impersonating the caller, so it can only remove
                // files the caller could delete themselves.
                responder = new QuarantineResponder(core.Quarantine, actor);
                break;
            default:
                await SendErrorAsync(ErrorCodes.BadRequest, $"Unknown scan action '{request.Action}'.", cancellationToken);
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
                () => core.Coordinator.ScanAsync(request.Paths, request.IncludeClean, useCache: true, responder, progress, scanCancel.Token));

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

    private QuarantineListReplyDto ListQuarantine(Actor actor, bool canManage) => new()
    {
        Items = [.. core.Quarantine.List()
            .Where(e => canManage || e.ActorSid == actor.Sid)
            .Select(e => new QuarantineItemDto
            {
                Id = e.Id,
                OriginalPath = e.OriginalPath,
                Sha256 = e.Sha256,
                SizeBytes = e.SizeBytes,
                QuarantinedUtc = e.QuarantinedUtc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                User = e.ActorName,
                Detections = [.. e.Detections],
                Origin = e.Origin,
            })],
    };

    private async Task QuarantineAddAsync(QuarantineAddDto request, WindowsIdentity caller, Actor actor, CancellationToken cancellationToken)
    {
        if (!ScanPathPolicy.IsLocalAbsolutePath(request.Path))
        {
            await SendErrorAsync(ErrorCodes.InvalidPath, $"'{request.Path}' is not a fully qualified local path.", cancellationToken);
            return;
        }

        // The file is opened and removed as the caller; only the vault write runs as the service.
        QuarantineResult result = WindowsIdentity.RunImpersonated(
            caller.AccessToken,
            () => core.Quarantine.Quarantine(request.Path, actor, [], expectedSha256: null, origin: "manual"));
        if (result.Succeeded)
        {
            Log.Quarantined(logger, actor.Name, request.Path, result.Entry!.Id);
        }
        else
        {
            Log.QuarantineFailed(logger, request.Path, actor.Name, WireNames.Of(result.Failure));
        }

        await SendAsync(MessageType.OperationReply, new OperationReplyDto
        {
            Succeeded = result.Succeeded,
            Code = WireNames.Of(result.Failure),
            Message = result.Message,
            QuarantineId = result.Entry?.Id,
            Path = request.Path,
        }, cancellationToken);
    }

    private async Task RestoreAsync(QuarantineRestoreDto request, WindowsIdentity caller, Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        if (!canManage)
        {
            const string reason = "Restoring a quarantined file requires an elevated administrator (run the command as administrator).";
            core.Quarantine.AuditDenied(actor, AuditActions.Restore, request.Id, reason);
            Log.Denied(logger, AuditActions.Restore, actor.Name, reason);
            await SendErrorAsync(ErrorCodes.AccessDenied, reason, cancellationToken);
            return;
        }

        if (request.TargetPath is not null && !ScanPathPolicy.IsLocalAbsolutePath(request.TargetPath))
        {
            await SendErrorAsync(ErrorCodes.InvalidPath, $"'{request.TargetPath}' is not a fully qualified local path.", cancellationToken);
            return;
        }

        // The restored file is created as the caller, so it lands only where the caller may write.
        RestoreResult result = WindowsIdentity.RunImpersonated(caller.AccessToken, () => core.Quarantine.Restore(request.Id, request.TargetPath, actor));
        Log.Restored(logger, actor.Name, request.Id, result.RestoredPath ?? request.TargetPath ?? "-", RestoreResult.WireName(result.Failure));
        await SendAsync(MessageType.OperationReply, new OperationReplyDto
        {
            Succeeded = result.Succeeded,
            Code = RestoreResult.WireName(result.Failure),
            Message = result.Succeeded && !result.MarkOfTheWeb ? "Restored, but the internet zone mark could not be written on this volume." : result.Message,
            QuarantineId = request.Id,
            Path = result.RestoredPath,
        }, cancellationToken);
    }

    private async Task DeleteAsync(QuarantineDeleteDto request, Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        QuarantineEntry? entry = core.Quarantine.Get(request.Id);
        if (entry is not null && !canManage && entry.ActorSid != actor.Sid)
        {
            const string reason = "Only an elevated administrator can delete items quarantined for another user.";
            core.Quarantine.AuditDenied(actor, AuditActions.Delete, request.Id, reason);
            Log.Denied(logger, AuditActions.Delete, actor.Name, reason);
            await SendErrorAsync(ErrorCodes.AccessDenied, reason, cancellationToken);
            return;
        }

        bool deleted = entry is not null && core.Quarantine.Delete(request.Id, actor);
        Log.QuarantineDeleted(logger, actor.Name, request.Id, deleted);
        await SendAsync(MessageType.OperationReply, new OperationReplyDto
        {
            Succeeded = deleted,
            Code = deleted ? "none" : "notFound",
            Message = deleted ? null : $"No quarantined item with id '{request.Id}'.",
            QuarantineId = request.Id,
        }, cancellationToken);
    }

    private async Task ExclusionsListAsync(Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        if (!canManage)
        {
            Log.Denied(logger, "exclusionList", actor.Name, "not an elevated administrator");
            await SendErrorAsync(ErrorCodes.AccessDenied, "Viewing exclusions requires an elevated administrator.", cancellationToken);
            return;
        }

        await SendAsync(MessageType.ExclusionsReply, ExclusionsReply(), cancellationToken);
    }

    private async Task ExclusionsChangeAsync(ExclusionChangeDto request, Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        string? action = request.Operation switch
        {
            "add" => AuditActions.ExclusionAdd,
            "remove" => AuditActions.ExclusionRemove,
            _ => null,
        };
        if (action is null)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, $"Unknown exclusion operation '{request.Operation}'.", cancellationToken);
            return;
        }

        if (!canManage)
        {
            const string reason = "Changing exclusions requires an elevated administrator.";
            core.Quarantine.AuditDenied(actor, action, request.Value, reason);
            Log.Denied(logger, action, actor.Name, reason);
            await SendErrorAsync(ErrorCodes.AccessDenied, reason, cancellationToken);
            return;
        }

        string? problem = action == AuditActions.ExclusionAdd ? core.Exclusions.Add(request.Value) : core.Exclusions.Remove(request.Value);
        core.Quarantine.AuditEvent(actor, action, request.Value, problem is null ? AuditOutcomes.Succeeded : AuditOutcomes.Failed, problem);
        Log.ExclusionChanged(logger, actor.Name, request.Operation, request.Value, problem ?? "done");
        if (problem is not null)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, problem, cancellationToken);
            return;
        }

        await SendAsync(MessageType.ExclusionsReply, ExclusionsReply(), cancellationToken);
    }

    private async Task DetectionsAsync(DetectionsQueryDto request, WindowsIdentity caller, bool canManage, CancellationToken cancellationToken)
    {
        if (request.Max is < 1 or > 500)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, "max must be between 1 and 500.", cancellationToken);
            return;
        }

        // Administrators see everything; other users see findings under their own profile folder.
        string? profile = canManage ? null : ProfileDirectory(caller);
        var items = core.History.Recent(request.Max, r => canManage
            || (profile is not null && (r.Path.StartsWith(profile + "\\", StringComparison.OrdinalIgnoreCase) || r.Path.Equals(profile, StringComparison.OrdinalIgnoreCase))));
        await SendAsync(MessageType.DetectionsReply, new DetectionsReplyDto
        {
            Items = [.. items.Select(r => new DetectionRecordDto
            {
                TimeUtc = r.TimeUtc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                Source = r.Source,
                Path = r.Path,
                Status = WireNames.Of(r.Status),
                Names = [.. r.Names],
                Action = r.Action,
            })],
        }, cancellationToken);
    }

    private static string? ProfileDirectory(WindowsIdentity caller)
    {
        string? sid = caller.User?.Value;
        if (sid is null)
        {
            return null;
        }

        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        return key?.GetValue("ProfileImagePath") is string path ? Environment.ExpandEnvironmentVariables(path).TrimEnd('\\') : null;
    }

    private async Task ContentImportAsync(ContentImportDto request, WindowsIdentity caller, Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        const string action = "contentUpdate";
        if (!canManage)
        {
            const string reason = "Installing content updates requires an elevated administrator.";
            core.Quarantine.AuditDenied(actor, action, request.Path, reason);
            Log.Denied(logger, action, actor.Name, reason);
            await SendErrorAsync(ErrorCodes.AccessDenied, reason, cancellationToken);
            return;
        }

        if (!ScanPathPolicy.IsLocalAbsolutePath(request.Path))
        {
            await SendErrorAsync(ErrorCodes.InvalidPath, $"'{request.Path}' is not a fully qualified local path.", cancellationToken);
            return;
        }

        ContentImportReplyDto reply;
        try
        {
            // The package is read with the caller's rights and a size limit; it is verified as the service.
            byte[] package = WindowsIdentity.RunImpersonated(caller.AccessToken, () => ReadPackage(request.Path));
            Kshatriya.Updates.VerifiedContent content = await core.ImportContentAsync(package, cancellationToken);
            reply = new ContentImportReplyDto
            {
                Succeeded = true,
                Code = "none",
                Sequence = content.Manifest.Sequence,
                ExpiresUtc = content.Manifest.ExpiresUtc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                Message = $"Content {content.Manifest.Sequence} ({content.Files.Count} file(s), signed by key {content.KeyId}) is active.",
            };
            core.Quarantine.AuditEvent(actor, action, request.Path, AuditOutcomes.Succeeded, $"sequence {content.Manifest.Sequence}; key {content.KeyId}");
        }
        catch (Kshatriya.Updates.ContentVerificationException ex)
        {
            reply = new ContentImportReplyDto { Succeeded = false, Code = ex.Code, Message = ex.Message };
            core.Quarantine.AuditEvent(actor, action, request.Path, AuditOutcomes.Failed, $"{ex.Code}: {ex.Message}");
            Log.ContentRefused(logger, actor.Name, ex.Code, ex.Message);
        }
        catch (ScanCapacityException ex)
        {
            await SendErrorAsync(ErrorCodes.Busy, ex.Message, cancellationToken);
            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            reply = new ContentImportReplyDto { Succeeded = false, Code = "ioError", Message = ex.Message };
            core.Quarantine.AuditEvent(actor, action, request.Path, AuditOutcomes.Failed, ex.Message);
        }

        await SendAsync(MessageType.ContentImportReply, reply, cancellationToken);
    }

    private static byte[] ReadPackage(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > Kshatriya.Updates.ContentPackage.MaxPackageBytes)
        {
            throw new Kshatriya.Updates.ContentVerificationException(Kshatriya.Updates.ContentErrors.TooLarge, "The package is too large.");
        }

        byte[] data = new byte[stream.Length];
        stream.ReadExactly(data);
        return data;
    }

    private ExclusionsReplyDto ExclusionsReply()
    {
        var current = core.Exclusions.Current;
        return new ExclusionsReplyDto { Paths = [.. current.Paths], Sha256 = [.. current.Hashes.Order(StringComparer.Ordinal)] };
    }

    private async Task AuditAsync(AuditQueryDto request, Actor actor, bool canManage, CancellationToken cancellationToken)
    {
        if (!canManage)
        {
            const string reason = "not an elevated administrator";
            core.Quarantine.AuditDenied(actor, AuditActions.AuditRead, "audit log", reason);
            Log.Denied(logger, AuditActions.AuditRead, actor.Name, reason);
            await SendErrorAsync(ErrorCodes.AccessDenied, "Reading the audit log requires an elevated administrator.", cancellationToken);
            return;
        }

        if (request.Max is < 1 or > 1000)
        {
            await SendErrorAsync(ErrorCodes.BadRequest, "max must be between 1 and 1000.", cancellationToken);
            return;
        }

        AuditVerification verification = core.Quarantine.Audit.Verify();
        await SendAsync(MessageType.AuditReply, new AuditReplyDto
        {
            Records = [.. core.Quarantine.Audit.ReadRecent(request.Max).Select(r => new AuditRecordDto
            {
                Seq = r.Sequence,
                TimeUtc = r.TimeUtc.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                User = r.ActorName,
                Sid = r.ActorSid,
                Action = r.Action,
                Target = r.Target,
                Outcome = r.Outcome,
                Detail = r.Detail,
                QuarantineId = r.QuarantineId,
            })],
            ChainValid = verification.Valid,
            Problem = verification.Problem,
        }, cancellationToken);
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
