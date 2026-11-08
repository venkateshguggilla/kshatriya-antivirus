using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Sentinel.Core;
using Sentinel.Response.Native;
using Sentinel.Scanning;

namespace Sentinel.Response;

/// <summary>Result of a quarantine attempt.</summary>
public sealed record QuarantineResult(QuarantineEntry? Entry, ActionFailure Failure, string? Message)
{
    public bool Succeeded => Entry is not null;

    public ItemAction ToAction() => Entry is not null ? ItemAction.Quarantined(Entry.Id) : ItemAction.Failed(Failure, Message);
}

/// <summary>Why a restore failed.</summary>
public enum RestoreFailure
{
    None,
    NotFound,
    InvalidPath,
    TargetExists,
    AccessDenied,
    IntegrityError,
    IoError,
}

/// <summary>Result of a restore attempt.</summary>
public sealed record RestoreResult(RestoreFailure Failure, string? RestoredPath, string? Message, bool MarkOfTheWeb)
{
    public bool Succeeded => Failure == RestoreFailure.None;

    public static string WireName(RestoreFailure failure) => failure switch
    {
        RestoreFailure.None => "none",
        RestoreFailure.NotFound => "notFound",
        RestoreFailure.InvalidPath => "invalidPath",
        RestoreFailure.TargetExists => "targetExists",
        RestoreFailure.AccessDenied => "accessDenied",
        RestoreFailure.IntegrityError => "integrityError",
        RestoreFailure.IoError => "ioError",
        _ => throw new ArgumentOutOfRangeException(nameof(failure)),
    };
}

/// <summary>
/// Removes files into the encrypted vault and restores them, acting only on handles it opened and
/// verified itself:
/// <list type="bullet">
/// <item>The file is opened without following reparse points, with read + delete access, and shared for
/// reading only, so nobody can change, rename or delete it while it is verified and stored.</item>
/// <item>Its content is hashed while it is encrypted into the vault; if the hash differs from what the scan
/// saw, nothing is changed.</item>
/// <item>Only after the vault copy is durable is the <em>same handle</em> marked for deletion. If that fails
/// (for example a running program), the vault copy is discarded and the file stays where it was.</item>
/// </list>
/// File access happens as the calling thread's identity (the client, when the service impersonates);
/// vault and audit access go through <see cref="IPrivilegeScope"/>. Every attempt is audited.
/// </summary>
public sealed class QuarantineManager
{
    public const long DefaultMaxFileBytes = 1024L * 1024 * 1024;

    private readonly IPrivilegeScope _privileged;
    private readonly long _maxFileBytes;
    private readonly TimeProvider _time;

    public QuarantineManager(QuarantineVault vault, AuditLog audit, IPrivilegeScope? privileged = null, long maxFileBytes = DefaultMaxFileBytes, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(vault);
        ArgumentNullException.ThrowIfNull(audit);
        Vault = vault;
        Audit = audit;
        _privileged = privileged ?? CurrentIdentityScope.Instance;
        _maxFileBytes = maxFileBytes;
        _time = time ?? TimeProvider.System;
    }

    public QuarantineVault Vault { get; }

    public AuditLog Audit { get; }

    public IReadOnlyList<QuarantineEntry> List() => _privileged.Run(Vault.List);

    public QuarantineEntry? Get(string id) => _privileged.Run(() => Vault.Get(id));

    /// <summary>Quarantines <paramref name="path"/>. <paramref name="expectedSha256"/> (from a scan) must still match.</summary>
    public QuarantineResult Quarantine(string path, Actor actor, IReadOnlyList<string> detections, string? expectedSha256, string origin)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentNullException.ThrowIfNull(detections);
        QuarantineResult result = QuarantineCore(path, actor, detections, expectedSha256, origin);
        string detail = result.Succeeded
            ? $"{origin}; sha256 {result.Entry!.Sha256}" + (detections.Count > 0 ? $"; {string.Join(", ", detections)}" : string.Empty)
            : $"{origin}; {WireNames.Of(result.Failure)}: {result.Message}";
        AuditSafely(actor, AuditActions.Quarantine, path, result.Succeeded ? AuditOutcomes.Succeeded : AuditOutcomes.Failed, detail, result.Entry?.Id);
        return result;
    }

    /// <summary>
    /// Restores an item to <paramref name="targetPath"/> (default: its original path). Never overwrites:
    /// the target must not exist. The restored file is marked as downloaded from the internet
    /// (Zone.Identifier, zone 3) so Windows keeps treating it with caution.
    /// </summary>
    public RestoreResult Restore(string id, string? targetPath, Actor actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        RestoreResult result = RestoreCore(id, targetPath, out QuarantineEntry? entry);
        string target = result.RestoredPath ?? targetPath ?? entry?.OriginalPath ?? id;
        string detail = result.Succeeded
            ? $"restored{(result.MarkOfTheWeb ? string.Empty : " (Zone.Identifier could not be written)")}"
            : $"{RestoreResult.WireName(result.Failure)}: {result.Message}";
        AuditSafely(actor, AuditActions.Restore, target, result.Succeeded ? AuditOutcomes.Succeeded : AuditOutcomes.Failed, detail, id);
        return result;
    }

    /// <summary>Permanently deletes a vault item. Returns false if it did not exist.</summary>
    public bool Delete(string id, Actor actor)
    {
        ArgumentNullException.ThrowIfNull(actor);
        QuarantineEntry? entry = Get(id);
        bool deleted = entry is not null && _privileged.Run(() => Vault.Delete(id));
        AuditSafely(actor, AuditActions.Delete, entry?.OriginalPath ?? id, deleted ? AuditOutcomes.Succeeded : AuditOutcomes.Failed, deleted ? "deleted permanently" : "not found", id);
        return deleted;
    }

    /// <summary>Records an operation that was refused before it started (for example a non-administrator restore).</summary>
    public void AuditDenied(Actor actor, string action, string target, string detail) =>
        AuditSafely(actor, action, target, AuditOutcomes.Denied, detail, null);

    /// <summary>Records any other audited event (for example exclusion changes).</summary>
    public void AuditEvent(Actor actor, string action, string target, string outcome, string? detail) =>
        AuditSafely(actor, action, target, outcome, detail, null);

    private QuarantineResult QuarantineCore(string path, Actor actor, IReadOnlyList<string> detections, string? expectedSha256, string origin)
    {
        if (!PathPolicy.IsLocalAbsolutePath(path))
        {
            return new QuarantineResult(null, ActionFailure.NotRegularFile, "Only fully qualified local paths can be quarantined.");
        }

        // Folders cannot be opened as files (the open would fail with "access denied"), so name the real
        // reason up front. GetFileAttributes does not follow links. The handle is re-checked after opening.
        if (TryGetAttributes(path) is FileAttributes pre && (pre & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            return new QuarantineResult(null, ActionFailure.NotRegularFile, "Only regular files can be quarantined (not links or folders).");
        }

        using SafeFileHandle handle = ResponseNative.CreateFile(
            PathPolicy.ToExtendedLengthPath(path),
            ResponseNative.GenericRead | ResponseNative.Delete | ResponseNative.FileReadAttributes,
            ResponseNative.FileShareRead,
            IntPtr.Zero,
            ResponseNative.OpenExisting,
            ResponseNative.FileFlagOpenReparsePoint | ResponseNative.FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            return new QuarantineResult(null, MapOpenError(error), new Win32Exception(error).Message);
        }

        if (!ResponseNative.GetFileInformationByHandleEx(handle, ResponseNative.FileAttributeTagInfoClass, out ResponseNative.FileAttributeTagInfo tag, (uint)Marshal.SizeOf<ResponseNative.FileAttributeTagInfo>())
            || !ResponseNative.GetFileInformationByHandle(handle, out ResponseNative.ByHandleFileInformation info))
        {
            int error = Marshal.GetLastPInvokeError();
            return new QuarantineResult(null, ActionFailure.IoError, new Win32Exception(error).Message);
        }

        var attributes = (FileAttributes)tag.FileAttributes;
        if ((attributes & FileAttributes.Directory) != 0 || PathPolicy.Classify(attributes) != ScanReason.None)
        {
            return new QuarantineResult(null, ActionFailure.NotRegularFile, "Only regular, locally present files can be quarantined (not links, folders or cloud placeholders).");
        }

        if (info.NumberOfLinks > 1)
        {
            return new QuarantineResult(null, ActionFailure.HardLinked, $"The file has {info.NumberOfLinks} hard links; removing one name would leave the content in place.");
        }

        // The FileStream does not own the handle's lifetime decisions below: disposition is set on the
        // same handle before the stream (and with it the handle) is closed.
        using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 0);
        if (stream.Length > _maxFileBytes)
        {
            return new QuarantineResult(null, ActionFailure.TooLarge, $"The file is larger than the {_maxFileBytes}-byte quarantine limit.");
        }

        QuarantineEntry entry;
        try
        {
            var draft = new QuarantineDraft(Path.GetFullPath(path), actor, detections, origin);
            entry = _privileged.Run(() => Vault.Store(stream, draft, expectedSha256, _time));
        }
        catch (VaultContentMismatchException ex)
        {
            return new QuarantineResult(null, ActionFailure.Changed, ex.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or VaultIntegrityException)
        {
            return new QuarantineResult(null, ex is IOException && stream.Position == 0 ? ActionFailure.IoError : ActionFailure.VaultError, ex.Message);
        }

        int deleteError = ResponseNative.MarkForDeletion(handle);
        if (deleteError != 0)
        {
            _privileged.Run(() => Vault.Delete(entry.Id));
            ActionFailure failure = deleteError is ResponseNative.ErrorAccessDenied or ResponseNative.ErrorSharingViolation
                ? ActionFailure.InUse
                : ActionFailure.IoError;
            return new QuarantineResult(null, failure, $"The file could not be removed ({new Win32Exception(deleteError).Message}); it was left in place.");
        }

        return new QuarantineResult(entry, ActionFailure.None, null);
    }

    private RestoreResult RestoreCore(string id, string? targetPath, out QuarantineEntry? entry)
    {
        entry = QuarantineVault.IsValidId(id) ? Get(id) : null;
        if (entry is null)
        {
            return new RestoreResult(RestoreFailure.NotFound, null, $"No quarantined item with id '{id}'.", false);
        }

        string target = targetPath ?? entry.OriginalPath;
        if (!PathPolicy.IsLocalAbsolutePath(target))
        {
            return new RestoreResult(RestoreFailure.InvalidPath, null, $"'{target}' is not a fully qualified local path.", false);
        }

        target = Path.GetFullPath(target);
        SafeFileHandle handle = ResponseNative.CreateFile(
            PathPolicy.ToExtendedLengthPath(target),
            ResponseNative.GenericWrite | ResponseNative.Delete,
            ResponseNative.FileShareNone,
            IntPtr.Zero,
            ResponseNative.CreateNew,
            ResponseNative.FileAttributeNormal,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            RestoreFailure failure = error switch
            {
                ResponseNative.ErrorFileExists or ResponseNative.ErrorAlreadyExists => RestoreFailure.TargetExists,
                ResponseNative.ErrorPathNotFound or ResponseNative.ErrorInvalidName => RestoreFailure.InvalidPath,
                ResponseNative.ErrorAccessDenied => RestoreFailure.AccessDenied,
                _ => RestoreFailure.IoError,
            };
            string message = failure == RestoreFailure.TargetExists
                ? $"'{target}' already exists; restore never overwrites. Choose another location."
                : new Win32Exception(error).Message;
            return new RestoreResult(failure, null, message, false);
        }

        using (var stream = new FileStream(handle, FileAccess.Write, bufferSize: 0))
        {
            try
            {
                QuarantineEntry item = entry;
                _privileged.Run(() =>
                {
                    Vault.ExtractTo(item, stream);
                    return true;
                });
                stream.Flush(flushToDisk: true);
            }
            catch (Exception ex) when (ex is VaultIntegrityException or CryptographicException or IOException or UnauthorizedAccessException)
            {
                // Remove the partial file through the handle that created it.
                _ = ResponseNative.MarkForDeletion(handle);
                RestoreFailure failure = ex is VaultIntegrityException or CryptographicException ? RestoreFailure.IntegrityError : RestoreFailure.IoError;
                return new RestoreResult(failure, null, ex.Message, false);
            }
        }

        bool motw = TryWriteMarkOfTheWeb(target);
        string restoredId = entry.Id;
        _privileged.Run(() => Vault.Delete(restoredId));
        return new RestoreResult(RestoreFailure.None, target, null, motw);
    }

    private static bool TryWriteMarkOfTheWeb(string target)
    {
        try
        {
            using var stream = new FileStream(PathPolicy.ToExtendedLengthPath(target) + ":Zone.Identifier", FileMode.Create, FileAccess.Write, FileShare.None);
            stream.Write(Encoding.ASCII.GetBytes("[ZoneTransfer]\r\nZoneId=3\r\n"));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            // FAT volumes have no alternate data streams. The restore itself still succeeded.
            return false;
        }
    }

    private static FileAttributes? TryGetAttributes(string path)
    {
        try
        {
            return File.GetAttributes(PathPolicy.ToExtendedLengthPath(path));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private static ActionFailure MapOpenError(int error) => error switch
    {
        ResponseNative.ErrorFileNotFound or ResponseNative.ErrorPathNotFound or ResponseNative.ErrorInvalidName => ActionFailure.NotFound,
        ResponseNative.ErrorAccessDenied or ResponseNative.ErrorCantAccessFile => ActionFailure.AccessDenied,
        ResponseNative.ErrorSharingViolation or ResponseNative.ErrorLockViolation => ActionFailure.Locked,
        _ => ActionFailure.IoError,
    };

    private void AuditSafely(Actor actor, string action, string target, string outcome, string? detail, string? quarantineId)
    {
        // A failing audit write must surface: callers see the exception rather than an unaudited success.
        _privileged.Run(() => Audit.Append(actor, action, target, outcome, detail, quarantineId));
    }
}

/// <summary>
/// Quarantines detected files during a scan. Only confirmed, high-confidence detections qualify
/// (category malware or test, confidence high); suspicious (heuristic) and potentially unwanted
/// findings are reported only, never actioned automatically. A detection inside an archive
/// quarantines the whole archive file.
/// </summary>
public sealed class QuarantineResponder(QuarantineManager manager, Actor actor) : IItemResponder
{
    public static bool IsEligible(ScanItemResult item)
    {
        ArgumentNullException.ThrowIfNull(item);
        return item.Status == ScanStatus.Detected
            && item.Kind == ScanItemKind.File
            && item.Sha256 is not null
            && item.Detections.Any(d => d.Confidence == DetectionConfidence.High && d.Category is DetectionCategory.Malware or DetectionCategory.TestFile);
    }

    public ValueTask<ItemAction?> RespondAsync(ScanItemResult item, CancellationToken cancellationToken)
    {
        if (!IsEligible(item))
        {
            return ValueTask.FromResult<ItemAction?>(null);
        }

        string[] names = [.. item.Detections.Where(d => d.Category != DetectionCategory.Suspicious).Select(d => d.Name).Distinct(StringComparer.Ordinal)];
        QuarantineResult result = manager.Quarantine(item.Path, actor, names, item.Sha256, "scan");
        return ValueTask.FromResult<ItemAction?>(result.ToAction());
    }
}
