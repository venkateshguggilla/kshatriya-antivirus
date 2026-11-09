using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Service.RealTime;

/// <summary>A position in a volume's NTFS change journal.</summary>
public readonly record struct UsnCheckpoint(ulong JournalId, long Usn);

/// <summary>
/// Read access to one NTFS volume's change journal, used to find what changed while file-change
/// notifications were lost. Needs administrator or SYSTEM (opening the volume). Only metadata is read:
/// parent folders are opened by id for their path, without following reparse points; file contents are
/// opened later, by the normal scan through <c>SafeFileOpener</c>.
/// </summary>
public sealed partial class UsnJournal : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x80;
    private const uint ShareAll = 0x7;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint FsctlQueryUsnJournal = 0x000900F4;
    private const uint FsctlReadUsnJournal = 0x000900BB;
    private const int ErrorHandleEof = 38;

    private readonly SafeFileHandle _volume;
    private readonly SafeFileHandle _root;
    private readonly char[] _pathBuffer = new char[32768];

    private UsnJournal(SafeFileHandle volume, SafeFileHandle root)
    {
        _volume = volume;
        _root = root;
    }

    /// <summary>Opens the journal of the volume holding <paramref name="path"/>, or explains why it cannot.</summary>
    public static UsnJournal? TryOpen(string path, out string reason)
    {
        string? root = Path.GetPathRoot(Path.GetFullPath(path));
        if (root is null || root.Length != 3 || root[1] != ':')
        {
            reason = "not on a local drive";
            return null;
        }

        try
        {
            if (!string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            {
                reason = "the drive is not NTFS";
                return null;
            }
        }
        catch (IOException ex)
        {
            reason = ex.Message;
            return null;
        }

        SafeFileHandle volume = CreateFileW(@"\\.\" + root[..2], GenericRead, ShareAll, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (volume.IsInvalid)
        {
            reason = $"the volume cannot be opened ({new Win32Exception(Marshal.GetLastPInvokeError()).Message})";
            volume.Dispose();
            return null;
        }

        SafeFileHandle rootHandle = CreateFileW(root, FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero);
        if (rootHandle.IsInvalid)
        {
            reason = $"the drive root cannot be opened ({new Win32Exception(Marshal.GetLastPInvokeError()).Message})";
            rootHandle.Dispose();
            volume.Dispose();
            return null;
        }

        reason = "";
        return new UsnJournal(volume, rootHandle);
    }

    /// <summary>The journal's current end, or null (with a reason) if the journal is not active.</summary>
    public unsafe UsnCheckpoint? Current(out string reason)
    {
        byte* data = stackalloc byte[56]; // USN_JOURNAL_DATA_V0
        if (!DeviceIoControl(_volume, FsctlQueryUsnJournal, null, 0, data, 56, out int returned, IntPtr.Zero) || returned < 24)
        {
            reason = $"the change journal is not available ({new Win32Exception(Marshal.GetLastPInvokeError()).Message})";
            return null;
        }

        var span = new ReadOnlySpan<byte>(data, 56);
        reason = "";
        return new UsnCheckpoint(BinaryPrimitives.ReadUInt64LittleEndian(span), BinaryPrimitives.ReadInt64LittleEndian(span[16..]));
    }

    /// <summary>
    /// Full paths changed since <paramref name="from"/> (files that still exist under that name, and
    /// folders created or moved in). Returns null with a reason when the journal cannot cover the whole
    /// range (entries overwritten, journal recreated) or when more than <paramref name="maxPaths"/> paths
    /// changed; the caller then rescans in full.
    /// </summary>
    public unsafe IReadOnlyCollection<string>? ChangedSince(UsnCheckpoint from, int maxPaths, out string reason)
    {
        if (Current(out reason) is not UsnCheckpoint end)
        {
            return null;
        }

        if (end.JournalId != from.JournalId)
        {
            reason = "the change journal was recreated";
            return null;
        }

        // Latest state per file id: records arrive in order, so a later delete or rename-away undoes an
        // earlier create or write of the same file.
        var paths = new Dictionary<ulong, string>();
        var folders = new Dictionary<ulong, string?>();
        byte[] output = new byte[64 * 1024];
        byte* input = stackalloc byte[40]; // READ_USN_JOURNAL_DATA_V0
        var request = new Span<byte>(input, 40);
        long next = from.Usn;
        while (next < end.Usn)
        {
            request.Clear();
            BinaryPrimitives.WriteInt64LittleEndian(request, next);
            BinaryPrimitives.WriteUInt32LittleEndian(request[8..], uint.MaxValue); // every reason
            BinaryPrimitives.WriteUInt64LittleEndian(request[32..], from.JournalId);
            int returned;
            bool ok;
            fixed (byte* buffer = output)
            {
                ok = DeviceIoControl(_volume, FsctlReadUsnJournal, input, 40, buffer, output.Length, out returned, IntPtr.Zero);
            }

            if (!ok)
            {
                int error = Marshal.GetLastPInvokeError();
                if (error == ErrorHandleEof)
                {
                    break;
                }

                reason = $"the change journal could not be read ({new Win32Exception(error).Message})";
                return null;
            }

            if (returned < 8)
            {
                break;
            }

            long following = BinaryPrimitives.ReadInt64LittleEndian(output);
            foreach (UsnEntry entry in UsnRecords.Parse(output.AsSpan(8, returned - 8)))
            {
                if (!UsnRecords.IsScannable(entry))
                {
                    if ((entry.Reason & (UsnRecords.ReasonFileDelete | UsnRecords.ReasonRenameOldName)) != 0)
                    {
                        paths.Remove(entry.FileReference);
                    }
                }
                else if (FolderPath(entry.ParentReference, folders) is string parent)
                {
                    paths[entry.FileReference] = Path.Join(parent, entry.Name);
                    if (paths.Count > maxPaths)
                    {
                        reason = $"more than {maxPaths} paths changed";
                        return null;
                    }
                }
            }

            if (following <= next)
            {
                break; // no progress: stop rather than loop
            }

            next = following;
        }

        reason = "";
        return paths.Values.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        _root.Dispose();
        _volume.Dispose();
    }

    private unsafe string? FolderPath(ulong reference, Dictionary<ulong, string?> cache)
    {
        if (cache.TryGetValue(reference, out string? known))
        {
            return known;
        }

        byte* descriptor = stackalloc byte[24]; // FILE_ID_DESCRIPTOR: size, type 0 (64-bit id), id
        var span = new Span<byte>(descriptor, 24);
        span.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(span, 24);
        BinaryPrimitives.WriteUInt64LittleEndian(span[8..], reference);
        string? path = null;
        using (SafeFileHandle folder = OpenFileById(_root, descriptor, FileReadAttributes, ShareAll, IntPtr.Zero, BackupSemantics | OpenReparsePoint))
        {
            if (!folder.IsInvalid)
            {
                uint length;
                fixed (char* name = _pathBuffer)
                {
                    length = GetFinalPathNameByHandleW(folder, name, (uint)_pathBuffer.Length, 0);
                }

                if (length > 0 && length < _pathBuffer.Length)
                {
                    path = new string(_pathBuffer, 0, (int)length);
                    path = path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal) ? null
                        : path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
                }
            }
        }

        cache[reference] = path; // a folder deleted since then resolves to null and its entries are skipped
        return path;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool DeviceIoControl(SafeFileHandle device, uint code, byte* input, int inputSize, byte* output, int outputSize, out int returned, IntPtr overlapped);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial SafeFileHandle OpenFileById(SafeFileHandle volumeHint, byte* fileId, uint access, uint share, IntPtr security, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandleW(SafeFileHandle file, char* path, uint length, uint flags);
}
