using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Sentinel.Core;
using Sentinel.Scanning.Native;

namespace Sentinel.Scanning;

/// <summary>Result of attempting to open a file for scanning.</summary>
public readonly record struct OpenResult(SafeFileHandle? Handle, ScanReason FailureReason, string? Message)
{
    public bool Success => Handle is not null;
}

/// <summary>
/// Opens files strictly read-only, without following reparse points, while allowing other processes
/// to keep reading, writing and deleting the file (the scanner must never block the user).
/// </summary>
public static class SafeFileOpener
{
    public static OpenResult Open(string fullPath)
    {
        string extended = PathPolicy.ToExtendedLengthPath(fullPath);
        SafeFileHandle handle = NativeMethods.CreateFile(
            extended,
            NativeMethods.GenericRead,
            NativeMethods.FileShareAll,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagOpenReparsePoint | NativeMethods.FileFlagSequentialScan,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            return new OpenResult(null, MapError(error), new Win32Exception(error).Message);
        }

        // The entry may have been replaced between enumeration and open (for example swapped for a
        // symbolic link). Because the open did not follow reparse points, re-checking the handle's own
        // attributes closes that race: we never read through a link.
        if (!NativeMethods.GetFileInformationByHandleEx(
                handle,
                NativeMethods.FileAttributeTagInfoClass,
                out NativeMethods.FileAttributeTagInfo info,
                (uint)Marshal.SizeOf<NativeMethods.FileAttributeTagInfo>()))
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            return new OpenResult(null, ScanReason.IoError, new Win32Exception(error).Message);
        }

        var attributes = (FileAttributes)info.FileAttributes;
        if ((attributes & FileAttributes.Directory) != 0)
        {
            handle.Dispose();
            return new OpenResult(null, ScanReason.IoError, "Entry became a directory after enumeration.");
        }

        ScanReason policy = PathPolicy.Classify(attributes);
        if (policy != ScanReason.None)
        {
            handle.Dispose();
            return new OpenResult(null, policy, "Entry attributes changed after enumeration.");
        }

        return new OpenResult(handle, ScanReason.None, null);
    }

    /// <summary>Maps a Win32 error code from CreateFile to a scan reason.</summary>
    public static ScanReason MapError(int win32Error) => win32Error switch
    {
        NativeMethods.ErrorFileNotFound or NativeMethods.ErrorPathNotFound or NativeMethods.ErrorInvalidName => ScanReason.NotFound,
        NativeMethods.ErrorAccessDenied or NativeMethods.ErrorCantAccessFile => ScanReason.AccessDenied,
        NativeMethods.ErrorSharingViolation or NativeMethods.ErrorLockViolation => ScanReason.Locked,
        _ => ScanReason.IoError,
    };

    /// <summary>
    /// Returns a stable identity (volume serial + file index) for a directory, without following reparse points.
    /// Returns null if the directory cannot be opened for attribute reads.
    /// </summary>
    internal static (uint Volume, ulong Index)? TryGetDirectoryIdentity(string fullPath)
    {
        using SafeFileHandle handle = NativeMethods.CreateFile(
            PathPolicy.ToExtendedLengthPath(fullPath),
            NativeMethods.FileReadAttributes,
            NativeMethods.FileShareAll,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagOpenReparsePoint,
            IntPtr.Zero);

        if (handle.IsInvalid || !NativeMethods.GetFileInformationByHandle(handle, out NativeMethods.ByHandleFileInformation info))
        {
            return null;
        }

        return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow);
    }
}
