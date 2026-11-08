using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sentinel.Response.Native;

/// <summary>Win32 surface for handle-based removal, restore and DPAPI key protection.</summary>
internal static partial class ResponseNative
{
    internal const uint GenericRead = 0x80000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint Delete = 0x00010000;
    internal const uint FileReadAttributes = 0x0080;

    internal const uint FileShareRead = 0x1;
    internal const uint FileShareNone = 0x0;

    internal const uint CreateNew = 1;
    internal const uint OpenExisting = 3;

    internal const uint FileAttributeNormal = 0x80;
    internal const uint FileFlagOpenReparsePoint = 0x00200000;
    internal const uint FileFlagSequentialScan = 0x08000000;

    internal const int ErrorInvalidFunction = 1;
    internal const int ErrorFileNotFound = 2;
    internal const int ErrorPathNotFound = 3;
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorSharingViolation = 32;
    internal const int ErrorLockViolation = 33;
    internal const int ErrorNotSupported = 50;
    internal const int ErrorFileExists = 80;
    internal const int ErrorInvalidParameter = 87;
    internal const int ErrorInvalidName = 123;
    internal const int ErrorAlreadyExists = 183;
    internal const int ErrorCantAccessFile = 1920;

    internal const int FileDispositionInfoClass = 4;
    internal const int FileAttributeTagInfoClass = 9;
    internal const int FileDispositionInfoExClass = 21;

    internal const uint FileDispositionFlagDelete = 0x1;
    internal const uint FileDispositionFlagPosixSemantics = 0x2;
    internal const uint FileDispositionFlagIgnoreReadonlyAttribute = 0x10;

    internal const uint CryptProtectUiForbidden = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileDispositionInfoEx
    {
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileDispositionInfo
    {
        public byte DeleteFile;
    }

    /// <summary>BY_HANDLE_FILE_INFORMATION (FILETIME members are 4-byte aligned, hence Pack = 4).</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DataBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandleEx(SafeFileHandle file, int fileInformationClass, out FileAttributeTagInfo info, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);

    [LibraryImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetDispositionEx(SafeFileHandle file, int fileInformationClass, in FileDispositionInfoEx info, uint size);

    [LibraryImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetDisposition(SafeFileHandle file, int fileInformationClass, in FileDispositionInfo info, uint size);

    [LibraryImport("crypt32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptProtectData(in DataBlob dataIn, string? description, in DataBlob entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptUnprotectData(in DataBlob dataIn, IntPtr description, in DataBlob entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob dataOut);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr LocalFree(IntPtr memory);

    /// <summary>
    /// Marks an open file for deletion. POSIX semantics remove the name as soon as the handle closes even
    /// if other share-delete handles exist; the read-only attribute is ignored. Falls back to the classic
    /// disposition on file systems without the extended class. Returns 0 or the Win32 error.
    /// </summary>
    internal static int MarkForDeletion(SafeFileHandle handle)
    {
        var ex = new FileDispositionInfoEx
        {
            Flags = FileDispositionFlagDelete | FileDispositionFlagPosixSemantics | FileDispositionFlagIgnoreReadonlyAttribute,
        };
        if (SetDispositionEx(handle, FileDispositionInfoExClass, in ex, (uint)Marshal.SizeOf<FileDispositionInfoEx>()))
        {
            return 0;
        }

        int error = Marshal.GetLastPInvokeError();
        if (error is not (ErrorInvalidParameter or ErrorNotSupported or ErrorInvalidFunction))
        {
            return error;
        }

        var classic = new FileDispositionInfo { DeleteFile = 1 };
        return SetDisposition(handle, FileDispositionInfoClass, in classic, (uint)Marshal.SizeOf<FileDispositionInfo>())
            ? 0
            : Marshal.GetLastPInvokeError();
    }
}
