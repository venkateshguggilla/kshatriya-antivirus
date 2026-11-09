using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Scanning.Native;

/// <summary>Minimal Win32 surface used for safe, read-only file access.</summary>
internal static partial class NativeMethods
{
    internal const uint GenericRead = 0x80000000;
    internal const uint FileReadAttributes = 0x0080;

    internal const uint FileShareRead = 0x1;
    internal const uint FileShareWrite = 0x2;
    internal const uint FileShareDelete = 0x4;
    internal const uint FileShareAll = FileShareRead | FileShareWrite | FileShareDelete;

    internal const uint OpenExisting = 3;

    internal const uint FileFlagBackupSemantics = 0x02000000;
    internal const uint FileFlagOpenReparsePoint = 0x00200000;
    internal const uint FileFlagSequentialScan = 0x08000000;

    internal const int ErrorFileNotFound = 2;
    internal const int ErrorPathNotFound = 3;
    internal const int ErrorAccessDenied = 5;
    internal const int ErrorSharingViolation = 32;
    internal const int ErrorLockViolation = 33;
    internal const int ErrorInvalidName = 123;
    internal const int ErrorVirusInfected = 225;
    internal const int ErrorVirusDeleted = 226;
    internal const int ErrorCantAccessFile = 1920;

    /// <summary>FILE_INFO_BY_HANDLE_CLASS.FileBasicInfo.</summary>
    internal const int FileBasicInfoClass = 0;

    /// <summary>FILE_INFO_BY_HANDLE_CLASS.FileAttributeTagInfo.</summary>
    internal const int FileAttributeTagInfoClass = 9;

    /// <summary>FILE_INFO_BY_HANDLE_CLASS.FileIdInfo.</summary>
    internal const int FileIdInfoClass = 18;

    /// <summary>FILE_BASIC_INFO (LARGE_INTEGER members are 8-byte aligned).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileBasicInfo
    {
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public long ChangeTime;
        public uint FileAttributes;
    }

    /// <summary>FILE_ID_INFO: 64-bit volume serial number and 128-bit file identifier.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        public ulong FileIdLow;
        public ulong FileIdHigh;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    /// <summary>
    /// BY_HANDLE_FILE_INFORMATION. The FILETIME members are pairs of DWORDs with 4-byte alignment, so the
    /// struct must be packed to 4: with natural 8-byte alignment of <see cref="long"/> every field after
    /// <c>FileAttributes</c> would be read from the wrong offset.
    /// </summary>
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
    internal static partial bool GetFileInformationByHandleEx(
        SafeFileHandle file,
        int fileInformationClass,
        out FileAttributeTagInfo fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileBasicInfo(
        SafeFileHandle file,
        int fileInformationClass,
        out FileBasicInfo fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileIdInfo(
        SafeFileHandle file,
        int fileInformationClass,
        out FileIdInfo fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);
}
