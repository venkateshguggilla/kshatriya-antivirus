using System.ComponentModel;
using System.Runtime.InteropServices;
using Kshatriya.Engines;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Scanning.Native;

/// <summary>A read-only file-mapping (section) handle.</summary>
public sealed class SafeSectionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeSectionHandle()
        : base(ownsHandle: true)
    {
    }

    public SafeSectionHandle(IntPtr handle, bool ownsHandle)
        : base(ownsHandle) => SetHandle(handle);

    protected override bool ReleaseHandle() => FileMapping.CloseHandle(handle);
}

/// <summary>
/// Read-only memory mapping of a file that was already opened through <see cref="SafeFileOpener"/>. Lets
/// files far larger than memory be scanned: pages are read on demand and are file-backed, so they do not
/// count as private memory (the sandboxed worker's memory cap stays meaningful). While a section exists the
/// file cannot be truncated below its mapped size, so a mapped view never shrinks under a reader.
/// </summary>
public static partial class FileMapping
{
    /// <summary>Access right that allows read-only views (FILE_MAP_READ).</summary>
    public const uint MapRead = 0x0004;

    private const uint PageReadOnly = 0x02;

    /// <summary>Creates a read-only section for the whole file (which must not be empty).</summary>
    public static SafeSectionHandle CreateReadOnlySection(SafeFileHandle file)
    {
        ArgumentNullException.ThrowIfNull(file);
        SafeSectionHandle section = CreateFileMappingW(file, IntPtr.Zero, PageReadOnly, 0, 0, IntPtr.Zero);
        if (section.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            section.Dispose();
            throw new IOException($"The file could not be mapped for reading: {new Win32Exception(error).Message}", error);
        }

        return section;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, EntryPoint = "CreateFileMappingW")]
    private static partial SafeSectionHandle CreateFileMappingW(SafeFileHandle file, IntPtr attributes, uint protect, uint maximumSizeHigh, uint maximumSizeLow, IntPtr name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static unsafe partial void* MapViewOfFile(SafeSectionHandle section, uint access, uint offsetHigh, uint offsetLow, nuint bytes);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool UnmapViewOfFile(void* address);

    [LibraryImport("kernel32.dll")]
    internal static unsafe partial nuint VirtualQuery(void* address, MemoryBasicInformation* buffer, nuint length);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nuint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}

/// <summary>A mapped read-only view of a whole section, exposed as <see cref="ContentMemory"/> and as a stream.</summary>
public sealed unsafe class MappedView : IDisposable
{
    private void* _address;

    private MappedView(void* address, long length)
    {
        _address = address;
        Memory = new ContentMemory((byte*)address, length);
    }

    public ContentMemory Memory { get; }

    /// <summary>
    /// Maps <paramref name="section"/> and checks that the view covers <paramref name="length"/> bytes, so
    /// reading the content can never run past the view.
    /// </summary>
    public static MappedView Map(SafeSectionHandle section, long length)
    {
        ArgumentNullException.ThrowIfNull(section);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        void* address = FileMapping.MapViewOfFile(section, FileMapping.MapRead, 0, 0, 0);
        if (address is null)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new IOException($"The file could not be mapped for reading: {new Win32Exception(error).Message}", error);
        }

        FileMapping.MemoryBasicInformation info;
        if (FileMapping.VirtualQuery(address, &info, (nuint)sizeof(FileMapping.MemoryBasicInformation)) == 0 || (ulong)info.RegionSize < (ulong)length)
        {
            FileMapping.UnmapViewOfFile(address);
            throw new IOException("The mapped view is smaller than the content length; the file changed while it was being scanned.");
        }

        return new MappedView(address, length);
    }

    /// <summary>A read-only stream over the view (for archive expansion and stream-based engines).</summary>
    public UnmanagedMemoryStream OpenStream() => new(Memory.Start, Memory.Length, Memory.Length, FileAccess.Read);

    public void Dispose()
    {
        if (_address is not null)
        {
            FileMapping.UnmapViewOfFile(_address);
            _address = null;
        }
    }
}
