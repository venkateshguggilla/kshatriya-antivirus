using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Service.DeviceLock;

/// <summary>
/// Disk arrival notifications and device enable/disable through the Configuration Manager API (cfgmgr32), as
/// the service (ADR 0023). Constants and layouts are from the Windows SDK headers (cfgmgr32.h, 10.0.26100.0).
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed unsafe partial class WindowsDeviceControl : IDeviceControl
{
    /// <summary>GUID_DEVINTERFACE_DISK.</summary>
    private static readonly Guid s_diskInterface = new("53f56307-b6bf-11d0-94f2-00a0c91efb8b");

    private const uint CrSuccess = 0;
    private const uint CrRemoveVetoed = 0x17;
    private const uint CmDisableUiNotOk = 0x4; // CM_DISABLE_POLITE (0) | CM_DISABLE_UI_NOT_OK; no CM_DISABLE_PERSIST
    private const uint CmNotifyFilterTypeDeviceInterface = 0;
    private const uint CmNotifyActionDeviceInterfaceArrival = 0;
    private const int MaxDeviceIdLength = 200;
    private const uint IoctlStorageGetDeviceNumber = 0x2D1080;
    private const uint IoctlDiskGetLengthInfo = 0x7405C;

    private static readonly DevPropKey s_instanceIdKey = new(new Guid("78c34fc8-104a-4aca-9ea4-524d52996e57"), 256);
    private static readonly DevPropKey s_friendlyNameKey = new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 14);
    private static readonly DevPropKey s_deviceDescKey = new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 2);

    private readonly object _gate = new();
    private IntPtr _notification;
    private GCHandle _self;
    private Action<string>? _arrived;

    public void StartNotifications(Action<string> arrived)
    {
        lock (_gate)
        {
            if (_notification != IntPtr.Zero)
            {
                return;
            }

            _arrived = arrived;
            _self = GCHandle.Alloc(this);
            var filter = new CmNotifyFilter { Size = (uint)sizeof(CmNotifyFilter), FilterType = CmNotifyFilterTypeDeviceInterface, ClassGuid = s_diskInterface };
            uint result = CM_Register_Notification(&filter, GCHandle.ToIntPtr(_self), &OnNotification, out _notification);
            if (result != CrSuccess)
            {
                _self.Free();
                _notification = IntPtr.Zero;
                throw new InvalidOperationException($"Disk notifications could not be registered (CONFIGRET 0x{result:X}).");
            }
        }
    }

    public void StopNotifications()
    {
        lock (_gate)
        {
            if (_notification == IntPtr.Zero)
            {
                return;
            }

            _ = CM_Unregister_Notification(_notification);
            _notification = IntPtr.Zero;
            _self.Free();
            _arrived = null;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static uint OnNotification(IntPtr notify, IntPtr context, uint action, IntPtr eventData, uint eventDataSize)
    {
        // CM_NOTIFY_EVENT_DATA: FilterType (4), Reserved (4), ClassGuid (16), then the symbolic link.
        if (action != CmNotifyActionDeviceInterfaceArrival || eventDataSize <= 24 || context == IntPtr.Zero)
        {
            return 0;
        }

        try
        {
            if (GCHandle.FromIntPtr(context).Target is WindowsDeviceControl self && self._arrived is { } arrived)
            {
                string? link = Marshal.PtrToStringUni(eventData + 24);
                if (link is not null && InstanceIdOf(link) is { } id)
                {
                    // Never block the notification thread: the work (and any CM call) runs elsewhere.
                    ThreadPool.QueueUserWorkItem(_ => arrived(id));
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            // Ignore: a malformed notification must not take the service down.
        }

        return 0;
    }

    public IReadOnlyList<string> PresentDisks()
    {
        var ids = new List<string>();
        foreach (string link in InterfaceList(s_diskInterface))
        {
            if (InstanceIdOf(link) is { } id)
            {
                ids.Add(id);
            }
        }

        return ids;
    }

    public DiskInfo? Describe(string instanceId)
    {
        if (!TryLocate(instanceId, out uint devInst))
        {
            return null;
        }

        bool usb = instanceId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase);
        uint current = devInst;
        for (int depth = 0; depth < 16 && !usb; depth++)
        {
            if (CM_Get_Parent(out uint parent, current, 0) != CrSuccess)
            {
                break;
            }

            string? parentId = DeviceId(parent);
            usb = parentId is not null && (parentId.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase) || parentId.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase));
            current = parent;
        }

        string name = StringProperty(devInst, s_friendlyNameKey) ?? StringProperty(devInst, s_deviceDescKey) ?? "USB drive";
        string? link = InterfaceList(s_diskInterface).FirstOrDefault(l => string.Equals(InstanceIdOf(l), instanceId, StringComparison.OrdinalIgnoreCase));
        int? number = link is null ? null : DiskNumber(link);
        long? size = link is null ? null : DiskLength(link);

        // Fail safe: a disk whose number cannot be read, or any disk when the protected disks cannot all be
        // identified, is treated as protected and never locked.
        HashSet<int>? protectedDisks = ProtectedDiskNumbers();
        bool isProtected = number is null || protectedDisks is null || protectedDisks.Contains(number.Value);
        return new DiskInfo(instanceId, name, size, usb, isProtected);
    }

    public bool IsPresent(string instanceId) => TryLocate(instanceId, out _);

    public string? Disable(string instanceId)
    {
        if (!TryLocate(instanceId, out uint devInst))
        {
            return "The drive is no longer connected.";
        }

        uint result = CM_Disable_DevNode(devInst, CmDisableUiNotOk);
        return result switch
        {
            CrSuccess => null,
            CrRemoveVetoed => "The drive is in use (a program has files open on it).",
            _ => $"Windows refused (CONFIGRET 0x{result:X}).",
        };
    }

    public string? Enable(string instanceId)
    {
        if (!TryLocate(instanceId, out uint devInst))
        {
            return "The drive is no longer connected.";
        }

        uint result = CM_Enable_DevNode(devInst, 0);
        return result == CrSuccess ? null : $"Windows refused (CONFIGRET 0x{result:X}).";
    }

    public void Dispose() => StopNotifications();

    /// <summary>
    /// Disk numbers holding Windows, Kshatriya's program folder or its data folder; null when any of them cannot
    /// be identified (for example a volume spanning several disks), which makes every disk protected.
    /// </summary>
    private static HashSet<int>? ProtectedDiskNumbers()
    {
        var numbers = new HashSet<int>();
        string[] paths =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            AppContext.BaseDirectory,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        ];
        foreach (string root in paths.Select(Path.GetPathRoot).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (DiskNumber(@"\\.\" + root.TrimEnd('\\')) is not { } n)
            {
                return null;
            }

            numbers.Add(n);
        }

        return numbers;
    }

    private static int? DiskNumber(string path)
    {
        using SafeFileHandle handle = CreateFileW(path, 0, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return null;
        }

        StorageDeviceNumber number;
        return DeviceIoControl(handle, IoctlStorageGetDeviceNumber, IntPtr.Zero, 0, &number, (uint)sizeof(StorageDeviceNumber), out _, IntPtr.Zero)
            ? (int)number.DeviceNumber
            : null;
    }

    private static long? DiskLength(string link)
    {
        using SafeFileHandle handle = CreateFileW(link, 0x80000000 /* GENERIC_READ */, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return null;
        }

        long length;
        return DeviceIoControl(handle, IoctlDiskGetLengthInfo, IntPtr.Zero, 0, &length, sizeof(long), out _, IntPtr.Zero) ? length : null;
    }

    private static bool TryLocate(string instanceId, out uint devInst) =>
        CM_Locate_DevNodeW(out devInst, instanceId, 0) == CrSuccess;

    private static string? DeviceId(uint devInst)
    {
        char* buffer = stackalloc char[MaxDeviceIdLength + 1];
        return CM_Get_Device_IDW(devInst, buffer, MaxDeviceIdLength + 1, 0) == CrSuccess ? new string(buffer) : null;
    }

    private static string? StringProperty(uint devInst, DevPropKey key)
    {
        byte* buffer = stackalloc byte[1024];
        uint size = 1024;
        DevPropKey k = key;
        return CM_Get_DevNode_PropertyW(devInst, &k, out _, buffer, ref size, 0) == CrSuccess && size >= 2
            ? new string((char*)buffer, 0, (int)(size / 2)).TrimEnd('\0')
            : null;
    }

    private static string? InstanceIdOf(string link)
    {
        byte* buffer = stackalloc byte[(MaxDeviceIdLength + 1) * 2];
        uint size = (MaxDeviceIdLength + 1) * 2;
        DevPropKey key = s_instanceIdKey;
        return CM_Get_Device_Interface_PropertyW(link, &key, out _, buffer, ref size, 0) == CrSuccess && size >= 2
            ? new string((char*)buffer, 0, (int)(size / 2)).TrimEnd('\0')
            : null;
    }

    private static List<string> InterfaceList(Guid interfaceClass)
    {
        Guid g = interfaceClass;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (CM_Get_Device_Interface_List_SizeW(out uint length, &g, null, 0) != CrSuccess || length == 0)
            {
                return [];
            }

            char[] buffer = new char[length];
            fixed (char* p = buffer)
            {
                uint result = CM_Get_Device_Interface_ListW(&g, null, p, length, 0);
                if (result == 0x1A /* CR_BUFFER_SMALL: a disk arrived meanwhile */)
                {
                    continue;
                }

                if (result != CrSuccess)
                {
                    return [];
                }
            }

            return [.. new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries)];
        }

        return [];
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DevPropKey(Guid fmtid, uint pid)
    {
        public readonly Guid Fmtid = fmtid;
        public readonly uint Pid = pid;
    }

    /// <summary>CM_NOTIFY_FILTER: 16-byte header, then a union whose largest member is WCHAR[200].</summary>
    [StructLayout(LayoutKind.Explicit, Size = 416)]
    private struct CmNotifyFilter
    {
        [FieldOffset(0)]
        public uint Size;

        [FieldOffset(4)]
        public uint Flags;

        [FieldOffset(8)]
        public uint FilterType;

        [FieldOffset(12)]
        public uint Reserved;

        [FieldOffset(16)]
        public Guid ClassGuid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StorageDeviceNumber
    {
        public uint DeviceType;
        public uint DeviceNumber;
        public uint PartitionNumber;
    }

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Register_Notification(CmNotifyFilter* filter, IntPtr context, delegate* unmanaged[Stdcall]<IntPtr, IntPtr, uint, IntPtr, uint, uint> callback, out IntPtr notifyContext);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Unregister_Notification(IntPtr notifyContext);

    [LibraryImport("cfgmgr32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint CM_Locate_DevNodeW(out uint devInst, string deviceId, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Get_Parent(out uint parent, uint devInst, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Get_Device_IDW(uint devInst, char* buffer, uint bufferLength, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Get_DevNode_PropertyW(uint devInst, DevPropKey* key, out uint type, byte* buffer, ref uint size, uint flags);

    [LibraryImport("cfgmgr32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint CM_Get_Device_Interface_PropertyW(string deviceInterface, DevPropKey* key, out uint type, byte* buffer, ref uint size, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Get_Device_Interface_List_SizeW(out uint length, Guid* interfaceClass, char* deviceId, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Get_Device_Interface_ListW(Guid* interfaceClass, char* deviceId, char* buffer, uint bufferLength, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Disable_DevNode(uint devInst, uint flags);

    [LibraryImport("cfgmgr32.dll")]
    private static partial uint CM_Enable_DevNode(uint devInst, uint flags);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeviceIoControl(SafeFileHandle device, uint code, IntPtr input, uint inputSize, void* output, uint outputSize, out uint returned, IntPtr overlapped);
}
