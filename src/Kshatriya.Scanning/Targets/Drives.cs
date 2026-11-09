using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Kshatriya.Scanning.Targets;

/// <summary>A drive that can be scanned.</summary>
/// <param name="Root">Drive root, for example <c>E:\</c>.</param>
/// <param name="IsExternal">USB, SD/MMC or FireWire storage, or media Windows marks removable.</param>
/// <param name="Label">For people: letter, kind, volume label, device name and size.</param>
public sealed record DriveDescription(string Root, bool IsExternal, string Label);

/// <summary>
/// Lists the local drives and tells internal disks from external ones. Windows reports USB hard disks and
/// SSDs as fixed drives, so the connection type (bus) is read from the storage driver as well.
/// </summary>
public static partial class Drives
{
    // STORAGE_BUS_TYPE values (winioctl.h).
    internal const int Bus1394 = 4;
    internal const int BusUsb = 7;
    internal const int BusSd = 0xC;
    internal const int BusMmc = 0xD;

    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const uint ShareReadWrite = 0x3;
    private const uint OpenExisting = 3;

    /// <summary>External storage: removable media, or a disk attached over USB, SD/MMC or FireWire.</summary>
    public static bool IsExternal(DriveType type, int busType) =>
        type == DriveType.Removable || busType is BusUsb or Bus1394 or BusSd or BusMmc;

    /// <summary>Ready fixed and removable drives (network and optical drives are not offered).</summary>
    public static IReadOnlyList<DriveDescription> Local()
    {
        var drives = new List<DriveDescription>();
        foreach (DriveInfo drive in DriveInfo.GetDrives().Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable))
        {
            try
            {
                if (!drive.IsReady || !PathPolicy.IsLocalAbsolutePath(drive.RootDirectory.FullName))
                {
                    continue;
                }

                (int bus, string? product) = QueryDevice(drive.Name);
                bool external = IsExternal(drive.DriveType, bus);
                drives.Add(new DriveDescription(drive.RootDirectory.FullName, external, Describe(drive, external, bus, product)));
            }
            catch (IOException)
            {
                // Removed or not ready while listing.
            }
        }

        return drives;
    }

    /// <summary>Roots of the connected, ready external drives (cheap enough to poll every few seconds).</summary>
    public static IReadOnlyList<string> ExternalRoots()
    {
        var roots = new List<string>();
        foreach (DriveInfo drive in DriveInfo.GetDrives().Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable))
        {
            try
            {
                if (drive.IsReady && PathPolicy.IsLocalAbsolutePath(drive.RootDirectory.FullName) && IsExternal(drive.DriveType, QueryDevice(drive.Name).Bus))
                {
                    roots.Add(drive.RootDirectory.FullName);
                }
            }
            catch (IOException)
            {
                // Removed or not ready while listing.
            }
        }

        return roots;
    }

    private static string Describe(DriveInfo drive, bool external, int bus, string? product)
    {
        string kind = !external ? "Local disk"
            : bus switch
            {
                BusUsb => "External drive (USB)",
                BusSd or BusMmc => "Memory card",
                Bus1394 => "External drive (FireWire)",
                _ => "Removable drive",
            };
        string name = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? string.Empty : $" \"{drive.VolumeLabel}\"";
        string device = external && !string.IsNullOrWhiteSpace(product) ? $" {product}" : string.Empty;
        return $"{drive.Name.TrimEnd('\\')}  {kind}{name}{device}, {Size(drive.TotalSize)}";
    }

    private static string Size(long bytes) => bytes >= 1_000_000_000 ? $"{bytes / 1e9:N0} GB" : $"{bytes / 1e6:N0} MB";

    /// <summary>The bus type and product name of the device behind a drive; (0, null) when unknown.</summary>
    private static unsafe (int Bus, string? Product) QueryDevice(string root)
    {
        // No access rights are needed for this query, so it works without administrator rights.
        using SafeFileHandle volume = CreateFileW(@"\\.\" + root.TrimEnd('\\'), 0, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (volume.IsInvalid)
        {
            return (0, null);
        }

        byte* query = stackalloc byte[12]; // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
        new Span<byte>(query, 12).Clear();
        byte[] output = new byte[1024];
        fixed (byte* buffer = output)
        {
            if (!DeviceIoControl(volume, IoctlStorageQueryProperty, query, 12, buffer, output.Length, out int returned, IntPtr.Zero) || returned < 36)
            {
                return (0, null);
            }

            // STORAGE_DEVICE_DESCRIPTOR: ProductIdOffset at 16, BusType at 28.
            var descriptor = new ReadOnlySpan<byte>(buffer, returned);
            int bus = BinaryPrimitives.ReadInt32LittleEndian(descriptor[28..]);
            int productOffset = BinaryPrimitives.ReadInt32LittleEndian(descriptor[16..]);
            string? product = null;
            if (productOffset > 0 && productOffset < returned)
            {
                ReadOnlySpan<byte> text = descriptor[productOffset..];
                int end = text.IndexOf((byte)0);
                product = Encoding.ASCII.GetString(end < 0 ? text : text[..end]).Trim();
            }

            return (bus, string.IsNullOrEmpty(product) ? null : product);
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool DeviceIoControl(SafeFileHandle device, uint code, byte* input, int inputSize, byte* output, int outputSize, out int returned, IntPtr overlapped);
}
